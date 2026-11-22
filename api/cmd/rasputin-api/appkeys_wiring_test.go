package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-1084-31: under openbao the store CA's sweeper registers the key leaf,
// openbao-app-keys, clientAuth with CN rasputin-app-keys, chained to the store
// CA; it is required only with the store selected, and a configuration that
// does not register it is refused naming it. Its reload closes the key
// client's idle connections and leaves the kv client's alone.
func TestStoreAppKeysLeaf(t *testing.T) {
	clock := &testClock{now: time.Now()}
	deps := tlsca.Deps{Now: clock.Now, Rand: rand.Reader, Log: slog.New(slog.DiscardHandler)}
	ca := ensureStoreCA(t, t.TempDir(), deps)
	certPEM, key, err := ca.MintLeaf(storeServerLeafSpec())
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(certPEM, key.Reveal())
	key.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	// handshakes counts new connections by the client leaf's CommonName.
	var mu sync.Mutex
	handshakes := map[string]int{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false,"version":"2.7.2"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: pool, MinVersion: tls.VersionTLS13, Time: clock.Now,
		VerifyConnection: func(cs tls.ConnectionState) error {
			mu.Lock()
			handshakes[cs.PeerCertificates[0].Subject.CommonName]++
			mu.Unlock()
			return nil
		}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	dataDir := t.TempDir()
	w, err := wireSecretStore(t.Context(), slog.New(slog.DiscardHandler), "openbao", srv.URL, ca, dataDir, (&recordedRun{}).run, noRestartHook)
	if err != nil || w.mode != storeModeOpenBao {
		t.Fatalf("wireSecretStore = %v, %v; want openbao", w.mode, err)
	}
	keyClient, ok := w.keyTransit.(*secretstore.Client)
	if !ok || any(w.keyLogin) != any(keyClient) || keyClient == w.client {
		t.Fatalf("keyTransit = %T, keyLogin = %T: want one client of its own", w.keyTransit, w.keyLogin)
	}
	t.Cleanup(keyClient.CloseIdleConnections)
	t.Cleanup(w.client.CloseIdleConnections)
	if !slices.Contains(w.registeredNames(), storeAppKeysLeafName) {
		t.Fatalf("registered = %v, want %s", w.registeredNames(), storeAppKeysLeafName)
	}
	waitSweep(t, startLeafSweep(t.Context(), w.sweeper, slog.New(slog.DiscardHandler), "secretstore"))
	leafPEM := filepath.Join(dataDir, "tls", storeAppKeysLeafName, "leaf.pem")
	leaf := parseLeaf(t, leafPEM)
	if leaf.Subject.CommonName != "rasputin-app-keys" || !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Errorf("key leaf CN %q EKU %v; want rasputin-app-keys, clientAuth", leaf.Subject.CommonName, leaf.ExtKeyUsage)
	}
	if err := verifyAgainst(leaf, ca.CertPEM, x509.ExtKeyUsageClientAuth); err != nil {
		t.Errorf("the key leaf does not chain to the store CA: %v", err)
	}

	k, err := secretstore.NewTransitKey("rasputin-app-keys", "k")
	if err != nil {
		t.Fatal(err)
	}
	calls := func() {
		t.Helper()
		if _, err := w.store.Health(t.Context()); err != nil {
			t.Fatalf("kv client: %v", err)
		}
		if err := keyClient.TransitCreateKey(t.Context(), secret.New([]byte("t")), k); err != nil {
			t.Fatalf("key client: %v", err)
		}
	}
	calls()
	calls() // kept-alive connections serve the second pair
	// Only the key leaf is re-minted: its files are gone, so the sweep mints
	// it and runs its reload, and no other leaf's.
	if err := os.RemoveAll(filepath.Join(dataDir, "tls", storeAppKeysLeafName)); err != nil {
		t.Fatal(err)
	}
	rep := w.sweeper.Sweep(t.Context(), func(string, string) {})
	if !slices.Equal(rep.Reloaded, []string{storeAppKeysLeafName}) {
		t.Fatalf("sweep report %+v, want only %s reloaded", rep, storeAppKeysLeafName)
	}
	calls()
	mu.Lock()
	got := map[string]int{storeClientCN: handshakes[storeClientCN], storeAppKeysCN: handshakes[storeAppKeysCN]}
	mu.Unlock()
	if got[storeClientCN] != 1 || got[storeAppKeysCN] != 2 {
		t.Errorf("handshakes by CN %v; want the kv client's connection kept (1) and the key client's re-made (2)", got)
	}

	if !slices.Contains(requiredLeafConsumers(false, false, true), storeAppKeysLeafName) {
		t.Error("the key leaf is not required with the store selected")
	}
	if slices.Contains(requiredLeafConsumers(true, true, false), storeAppKeysLeafName) {
		t.Error("the key leaf is required with the store off or the mock")
	}
	var without []string
	for _, n := range w.registeredNames() {
		if n != storeAppKeysLeafName {
			without = append(without, n)
		}
	}
	if err := verifyLeafConsumers(without, requiredLeafConsumers(false, false, true)); err == nil || !strings.Contains(err.Error(), storeAppKeysLeafName) {
		t.Errorf("verifyLeafConsumers without the key leaf = %v, want an error naming %s", err, storeAppKeysLeafName)
	}
	for _, backend := range []string{"", storeModeMock} {
		off, err := wireSecretStore(t.Context(), slog.New(slog.DiscardHandler), backend, defaultSecretStoreAddr, ensureStoreCA(t, t.TempDir(), tlscatest.Deps()), t.TempDir(), (&recordedRun{}).run, noRestartHook)
		if err != nil || off.keyLogin == nil || off.keyTransit == nil || len(off.registeredNames()) != 0 {
			t.Errorf("%q: key login %T, transit %T, registered %v, err %v; want both set and no leaf", backend, off.keyLogin, off.keyTransit, off.registeredNames(), err)
		}
	}
}

// observerSpy counts the login outcomes it is told.
type observerSpy struct {
	mu  sync.Mutex
	got []error
}

func (o *observerSpy) ObserveAudited(_ context.Context, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.got = append(o.got, err)
}

func (o *observerSpy) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.got)
}

// refusedLogin is a store that refuses every login, as a store initialised
// before rasputin-app-keys does the key identity's.
type refusedLogin struct{}

func (refusedLogin) CertLogin(context.Context, string) (secret.Value, error) {
	return secret.Value{}, &secretstore.Error{Op: "login", Status: http.StatusBadRequest, Kind: secretstore.ErrDenied}
}

// unreachableTransit fails every Transit call as an unreachable store.
type unreachableTransit struct{ secretstore.Disabled }

func (unreachableTransit) TransitCreateKey(context.Context, secret.Value, secretstore.TransitKey) error {
	return &secretstore.Error{Op: "transit_create", Kind: secretstore.ErrUnreachable, Err: net.ErrClosed}
}

// TC-1084-32: the key session has no readiness observer. A refused key login
// and a key call that fails unreachable reach no observer; the kv session's
// login still reports to the monitor's observer.
func TestStoreKeySession_StaysOffReadiness(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	obs := &observerSpy{}
	m := secretstore.NewMock(time.Now)
	kv, err := storeSessionWiring(m, m, obs, log)
	if err != nil {
		t.Fatal(err)
	}
	k, err := secretstore.NewTransitKey("rasputin-app-keys", "k")
	if err != nil {
		t.Fatal(err)
	}
	refused, err := storeKeySessionWiring(refusedLogin{}, secretstore.Disabled{}, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := refused.TransitCreateKey(t.Context(), k); !errors.Is(err, secretstore.ErrDenied) {
		t.Fatalf("a key call on a refused login = %v, want ErrDenied", err)
	}
	down, err := storeKeySessionWiring(m, unreachableTransit{}, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := down.TransitCreateKey(t.Context(), k); !errors.Is(err, secretstore.ErrUnreachable) {
		t.Fatalf("a key call on an unreachable store = %v, want ErrUnreachable", err)
	}
	if n := obs.count(); n != 0 {
		t.Fatalf("the readiness observer got %d observations from the key session, want 0", n)
	}
	p, _ := secretstore.NewKVPath("rasputin-secrets", "apps/x")
	_, _ = kv.Read(t.Context(), p, 0)
	if n := obs.count(); n != 1 {
		t.Errorf("the kv session's login reported %d times, want 1", n)
	}
	d := secretstore.Disabled{}
	if _, err := storeKeySessionWiring(nil, d, log); err == nil {
		t.Error("a nil login was accepted")
	}
	if _, err := storeKeySessionWiring(d, nil, log); err == nil {
		t.Error("a nil Transit store was accepted")
	}
	if _, err := storeKeySessionWiring(d, d, nil); err == nil {
		t.Error("a nil logger was accepted")
	}
}
