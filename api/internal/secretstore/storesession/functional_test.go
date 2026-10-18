package storesession_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The functional switch and binary are the smoke test's
// (docs/testing-secret-store.md): CI installs the pinned release and sets
// RASPUTIN_SECRETSTORE_FUNCTIONAL=required, so a missing binary fails the
// backend job instead of skipping.
const (
	binEnv    = "RASPUTIN_SECRETSTORE_BIN"
	switchEnv = "RASPUTIN_SECRETSTORE_FUNCTIONAL"
)

const (
	// revokerRole is a test-only role whose token may revoke another token.
	revokerRole = "revoker"
	// expiringRole is a test-only role with the api's policy and a short
	// token_ttl, so a token it issues expires during the test.
	expiringRole = "rasputin-api-expiring"
	// expiringTTL is that role's token_ttl.
	expiringTTL = 2 * time.Second
	// expiryDeadline bounds the wait for the store to refuse the expired
	// token. It is many times expiringTTL; the wait ends on the refusal.
	expiryDeadline = 30 * time.Second
	// expiryRecheck paces the re-asks during that wait.
	expiryRecheck = 250 * time.Millisecond
	// valueText is the secret the test writes and reads back.
	valueText = "sentinel-session-value-41d2"
)

// capturingStore forwards to the observed store, keeps a copy of the last
// token it carried, and keeps every error the store returned.
type capturingStore struct {
	inner storesession.Store

	mu     sync.Mutex
	last   secret.Value
	toks   []string
	denied int
	errs   []error
}

func (c *capturingStore) seen(tok secret.Value, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = secret.New(tok.Reveal())
	c.toks = append(c.toks, string(tok.Reveal()))
	if err != nil {
		c.errs = append(c.errs, err)
		if errors.Is(err, secretstore.ErrDenied) {
			c.denied++
		}
	}
}

func (c *capturingStore) Read(ctx context.Context, tok secret.Value, p secretstore.KVPath, v int) (secretstore.KV, error) {
	kv, err := c.inner.Read(ctx, tok, p, v)
	c.seen(tok, err)
	return kv, err
}

func (c *capturingStore) Write(ctx context.Context, tok secret.Value, p secretstore.KVPath, d map[string]secret.Value, cas int) (int, error) {
	n, err := c.inner.Write(ctx, tok, p, d, cas)
	c.seen(tok, err)
	return n, err
}

func (c *capturingStore) Versions(ctx context.Context, tok secret.Value, p secretstore.KVPath) (secretstore.Metadata, error) {
	m, err := c.inner.Versions(ctx, tok, p)
	c.seen(tok, err)
	return m, err
}

func (c *capturingStore) lastToken() secret.Value {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

func (c *capturingStore) deniedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.denied
}

// realSession is a Session over the production client for role, a real
// Monitor and ObservedStore, a counting login and a capturing store.
type realSession struct {
	sess    *storesession.Session
	client  *secretstore.Client
	login   *countingLogin
	capture *capturingStore
	leafKey []string
}

func newRealSession(t *testing.T, s *secretstoretest.Store, role string, logger *slog.Logger) realSession {
	t.Helper()
	tc, err := s.ClientTLSFor(role)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	client, err := secretstore.New(secretstore.Config{Addr: u, TLS: tc, CallTimeout: 10 * time.Second, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	monitor, err := storestate.New(storestate.Deps{
		Store: client, Now: time.Now, Log: logger,
		JobRunning: func(context.Context, string) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := storestate.NewObservedStore(client, monitor)
	if err != nil {
		t.Fatal(err)
	}
	rs := realSession{client: client, login: &countingLogin{inner: client}, capture: &capturingStore{inner: observed}}
	rs.sess, err = storesession.New(storesession.Config{
		Role: role, Login: rs.login, Store: rs.capture, Observer: monitor, Log: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	rs.leafKey = leafKeyRenderings(t, tc)
	return rs
}

// leafKeyRenderings are the client leaf's private key as PEM body lines and
// whole base64, in both the PKCS#8 and SEC 1 encodings.
func leafKeyRenderings(t *testing.T, tc *tls.Config) []string {
	t.Helper()
	cert, err := tc.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	p8, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	ders := [][]byte{p8}
	if k, ok := cert.PrivateKey.(*ecdsa.PrivateKey); ok {
		sec1, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		ders = append(ders, sec1)
	}
	for _, der := range ders {
		out = append(out, base64.StdEncoding.EncodeToString(der))
		out = append(out, pemLines(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))...)
	}
	return out
}

// TC-759-17: the session against the pinned OpenBao. One login serves a write
// and two reads; a token revoked mid-run (T60) is refused once and the next
// read re-logs in once and returns the value. F-759-03: a token past its
// role's token_ttl (T61) is refused, and the session's next call re-logs in
// exactly once and succeeds. No token and no leaf key reaches a log record or
// an error rendering.
func TestSession_AgainstTheRealStore(t *testing.T) {
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return
	}
	apiPolicy, err := storepolicy.Text(storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	log, rec := logkittest.New()
	logger := slog.New(slog.NewMultiHandler(log.Handler(), slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug})))
	h, err := secretstoretest.New(secretstoretest.Config{
		BinaryPath: bin, TempParent: t.TempDir(), Logger: logger, Now: time.Now, Rand: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.StartWith(t.Context(), secretstoretest.Bootstrap{Mount: storepolicy.Mount, Roles: []secretstoretest.Role{
		{Name: role, Policy: storepolicy.APIPolicy, PolicyText: apiPolicy},
		{Name: revokerRole, Policy: revokerRole, PolicyText: []byte(`path "auth/token/revoke" { capabilities = ["update"] }` + "\n")},
		{Name: expiringRole, Policy: storepolicy.APIPolicy, PolicyText: apiPolicy, TokenTTL: expiringTTL},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// t.Context() is cancelled before Cleanup runs; Background lets the store
	// stop cleanly.
	t.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			t.Errorf("cleanup Close: %v", err)
		}
	})

	var secrets []string
	var errs []error
	api := newRealSession(t, s, role, logger)
	secrets = append(secrets, api.leafKey...)
	p, err := secretstore.NewKVPath(storepolicy.Mount, "apps/session-f14")
	if err != nil {
		t.Fatal(err)
	}
	readBack := func(t *testing.T, rs realSession, p secretstore.KVPath) {
		t.Helper()
		kv, err := rs.sess.Read(t.Context(), p, 0)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		defer kv.Destroy()
		if got := string(kv.Data["k"].Reveal()); got != valueText {
			t.Fatalf("read back %d bytes, want the value written", len(got))
		}
	}

	t.Run("write then read: one login", func(t *testing.T) {
		if _, err := api.sess.Write(t.Context(), p, map[string]secret.Value{"k": secret.New([]byte(valueText))}, 0); err != nil {
			t.Fatalf("Write: %v", err)
		}
		readBack(t, api, p)
		if n := api.login.n.Load(); n != 1 {
			t.Fatalf("logins = %d, want 1", n)
		}
	})

	t.Run("read again: still one login", func(t *testing.T) {
		readBack(t, api, p)
		if n := api.login.n.Load(); n != 1 {
			t.Fatalf("logins = %d, want 1", n)
		}
	})

	t.Run("T60 revoked token: one 403, one re-login", func(t *testing.T) {
		revoked := api.capture.lastToken()
		secrets = append(secrets, string(revoked.Reveal()))
		revoke(t, s, revoked, &secrets)
		readBack(t, api, p)
		if n, d := api.login.n.Load(), api.capture.deniedCount(); n != 2 || d != 1 {
			t.Fatalf("logins = %d, 403s = %d; want 2 and 1", n, d)
		}
		secrets = append(secrets, string(api.capture.lastToken().Reveal()))
	})

	t.Run("T61 token past its TTL: refused, then one re-login", func(t *testing.T) {
		exp := newRealSession(t, s, expiringRole, logger)
		secrets = append(secrets, exp.leafKey...)
		ep, err := secretstore.NewKVPath(storepolicy.Mount, "apps/session-expiry")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := exp.sess.Write(t.Context(), ep, map[string]secret.Value{"k": secret.New([]byte(valueText))}, 0); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if n := exp.login.n.Load(); n != 1 {
			t.Fatalf("logins = %d, want 1", n)
		}
		old := exp.capture.lastToken()
		secrets = append(secrets, string(old.Reveal()))
		errs = append(errs, waitRefused(t, exp.client, old, ep))
		readBack(t, exp, ep)
		if n, d := exp.login.n.Load(), exp.capture.deniedCount(); n != 2 || d != 1 {
			t.Fatalf("logins = %d, 403s = %d; want 2 and 1 (exactly one re-login)", n, d)
		}
		secrets = append(secrets, string(exp.capture.lastToken().Reveal()))
		errs = append(errs, exp.capture.errs...)
	})

	t.Run("redaction", func(t *testing.T) {
		errs = append(errs, api.capture.errs...)
		if len(errs) == 0 {
			t.Fatal("no store error was collected, so the scan would read nothing")
		}
		assertRedacted(t, secrets, rec.Text(), errs, api.sess)
	})
}

// revoke revokes tok through auth/token/revoke as the revoker role.
func revoke(t *testing.T, s *secretstoretest.Store, tok secret.Value, secrets *[]string) {
	t.Helper()
	revoker, err := s.TokenFor(t.Context(), revokerRole)
	if err != nil {
		t.Fatal(err)
	}
	*secrets = append(*secrets, string(revoker.Reveal()))
	tc, err := s.ClientTLSFor(revokerRole)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
	defer c.CloseIdleConnections()
	body, err := json.Marshal(map[string]string{"token": string(tok.Reveal())})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.URL()+"/v1/auth/token/revoke", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", string(revoker.Reveal()))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke answered %d, want 204", resp.StatusCode)
	}
}

// waitRefused re-asks the store with tok until it refuses it as ErrDenied,
// and returns that refusal. The wait ends on the refusal; the deadline only
// turns a store that never expires the token into a failure that says so.
func waitRefused(t *testing.T, c *secretstore.Client, tok secret.Value, p secretstore.KVPath) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), expiryDeadline)
	defer cancel()
	tick := time.NewTicker(expiryRecheck)
	defer tick.Stop()
	last := "no answer yet"
	for {
		kv, err := c.Read(ctx, tok, p, 0)
		kv.Destroy()
		if errors.Is(err, secretstore.ErrDenied) {
			return err
		}
		if err != nil {
			last = err.Error()
		} else {
			last = "accepted"
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatalf("a token issued with token_ttl %v was never refused within %v; the store's last answer: %s",
				expiringTTL, expiryDeadline, last)
			return fmt.Errorf("unreachable")
		}
	}
}
