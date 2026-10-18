package storesession_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// tlsToken is the token the fake store's login answers with.
const tlsToken = "sentinel-tls-login-token-5e1f"

// store is an httptest TLS 1.3 server that requires a store-CA client
// certificate and answers a cert login and a kv-v2 read, counting the
// requests it serves by path.
type store struct {
	ca                  *tlsca.CA
	srv                 *httptest.Server
	logins, reads, hits atomic.Int64
}

// newStore starts the server. now, when not nil, is the server's clock.
func newStore(t *testing.T, now func() time.Time) *store {
	t.Helper()
	ca, err := tlsca.Ensure(tlsca.StoreConfig(), t.TempDir(), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ca.MintLeafToDisk(filepath.Join(t.TempDir(), "server"), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "test store", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(sp.CertPath, sp.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	s := &store{ca: ca}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/auth/cert/login":
			s.logins.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": tlsToken}})
		case strings.HasPrefix(r.URL.Path, "/v1/rasputin-secrets/data/"):
			s.reads.Add(1)
			if r.Header.Get("X-Vault-Token") != tlsToken {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"errors":["permission denied"]}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"data":     map[string]any{"k": "v"},
				"metadata": map[string]any{"created_time": "2026-10-18T09:00:00Z", "deletion_time": "", "destroyed": false, "version": 1},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	s.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
		Time:         now,
	}
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

// client is the production client for s presenting the leaf at leaf, with
// now as its TLS clock when not nil.
func (s *store) client(t *testing.T, leaf tlsca.LeafPaths, now func() time.Time, lg *slog.Logger) *secretstore.Client {
	t.Helper()
	tc, err := secretstore.NewTLSConfig(s.ca.CertPEM, leaf.CertPath, leaf.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	tc.Time = now
	u, err := url.Parse(s.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := secretstore.New(secretstore.Config{Addr: u, TLS: tc, CallTimeout: 5 * time.Second, Logger: lg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// countingLogin counts the logins it forwards.
type countingLogin struct {
	inner storesession.Login
	n     atomic.Int64
}

func (c *countingLogin) CertLogin(ctx context.Context, r string) (secret.Value, error) {
	c.n.Add(1)
	return c.inner.CertLogin(ctx, r)
}

// countingStore counts the KV calls it forwards.
type countingStore struct {
	inner storesession.Store
	n     atomic.Int64
}

func (c *countingStore) Read(ctx context.Context, tok secret.Value, p secretstore.KVPath, v int) (secretstore.KV, error) {
	c.n.Add(1)
	return c.inner.Read(ctx, tok, p, v)
}

func (c *countingStore) Write(ctx context.Context, tok secret.Value, p secretstore.KVPath, d map[string]secret.Value, cas int) (int, error) {
	c.n.Add(1)
	return c.inner.Write(ctx, tok, p, d, cas)
}

func (c *countingStore) Versions(ctx context.Context, tok secret.Value, p secretstore.KVPath) (secretstore.Metadata, error) {
	c.n.Add(1)
	return c.inner.Versions(ctx, tok, p)
}

func (c *countingStore) Delete(ctx context.Context, tok secret.Value, p secretstore.KVPath) error {
	c.n.Add(1)
	return c.inner.Delete(ctx, tok, p)
}

type nopObserver struct{}

func (nopObserver) ObserveAudited(context.Context, error) {}

// TC-759-04, TC-759-05, TC-759-06: a client leaf that is absent, unreadable
// (the key path is a directory, which no user can read as a file, root
// included) or empty refuses the login as ErrUnreachable with no request sent
// and no KV call, holds no token, and the next call tries the login again.
// TC-759-13: the leaf's key and the token appear in no log or rendering.
func TestSession_UnusableCredentialRefuses(t *testing.T) {
	for _, tc := range []struct {
		id, name string
		spoil    func(t *testing.T, leaf tlsca.LeafPaths)
	}{
		{"TC-759-04", "absent", func(t *testing.T, leaf tlsca.LeafPaths) {
			for _, p := range []string{leaf.CertPath, leaf.KeyPath} {
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"TC-759-05", "key path is a directory", func(t *testing.T, leaf tlsca.LeafPaths) {
			if err := os.Remove(leaf.KeyPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(leaf.KeyPath, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"TC-759-06", "empty key file", func(t *testing.T, leaf tlsca.LeafPaths) {
			if err := os.Truncate(leaf.KeyPath, 0); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.id+" "+tc.name, func(t *testing.T) {
			s := newStore(t, nil)
			leaf, err := s.ca.MintLeafToDisk(filepath.Join(t.TempDir(), "client"), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: role})
			if err != nil {
				t.Fatal(err)
			}
			keyPEM, err := os.ReadFile(leaf.KeyPath)
			if err != nil {
				t.Fatal(err)
			}
			tc.spoil(t, leaf)
			lg, rec := logkittest.New()
			client := s.client(t, leaf, nil, lg)
			login := &countingLogin{inner: client}
			kv := &countingStore{inner: client}
			sess, err := storesession.New(storesession.Config{Role: role, Login: login, Store: kv, Observer: nopObserver{}, Log: lg})
			if err != nil {
				t.Fatal(err)
			}
			var errs []error
			for i := range 2 {
				_, err := sess.Read(t.Context(), path(t), 0)
				if !errors.Is(err, secretstore.ErrUnreachable) {
					t.Fatalf("call %d: err = %v, want ErrUnreachable", i+1, err)
				}
				errs = append(errs, err)
			}
			if got := s.hits.Load(); got != 0 {
				t.Errorf("server requests = %d, want 0", got)
			}
			if got := kv.n.Load(); got != 0 {
				t.Errorf("KV calls = %d, want 0", got)
			}
			if got := login.n.Load(); got != 2 {
				t.Errorf("logins = %d after two calls, want 2: no token is held", got)
			}
			assertRedacted(t, append(pemLines(keyPEM), string(keyPEM), tlsToken), rec.Text(), errs, sess)
		})
	}
}

// TC-759-11: at the boot clock floor (both ends' TLS clocks two hours behind
// the leaves' mint, past their one-hour backdate) the login fails as
// ErrUnreachable, never ErrDenied, once, with no KV request and no token
// held. Once the clock steps to real time the next call logs in once and
// succeeds.
func TestSession_ClockFloorRefusesWithoutLooping(t *testing.T) {
	var behind atomic.Int64
	behind.Store(int64(2 * time.Hour))
	now := func() time.Time { return time.Now().Add(-time.Duration(behind.Load())) }
	s := newStore(t, now)
	leaf, err := s.ca.MintLeafToDisk(filepath.Join(t.TempDir(), "client"), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: role})
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(leaf.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	lg, rec := logkittest.New()
	client := s.client(t, leaf, now, lg)
	login := &countingLogin{inner: client}
	kv := &countingStore{inner: client}
	sess, err := storesession.New(storesession.Config{Role: role, Login: login, Store: kv, Observer: nopObserver{}, Log: lg})
	if err != nil {
		t.Fatal(err)
	}

	_, floorErr := sess.Read(t.Context(), path(t), 0)
	if !errors.Is(floorErr, secretstore.ErrUnreachable) || errors.Is(floorErr, secretstore.ErrDenied) {
		t.Fatalf("at the floor: err = %v, want ErrUnreachable and not ErrDenied", floorErr)
	}
	if login.n.Load() != 1 || kv.n.Load() != 0 || s.reads.Load() != 0 {
		t.Fatalf("at the floor: logins = %d KV calls = %d server reads = %d, want 1, 0, 0",
			login.n.Load(), kv.n.Load(), s.reads.Load())
	}

	behind.Store(0)
	kvAfter, err := sess.Read(t.Context(), path(t), 0)
	if err != nil {
		t.Fatalf("after the step: %v", err)
	}
	defer kvAfter.Destroy()
	if got := string(kvAfter.Data["k"].Reveal()); got != "v" {
		t.Errorf("read %q, want v", got)
	}
	if login.n.Load() != 2 || s.logins.Load() != 1 || s.reads.Load() != 1 {
		t.Errorf("after the step: login attempts = %d, logins served = %d, reads served = %d; want 2, 1, 1",
			login.n.Load(), s.logins.Load(), s.reads.Load())
	}
	assertRedacted(t, append(pemLines(keyPEM), string(keyPEM), tlsToken), rec.Text(), []error{floorErr}, sess)
}

// pemLines are the base64 body lines of a PEM, each a secret on its own.
func pemLines(p []byte) []string {
	var out []string
	for _, l := range strings.Split(string(p), "\n") {
		if l != "" && !strings.HasPrefix(l, "-----") {
			out = append(out, l)
		}
	}
	return out
}
