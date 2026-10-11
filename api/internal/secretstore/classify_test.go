package secretstore_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-758-04: the client reads no ambient configuration. BAO_*, VAULT_* and
// the proxy variables all point elsewhere; every call still reaches only the
// configured server, verifies it, and sends no BAO_TOKEN.
func TestNoAmbientConfiguration(t *testing.T) {
	var proxyHits, otherHits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyHits.Add(1) }))
	t.Cleanup(proxy.Close)
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { otherHits.Add(1) }))
	t.Cleanup(other.Close)

	const ambientToken = "ambient-bao-token"
	for k, v := range map[string]string{
		"BAO_ADDR": other.URL, "BAO_TOKEN": ambientToken, "BAO_SKIP_VERIFY": "true",
		"VAULT_ADDR": other.URL, "VAULT_TOKEN": ambientToken,
		"HTTPS_PROXY": proxy.URL, "HTTP_PROXY": proxy.URL, "https_proxy": proxy.URL, "http_proxy": proxy.URL,
		"NO_PROXY": "", "no_proxy": "",
	} {
		t.Setenv(k, v)
	}

	var mu sync.Mutex
	var tokens []string
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tokens = append(tokens, r.Header.Get("X-Vault-Token"))
		mu.Unlock()
		switch {
		case r.URL.Path == "/v1/sys/health":
			writeJSON(w, http.StatusOK, healthBody(true, false))
		case strings.HasPrefix(r.URL.Path, "/v1/kv/metadata/"):
			writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"current_version": 1, "versions": map[string]any{}}})
		case r.Method == http.MethodPost:
			writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"version": 1}})
		default:
			writeJSON(w, http.StatusOK, kvBody(1, map[string]any{"k": "v"}))
		}
	})
	p := kvPath(t, "kv", "a")
	ctx := t.Context()
	if _, err := f.client.Health(ctx); err != nil {
		t.Errorf("Health: %v", err)
	}
	if _, err := f.client.Read(ctx, tok("configured"), p, 0); err != nil {
		t.Errorf("Read: %v", err)
	}
	if _, err := f.client.Write(ctx, tok("configured"), p, map[string]secret.Value{"k": tok("v")}, 0); err != nil {
		t.Errorf("Write: %v", err)
	}
	if _, err := f.client.Versions(ctx, tok("configured"), p); err != nil {
		t.Errorf("Versions: %v", err)
	}
	if got := f.hits.Load(); got != 4 {
		t.Errorf("configured server saw %d requests, want 4", got)
	}

	// A configured server whose certificate does not chain to the store CA is
	// refused, BAO_SKIP_VERIFY notwithstanding.
	ca := storeCA(t)
	untrusted := newClient(t, other.URL, mustTLS(t, ca.CertPEM, clientLeaf(t, ca)), slog.New(slog.DiscardHandler))
	if _, err := untrusted.Read(ctx, tok("configured"), p, 0); !errors.Is(err, secretstore.ErrUnreachable) {
		t.Errorf("untrusted server: err = %v, want ErrUnreachable", err)
	}
	if proxyHits.Load() != 0 || otherHits.Load() != 0 {
		t.Errorf("proxy saw %d, other server saw %d; want 0 and 0", proxyHits.Load(), otherHits.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, got := range tokens {
		if got == ambientToken {
			t.Error("a request carried the BAO_TOKEN value")
		}
	}
}

// kvAnswer is one scripted answer for a KV call, and for the sys/health
// question a 503 makes the client ask.
type kvAnswer struct {
	status int
	body   any
	health func(http.ResponseWriter) // nil: health is not expected
}

// scripted serves a for every KV path and a.health for sys/health.
func scripted(t *testing.T, a kvAnswer) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			if a.health == nil {
				t.Errorf("unexpected sys/health request")
				w.WriteHeader(http.StatusTeapot)
				return
			}
			a.health(w)
			return
		}
		writeJSON(w, a.status, a.body)
	}
}

func healthAnswer(status int, initialized, sealed bool) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { writeJSON(w, status, healthBody(initialized, sealed)) }
}

// hangUp is a sys/health that never answers: the connection is dropped.
func hangUp(w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// TC-758-05: each KV status gives exactly one kind, and *Error carries the
// op, mount, path and status.
func TestStatusTable(t *testing.T) {
	deleted := kvBody(2, map[string]any{"k": "v"})
	deleted["data"].(map[string]any)["metadata"].(map[string]any)["deletion_time"] = "2026-10-11T10:00:00Z"
	destroyed := kvBody(2, map[string]any{"k": "v"})
	destroyed["data"].(map[string]any)["metadata"].(map[string]any)["destroyed"] = true
	errs := func(m ...string) map[string]any { return map[string]any{"errors": m} }

	for _, tc := range []struct {
		name string
		a    kvAnswer
		want error
	}{
		{"403", kvAnswer{status: 403, body: errs("permission denied")}, secretstore.ErrDenied},
		{"404", kvAnswer{status: 404, body: errs()}, secretstore.ErrNotFound},
		{"200 data null", kvAnswer{status: 200, body: map[string]any{"data": nil}}, secretstore.ErrNotFound},
		{"200 deleted version", kvAnswer{status: 200, body: deleted}, secretstore.ErrNotFound},
		{"200 destroyed version", kvAnswer{status: 200, body: destroyed}, secretstore.ErrNotFound},
		{"400 check-and-set", kvAnswer{status: 400, body: errs("check-and-set parameter did not match the current version")}, secretstore.ErrCASMismatch},
		{"400 other", kvAnswer{status: 400, body: errs("invalid request")}, secretstore.ErrProtocol},
		{"500", kvAnswer{status: 500, body: errs("internal")}, secretstore.ErrUnreachable},
		{"502", kvAnswer{status: 502, body: errs("bad gateway")}, secretstore.ErrUnreachable},
		{"503 + health sealed", kvAnswer{status: 503, body: errs("Vault is sealed"), health: healthAnswer(503, true, true)}, secretstore.ErrSealed},
		{"503 + health 501", kvAnswer{status: 503, body: errs("x"), health: healthAnswer(501, false, true)}, secretstore.ErrUninitialised},
		{"503 + health 200", kvAnswer{status: 503, body: errs("x"), health: healthAnswer(200, true, false)}, secretstore.ErrUnreachable},
		{"503 + health no answer", kvAnswer{status: 503, body: errs("x"), health: hangUp}, secretstore.ErrUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, scripted(t, tc.a))
			_, err := f.client.Read(t.Context(), tok("t"), kvPath(t, "kv", "app/x"), 2)
			assertKind(t, err, tc.want)
			var se *secretstore.Error
			if !errors.As(err, &se) {
				t.Fatalf("err %v is not an *Error", err)
			}
			if se.Op != "read" || se.Mount != "kv" || se.Path != "app/x" || se.Status != tc.a.status {
				t.Errorf("*Error = op %q mount %q path %q status %d; want read kv app/x %d", se.Op, se.Mount, se.Path, se.Status, tc.a.status)
			}
		})
	}
}

// assertKind checks err is exactly the kind want, and no other kind.
func assertKind(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	for _, k := range allKinds {
		if k != want && errors.Is(err, k) {
			t.Errorf("err = %v is also %v", err, k)
		}
	}
}

var allKinds = []error{
	secretstore.ErrSealed, secretstore.ErrUninitialised, secretstore.ErrUnreachable, secretstore.ErrDenied,
	secretstore.ErrNotFound, secretstore.ErrCASMismatch, secretstore.ErrProtocol, secretstore.ErrInvalidValue,
	secretstore.ErrDisabled,
}

// TC-758-06: Health codes, and bodies that contradict their code.
func TestHealth(t *testing.T) {
	for _, tc := range []struct {
		name                string
		status              int
		initialized, sealed bool
		want                error
	}{
		{"200", 200, true, false, nil},
		{"501", 501, false, true, secretstore.ErrUninitialised},
		{"503", 503, true, true, secretstore.ErrSealed},
		{"429 standby", 429, true, false, secretstore.ErrUnreachable},
		{"472 DR secondary", 472, true, false, secretstore.ErrUnreachable},
		{"473 performance standby", 473, true, false, secretstore.ErrUnreachable},
		{"200 saying sealed", 200, true, true, secretstore.ErrProtocol},
		{"503 saying unsealed", 503, true, false, secretstore.ErrProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, tc.status, healthBody(tc.initialized, tc.sealed))
			})
			h, err := f.client.Health(t.Context())
			if tc.want == nil {
				if err != nil || !h.Initialized || h.Sealed || h.Version != "2.7.1" {
					t.Fatalf("Health = %+v, %v; want initialised and unsealed", h, err)
				}
				return
			}
			assertKind(t, err, tc.want)
		})
	}
}

// TC-758-07: transport failures.
func TestTransportFailures(t *testing.T) {
	p := kvPath(t, "kv", "a")

	t.Run("(a) nothing listening", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := "https://" + l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		ca := storeCA(t)
		c := newClient(t, addr, mustTLS(t, ca.CertPEM, clientLeaf(t, ca)), slog.New(slog.DiscardHandler))
		_, err = c.Read(t.Context(), tok("t"), p, 0)
		assertKind(t, err, secretstore.ErrUnreachable)
	})

	t.Run("(b) a stalled server runs out the call bound", func(t *testing.T) {
		f := newFixture(t, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
		u, _ := secretstore.ParseAddr(f.srv.URL)
		c, err := secretstore.New(secretstore.Config{Addr: u, TLS: mustTLS(t, f.ca.CertPEM, f.leaf), CallTimeout: 200 * time.Millisecond, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Read(t.Context(), tok("t"), p, 0)
		assertKind(t, err, secretstore.ErrUnreachable)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want context.DeadlineExceeded in the chain", err)
		}
	})

	t.Run("(c) the caller cancels mid-call", func(t *testing.T) {
		arrived := make(chan struct{})
		f := newFixture(t, func(_ http.ResponseWriter, r *http.Request) {
			close(arrived)
			<-r.Context().Done()
		})
		ctx, cancel := context.WithCancel(t.Context())
		go func() { <-arrived; cancel() }()
		_, err := f.client.Read(ctx, tok("t"), p, 0)
		assertKind(t, err, secretstore.ErrUnreachable)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled in the chain", err)
		}
	})

	// (d) F-758-07: the server's refusal of the client certificate arrives as
	// a *net.OpError "remote error", never as tls.AlertError, and is ErrDenied.
	refused := func(t *testing.T, tc *tls.Config, ca *tlsca.CA) {
		t.Helper()
		var hits atomic.Int64
		srv := startTLSServer(t, serverCert(t, ca), ca, tls.VersionTLS13, tls.VersionTLS13,
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
		c := newClient(t, srv.URL, tc, slog.New(slog.DiscardHandler))
		for name, call := range map[string]func() error{
			"Health": func() error { _, err := c.Health(t.Context()); return err },
			"Read":   func() error { _, err := c.Read(t.Context(), tok("t"), p, 0); return err },
		} {
			err := call()
			assertKind(t, err, secretstore.ErrDenied)
			var op *net.OpError
			if !errors.As(err, &op) || op.Op != "remote error" {
				t.Errorf("%s: err = %v, want a *net.OpError with Op \"remote error\" in the chain", name, err)
			}
			var ae tls.AlertError
			if errors.As(err, &ae) {
				t.Errorf("%s: crypto/tls returned tls.AlertError %d; the remote-alert path is untested", name, ae)
			}
		}
		if hits.Load() != 0 {
			t.Errorf("server handled %d requests, want 0", hits.Load())
		}
	}
	t.Run("(d) no client certificate (alert 116)", func(t *testing.T) {
		ca := storeCA(t)
		tc := mustTLS(t, ca.CertPEM, clientLeaf(t, ca))
		tc.GetClientCertificate = nil
		refused(t, tc, ca)
	})
	t.Run("(d) a leaf from a foreign store CA (alert 42)", func(t *testing.T) {
		ca, foreign := storeCA(t), storeCA(t)
		refused(t, mustTLS(t, ca.CertPEM, clientLeaf(t, foreign)), ca)
	})

	t.Run("(e) an unusable leaf sends nothing, and a written leaf then works", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Fatal("this case needs a non-root user: root ignores file modes, so a mode-000 leaf stays readable")
		}
		f := newFixture(t, okHandler())
		if err := os.Chmod(f.leaf.KeyPath, 0); err != nil {
			t.Fatal(err)
		}
		_, err := f.client.Health(t.Context())
		assertKind(t, err, secretstore.ErrUnreachable)
		for _, path := range []string{f.leaf.CertPath, f.leaf.KeyPath} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		_, err = f.client.Read(t.Context(), tok("t"), p, 0)
		assertKind(t, err, secretstore.ErrUnreachable)
		if f.hits.Load() != 0 {
			t.Fatalf("server handled %d requests while the leaf was unusable, want 0", f.hits.Load())
		}
		cert, key, err := f.ca.MintLeaf(tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
		if err != nil {
			t.Fatal(err)
		}
		if err := tlsca.WriteLeafFiles(f.leaf, cert, key); err != nil {
			t.Fatal(err)
		}
		key.Destroy()
		if _, err := f.client.Health(t.Context()); err != nil {
			t.Fatalf("Health after the leaf was written = %v, want success from the same client", err)
		}
	})
}

// TC-758-08: redirects, an oversized body, malformed JSON and a non-string
// value are ErrProtocol, and a redirect target is never contacted.
func TestBadResponses(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetHits.Add(1) }))
	t.Cleanup(target.Close)
	p := kvPath(t, "kv", "a")
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
	}{
		{"302", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
		}},
		{"307", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
		}},
		{"body over 1 MiB", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"data":{"data":{"k":"`+strings.Repeat("x", 1<<20)+`"}}}`)
		}},
		{"malformed JSON", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"data":`)
		}},
		{"a number value", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, kvBody(1, map[string]any{"k": 42}))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.h)
			_, err := f.client.Read(t.Context(), tok("t"), p, 0)
			assertKind(t, err, secretstore.ErrProtocol)
		})
	}
	if targetHits.Load() != 0 {
		t.Errorf("redirect target saw %d requests, want 0", targetHits.Load())
	}
}

// TC-758-09: options.cas is always on the wire, the token only in its header,
// and an invalid value is refused before any request.
func TestWrite(t *testing.T) {
	const token = "write-token-sentinel"
	type seen struct {
		url, header string
		body        []byte
	}
	var mu sync.Mutex
	var got []seen
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, seen{r.URL.String(), r.Header.Get("X-Vault-Token"), b})
		mu.Unlock()
		var req struct {
			Options struct {
				CAS *int `json:"cas"`
			} `json:"options"`
		}
		if json.Unmarshal(b, &req) != nil || req.Options.CAS == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"version": *req.Options.CAS + 1}})
	})
	p := kvPath(t, "kv", "a")
	for _, cas := range []int{0, 3} {
		v, err := f.client.Write(t.Context(), tok(token), p, map[string]secret.Value{"k": tok("v\"\\\n")}, cas)
		if err != nil || v != cas+1 {
			t.Fatalf("Write cas %d = %d, %v; want %d", cas, v, err, cas+1)
		}
	}
	mu.Lock()
	for i, s := range got {
		var req struct {
			Options struct {
				CAS *int `json:"cas"`
			} `json:"options"`
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal(s.body, &req); err != nil {
			t.Fatalf("body %d: %v", i, err)
		}
		if want := []int{0, 3}[i]; req.Options.CAS == nil || *req.Options.CAS != want {
			t.Errorf("body %d options.cas = %v, want %d", i, req.Options.CAS, want)
		}
		if req.Data["k"] != "v\"\\\n" {
			t.Errorf("body %d data.k = %q, want the value round-tripped", i, req.Data["k"])
		}
		if s.header != token {
			t.Errorf("request %d X-Vault-Token = %q, want the token", i, s.header)
		}
		if strings.Contains(s.url, token) || strings.Contains(string(s.body), token) {
			t.Errorf("request %d carries the token outside its header", i)
		}
	}
	mu.Unlock()

	before := f.hits.Load()
	for name, v := range map[string]secret.Value{
		"invalid UTF-8": secret.New([]byte{0xff, 0xfe}),
		"RFC 3339":      tok("2026-10-11T09:00:00Z"),
		"RFC 3339 nano": tok("2026-10-11T09:00:00.123456789+02:00"),
	} {
		_, err := f.client.Write(t.Context(), tok(token), p, map[string]secret.Value{"k": v}, 0)
		if !errors.Is(err, secretstore.ErrInvalidValue) {
			t.Errorf("%s: err = %v, want ErrInvalidValue", name, err)
		}
	}
	for name, call := range map[string]func() error{
		"negative cas":     func() error { _, err := f.client.Write(t.Context(), tok(token), p, nil, -1); return err },
		"negative version": func() error { _, err := f.client.Read(t.Context(), tok(token), p, -1); return err },
		"zero KVPath":      func() error { _, err := f.client.Versions(t.Context(), tok(token), secretstore.KVPath{}); return err },
		"empty key": func() error {
			_, err := f.client.Write(t.Context(), tok(token), p, map[string]secret.Value{"": tok("v")}, 0)
			return err
		},
	} {
		if err := call(); !errors.Is(err, secretstore.ErrInvalidValue) {
			t.Errorf("%s: err = %v, want ErrInvalidValue", name, err)
		}
	}
	if n := f.hits.Load() - before; n != 0 {
		t.Errorf("server saw %d requests for refused calls, want 0", n)
	}
	// A time-like value that is not RFC 3339 is an ordinary value.
	if _, err := f.client.Write(t.Context(), tok(token), p, map[string]secret.Value{"k": tok("2026-10-11 09:00:00")}, 5); err != nil {
		t.Errorf("non-RFC-3339 date: %v", err)
	}
}
