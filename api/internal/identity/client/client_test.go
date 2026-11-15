package idclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	tokenPath = "/realms/rasputin/protocol/openid-connect/token"
	adminRead = "/admin/realms/rasputin"
)

func okToken(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"access_token":"tok-1","token_type":"Bearer"}`)
}

// TC-978-08: New refuses every unsafe or incomplete config, and does no I/O
// for any config: a listener at the address sees no connection.
func TestNew_RefusesUnsafeConfigsWithoutIO(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	addr := mustURL(t, "https://"+ln.Addr().String())
	p := newPKI(t)
	good, err := looptls.NewClientTLS(p.ca.CertPEM, p.clientLeaf.CertPath, p.clientLeaf.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	insecure := good.Clone()
	insecure.InsecureSkipVerify = true
	noRoots := good.Clone()
	noRoots.RootCAs = nil
	log := slog.New(slog.DiscardHandler)
	valid := Config{Addr: addr, MgmtAddr: addr, TLS: good, CallTimeout: time.Second, Logger: log}
	for name, mutate := range map[string]func(*Config){
		"nil logger":      func(c *Config) { c.Logger = nil },
		"nil addr":        func(c *Config) { c.Addr = nil },
		"nil mgmt addr":   func(c *Config) { c.MgmtAddr = nil },
		"nil TLS":         func(c *Config) { c.TLS = nil },
		"skip verify":     func(c *Config) { c.TLS = insecure },
		"nil RootCAs":     func(c *Config) { c.TLS = noRoots },
		"zero timeout":    func(c *Config) { c.CallTimeout = 0 },
		"negative bound":  func(c *Config) { c.CallTimeout = -time.Second },
		"http addr":       func(c *Config) { c.Addr = mustURL(t, "http://127.0.0.1:8543") },
		"host name mgmt":  func(c *Config) { c.MgmtAddr = mustURL(t, "https://localhost:8544") },
		"non-loopback ip": func(c *Config) { c.Addr = mustURL(t, "https://10.0.0.1:8543") },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			mutate(&cfg)
			if c, err := New(cfg); err == nil || c != nil {
				t.Errorf("New = %v, %v; want a refusal", c, err)
			}
		})
	}
	if _, err := New(valid); err != nil {
		t.Fatalf("New(valid) = %v", err)
	}
	_ = ln.Close()
	if n := accepted.Load(); n != 0 {
		t.Errorf("the listener saw %d connections, want 0", n)
	}
}

// TC-978-09: the client speaks TLS 1.3 only and trusts the identity CA
// alone: a server offering at most TLS 1.2 fails the handshake, and a server
// whose leaf chains to another CA is ErrUnreachable with a
// certificate-verification cause. Neither handler sees a request.
func TestClient_TLS13AndTheIdentityCAAlone(t *testing.T) {
	p := newPKI(t)
	old := newServer(t, p, func(w http.ResponseWriter, _ *http.Request) { okToken(w) },
		func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 })
	c, _ := newClient(t, p, old.URL)
	if _, err := c.ClientCredentials(t.Context(), "rasputin", "rasputin-admin", nil); !errors.Is(err, ErrUnreachable) {
		t.Errorf("TLS 1.2 server: err = %v, want ErrUnreachable", err)
	}
	if old.requests() != 0 {
		t.Errorf("TLS 1.2 server saw %d requests", old.requests())
	}

	foreign := newPKI(t)
	other := newServer(t, foreign, func(w http.ResponseWriter, _ *http.Request) { okToken(w) }, nil)
	c, _ = newClient(t, p, other.URL)
	_, err := c.ClientCredentials(t.Context(), "rasputin", "rasputin-admin", nil)
	var verr *tls.CertificateVerificationError
	if !errors.Is(err, ErrUnreachable) || !errors.As(err, &verr) {
		t.Errorf("foreign server CA: err = %v, want ErrUnreachable with a certificate-verification cause", err)
	}
	if other.requests() != 0 {
		t.Errorf("foreign-CA server saw %d requests", other.requests())
	}
}

// TC-978-10: no endpoint follows a redirect. The token, Admin and ready
// endpoints each answering 302 and 307 to a second recording server are
// ErrProtocol, and the second server sees no request and no Authorization
// header.
func TestClient_NoRedirects(t *testing.T) {
	p := newPKI(t)
	var sawAuth atomic.Bool
	second := newServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth.Store(true)
		}
		okToken(w)
	}, nil)
	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		first := newServer(t, p, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, second.URL+r.URL.Path, code)
		}, nil)
		c, _ := newClient(t, p, first.URL)
		tok := secret.New([]byte("bearer-sentinel"))
		calls := map[string]func() error{
			"token": func() error {
				_, err := c.ClientCredentials(t.Context(), "rasputin", "rasputin-admin", nil)
				return err
			},
			"admin": func() error { _, err := c.Admin(t.Context(), tok, http.MethodGet, adminRead, nil, nil); return err },
			"ready": func() error { return c.Ready(t.Context()) },
		}
		for name, call := range calls {
			if err := call(); !errors.Is(err, ErrProtocol) {
				t.Errorf("%d %s: err = %v, want ErrProtocol", code, name, err)
			}
		}
	}
	if second.requests() != 0 || sawAuth.Load() {
		t.Errorf("the redirect target saw %d requests (Authorization %v), want none", second.requests(), sawAuth.Load())
	}
}

// TC-978-11: no environment variable changes what the client does. Proxy
// variables pointing at a recording proxy, SSL_CERT_FILE at a foreign CA and
// KC_* junk leave the call direct and successful, and the proxy sees no
// connection.
func TestClient_NoEnvironmentChangesBehaviour(t *testing.T) {
	p := newPKI(t)
	srv := newServer(t, p, func(w http.ResponseWriter, _ *http.Request) { okToken(w) }, nil)
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var proxied atomic.Int64
	go func() {
		for {
			c, err := proxy.Accept()
			if err != nil {
				return
			}
			proxied.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = proxy.Close() })
	purl := "http://" + proxy.Addr().String()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, purl)
	}
	t.Setenv("NO_PROXY", "")
	foreign := newPKI(t)
	t.Setenv("SSL_CERT_FILE", writeFile(t, "foreign.pem", foreign.ca.CertPEM))
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	t.Setenv("KC_HOSTNAME", "https://203.0.113.9:1")
	t.Setenv("KC_HTTPS_PORT", "1")

	c, _ := newClient(t, p, srv.URL)
	tok, err := c.ClientCredentials(t.Context(), "rasputin", "rasputin-admin", nil)
	if err != nil {
		t.Fatalf("ClientCredentials with the environment set: %v", err)
	}
	tok.Destroy()
	if srv.requests() != 1 || proxied.Load() != 0 {
		t.Errorf("server saw %d requests, proxy %d connections; want 1 and 0", srv.requests(), proxied.Load())
	}
}

// TC-978-12: every answer maps to exactly one kind, with errors.Is.
func TestClient_ErrorKinds(t *testing.T) {
	p := newPKI(t)
	type answer struct {
		status int
		body   string
	}
	var current atomic.Pointer[answer]
	srv := newServer(t, p, func(w http.ResponseWriter, _ *http.Request) {
		a := current.Load()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(a.status)
		_, _ = io.WriteString(w, a.body)
	}, nil)
	c, rec := newClient(t, p, srv.URL)
	tok := secret.New([]byte("admin-token"))
	token := func() error {
		v, err := c.ClientCredentials(t.Context(), "rasputin", "rasputin-admin", nil)
		v.Destroy()
		return err
	}
	admin := func() error {
		var out map[string]any
		_, err := c.Admin(t.Context(), tok, http.MethodGet, adminRead, nil, &out)
		return err
	}
	ready := func() error { return c.Ready(t.Context()) }
	huge := `{"access_token":"` + strings.Repeat("a", maxBody) + `"}`
	for _, tc := range []struct {
		name  string
		call  func() error
		a     answer
		want  error // nil is success
		oauth string
	}{
		{"token 200", token, answer{200, `{"access_token":"t"}`}, nil, ""},
		{"token 200 no token", token, answer{200, `{"token_type":"Bearer"}`}, ErrProtocol, ""},
		{"token 200 malformed", token, answer{200, `{"access_token":`}, ErrProtocol, ""},
		{"token 400 invalid_client", token, answer{400, `{"error":"invalid_client"}`}, ErrDenied, "invalid_client"},
		{"token 401 invalid_client", token, answer{401, `{"error":"invalid_client"}`}, ErrDenied, "invalid_client"},
		{"token 401 unauthorized_client", token, answer{401, `{"error":"unauthorized_client"}`}, ErrDenied, "unauthorized_client"},
		{"token 400 invalid_request", token, answer{400, `{"error":"invalid_request"}`}, ErrProtocol, "invalid_request"},
		{"token 404", token, answer{404, `{}`}, ErrProtocol, ""},
		{"token 503", token, answer{503, `{}`}, ErrUnreachable, ""},
		{"token oversized", token, answer{200, huge}, ErrProtocol, ""},
		{"admin 200", admin, answer{200, `{"realm":"rasputin"}`}, nil, ""},
		{"admin 204", admin, answer{204, ``}, nil, ""},
		{"admin 401", admin, answer{401, `{}`}, ErrTokenRefused, ""},
		{"admin 403", admin, answer{403, `{}`}, ErrForbidden, ""},
		{"admin 404", admin, answer{404, `{}`}, ErrNotFound, ""},
		{"admin 409", admin, answer{409, `{}`}, ErrConflict, ""},
		{"admin 500", admin, answer{500, `{}`}, ErrUnreachable, ""},
		{"admin 502", admin, answer{502, `{}`}, ErrUnreachable, ""},
		{"admin 418", admin, answer{418, `{}`}, ErrProtocol, ""},
		{"admin 200 malformed", admin, answer{200, `{"realm":`}, ErrProtocol, ""},
		{"admin oversized", admin, answer{200, huge}, ErrProtocol, ""},
		{"ready UP", ready, answer{200, `{"status":"UP","checks":[]}`}, nil, ""},
		{"ready 200 DOWN", ready, answer{200, `{"status":"DOWN"}`}, ErrProtocol, ""},
		{"ready 503", ready, answer{503, `{"status":"DOWN"}`}, ErrUnreachable, ""},
		{"ready 404", ready, answer{404, `{}`}, ErrProtocol, ""},
		{"ready oversized", ready, answer{200, huge}, ErrProtocol, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current.Store(&tc.a)
			err := tc.call()
			if tc.want == nil {
				if err != nil {
					t.Fatalf("err = %v, want success", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("err %T is not *Error", err)
			}
			if tc.oauth != "" {
				found := false
				for _, a := range e.LogAttrs() {
					if a.Key == "oauth_error" && a.Value.String() == tc.oauth {
						found = true
					}
				}
				if !found {
					t.Errorf("LogAttrs %v carry no oauth_error %q", e.LogAttrs(), tc.oauth)
				}
			}
		})
	}
	for _, level := range []slog.Level{slog.LevelDebug, slog.LevelWarn, slog.LevelError} {
		if len(rec.AtLevel(level)) == 0 {
			t.Errorf("no failure record at %v; the levels are DEBUG for 404/409, ERROR for protocol, WARN for the rest", level)
		}
	}

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := c.Admin(ctx, tok, http.MethodGet, adminRead, nil, nil)
		if !errors.Is(err, ErrUnreachable) || !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want ErrUnreachable matching context.Canceled", err)
		}
	})

	t.Run("client certificate refused at TLS", func(t *testing.T) {
		// The server trusts another CA for client leaves, so it refuses ours
		// with a TLS alert.
		foreign := newPKI(t)
		refusing := newServer(t, p, func(w http.ResponseWriter, _ *http.Request) { okToken(w) },
			func(c *tls.Config) { c.ClientCAs = foreign.pool() })
		rc, _ := newClient(t, p, refusing.URL)
		if _, err := rc.ClientCredentials(t.Context(), "rasputin", "rasputin-admin", nil); !errors.Is(err, ErrDenied) {
			t.Errorf("err = %v, want ErrDenied", err)
		}
		if refusing.requests() != 0 {
			t.Errorf("the refusing server saw %d requests", refusing.requests())
		}
	})

	t.Run("each refusal alert", func(t *testing.T) {
		for _, code := range []tls.AlertError{42, 46, 48, 116} {
			err := &net.OpError{Op: "remote error", Err: code}
			if kind, _ := classifyTransport(t.Context(), err); kind != ErrDenied {
				t.Errorf("alert %d: kind %v, want ErrDenied", code, kind)
			}
		}
		if kind, _ := classifyTransport(t.Context(), &net.OpError{Op: "remote error", Err: tls.AlertError(40)}); kind != ErrUnreachable {
			t.Errorf("alert 40 (handshake_failure): kind %v, want ErrUnreachable", kind)
		}
	})
}

// TC-978-05 (client half): with no client leaf on disk every call fails as
// ErrUnreachable before anything is sent; the server records no request.
func TestClient_MissingLeafSendsNothing(t *testing.T) {
	p := newPKI(t)
	srv := newServer(t, p, func(w http.ResponseWriter, _ *http.Request) { okToken(w) }, nil)
	cfg, err := looptls.NewClientTLS(p.ca.CertPEM, filepath.Join(t.TempDir(), "leaf.pem"), filepath.Join(t.TempDir(), "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Addr: mustURL(t, srv.URL), MgmtAddr: mustURL(t, srv.URL), TLS: cfg, CallTimeout: 5 * time.Second, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	tok := secret.New([]byte("t"))
	for name, err := range map[string]error{
		"token": func() error {
			_, err := c.ClientCredentials(t.Context(), "rasputin", "rasputin-admin", nil)
			return err
		}(),
		"admin": func() error { _, err := c.Admin(t.Context(), tok, http.MethodGet, adminRead, nil, nil); return err }(),
		"ready": c.Ready(t.Context()),
	} {
		if !errors.Is(err, ErrUnreachable) || !looptls.IsLeafError(err) {
			t.Errorf("%s: err = %v, want ErrUnreachable from the missing leaf", name, err)
		}
	}
	if srv.requests() != 0 {
		t.Errorf("the server saw %d requests, want 0", srv.requests())
	}
}

// TC-978-13: Admin sends nothing to a path outside /admin/realms/.
func TestClient_AdminPathGuard(t *testing.T) {
	p := newPKI(t)
	srv := newServer(t, p, func(w http.ResponseWriter, _ *http.Request) { okToken(w) }, nil)
	c, _ := newClient(t, p, srv.URL)
	tok := secret.New([]byte("t"))
	for _, path := range []string{"/realms/master/protocol/openid-connect/token", "admin/realms/x", "", "/admin/realms", "https://127.0.0.1:1/admin/realms/x"} {
		if _, err := c.Admin(t.Context(), tok, http.MethodGet, path, nil, nil); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Admin(%q): err = %v, want ErrInvalidValue", path, err)
		}
	}
	if _, err := c.ClientCredentials(t.Context(), "", "rasputin-admin", nil); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("empty realm: err = %v, want ErrInvalidValue", err)
	}
	if srv.requests() != 0 {
		t.Errorf("the server saw %d requests, want 0", srv.requests())
	}
}

// TC-978-14: the token travels only in Authorization: Bearer, the client
// secret only in the form body, whose buffer is zero after the call, and no
// sentinel reaches an error rendering or a log record for any failure kind.
func TestClient_SecretsNeverLeak(t *testing.T) {
	const (
		tokenSentinel  = "sentinel-token-7d1f"
		secretSentinel = "sentinel-secret+/=4c9e"
		bodySentinel   = "sentinel-body-a8b2"
	)
	p := newPKI(t)
	type captured struct{ url, auth, body string }
	var last atomic.Pointer[captured]
	var status atomic.Int64
	srv := newServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		last.Store(&captured{url: r.URL.String(), auth: r.Header.Get("Authorization"), body: string(b)})
		w.WriteHeader(int(status.Load()))
		_, _ = fmt.Fprintf(w, `{"error":"invalid_client","error_description":%q,"access_token":%q}`, bodySentinel, bodySentinel)
	}, nil)
	c, rec := newClient(t, p, srv.URL)

	status.Store(200)
	tok := secret.New([]byte(tokenSentinel))
	if _, err := c.Admin(t.Context(), tok, http.MethodGet, adminRead+"/users", nil, nil); err != nil {
		t.Fatal(err)
	}
	got := last.Load()
	if got.auth != "Bearer "+tokenSentinel || strings.Contains(got.url, tokenSentinel) || strings.Contains(got.body, tokenSentinel) {
		t.Errorf("the token travelled as auth %q url %q body %q; want only the Bearer header", got.auth, got.url, got.body)
	}

	sec := secret.New([]byte(secretSentinel))
	form := tokenForm("rasputin-recover-1", &sec)
	if _, e := c.token(t.Context(), tokenPath, form); e != nil {
		t.Fatal(e)
	}
	got = last.Load()
	q, err := url.ParseQuery(got.body)
	if err != nil || q.Get("client_secret") != secretSentinel || q.Get("client_id") != "rasputin-recover-1" || q.Get("grant_type") != "client_credentials" {
		t.Errorf("the form body %q does not carry the secret exactly once as client_secret (%v)", got.body, err)
	}
	if strings.Contains(got.url, "sentinel") || got.auth != "" {
		t.Errorf("the secret reached the URL %q or a header %q", got.url, got.auth)
	}
	if !bytes.Equal(form, make([]byte, len(form))) {
		t.Error("the form buffer is not all zero after the call")
	}

	for _, st := range []int{400, 401, 403, 404, 409, 418, 500} {
		status.Store(int64(st))
		var errs []error
		_, err := c.ClientCredentials(t.Context(), "rasputin", "rasputin-recover-1", &sec)
		errs = append(errs, err)
		_, err = c.Admin(t.Context(), tok, http.MethodPost, adminRead+"/users", map[string]string{"x": "y"}, nil)
		errs = append(errs, err)
		errs = append(errs, c.Ready(t.Context()))
		for _, err := range errs {
			if err == nil {
				t.Fatalf("status %d: a call succeeded", st)
			}
			for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
				text := fmt.Sprintf(verb, err) + err.Error()
				for _, s := range []string{tokenSentinel, secretSentinel, bodySentinel} {
					if strings.Contains(text, s) {
						t.Errorf("status %d: %s rendering carries sentinel %q: %s", st, verb, s, text)
					}
				}
			}
		}
	}
	text := rec.Text()
	for _, s := range []string{tokenSentinel, secretSentinel, bodySentinel, url.QueryEscape(secretSentinel)} {
		if strings.Contains(text, s) {
			t.Errorf("a log record carries sentinel %q", s)
		}
	}
	if len(rec.Records()) == 0 {
		t.Fatal("no records; the scan proved nothing")
	}
}

// The client leaf's reload: after CloseIdleConnections the next call makes a
// new handshake and presents the leaf now on disk (part of TC-978-06).
func TestClient_CloseIdleConnectionsPresentsTheNewLeaf(t *testing.T) {
	p := newPKI(t)
	var serial atomic.Pointer[string]
	srv := newServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		s := r.TLS.PeerCertificates[0].SerialNumber.String()
		serial.Store(&s)
		okToken(w)
	}, nil)
	c, _ := newClient(t, p, srv.URL)
	call := func() string {
		t.Helper()
		v, err := c.ClientCredentials(t.Context(), "rasputin", "rasputin-admin", nil)
		if err != nil {
			t.Fatal(err)
		}
		v.Destroy()
		return *serial.Load()
	}
	first := call()
	// A renewal writes a new leaf over the old one's files.
	fresh, err := p.ca.MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatal(err)
	}
	for from, to := range map[string]string{fresh.CertPath: p.clientLeaf.CertPath, fresh.KeyPath: p.clientLeaf.KeyPath} {
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if again := call(); again != first {
		t.Fatalf("the kept connection presented serial %s, want the first %s", again, first)
	}
	c.CloseIdleConnections()
	if next := call(); next == first {
		t.Errorf("after CloseIdleConnections the call presented the old leaf %s", first)
	}
}

// Disabled refuses every call with its kind and sends nothing.
func TestDisabled_RefusesWithItsKind(t *testing.T) {
	for _, kind := range []error{ErrDisabled, ErrMock} {
		d := Disabled{Kind: kind}
		_, e1 := d.ClientCredentials(t.Context(), "r", "c", nil)
		_, e2 := d.Admin(t.Context(), secret.Value{}, http.MethodGet, adminRead, nil, nil)
		e3 := d.Ready(t.Context())
		for i, err := range []error{e1, e2, e3} {
			if !errors.Is(err, kind) {
				t.Errorf("%v call %d: err = %v", kind, i, err)
			}
		}
	}
}
