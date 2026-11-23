package api

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door"
)

// baselineHeaders are the values every response carries unless it is the
// Grafana proxy's same-origin framing exception.
var baselineHeaders = map[string]string{
	"X-Content-Type-Options":  "nosniff",
	"X-Frame-Options":         "DENY",
	"Content-Security-Policy": contentSecurityPolicy,
	"Referrer-Policy":         "same-origin",
}

func assertHeaders(t *testing.T, label string, got http.Header, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if g := got.Get(k); g != v {
			t.Errorf("%s: %s = %q, want %q", label, k, g, v)
		}
	}
}

// headersFixture is the api fixture with a static UI export, so "/" is
// served by the UI handler rather than 404ing.
func headersFixture(t *testing.T) *apiFixture {
	t.Helper()
	f := newAPIFixture(t)
	uiDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(uiDir, "index.html"), []byte("<html>index</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.srv.SetUIDir(uiDir)
	f.handler = f.srv.Handler()
	return f
}

func withOrigin(r *http.Request, origin string) *http.Request {
	r.Header.Set("Origin", origin)
	return r
}

func overTLS(r *http.Request) *http.Request {
	r.TLS = &tls.ConnectionState{}
	return r
}

func TestSecurityHeadersOnRepresentativeRoutes(t *testing.T) {
	f := headersFixture(t)
	cookie := f.authenticate(t)

	cases := []struct {
		name   string
		req    *http.Request
		cookie bool
		code   int
	}{
		{"open JSON route", httptest.NewRequest(http.MethodGet, "/healthz", nil), false, http.StatusOK},
		{"gated route refused", httptest.NewRequest(http.MethodGet, "/api/jobs", nil), false, http.StatusUnauthorized},
		{"gated route served", httptest.NewRequest(http.MethodGet, "/api/jobs", nil), true, http.StatusOK},
		{"web UI page", httptest.NewRequest(http.MethodGet, "/", nil), false, http.StatusOK},
		{"CORS preflight", httptest.NewRequest(http.MethodOptions, "/api/jobs", nil), false, http.StatusNoContent},
		{"foreign Origin refused", withOrigin(httptest.NewRequest(http.MethodGet, "/api/jobs", nil), foreignOrigin), true, http.StatusForbidden},
		{"cross-origin POST refused", withOrigin(httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil), foreignOrigin), false, http.StatusForbidden},
		{"observability without a session", httptest.NewRequest(http.MethodGet, "/observability/d/x", nil), false, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		for _, tlsOn := range []bool{false, true} {
			req := tc.req.Clone(tc.req.Context())
			if tlsOn {
				req = overTLS(req)
			}
			if tc.cookie {
				req.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, req)
			label := tc.name
			if tlsOn {
				label += " (TLS)"
			}
			if w.Code != tc.code {
				t.Fatalf("%s: status %d, want %d", label, w.Code, tc.code)
			}
			assertHeaders(t, label, w.Header(), baselineHeaders)
			assertNoHSTS(t, label, w.Header())
		}
	}
}

// The Grafana proxy is the one route whose responses may be framed, and only
// by the api's own origin. Its CSP is frame-ancestors alone: the UI baseline's
// script rules would break Grafana's frontend.
func TestObservabilityProxyAllowsSameOriginFramingOnly(t *testing.T) {
	f := headersFixture(t)
	cookie := f.authenticate(t)
	req := overTLS(httptest.NewRequest(http.MethodGet, "/observability/d/x", nil))
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	// Observability is off in the fixture, so the proxy answers 503; the
	// headers are the proxy route's all the same.
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 from the proxy with observability off", w.Code)
	}
	assertHeaders(t, "observability proxy", w.Header(), map[string]string{
		"X-Frame-Options":         "SAMEORIGIN",
		"Content-Security-Policy": "frame-ancestors 'self'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "same-origin",
	})
	assertNoHSTS(t, "observability proxy", w.Header())
}

// The bootstrap listener: the baseline headers.
func TestBootstrapHandlerSecurityHeaders(t *testing.T) {
	f := headersFixture(t)
	h := f.srv.BootstrapHandler()
	for _, path := range []string{"/healthz", "/", "/api/jobs", "/api/setup/state"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		assertHeaders(t, "bootstrap "+path, w.Header(), baselineHeaders)
	}
}

func TestObsIngestHandlerSecurityHeaders(t *testing.T) {
	f := headersFixture(t)
	w := httptest.NewRecorder()
	f.srv.ObsIngestHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/obs/ingest", nil))
	assertHeaders(t, "obs ingest", w.Header(), baselineHeaders)
}

// No listener ever sends Strict-Transport-Security, over plain HTTP or TLS:
// it would lock a browser out of a re-flashed controlplane's new controlplane CA and
// of the plain-HTTP /trust page that installs it (see securityHeaders).
func TestNoListenerSendsHSTS(t *testing.T) {
	f := headersFixture(t)
	cookie := f.authenticate(t)
	listeners := []struct {
		name  string
		h     http.Handler
		paths []string
	}{
		{"main", f.handler, []string{"/healthz", "/", "/api/jobs", "/api/setup/state", "/observability/d/x", "/ws/jobs"}},
		{"bootstrap", f.srv.BootstrapHandler(), []string{"/healthz", "/", "/trust", "/api/setup/state", "/mesh-ca.pem", "/api/jobs"}},
		{"obs ingest", f.srv.ObsIngestHandler(), []string{"/api/obs/ingest", "/loki/api/v1/push"}},
	}
	for _, l := range listeners {
		for _, path := range l.paths {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				for _, tlsOn := range []bool{false, true} {
					req := httptest.NewRequest(method, path, nil)
					req.AddCookie(cookie)
					label := l.name + " " + method + " " + path
					if tlsOn {
						req = overTLS(req)
						label += " (TLS)"
					}
					w := httptest.NewRecorder()
					l.h.ServeHTTP(w, req)
					assertNoHSTS(t, label, w.Header())
				}
			}
		}
	}
	t.Run("home door and app door", noHSTSAtSigninDoors)
}

// TC-986-07: no answer at either sign-in door carries HSTS, though the
// identity service sends it on every answer: a relayed page, a redirect, a
// JSON answer, a theme file at the learned version, the door's own files and
// 404 page, the 421 and the not-ready page, each through NewSites over a real
// TLS server and each first at its expected status (F-986-03).
func noHSTSAtSigninDoors(t *testing.T) {
	r := newSitesRig(t, sitesOpts{})
	unbuilt := newSitesRig(t, sitesOpts{nilDoors: true})
	for _, d := range []struct {
		name string
		kind door.Kind
		host string
	}{{"home door", door.Home, r.table.Home.Host}, {"app door", door.App, r.table.App.Host}} {
		for _, c := range []struct {
			what, sni, host, target string
			rig                     *sitesRig
			status                  int
		}{
			{"HTML page", d.host, d.host, authQuery(d.kind, ""), r, http.StatusOK},
			{"redirect", d.host, d.host, authQueryState(d.kind, "redirect"), r, http.StatusFound},
			{"JSON", d.host, d.host, "/realms/rasputin/.well-known/openid-configuration", r, http.StatusOK},
			{"theme file", d.host, d.host, sitesLoginTheme + "css/signin.css", r, http.StatusOK},
			{"door file", d.host, d.host, "/_signin/css/signin.css", r, http.StatusOK},
			{"door 404", d.host, d.host, "/nothing", r, http.StatusNotFound},
			{"421", d.host, sitesConsole, "/", r, http.StatusMisdirectedRequest},
			{"not ready", d.host, d.host, "/", unbuilt, http.StatusServiceUnavailable},
		} {
			label := d.name + " " + c.what
			a := c.rig.do(c.sni, c.host, http.MethodGet, c.target, nil)
			if a.status != c.status {
				t.Errorf("%s: %d, want %d (%.120q)", label, a.status, c.status, a.body)
			}
			assertNoHSTS(t, label, a.header)
		}
	}
}

func assertNoHSTS(t *testing.T, label string, h http.Header) {
	t.Helper()
	if v := h.Values("Strict-Transport-Security"); len(v) != 0 {
		t.Errorf("%s: Strict-Transport-Security = %q, want none", label, v)
	}
}

// TC-988-15: the console's policy names no host source. The UI bundles its
// font, so no directive reaches another host: every source is a keyword
// ('self', 'none', 'unsafe-inline', 'wasm-unsafe-eval'), data: or blob:, and
// font-src is exactly 'self' data: (geekdojo/geekdojo-brain#988).
func TestCSPNamesNoHostSource(t *testing.T) {
	directives := map[string][]string{}
	for _, d := range strings.Split(contentSecurityPolicy, ";") {
		f := strings.Fields(d)
		if len(f) == 0 {
			continue
		}
		directives[f[0]] = f[1:]
		for _, src := range f[1:] {
			keyword := strings.HasPrefix(src, "'") && strings.HasSuffix(src, "'")
			if !keyword && src != "data:" && src != "blob:" {
				t.Errorf("CSP directive %s names the source %q, want only keywords, data: and blob:", f[0], src)
			}
		}
	}
	if got := strings.Join(directives["font-src"], " "); got != "'self' data:" {
		t.Errorf("font-src = %q, want %q", got, "'self' data:")
	}
	for _, host := range []string{"googleapis", "gstatic"} {
		if strings.Contains(contentSecurityPolicy, host) {
			t.Errorf("the CSP names %s: %s", host, contentSecurityPolicy)
		}
	}
}
