package api

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
			hsts := w.Header().Get("Strict-Transport-Security")
			switch {
			case tlsOn && hsts != strictTransportSecurity:
				t.Errorf("%s: Strict-Transport-Security = %q, want %q", label, hsts, strictTransportSecurity)
			case !tlsOn && hsts != "":
				t.Errorf("%s: Strict-Transport-Security = %q over plain HTTP, want none", label, hsts)
			}
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
		"X-Frame-Options":           "SAMEORIGIN",
		"Content-Security-Policy":   "frame-ancestors 'self'",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "same-origin",
		"Strict-Transport-Security": strictTransportSecurity,
	})
}

// The bootstrap listener is plain HTTP: the baseline headers, never HSTS.
func TestBootstrapHandlerSecurityHeaders(t *testing.T) {
	f := headersFixture(t)
	h := f.srv.BootstrapHandler()
	for _, path := range []string{"/healthz", "/", "/api/jobs", "/api/setup/state"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		assertHeaders(t, "bootstrap "+path, w.Header(), baselineHeaders)
		if hsts := w.Header().Get("Strict-Transport-Security"); hsts != "" {
			t.Errorf("bootstrap %s: Strict-Transport-Security = %q over plain HTTP, want none", path, hsts)
		}
	}
}

func TestObsIngestHandlerSecurityHeaders(t *testing.T) {
	f := headersFixture(t)
	w := httptest.NewRecorder()
	f.srv.ObsIngestHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/obs/ingest", nil))
	assertHeaders(t, "obs ingest", w.Header(), baselineHeaders)
}
