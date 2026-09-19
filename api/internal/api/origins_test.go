package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// The fixture's origin allowlist is the dev one, http://localhost:3000 (see
// newAPIFixture). Everything below is decided by that one list.
const (
	allowedOrigin = "http://localhost:3000"
	foreignOrigin = "https://evil.example"
)

func TestCORSEchoesOnlyAllowlistedOrigins(t *testing.T) {
	f := newAPIFixture(t)
	for _, tc := range []struct {
		origin    string
		wantACAO  string
		wantCreds string
	}{
		{allowedOrigin, allowedOrigin, "true"},
		{foreignOrigin, "", ""},
		{"https://localhost:3000", "", ""}, // same host, other scheme
		{"null", "", ""},
	} {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200 (an open GET is served; CORS only withholds it from the page)", tc.origin, w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != tc.wantACAO {
			t.Errorf("%s: ACAO = %q, want %q", tc.origin, got, tc.wantACAO)
		}
		if got := w.Header().Get("Access-Control-Allow-Credentials"); got != tc.wantCreds {
			t.Errorf("%s: ACAC = %q, want %q", tc.origin, got, tc.wantCreds)
		}
		if got := w.Header().Get("Vary"); got != "Origin" {
			t.Errorf("%s: Vary = %q, want Origin", tc.origin, got)
		}
	}
}

func TestCORSPreflightRefusesForeignOrigin(t *testing.T) {
	f := newAPIFixture(t)
	req := httptest.NewRequest(http.MethodOptions, "/api/jobs", nil)
	req.Header.Set("Origin", foreignOrigin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", w.Code)
	}
	for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Methods"} {
		if got := w.Header().Get(h); got != "" {
			t.Errorf("%s = %q on a refused preflight", h, got)
		}
	}

	// The allowlisted dev origin's preflight names every method the UI uses.
	req = httptest.NewRequest(http.MethodOptions, "/api/apps/x/compose", nil)
	req.Header.Set("Origin", allowedOrigin)
	req.Header.Set("Access-Control-Request-Method", "PUT")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("allowed preflight: status %d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "PUT") {
		t.Errorf("Access-Control-Allow-Methods = %q, want PUT among them", got)
	}
}

// An unsafe method from a foreign origin is refused before any handler runs —
// including the routes that have no session gate, such as the auth
// ceremonies. A non-browser client (no Origin, no Sec-Fetch-Site) and the
// allowlisted origin are not.
func TestCrossOriginProtectionOnUnsafeMethods(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	post := func(path, origin, fetchSite string, withCookie bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if fetchSite != "" {
			req.Header.Set("Sec-Fetch-Site", fetchSite)
		}
		if withCookie {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, req)
		return w
	}

	for _, path := range []string{"/api/auth/login/begin", "/api/restore", "/api/setup/complete"} {
		w := post(path, foreignOrigin, "cross-site", true)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s from a foreign origin (Sec-Fetch-Site): status %d, want 403", path, w.Code)
		}
		// Without Sec-Fetch-Site, the Origin/Host comparison decides.
		w = post(path, foreignOrigin, "", true)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s from a foreign origin (Origin only): status %d, want 403", path, w.Code)
		}
	}

	// Not refused as cross-origin: whatever the route then answers, it is
	// not the 403 this layer writes.
	notRefused := func(label string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "cross-origin") {
			t.Errorf("%s: refused as cross-origin: %s", label, w.Body.String())
		}
	}
	notRefused("allowlisted origin", post("/api/auth/login/begin", allowedOrigin, "same-site", false))
	notRefused("no browser headers", post("/api/auth/login/begin", "", "", false))
	notRefused("same-origin fetch", post("/api/auth/login/begin", "", "same-origin", false))
}

// RequireSession's Origin check refuses a foreign Origin on a gated API route
// even when the session cookie is valid.
func TestGatedRouteRefusesForeignOrigin(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	get := func(origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/jobs", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, req)
		return w
	}
	if w := get(foreignOrigin); w.Code != http.StatusForbidden {
		t.Errorf("foreign Origin: status %d, want 403", w.Code)
	}
	if w := get(allowedOrigin); w.Code != http.StatusOK {
		t.Errorf("allowlisted Origin: status %d, want 200", w.Code)
	}
	if w := get(""); w.Code != http.StatusOK {
		t.Errorf("no Origin: status %d, want 200", w.Code)
	}
}

// The WebSocket endpoints, end to end over a real listener: the allowlisted
// origin upgrades; a foreign origin, and an origin that matches the Host but
// not the scheme (which the WebSocket library alone would let through), are
// refused before the upgrade.
func TestWebSocketUpgradeOriginPolicy(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	ts := httptest.NewServer(f.handler)
	t.Cleanup(ts.Close)
	wsBase := "ws" + strings.TrimPrefix(ts.URL, "http")
	host := strings.TrimPrefix(ts.URL, "http://")

	dial := func(path, origin string) (*websocket.Conn, *http.Response, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h := http.Header{"Cookie": {cookie.String()}}
		if origin != "" {
			h.Set("Origin", origin)
		}
		return websocket.Dial(ctx, wsBase+path, &websocket.DialOptions{HTTPHeader: h})
	}

	for _, path := range []string{"/ws/jobs", "/ws/bmc/some-node/sol"} {
		for _, origin := range []string{foreignOrigin, "https://" + host} {
			c, resp, err := dial(path, origin)
			if err == nil {
				c.Close(websocket.StatusNormalClosure, "")
				t.Errorf("%s from %s: upgraded, want refused", path, origin)
				continue
			}
			if resp == nil || resp.StatusCode != http.StatusForbidden {
				code := 0
				if resp != nil {
					code = resp.StatusCode
				}
				t.Errorf("%s from %s: status %d, want 403", path, origin, code)
			}
		}
	}

	c, resp, err := dial("/ws/jobs", allowedOrigin)
	if err != nil {
		t.Fatalf("allowlisted origin: %v", err)
	}
	c.Close(websocket.StatusNormalClosure, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("allowlisted origin: status %d, want 101", resp.StatusCode)
	}
}

// The /trust page reads /api/setup/state over plain HTTP on a device that
// does not trust the Mesh CA yet, so the bootstrap listener serves it rather
// than redirecting it to https://. Only GET: anything else still redirects.
func TestBootstrapServesSetupState(t *testing.T) {
	f := newAPIFixture(t)
	h := f.srv.BootstrapHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/setup/state", nil)
	req.Host = "rasputin.local"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/setup/state on :80: status %d, want 200 (Location %q)", w.Code, w.Header().Get("Location"))
	}
	var state map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, w.Body.String())
	}
	if state["clusterHostname"] != "test1.local" {
		t.Errorf("clusterHostname = %v, want the fixture's test1.local", state["clusterHostname"])
	}

	req = httptest.NewRequest(http.MethodPost, "/api/setup/state", nil)
	req.Host = "rasputin.local"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://rasputin.local/api/setup/state" {
		t.Errorf("POST /api/setup/state on :80: %d %q, want a 302 to https", w.Code, w.Header().Get("Location"))
	}
}
