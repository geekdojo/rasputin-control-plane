package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
)

// provisionMeshCA drops a real Mesh CA into the fixture's trust dir (the
// fixture wires trustDir == f.dir) so the CA-download endpoints have
// something to serve.
func provisionMeshCA(t *testing.T, f *apiFixture) {
	t.Helper()
	if _, err := mesh.EnsureMeshCA(f.dir, "test-install"); err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
}

// ============================================================================
// CA-download endpoints (open — no session cookie on any request below)
// ============================================================================

func TestMeshCAPEM_OpenAndServed(t *testing.T) {
	f := newAPIFixture(t)
	provisionMeshCA(t, f)

	w := f.do(t, http.MethodGet, "/mesh-ca.pem", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 without auth, got %d (%s)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/x-pem-file" {
		t.Errorf("Content-Type = %q, want application/x-pem-file", got)
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, `filename="rasputin-mesh-ca.pem"`) {
		t.Errorf("Content-Disposition = %q, want rasputin-mesh-ca.pem filename", got)
	}
	if !strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
		t.Errorf("body is not PEM: %q", w.Body.String()[:min(80, w.Body.Len())])
	}
}

func TestMeshIOSProfile_Open(t *testing.T) {
	f := newAPIFixture(t)
	provisionMeshCA(t, f)

	// No cookie — must succeed anyway (first-run has no users yet).
	w := f.do(t, http.MethodGet, "/api/mesh/ios-profile", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 without auth, got %d (%s)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/x-apple-aspen-config" {
		t.Errorf("Content-Type = %q", got)
	}
}

func TestCAEndpoints_404WhenCAMissing(t *testing.T) {
	f := newAPIFixture(t) // trustDir exists but holds no mesh-ca.pem
	for _, p := range []string{"/mesh-ca.pem", "/api/mesh/ios-profile"} {
		w := f.do(t, http.MethodGet, p, "", nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s: want 404 when CA missing, got %d", p, w.Code)
		}
	}
}

// ============================================================================
// BootstrapHandler — the plain-HTTP surface when HTTPS is enabled
// ============================================================================

// doBootstrap runs a request against the fixture's BootstrapHandler.
func doBootstrap(f *apiFixture, method, target, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if host != "" {
		req.Host = host
	}
	w := httptest.NewRecorder()
	f.srv.BootstrapHandler().ServeHTTP(w, req)
	return w
}

func TestBootstrap_HealthzStaysHTTP(t *testing.T) {
	f := newAPIFixture(t)
	w := doBootstrap(f, http.MethodGet, "/healthz", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestBootstrap_CAEndpointsServed(t *testing.T) {
	f := newAPIFixture(t)
	provisionMeshCA(t, f)
	for _, p := range []string{"/mesh-ca.pem", "/api/mesh/ios-profile"} {
		w := doBootstrap(f, http.MethodGet, p, "")
		if w.Code != http.StatusOK {
			t.Errorf("GET %s over bootstrap HTTP: want 200, got %d", p, w.Code)
		}
	}
}

func TestBootstrap_RootLandsOnTrust(t *testing.T) {
	f := newAPIFixture(t)
	w := doBootstrap(f, http.MethodGet, "/", "rasputin.local")
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", w.Code)
	}
	// Must stay on plain HTTP — bouncing "/" to https:// would surface the
	// cert warning the trust page exists to prevent.
	if got := w.Header().Get("Location"); got != "/trust" {
		t.Errorf("Location = %q, want /trust", got)
	}
}

func TestBootstrap_RedirectsToHTTPSWithPortStripped(t *testing.T) {
	f := newAPIFixture(t)
	cases := []struct {
		method, target, host, wantLoc string
	}{
		{http.MethodGet, "/login", "rasputin.local", "https://rasputin.local/login"},
		{http.MethodGet, "/api/jobs?limit=5", "rasputin.local:80", "https://rasputin.local/api/jobs?limit=5"},
		{http.MethodGet, "/firewall/rules", "192.168.7.2:80", "https://192.168.7.2/firewall/rules"},
		// Mutations must not execute over plain HTTP — they bounce too.
		{http.MethodPost, "/api/firewall/apply", "rasputin.local", "https://rasputin.local/api/firewall/apply"},
		{http.MethodDelete, "/api/nodes/n1", "rasputin.local:80", "https://rasputin.local/api/nodes/n1"},
		// WS endpoints aren't served on the bootstrap surface either.
		{http.MethodGet, "/ws/jobs", "rasputin.local", "https://rasputin.local/ws/jobs"},
	}
	for _, c := range cases {
		w := doBootstrap(f, c.method, c.target, c.host)
		if w.Code != http.StatusFound {
			t.Errorf("%s %s: want 302, got %d", c.method, c.target, w.Code)
			continue
		}
		if got := w.Header().Get("Location"); got != c.wantLoc {
			t.Errorf("%s %s: Location = %q, want %q", c.method, c.target, got, c.wantLoc)
		}
	}
}

func TestBootstrap_NoMutationRouteExecutes(t *testing.T) {
	f := newAPIFixture(t)
	// POST /api/jobs on the main handler (unauthenticated) is a 401; on the
	// bootstrap handler it must be a redirect, never a handler execution.
	w := doBootstrap(f, http.MethodPost, "/api/jobs", "rasputin.local")
	if w.Code != http.StatusFound {
		t.Fatalf("want 302 (redirect, not execution), got %d", w.Code)
	}
}

func TestBootstrap_ServesTrustPageAndAssets(t *testing.T) {
	f := newAPIFixture(t)

	// Fake static export with just enough for /trust.
	uiDir := t.TempDir()
	mustWrite(t, filepath.Join(uiDir, "trust.html"), "<html>SECURE YOUR CONNECTION</html>")
	mustWrite(t, filepath.Join(uiDir, "_next", "static", "app.css"), "body{}")
	mustWrite(t, filepath.Join(uiDir, "favicon.ico"), "icon")
	mustWrite(t, filepath.Join(uiDir, "login.html"), "<html>login</html>")
	f.srv.SetUIDir(uiDir)

	// /trust renders over plain HTTP.
	w := doBootstrap(f, http.MethodGet, "/trust", "rasputin.local")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /trust: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "SECURE YOUR CONNECTION") {
		t.Errorf("GET /trust: unexpected body %q", w.Body.String())
	}

	// Assets render over plain HTTP.
	for _, p := range []string{"/_next/static/app.css", "/favicon.ico"} {
		w := doBootstrap(f, http.MethodGet, p, "rasputin.local")
		if w.Code != http.StatusOK {
			t.Errorf("GET %s: want 200, got %d", p, w.Code)
		}
	}

	// But page ROUTES other than /trust still bounce to HTTPS even though
	// the export could serve them — passkeys don't work without a secure
	// context, so rendering /login over HTTP would be a dead end.
	w = doBootstrap(f, http.MethodGet, "/login", "rasputin.local")
	if w.Code != http.StatusFound {
		t.Fatalf("GET /login with uiDir set: want 302, got %d", w.Code)
	}
	if got := w.Header().Get("Location"); got != "https://rasputin.local/login" {
		t.Errorf("Location = %q", got)
	}
}

func TestBootstrap_TrustWithoutUIDirRedirects(t *testing.T) {
	f := newAPIFixture(t) // headless: no uiDir
	w := doBootstrap(f, http.MethodGet, "/trust", "rasputin.local")
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", w.Code)
	}
	if got := w.Header().Get("Location"); got != "https://rasputin.local/trust" {
		t.Errorf("Location = %q", got)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
