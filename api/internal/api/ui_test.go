package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// exportFS mimics the shape of a Next.js static export (out/).
func exportFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                  {Data: []byte("<html>index</html>")},
		"login.html":                  {Data: []byte("<html>login</html>")},
		"login.txt":                   {Data: []byte("rsc-payload")},
		"404.html":                    {Data: []byte("<html>not found</html>")},
		"firewall/rules.html":         {Data: []byte("<html>rules</html>")},
		"_next/static/chunks/main.js": {Data: []byte("js")},
	}
}

func TestUIHandlerResolution(t *testing.T) {
	h := uiHandler{fsys: exportFS()}

	cases := []struct {
		path       string
		wantStatus int
		wantBody   string // substring
		wantCache  string // exact Cache-Control, "" = don't check
	}{
		{"/", 200, "index", "no-cache"},
		{"/login", 200, "login", "no-cache"},
		{"/login.txt", 200, "rsc-payload", "no-cache"},
		{"/firewall/rules", 200, "rules", "no-cache"},
		{"/_next/static/chunks/main.js", 200, "js", "public, max-age=31536000, immutable"},
		{"/nope", 404, "not found", ""},
		{"/nope/deeper", 404, "not found", ""},
		// Traversal attempts must not escape (or 500): cleaned, then 404.
		{"/../../etc/passwd", 404, "", ""},
		{"/..%2f..%2fetc/passwd", 404, "", ""},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.wantStatus {
			t.Errorf("%s: status = %d, want %d", tc.path, rec.Code, tc.wantStatus)
		}
		if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
			t.Errorf("%s: body %q does not contain %q", tc.path, rec.Body.String(), tc.wantBody)
		}
		if tc.wantCache != "" && rec.Header().Get("Cache-Control") != tc.wantCache {
			t.Errorf("%s: Cache-Control = %q, want %q", tc.path, rec.Header().Get("Cache-Control"), tc.wantCache)
		}
	}
}

// The UI is the mux *fallback*: API routes and /healthz must still win, and
// without SetUIDir the root must stay a 404 (headless dev mode).
func TestUIRoutingPrecedence(t *testing.T) {
	f := newAPIFixture(t)

	// Headless (no SetUIDir): / is a plain 404.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("headless GET / = %d, want 404", rec.Code)
	}

	// With a UI dir: / serves index.html, /healthz still answers, and an
	// /api path still requires a session (401, not the UI's 404 page).
	dir := t.TempDir()
	for name, body := range map[string]string{
		"index.html": "<html>ui-root</html>",
		"404.html":   "<html>ui-404</html>",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f.srv.SetUIDir(dir)
	handler := f.srv.Handler()

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ui-root") {
		t.Fatalf("GET / = %d %q, want 200 ui-root", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/nodes without session = %d, want 401", rec.Code)
	}
}
