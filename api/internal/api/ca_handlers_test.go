package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
)

var caRoutes = []string{"/mesh-ca.pem", "/mesh-ca.crt", "/api/mesh/ios-profile"}

// TC-741-10 (endpoint half): with both CAs in the trust dir, every CA download
// route serves the controlplane CA and never the store CA, on unchanged
// routes, on the main handler and the plain-HTTP bootstrap surface alike.
func TestCARoutes_ServeTheControlplaneCAOnly(t *testing.T) {
	f := newAPIFixture(t)
	cp := tlscatest.Controlplane(t, f.srv.trustDir)
	store, err := tlsca.Ensure(tlsca.StoreConfig(), f.srv.trustDir, "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	storeDER := base64.StdEncoding.EncodeToString(store.Cert.Raw)[:64]
	cpDER := base64.StdEncoding.EncodeToString(cp.Cert.Raw)[:64]
	for _, h := range map[string]http.Handler{"main": f.srv.Handler(), "bootstrap": f.srv.BootstrapHandler()} {
		for _, route := range caRoutes {
			w := serve(h, route)
			if w.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", route, w.Code, w.Body)
			}
			body := w.Body.Bytes()
			if bytes.Contains(body, bytes.TrimSpace(store.CertPEM)) || strings.Contains(string(body), storeDER) {
				t.Errorf("%s serves the store CA", route)
			}
			if route == "/api/mesh/ios-profile" {
				// The profile carries the DER base64-wrapped at 64 columns.
				if !strings.Contains(string(body), cpDER) {
					t.Errorf("%s does not carry the controlplane CA", route)
				}
				continue
			}
			if !bytes.Equal(body, cp.CertPEM) {
				t.Errorf("%s body is not the controlplane CA's bytes", route)
			}
		}
	}
}

func serve(h http.Handler, route string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, route, nil))
	return w
}

// TC-741-30: an unreadable or missing controlplane CA answers every CA route
// with only "controlplane CA not available" — no path, no os error text — and
// writes one ERROR with the path and err to the Server's own logger.
func TestCARoutes_KeepInternalDetailOffTheWire(t *testing.T) {
	for _, tc := range []struct {
		name    string
		breakCA func(t *testing.T, path string)
		status  int
	}{
		{"unreadable (a directory)", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}, http.StatusInternalServerError},
		{"missing", func(*testing.T, string) {}, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAPIFixture(t)
			logs := &logCapture{}
			f.srv.log = slog.New(logs)
			path := filepath.Join(f.srv.trustDir, tlsca.ControlplaneCertFile)
			_ = os.Remove(path)
			tc.breakCA(t, path)
			for _, route := range caRoutes {
				w := serve(f.srv.Handler(), route)
				if w.Code != tc.status {
					t.Errorf("%s: status %d, want %d", route, w.Code, tc.status)
				}
				var body map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatalf("%s: body %s", route, w.Body)
				}
				if len(body) != 1 || body["error"] != "controlplane CA not available" {
					t.Errorf("%s: body %v, want only the generic message", route, body)
				}
				if strings.Contains(w.Body.String(), f.srv.trustDir) {
					t.Errorf("%s: the trust dir path reached the client", route)
				}
			}
			recs := logs.withAttr("path", path)
			if len(recs) != len(caRoutes) {
				t.Fatalf("%d records carry the path, want one per request", len(recs))
			}
			for _, r := range recs {
				if r.Level != slog.LevelError {
					t.Errorf("record level %s", r.Level)
				}
				if v, ok := recAttr(r, "err"); !ok || v == "" {
					t.Error("record carries no err")
				}
			}
		})
	}
}
