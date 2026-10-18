package secretstore_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
)

// TC-761-18: Client.Delete sends DELETE /v1/<mount>/metadata/<path> with the
// token only in X-Vault-Token and no body; 204 and 404 are nil, and every
// other answer is one kind with Op "delete". The zero KVPath sends nothing.
func TestClient_Delete(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(w http.ResponseWriter)
		want   error // nil: success
	}{
		{"204", func(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }, nil},
		{"404", func(w http.ResponseWriter) { writeJSON(w, http.StatusNotFound, map[string]any{"errors": []string{}}) }, nil},
		{"403", func(w http.ResponseWriter) {
			writeJSON(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
		}, secretstore.ErrDenied},
		{"503 with health sealed", func(w http.ResponseWriter) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"errors": []string{"Vault is sealed"}})
		}, secretstore.ErrSealed},
		{"500", func(w http.ResponseWriter) {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"errors": []string{"internal"}})
		}, secretstore.ErrUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/health" {
					writeJSON(w, http.StatusServiceUnavailable, healthBody(true, true))
					return
				}
				if r.Method != http.MethodDelete || r.URL.Path != "/v1/rasputin-secrets/metadata/apps/X/k" || r.URL.RawQuery != "" {
					t.Errorf("request %s %s?%s, want DELETE /v1/rasputin-secrets/metadata/apps/X/k", r.Method, r.URL.Path, r.URL.RawQuery)
				}
				if r.Header.Get("X-Vault-Token") != loginToken || strings.Contains(r.URL.String(), loginToken) {
					t.Error("the token is not only in X-Vault-Token")
				}
				if b, _ := io.ReadAll(r.Body); len(b) != 0 {
					t.Errorf("the request carries a %d-byte body", len(b))
				}
				tc.answer(w)
			})
			err := f.client.Delete(t.Context(), tok(loginToken), kvPath(t, "rasputin-secrets", "apps/X/k"))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Delete = %v, want nil", err)
				}
				return
			}
			var se *secretstore.Error
			if !errors.Is(err, tc.want) || !errors.As(err, &se) || se.Op != "delete" {
				t.Fatalf("Delete = %v, want %v with Op delete", err, tc.want)
			}
			if strings.Contains(err.Error(), loginToken) || strings.Contains(f.rec.Text(), loginToken) {
				t.Error("the token reached the error or the log")
			}
		})
	}

	f := newFixture(t, func(http.ResponseWriter, *http.Request) {})
	if err := f.client.Delete(t.Context(), tok(loginToken), secretstore.KVPath{}); !errors.Is(err, secretstore.ErrInvalidValue) || f.hits.Load() != 0 {
		t.Errorf("Delete of the zero KVPath = %v after %d requests; want ErrInvalidValue and none", err, f.hits.Load())
	}
}
