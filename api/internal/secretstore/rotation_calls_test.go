package secretstore_test

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

const loginToken = "hvs.LOGIN-TOKEN-a1b2c3d4e5f6g7h8"

// TC-830-12: CertLogin's answers map to a token or exactly one kind, the role
// is sent in the body, and no error string carries the body or the token.
func TestClient_CertLogin(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(w http.ResponseWriter)
		want   error // nil: a token
	}{
		{"200 with a token", func(w http.ResponseWriter) {
			writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": loginToken}})
		}, nil},
		{"200 with an empty token", func(w http.ResponseWriter) {
			writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": ""}})
		}, secretstore.ErrProtocol},
		{"200 with no auth", func(w http.ResponseWriter) { writeJSON(w, 200, map[string]any{"data": nil}) }, secretstore.ErrProtocol},
		{"200 with a token that is not a string", func(w http.ResponseWriter) {
			writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": 7}})
		}, secretstore.ErrProtocol},
		{"403", func(w http.ResponseWriter) {
			writeJSON(w, 403, map[string]any{"errors": []string{"permission denied " + loginToken}})
		}, secretstore.ErrDenied},
		{"503 with health sealed", nil, secretstore.ErrSealed},
		{"a closed connection", hangUp, secretstore.ErrUnreachable},
		{"a malformed body", func(w http.ResponseWriter) {
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"auth": {"client_token": "`+loginToken)
		}, secretstore.ErrProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body string
			f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/health" {
					writeJSON(w, 503, healthBody(true, true))
					return
				}
				if r.URL.Path != "/v1/auth/cert/login" || r.Method != http.MethodPost || r.Header.Get("X-Vault-Token") != "" {
					t.Errorf("request %s %s, token header %q", r.Method, r.URL.Path, r.Header.Get("X-Vault-Token"))
				}
				b, _ := io.ReadAll(r.Body)
				body = string(b)
				if tc.answer == nil {
					writeJSON(w, 503, map[string]any{"errors": []string{"Vault is sealed"}})
					return
				}
				tc.answer(w)
			})
			v, err := f.client.CertLogin(t.Context(), "rasputin-seal-rotate")
			if body != `{"name":"rasputin-seal-rotate"}` {
				t.Errorf("login body = %q", body)
			}
			if tc.want == nil {
				if err != nil || string(v.Reveal()) != loginToken {
					t.Fatalf("CertLogin = %v, %v", v.Len(), err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if v.Len() != 0 {
				t.Error("a failed login returned a token")
			}
			if strings.Contains(err.Error(), loginToken) || strings.Contains(err.Error(), "permission denied") {
				t.Errorf("error %q carries the body or the token", err)
			}
		})
	}
	f := newFixture(t, func(http.ResponseWriter, *http.Request) {})
	if _, err := f.client.CertLogin(t.Context(), ""); !errors.Is(err, secretstore.ErrInvalidValue) || f.hits.Load() != 0 {
		t.Errorf("an empty role: %v after %d requests", err, f.hits.Load())
	}
}

// TC-830-12: RotateRoot sends the token only in X-Vault-Token, maps 204 to
// nil and every other answer to one kind, with no body or token in its error.
func TestClient_RotateRoot(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(w http.ResponseWriter)
		want   error
	}{
		{"204", func(w http.ResponseWriter) { w.WriteHeader(204) }, nil},
		{"403", func(w http.ResponseWriter) {
			writeJSON(w, 403, map[string]any{"errors": []string{"permission denied"}})
		}, secretstore.ErrDenied},
		{"500", func(w http.ResponseWriter) {
			writeJSON(w, 500, map[string]any{"errors": []string{"failed to rotate"}})
		}, secretstore.ErrUnreachable},
		{"a closed connection", hangUp, secretstore.ErrUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/sys/rotate/root" || r.Method != http.MethodPost {
					t.Errorf("request %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("X-Vault-Token") != loginToken || strings.Contains(r.URL.String(), loginToken) {
					t.Error("the token is not only in X-Vault-Token")
				}
				b, _ := io.ReadAll(r.Body)
				if strings.Contains(string(b), loginToken) {
					t.Error("the token is in the body")
				}
				tc.answer(w)
			})
			err := f.client.RotateRoot(t.Context(), tok(loginToken))
			if tc.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), loginToken) || strings.Contains(err.Error(), "failed to rotate") {
				t.Errorf("error %q carries the body or the token", err)
			}
			if strings.Contains(f.rec.Text(), loginToken) {
				t.Error("the token reached the log")
			}
		})
	}
}

// TC-830-13 (the client half): a leaf mint that fails fails the handshake as
// ErrUnreachable with no request sent, and the minted config trusts only the
// store CA over TLS 1.3.
func TestNewMintedTLSConfig(t *testing.T) {
	ca := storeCA(t)
	if _, err := secretstore.NewMintedTLSConfig(ca.CertPEM, nil); err == nil {
		t.Error("a nil mint accepted")
	}
	if _, err := secretstore.NewMintedTLSConfig([]byte("no pem"), func() (*tls.Certificate, error) { return nil, nil }); err == nil {
		t.Error("a CA PEM with no certificate accepted")
	}
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	cfg, err := secretstore.NewMintedTLSConfig(f.ca.CertPEM, func() (*tls.Certificate, error) {
		return nil, errors.New("clock gate refused")
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.RootCAs == nil {
		t.Errorf("config: min %x, roots %v", cfg.MinVersion, cfg.RootCAs)
	}
	lg, _ := logkittest.New()
	c := newClient(t, f.srv.URL, cfg, lg)
	if err := c.RotateRoot(t.Context(), tok(loginToken)); !errors.Is(err, secretstore.ErrUnreachable) {
		t.Fatalf("RotateRoot with a failing mint = %v, want ErrUnreachable", err)
	}
	if f.hits.Load() != 0 {
		t.Errorf("%d requests reached the store", f.hits.Load())
	}
}
