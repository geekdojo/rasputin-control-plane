package identitytest_test

// The disabled-feature capability row (T73, geekdojo/geekdojo-brain#980): the
// pinned Keycloak, built with identity/keycloak-build.conf, serves nothing at
// the features that file disables. It shares pkg and TestMain with
// selftest_functional_test.go and sends no credential, so
// TestIdentity_NoSecretInLogs is unaffected.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest"
)

// TC-980-21: through the front, the admin console, the account console, PAR
// and CIBA answer 404; the token endpoint refuses the device-code and
// token-exchange grants with unsupported_grant_type; and discovery has no
// device_authorization_endpoint. Each is a named subtest.
func TestIdentity_DisabledFeaturesServeNothing(t *testing.T) {
	env := pkg.Env(t)
	tr := &http.Transport{TLSClientConfig: env.ClientTLS()}
	defer tr.CloseIdleConnections()
	// A redirect is an answer, not something to follow: a 404 must be the
	// endpoint's own.
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	realm := env.FrontURL() + "/realms/" + identitytest.Realm
	form := func(v url.Values) io.Reader { return strings.NewReader(v.Encode()) }

	do := func(t *testing.T, method, target string, body io.Reader) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, target, body)
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s %s: read the body: %v", method, target, err)
		}
		return resp.StatusCode, b
	}

	notFound := []struct{ name, method, path string }{
		{"admin console answers 404", http.MethodGet, env.FrontURL() + "/admin/"},
		{"account console answers 404", http.MethodGet, realm + "/account"},
		{"PAR answers 404", http.MethodPost, realm + "/protocol/openid-connect/ext/par/request"},
		{"CIBA auth answers 404", http.MethodPost, realm + "/protocol/openid-connect/ext/ciba/auth"},
	}
	for _, c := range notFound {
		t.Run(c.name, func(t *testing.T) {
			var body io.Reader
			if c.method == http.MethodPost {
				body = form(url.Values{"client_id": {identitytest.ClientID}})
			}
			if code, b := do(t, c.method, c.path, body); code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404 (body %.200q)", c.method, c.path, code, b)
			}
		})
	}

	grants := []struct{ name, grant string }{
		{"device-code grant is unsupported", "urn:ietf:params:oauth:grant-type:device_code"},
		{"token-exchange grant is unsupported", "urn:ietf:params:oauth:grant-type:token-exchange"},
	}
	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			code, b := do(t, http.MethodPost, realm+"/protocol/openid-connect/token",
				form(url.Values{"grant_type": {g.grant}, "client_id": {identitytest.ClientID}}))
			var answer struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(b, &answer); err != nil {
				t.Fatalf("token endpoint answered %d with a body that is not JSON: %v (%.200q)", code, err, b)
			}
			if answer.Error != "unsupported_grant_type" {
				t.Errorf("grant_type=%s: error = %q (status %d), want unsupported_grant_type", g.grant, answer.Error, code)
			}
		})
	}

	t.Run("discovery has no device_authorization_endpoint", func(t *testing.T) {
		code, b := do(t, http.MethodGet, realm+"/.well-known/openid-configuration", nil)
		if code != http.StatusOK {
			t.Fatalf("discovery = %d, want 200 (body %.200q)", code, b)
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("discovery is not JSON: %v", err)
		}
		if _, ok := doc["token_endpoint"]; !ok {
			t.Fatal("discovery has no token_endpoint, so it is not the realm's document")
		}
		if v, ok := doc["device_authorization_endpoint"]; ok {
			t.Errorf("discovery advertises device_authorization_endpoint %v, want none", v)
		}
	})
}
