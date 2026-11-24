package identitytest

// TC-980-25: the realm baseline as the pinned Keycloak builds it
// (geekdojo/geekdojo-brain#980). The repo's identity/realm-baseline.json is
// imported as realm rasputin by Keycloak's own import command, so its
// RealmManager import runs exactly as it will on a cluster: the built-in
// client scopes are created, clientScopeMappings and default client scopes
// are applied. Then rasputin-admin, authenticated by client-x509 with a leaf
// whose subject is the api's, uses the Admin API, and each authorization-code
// client yields a token through a headless password sign-in.
//
// It is in package identitytest, not identitytest_test, because the import
// runs a second kc.sh against the Env's own database and keycloak.conf, which
// only the package sees. So it starts an Env of its own, closed with proof in
// its cleanup, and leaves the shared pkg Env (and TestIdentity_NoSecretInLogs'
// recorder) untouched. It skips without RASPUTIN_IDENTITY_HOME and fails
// instead under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job
// sets it.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest/signin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

const (
	// baselineRealm is the realm identity/realm-baseline.json declares.
	baselineRealm = "rasputin"
	// baselineAdminClient is the api's Admin API client in the baseline.
	baselineAdminClient = "rasputin-admin"
	// baselineConsole is the console client, whose roles reach the token as
	// rasputin_roles (identity-authz.md §3.1).
	baselineConsole = "rasputin-console"
	// baselineMesh is the one client that authenticates by client secret.
	baselineMesh = "rasputin-mesh"
)

// baselineCodeClients are the baseline's authorization-code clients.
var baselineCodeClients = []string{baselineConsole, "rasputin-account", "rasputin-reset-home", "rasputin-reset-app", baselineMesh}

// importBaseline imports the repo's realm baseline into env's database with
// kc.sh import, the running server's own build and keycloak.conf, under the
// unit's JVM environment. The realm is new to the running server, so it has
// nothing cached for it and reads it from the database on first use.
func importBaseline(t *testing.T, env *Env) {
	t.Helper()
	baseline, err := os.ReadFile(filepath.Join("..", "..", "..", "identity", "realm-baseline.json"))
	if err != nil {
		t.Fatalf("read the repo's realm baseline: %v", err)
	}
	dir := filepath.Join(env.root, "baseline-import")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, baselineRealm+"-realm.json")
	if err := os.WriteFile(file, baseline, 0o600); err != nil {
		t.Fatal(err)
	}
	kcCommand(t, env, "import of identity/realm-baseline.json", "import", "--optimized", "--file", file)
	env.log.Info("realm baseline imported", "realm", baselineRealm, "file", file)
}

// kcCommand runs a second kc.sh against env's database and keycloak.conf,
// the running server's own build, under the unit's JVM environment, and
// fails the test, naming what, unless it succeeds.
func kcCommand(t *testing.T, env *Env, what string, args ...string) {
	t.Helper()
	cfg := env.h.cfg
	home := filepath.Join(env.root, "kc")
	out, err := cfg.Run(t.Context(), "/usr/bin/env", append([]string{"-i",
		"PATH=/usr/bin:/bin",
		"HOME=" + env.root,
		"JAVA_HOME=" + cfg.JavaHome,
		"MALLOC_ARENA_MAX=" + mallocArenaMax,
		"JAVA_OPTS_KC_HEAP=" + javaOptsHeap,
		"JAVA_OPTS_APPEND=" + javaOptsAppend,
		filepath.Join(home, "bin", "kc.sh"), "--config-file=" + filepath.Join(env.root, "keycloak.conf")}, args...)...)
	if err != nil {
		t.Fatalf("kc.sh %s: %v\n%s", what, err, tail(out, 40))
	}
}

// tail is the last n lines of out.
func tail(out []byte, n int) string {
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// apiLeafTLS mints a client leaf with the api's identity subject under the
// Env's CA and returns a TLS 1.3 config that presents it to whatever asks.
func apiLeafTLS(t *testing.T, env *Env) *tls.Config {
	t.Helper()
	paths, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatalf("mint the api leaf: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(paths.CertPath, paths.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := pair.Leaf.Subject.String(); got != AdminSubjectDN {
		t.Fatalf("api leaf subject %q, want exactly %q", got, AdminSubjectDN)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    env.Roots(),
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &pair, nil
		},
	}
}

// adminAPI calls realm rasputin's Admin API on Keycloak's own port as
// rasputin-admin.
type adminAPI struct {
	t      *testing.T
	client *http.Client
	base   string // <KeycloakURL>/admin/realms/rasputin
	token  string
}

// do sends body (JSON-encoded unless nil) and returns the status, the
// Location header and the body.
func (a adminAPI) do(method, path string, body any) (int, string, []byte) {
	a.t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			a.t.Fatal(err)
		}
		defer clear(b)
		r = bytes.NewReader(b)
	}
	target := path
	if !strings.HasPrefix(path, "https://") {
		target = a.base + path
	}
	req, err := http.NewRequestWithContext(a.t.Context(), method, target, r)
	if err != nil {
		a.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		a.t.Fatalf("%s %s: read the body: %v", method, target, err)
	}
	return resp.StatusCode, resp.Header.Get("Location"), out
}

// must is do, failing the test unless the status is want.
func (a adminAPI) must(want int, method, path string, body any) (string, []byte) {
	a.t.Helper()
	status, loc, out := a.do(method, path, body)
	if status != want {
		a.t.Fatalf("Admin API %s %s answered %d, want %d: %.300s", method, path, status, want, out)
	}
	return loc, out
}

// clientRep is the client's full representation and its internal id.
func (a adminAPI) clientRep(clientID string) (string, map[string]any) {
	a.t.Helper()
	_, out := a.must(http.StatusOK, http.MethodGet, "/clients?clientId="+url.QueryEscape(clientID), nil)
	var reps []map[string]any
	if err := json.Unmarshal(out, &reps); err != nil || len(reps) != 1 {
		a.t.Fatalf("client %s: %d representations (%v), want 1", clientID, len(reps), err)
	}
	id, _ := reps[0]["id"].(string)
	if id == "" {
		a.t.Fatalf("client %s has no id", clientID)
	}
	return id, reps[0]
}

// tokenCatch carries a sign-in's requests and keeps the access token from
// the token endpoint's answer. With basicUser set it authenticates the token
// request by client secret (RFC 6749 §2.3.1), which signin's exchange does
// not send itself.
type tokenCatch struct {
	inner                http.RoundTripper
	basicUser, basicPass string
	access               string
}

func (c *tokenCatch) RoundTrip(req *http.Request) (*http.Response, error) {
	isToken := strings.HasSuffix(req.URL.Path, "/protocol/openid-connect/token")
	if isToken && c.basicUser != "" {
		req = req.Clone(req.Context())
		req.SetBasicAuth(url.QueryEscape(c.basicUser), url.QueryEscape(c.basicPass))
	}
	resp, err := c.inner.RoundTrip(req)
	if err != nil || !isToken {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(body, &tok) == nil {
		c.access = tok.AccessToken
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// jwtClaims decodes a JWT's payload without checking its signature: it came
// over TLS from the issuer.
func jwtClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatal("the access token is not a JWS compact serialization")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("the access token payload: %v", err)
	}
	var c map[string]any
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatalf("the access token payload: %v", err)
	}
	return c
}

// baselineAdmin is realm rasputin's Admin API as rasputin-admin, authenticated
// by client-x509 with a leaf whose subject is the api's, and that leaf's TLS
// config. The baseline must be imported.
func baselineAdmin(t *testing.T, env *Env) (adminAPI, *tls.Config) {
	t.Helper()
	leafTLS := apiLeafTLS(t, env)
	tr := &http.Transport{TLSClientConfig: leafTLS}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// rasputin-admin's client_credentials token, straight from Keycloak so
	// the request presents the api leaf.
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {baselineAdminClient}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		env.KeycloakURL()+"/realms/"+baselineRealm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("rasputin-admin token request: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	_ = json.Unmarshal(body, &tok) // a body that is not JSON leaves both empty
	clear(body)
	if resp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("rasputin-admin by client-x509: status %d, error %q, token present %v; want 200 with a token",
			resp.StatusCode, tok.Error, tok.AccessToken != "")
	}
	return adminAPI{t: t, client: client, base: env.KeycloakURL() + "/admin/realms/" + baselineRealm, token: tok.AccessToken}, leafTLS
}

// TC-980-25: the real baseline, imported by the pinned Keycloak, gives
// rasputin-admin a working Admin API (read and write) over client-x509, and
// each authorization-code client a token through a headless sign-in; the
// console's access token carries auth_time and rasputin_roles.
//
// TC-988-27: the baseline selects the Rasputin login theme (loginTheme), so
// every page of each sign-in carries data-rasputin-theme, and the harness
// still finds the page fields capability row T98 names.
func TestIdentity_BaselineImportedWorks(t *testing.T) {
	p := NewPackage(ConfigFromEnv)
	if !p.RequireTheme(t) {
		return
	}
	env := p.Env(t)
	if env == nil {
		return
	}
	t.Cleanup(func() {
		// t.Context() has ended by now; Close stops Keycloak cleanly and
		// proves its containers, processes and root are gone.
		if err := env.Close(context.Background()); err != nil {
			t.Errorf("identitytest: teardown proof failed: %v", err)
		}
	})
	importBaseline(t, env)

	api, leafTLS := baselineAdmin(t, env)

	t.Run("rasputin-admin reads the realm", func(t *testing.T) {
		api := api
		api.t = t
		_, out := api.must(http.StatusOK, http.MethodGet, "", nil)
		var realm struct {
			Realm string `json:"realm"`
		}
		if err := json.Unmarshal(out, &realm); err != nil || realm.Realm != baselineRealm {
			t.Errorf("GET the realm: realm %q (%v), want %q", realm.Realm, err, baselineRealm)
		}
	})

	t.Run("rasputin-admin creates then deletes a user", func(t *testing.T) {
		api := api
		api.t = t
		loc, _ := api.must(http.StatusCreated, http.MethodPost, "/users", map[string]any{
			"username": "tc-980-25-write", "enabled": true,
		})
		if !strings.HasPrefix(loc, api.base+"/users/") {
			t.Fatalf("create user: Location %q, want one under %s/users/", loc, api.base)
		}
		api.must(http.StatusNoContent, http.MethodDelete, loc, nil)
		api.must(http.StatusNotFound, http.MethodGet, loc, nil)
	})

	// The sign-in user: a full profile, so no update-profile page, a
	// password, and the console role viewer, granted as the api grants it.
	password, err := randomSecret(env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	defer password.Destroy()
	const user = "tc-980-25-user"
	userLoc, _ := api.must(http.StatusCreated, http.MethodPost, "/users", map[string]any{
		"username": user, "enabled": true, "email": "tc-980-25@identitytest.invalid", "emailVerified": true,
		"firstName": "Baseline", "lastName": "User", "requiredActions": []string{},
		"credentials": []map[string]any{{"type": "password", "value": string(password.Reveal()), "temporary": false}},
	})
	consoleID, _ := api.clientRep(baselineConsole)
	_, viewer := api.must(http.StatusOK, http.MethodGet, "/clients/"+consoleID+"/roles/viewer", nil)
	var viewerRole map[string]any
	if err := json.Unmarshal(viewer, &viewerRole); err != nil {
		t.Fatal(err)
	}
	api.must(http.StatusNoContent, http.MethodPost, userLoc+"/role-mappings/clients/"+consoleID, []map[string]any{viewerRole})

	for _, clientID := range baselineCodeClients {
		t.Run(clientID+" signs the user in", func(t *testing.T) {
			api := api
			api.t = t
			// The redirect URI is per cluster, so the baseline has none
			// (TC-980-13); converge sets it, and so does this test.
			id, rep := api.clientRep(clientID)
			rep["redirectUris"] = []string{RedirectURI}
			api.must(http.StatusNoContent, http.MethodPut, "/clients/"+id, rep)

			catch := &tokenCatch{inner: &http.Transport{TLSClientConfig: leafTLS}}
			defer catch.inner.(*http.Transport).CloseIdleConnections()
			if clientID == baselineMesh {
				// The baseline carries no secret value (TC-980-13); the
				// cluster sets one, as this does.
				_, out := api.must(http.StatusOK, http.MethodPost, "/clients/"+id+"/client-secret", nil)
				var cred struct {
					Value string `json:"value"`
				}
				if err := json.Unmarshal(out, &cred); err != nil || cred.Value == "" {
					t.Fatalf("regenerate the mesh client's secret: no value (%v)", err)
				}
				clear(out)
				catch.basicUser, catch.basicPass = clientID, cred.Value
			}
			c, err := signin.New(signin.Config{
				Transport: catch,
				// Keycloak's own port, so the code exchange presents the
				// api leaf; the sign-in form posts to the front, which the
				// hostname names.
				Issuer:   env.KeycloakURL() + "/realms/" + baselineRealm,
				ClientID: clientID, RedirectURI: RedirectURI,
				Rand: env.h.cfg.Rand, Logger: env.log,
			})
			if err != nil {
				t.Fatal(err)
			}
			res, err := c.PasswordCodeFlow(t.Context(), user, password)
			if err != nil {
				t.Fatalf("PasswordCodeFlow for %s: %v (pages %v)", clientID, err, res.PageIDs)
			}
			for i, id := range res.PageIDs {
				if res.Themes[i] != "rasputin" {
					t.Errorf("page %s carries data-rasputin-theme %q, want rasputin (TC-988-27)", id, res.Themes[i])
				}
			}
			if len(res.PageIDs) == 0 {
				t.Error("the sign-in passed no page (TC-988-27)")
			}
			if want := env.FrontURL() + "/realms/" + baselineRealm; res.Claims.Iss != want {
				t.Errorf("iss = %q, want %q", res.Claims.Iss, want)
			}
			if !slices.Contains(res.Claims.Aud, clientID) || res.Claims.Sub == "" {
				t.Errorf("aud = %v, sub present %v; want aud holding %s and a sub", res.Claims.Aud, res.Claims.Sub != "", clientID)
			}
			if catch.access == "" {
				t.Fatal("the token answer carried no access token")
			}
			claims := jwtClaims(t, catch.access)
			if clientID != baselineConsole {
				// TC-1000-22 (IA-F6, TS-20's own-client half): the user
				// holds the console role viewer, and no other client's
				// token carries console roles or client-role maps.
				for _, k := range []string{"rasputin_roles", "resource_access"} {
					if v, ok := claims[k]; ok {
						t.Errorf("TC-1000-22: %s's access token carries %s = %v", clientID, k, v)
					}
				}
				return
			}
			if at, _ := claims["auth_time"].(float64); at <= 0 {
				t.Errorf("the console access token's auth_time = %v, want a sign-in time", claims["auth_time"])
			}
			roles, _ := claims["rasputin_roles"].([]any)
			if !slices.Contains(roles, any("viewer")) {
				t.Errorf("the console access token's rasputin_roles = %v, want it to hold viewer", claims["rasputin_roles"])
			}
		})
	}
}
