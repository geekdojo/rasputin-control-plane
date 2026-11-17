package identitytest

// TC-978-26 to TC-978-29: the api's identity client, its Admin API session
// and identity.recover_admin against the real pinned Keycloak with the
// repo's realm baseline imported (geekdojo/geekdojo-brain#978, Identity 3.2).
//
// It is in package identitytest because the recovery stops the Env's
// Keycloak, runs the Env's own kc.sh bootstrap-admin against its database and
// keycloak.conf, and starts it again on the same ports, which only the
// package sees. It starts an Env of its own, closed with proof in its
// cleanup. It skips without RASPUTIN_IDENTITY_HOME and fails instead under
// RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/recoveradmin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// countingLogin is the production client as the session's TokenSource,
// counting logins and keeping the last token's text for the revocation.
type countingLogin struct {
	inner *idclient.Client
	n     atomic.Int64
	mu    sync.Mutex
	last  string
}

func (c *countingLogin) ClientCredentials(ctx context.Context, realm, clientID string, s *secret.Value) (secret.Value, error) {
	v, err := c.inner.ClientCredentials(ctx, realm, clientID, s)
	if err == nil {
		c.n.Add(1)
		c.mu.Lock()
		c.last = string(v.Reveal())
		c.mu.Unlock()
	}
	return v, err
}

func (c *countingLogin) held() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// productionClient is idclient.New over looptls.NewClientTLS with the leaf
// at paths, as wireIdentity builds it.
func productionClient(t *testing.T, env *Env, paths tlsca.LeafPaths) *idclient.Client {
	t.Helper()
	cfg, err := looptls.NewClientTLS(env.CA().CertPEM, paths.CertPath, paths.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(env.KeycloakURL())
	if err != nil {
		t.Fatal(err)
	}
	m, err := url.Parse(env.ManagementURL())
	if err != nil {
		t.Fatal(err)
	}
	c, err := idclient.New(idclient.Config{Addr: u, MgmtAddr: m, TLS: cfg, CallTimeout: 30 * time.Second, Logger: env.log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// loginReasons are the session's login records' reasons, in order.
func loginReasons(rec *logkittest.Recorder) []string {
	var out []string
	for _, r := range rec.Matching(slog.LevelInfo, "identity service login") {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "reason" {
				out = append(out, a.Value.String())
			}
			return true
		})
	}
	return out
}

// envUnits stands in for keycloak.service: Stop stops the Env's Keycloak,
// Start starts it again from the same spec on the ports it reported, and
// Active is whether that process is still running.
type envUnits struct {
	env         *Env
	home, conf  string
	https, mgmt int
}

func (u *envUnits) Stop(ctx context.Context) error { return u.env.kc.Stop(ctx) }

func (u *envUnits) Start(context.Context) error {
	p, err := proctest.Start(u.env.keycloakSpec(u.home, u.conf, "start", "--optimized",
		"--https-port="+strconv.Itoa(u.https), "--http-management-port="+strconv.Itoa(u.mgmt)))
	if err != nil {
		return err
	}
	u.env.kc = p // the Env's teardown stops the running one
	return nil
}

func (u *envUnits) Active(context.Context) (bool, error) {
	select {
	case <-u.env.kc.Exited():
		return false, nil
	default:
		return true, nil
	}
}

// psqlCount runs a count query in the Env's database container.
func psqlCount(t *testing.T, env *Env, sql string) string {
	t.Helper()
	out, err := env.docker.exec(t.Context(), env.pgID, "psql", "-U", dbUser, "-d", dbName, "-X", "-A", "-t", "-c", sql)
	if err != nil {
		t.Fatalf("psql %q: %v (%s)", sql, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TC-978-26 to TC-978-29, in order on one Env.
func TestIdentityClient_AgainstPinnedKeycloak(t *testing.T) {
	recLog, rec := logkittest.New()
	p := NewPackage(func() (Config, error) {
		cfg, err := ConfigFromEnv()
		if err != nil {
			return cfg, err
		}
		cfg.Logger = slog.New(slog.NewMultiHandler(cfg.Logger.Handler(), recLog.Handler()))
		return cfg, nil
	})
	env := p.Env(t)
	if env == nil {
		return
	}
	t.Cleanup(func() {
		if err := env.Close(context.Background()); err != nil {
			t.Errorf("identitytest: teardown proof failed: %v", err)
		}
	})
	importBaseline(t, env)

	apiLeaf, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatal(err)
	}
	client := productionClient(t, env, apiLeaf)
	login := &countingLogin{inner: client}
	session, err := idclient.NewSession(idclient.SessionConfig{
		Login: login, Admin: client, Realm: baselineRealm, ClientID: baselineAdminClient, Log: env.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	readRealm := func(t *testing.T) {
		t.Helper()
		var realm struct {
			Realm string `json:"realm"`
		}
		resp, err := session.Admin(t.Context(), http.MethodGet, "/admin/realms/"+baselineRealm, nil, &realm)
		if err != nil || resp.Status != http.StatusOK || realm.Realm != baselineRealm {
			t.Fatalf("session GET the realm = %d %q, %v; want 200 rasputin", resp.Status, realm.Realm, err)
		}
	}
	leafHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: apiLeafTLS(t, env)},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(leafHTTP.CloseIdleConnections)
	// rawStatus is a GET of the realm with tok as the bearer, outside the
	// session, so it makes no login.
	rawStatus := func(t *testing.T, tok string) int {
		t.Helper()
		api := adminAPI{t: t, client: leafHTTP, base: env.KeycloakURL() + "/admin/realms/" + baselineRealm, token: tok}
		status, _, _ := api.do(http.MethodGet, "", nil)
		return status
	}

	t.Run("TC-978-26 a revoked token gets one re-login", func(t *testing.T) {
		readRealm(t)
		if n := login.n.Load(); n != 1 {
			t.Fatalf("logins after the first GET = %d, want 1", n)
		}
		held := login.held()
		form := url.Values{"token": {held}, "token_type_hint": {"access_token"}, "client_id": {baselineAdminClient}}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			env.KeycloakURL()+"/realms/"+baselineRealm+"/protocol/openid-connect/revoke", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := leafHTTP.Do(req)
		if err != nil {
			t.Fatalf("revoke: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("RFC 7009 revoke answered %d, want 200", resp.StatusCode)
		}
		if st := rawStatus(t, held); st != http.StatusUnauthorized {
			// The reviewer's fallback (F-978-08): the Admin API still takes
			// the revoked token, so end it by retiring the realm's signing
			// key instead.
			t.Logf("the Admin API answered %d to the revoked token; rotating the realm's signing key instead", st)
			rotateSigningKey(t, env, client, leafHTTP)
			if st := rawStatus(t, held); st != http.StatusUnauthorized {
				t.Fatalf("the held token still answers %d after the key rotation, want 401", st)
			}
		}
		readRealm(t)
		if n := login.n.Load(); n != 2 {
			t.Errorf("logins = %d, want 2: exactly one re-login", n)
		}
		if r := loginReasons(rec); !slices.Equal(r, []string{"no-token", "refused"}) {
			t.Errorf("login reasons = %v, want [no-token refused]", r)
		}
	})

	t.Run("TC-978-27 a foreign-CA leaf is refused at TLS", func(t *testing.T) {
		d := tlsca.Deps{Now: env.h.cfg.Now, Rand: env.h.cfg.Rand, Log: env.log}
		foreign, err := tlsca.Ensure(caConfig(), filepath.Join(t.TempDir(), "foreign"), "foreign", d)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := foreign.MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
		if err != nil {
			t.Fatal(err)
		}
		c := productionClient(t, env, leaf)
		tok, err := c.ClientCredentials(t.Context(), baselineRealm, baselineAdminClient, nil)
		if !errors.Is(err, idclient.ErrDenied) || tok.Len() != 0 {
			t.Errorf("foreign-CA leaf: err = %v, token %d bytes; want ErrDenied and none", err, tok.Len())
		}
		var e *idclient.Error
		if errors.As(err, &e) && e.Status != 0 {
			t.Errorf("the refusal carried HTTP status %d, want a TLS refusal", e.Status)
		}
	})

	t.Run("TC-978-28 the door leaf is not the administrator", func(t *testing.T) {
		leaf, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-door"})
		if err != nil {
			t.Fatal(err)
		}
		c := productionClient(t, env, leaf)
		tok, err := c.ClientCredentials(t.Context(), baselineRealm, baselineAdminClient, nil)
		var e *idclient.Error
		if !errors.Is(err, idclient.ErrDenied) || !errors.As(err, &e) || e.OAuthError != "invalid_client" || tok.Len() != 0 {
			t.Errorf("door leaf: err = %v, want ErrDenied with invalid_client and no token", err)
		}
		if err := client.Ready(t.Context()); err != nil {
			t.Errorf("Ready over mutual TLS with the api leaf: %v", err)
		}
	})

	t.Run("TC-978-29 recover_admin restores the admin client and leaves master empty", func(t *testing.T) {
		tok, err := client.ClientCredentials(t.Context(), baselineRealm, baselineAdminClient, nil)
		if err != nil {
			t.Fatal(err)
		}
		api := adminAPI{t: t, client: leafHTTP, base: env.KeycloakURL() + "/admin/realms/" + baselineRealm, token: string(tok.Reveal())}
		id, _ := api.clientRep(baselineAdminClient)
		api.must(http.StatusNoContent, http.MethodDelete, "/clients/"+id, nil)
		tok.Destroy()
		if _, err := client.ClientCredentials(t.Context(), baselineRealm, baselineAdminClient, nil); !errors.Is(err, idclient.ErrDenied) {
			t.Fatalf("after deleting %s its login = %v, want ErrDenied", baselineAdminClient, err)
		}

		rec2, seen := newEnvRecoverer(t, env, client, readRepoBaseline, func(context.Context, string) error { return nil })
		before := login.n.Load()
		res, err := rec2.Workflow().Steps[0].Do(&jobs.StepCtx{Ctx: t.Context(), JobID: "01TC978029"})
		if err != nil {
			t.Fatalf("the restore step: %v", err)
		}
		if string(res) != `{"restored":true}` {
			t.Errorf("result = %s, want {\"restored\":true}", res)
		}

		// The session's token is the deleted client's: one re-login.
		readRealm(t)
		if n := login.n.Load() - before; n != 1 {
			t.Errorf("logins after the restore = %d, want exactly 1", n)
		}
		resp, err := session.Admin(t.Context(), http.MethodPost, "/admin/realms/"+baselineRealm+"/users",
			map[string]any{"username": "tc-978-29-write", "enabled": true}, nil)
		if err != nil || resp.Status != http.StatusCreated {
			t.Fatalf("create a user as the restored client: %d, %v", resp.Status, err)
		}
		loc, err := url.Parse(resp.Location)
		if err != nil || !strings.HasPrefix(loc.Path, "/admin/realms/"+baselineRealm+"/users/") {
			t.Fatalf("create user: Location %q", resp.Location)
		}
		if resp, err := session.Admin(t.Context(), http.MethodDelete, loc.Path, nil, nil); err != nil || resp.Status != http.StatusNoContent {
			t.Errorf("delete the user as the restored client: %d, %v", resp.Status, err)
		}

		if n := psqlCount(t, env, "SELECT count(*) FROM user_entity u JOIN realm r ON u.realm_id = r.id WHERE r.name = 'master'"); n != "0" {
			t.Errorf("users in realm master = %s, want 0", n)
		}
		if n := psqlCount(t, env, "SELECT count(*) FROM client c JOIN realm r ON c.realm_id = r.id WHERE r.name = 'master' AND c.client_id LIKE '"+recoveradmin.TempClientPrefix+"%'"); n != "0" {
			t.Errorf("rasputin-recover-* clients in realm master = %s, want 0", n)
		}
		secretText := seen.secret()
		if len(secretText) != 43 {
			t.Fatalf("the recovery command's environment carried a %d-character secret, want 43", len(secretText))
		}
		if strings.Contains(rec.Text(), secretText) || strings.Contains(string(seen.output()), secretText) {
			t.Error("the temporary secret appears in a log record or in kc.sh's output")
		}
		if len(rec.Records()) == 0 {
			t.Fatal("no records were recorded; the secret scan proved nothing")
		}
	})
}

// rotateSigningKey adds a new RS256 key provider to the realm at a higher
// priority and deletes the old one, so every token signed by the old key is
// refused (F-978-08's fallback). It acts with a fresh token of its own.
func rotateSigningKey(t *testing.T, env *Env, client *idclient.Client, httpc *http.Client) {
	t.Helper()
	tok, err := client.ClientCredentials(t.Context(), baselineRealm, baselineAdminClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Destroy()
	api := adminAPI{t: t, client: httpc, base: env.KeycloakURL() + "/admin/realms/" + baselineRealm, token: string(tok.Reveal())}
	_, out := api.must(http.StatusOK, http.MethodGet, "", nil)
	var realm struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &realm); err != nil || realm.ID == "" {
		t.Fatalf("the realm's id: %v", err)
	}
	_, out = api.must(http.StatusOK, http.MethodGet, "/components?type=org.keycloak.keys.KeyProvider", nil)
	var comps []struct {
		ID         string `json:"id"`
		ProviderID string `json:"providerId"`
	}
	if err := json.Unmarshal(out, &comps); err != nil {
		t.Fatal(err)
	}
	api.must(http.StatusCreated, http.MethodPost, "/components", map[string]any{
		"name": "tc-978-26-rotated", "providerId": "rsa-generated", "providerType": "org.keycloak.keys.KeyProvider",
		"parentId": realm.ID, "config": map[string][]string{"priority": {"1000"}},
	})
	for _, c := range comps {
		if c.ProviderID == "rsa-generated" {
			api.must(http.StatusNoContent, http.MethodDelete, "/components/"+c.ID, nil)
		}
	}
}
