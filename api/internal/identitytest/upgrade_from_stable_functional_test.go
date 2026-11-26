package identitytest

// TC-988-44 (F-1012-18): a realm imported from the v2026.11.3 baseline, which
// set no login theme, gets the Rasputin theme from converge's first run after
// an update, on the pinned Keycloak, with no restart.
//
// Keycloak's import skips a realm that exists, so an updated cluster keeps the
// realm its stable release imported; only converge changes it afterwards. The
// fixture is that release's identity/realm-baseline.json byte for byte
// (package converge's guard checks its hash). The test starts an Env of its
// own with the built theme, closed with proof in its cleanup. It skips without
// RASPUTIN_IDENTITY_HOME or RASPUTIN_IDENTITY_THEME and fails instead under
// RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/converge"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest/signin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// rasputinTheme is the login theme the pages must carry, written out rather
// than read from converge.LoginTheme: it is the contract the theme's marker
// and the door's resource path name, and the test also builds against a
// converge without the constant, to show it fails there.
const rasputinTheme = "rasputin"

// shippedBaselineFixture is v2026.11.3's realm baseline.
var shippedBaselineFixture = filepath.Join("..", "..", "..", "identity", "testdata", "realm-baseline-v2026.11.3.json")

func TestIdentity_UpgradeFromStableTheme(t *testing.T) {
	p := NewPackage(ConfigFromEnv)
	if !p.RequireTheme(t) {
		return
	}
	env := p.Env(t)
	if env == nil {
		return
	}
	t.Cleanup(func() {
		if err := env.Close(context.Background()); err != nil {
			t.Errorf("identitytest: teardown proof failed: %v", err)
		}
	})
	fixture, err := filepath.Abs(shippedBaselineFixture)
	if err != nil {
		t.Fatal(err)
	}
	kcCommand(t, env, "import of the v2026.11.3 realm baseline", "import", "--optimized", "--file", fixture)

	// loginTheme is the realm's login theme as the Admin API reads it, with a
	// fresh rasputin-admin token each time (a converge run under a slow
	// identity service can outlast one).
	loginTheme := func(t *testing.T) any {
		t.Helper()
		api, _ := baselineAdmin(t, env)
		_, out := api.must(http.StatusOK, http.MethodGet, "", nil)
		var realm map[string]any
		if err := json.Unmarshal(out, &realm); err != nil {
			t.Fatalf("read the realm: %v", err)
		}
		return realm["loginTheme"]
	}
	// page is the console client's first sign-in page.
	_, leafTLS := baselineAdmin(t, env)
	page := func(t *testing.T) signin.Page {
		t.Helper()
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: leafTLS}}
		defer c.CloseIdleConnections()
		q := url.Values{"client_id": {baselineConsole}, "redirect_uri": {RedirectURI}, "response_type": {"code"},
			"scope": {"openid"}, "state": {"s"}, "nonce": {"n"},
			"code_challenge": {signin.Challenge("upgrade-from-stable-theme-verifier-0123456789")}, "code_challenge_method": {"S256"}}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
			env.KeycloakURL()+"/realms/"+baselineRealm+"/protocol/openid-connect/auth?"+q.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		pg, err := signin.ParsePage(b)
		if err != nil {
			t.Fatalf("status %d: %v", resp.StatusCode, err)
		}
		t.Logf("status %d page %s theme %q", resp.StatusCode, pg.ID, pg.Theme)
		return pg
	}

	// The red half: the fixture reproduces the defect.
	before := loginTheme(t)
	t.Logf("before converge: loginTheme=%v", before)
	if before != nil {
		t.Fatalf("the v2026.11.3 realm reads loginTheme %v, want none", before)
	}
	api, _ := baselineAdmin(t, env)
	id, rep := api.clientRep(baselineConsole)
	rep["redirectUris"] = []string{RedirectURI}
	api.must(http.StatusNoContent, http.MethodPut, "/clients/"+id, rep)
	if pg := page(t); pg.ID != "login-login" || pg.Theme != "" {
		t.Fatalf("before converge: page %s theme %q, want login-login with no theme marker", pg.ID, pg.Theme)
	}

	// Converge, as the first run after the update: the stored hash is the
	// previous release's.
	leaf, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatal(err)
	}
	rig := newRealmRig(t, env, productionClient(t, env, leaf), baselineRealm)
	rig.conv, err = converge.New(converge.Deps{
		Admin: rig.admin, Settings: rig.settings, Realm: baselineRealm, Lock: rig.lock,
		Inputs: func(context.Context) (converge.Inputs, error) {
			return converge.Inputs{InstallName: convergeInstallName, RedirectURIs: map[string][]string{baselineConsole: {RedirectURI}}, ClockSynced: true}, nil
		},
		Now: time.Now, Ready: func(context.Context) error { return nil }, Log: env.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	rig.settings.m[converge.HashKey] = "the-previous-release"
	fields := rig.converge(t)
	if !slices.Contains(fields, "realm.loginTheme") {
		t.Errorf("converge repaired %v, want realm.loginTheme among them", fields)
	}
	after := loginTheme(t)
	t.Logf("after converge: loginTheme=%v", after)
	if after != rasputinTheme {
		t.Errorf("after converge the realm reads loginTheme %v, want %s", after, rasputinTheme)
	}
	if pg := page(t); pg.ID != "login-login" || pg.Theme != rasputinTheme {
		t.Errorf("after converge: page %s theme %q, want login-login with theme %q", pg.ID, pg.Theme, rasputinTheme)
	}
	if a := rig.conv.Alerts(t.Context(), time.Now()); len(a) != 0 {
		t.Errorf("alerts after the first run = %+v, want none", a)
	}

	// It stays put: a second run repairs nothing and writes nothing.
	writes := rig.admin.writeCount()
	if again := rig.converge(t); len(again) != 0 {
		t.Errorf("second run repaired %v, want nothing", again)
	}
	if n := rig.admin.writeCount() - writes; n != 0 {
		t.Errorf("second run made %d writes, want none", n)
	}
}
