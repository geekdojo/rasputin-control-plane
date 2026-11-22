package identitytest

// TC-981-01 to TC-981-04, TC-981-10 and TC-981-17: identity.converge, the
// features check and the migrations runner against the real pinned Keycloak
// with the repo's realm baseline imported (geekdojo/geekdojo-brain#981,
// Identity 3.5).
//
// It is in package identitytest because the one-end-state case imports and
// exports realms with a second kc.sh against the Env's own database and
// keycloak.conf, which only the package sees. It starts an Env of its own,
// closed with proof in its cleanup. It skips without RASPUTIN_IDENTITY_HOME
// and fails instead under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's
// backend job sets it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/converge"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/migrations"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

const convergeInstallName = "Test Home"

// countingAdmin is a session as converge's Admin, counting the calls that
// write.
type countingAdmin struct {
	inner  *idclient.Session
	mu     sync.Mutex
	writes int
}

func (c *countingAdmin) Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error) {
	if method != http.MethodGet {
		c.mu.Lock()
		c.writes++
		c.mu.Unlock()
	}
	return c.inner.Admin(ctx, method, path, in, out)
}

func (c *countingAdmin) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

// realmRig is one realm's converger and migrations lock over the api's own
// session as rasputin-admin of that realm.
type realmRig struct {
	name     string
	admin    *countingAdmin
	settings *memSettings
	lock     *sync.Mutex
	conv     *converge.Converger
}

func newRealmRig(t *testing.T, env *Env, client *idclient.Client, realm string) *realmRig {
	t.Helper()
	sess, err := idclient.NewSession(idclient.SessionConfig{Login: client, Admin: client, Realm: realm, ClientID: baselineAdminClient, Log: env.log})
	if err != nil {
		t.Fatal(err)
	}
	r := &realmRig{name: realm, admin: &countingAdmin{inner: sess}, settings: &memSettings{m: map[string]string{}}, lock: &sync.Mutex{}}
	r.conv, err = converge.New(converge.Deps{
		Admin: r.admin, Settings: r.settings, Realm: realm, Lock: r.lock,
		Inputs: func(context.Context) (converge.Inputs, error) {
			return converge.Inputs{InstallName: convergeInstallName, RedirectURIs: map[string][]string{}}, nil
		},
		Now: time.Now, Log: env.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// runner is a migrations runner over all for the rig's realm.
func (r *realmRig) runner(t *testing.T, env *Env, all []migrations.Migration) *migrations.Runner {
	t.Helper()
	m, err := migrations.New(migrations.Deps{Admin: r.admin, Realm: r.name, Lock: r.lock, All: all, Log: env.log})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (r *realmRig) converge(t *testing.T) []string {
	t.Helper()
	fields, err := r.conv.Run(t.Context())
	if err != nil {
		t.Fatalf("converge %s: %v", r.name, err)
	}
	return fields
}

func TestConverge_AgainstPinnedKeycloak(t *testing.T) {
	p := NewPackage(ConfigFromEnv)
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
	leafHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: apiLeafTLS(t, env)},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(leafHTTP.CloseIdleConnections)
	// raw is realm's Admin API as rasputin-admin with a fresh token, outside
	// converge.
	raw := func(t *testing.T, realm string) adminAPI {
		t.Helper()
		tok, err := client.ClientCredentials(t.Context(), realm, baselineAdminClient, nil)
		if err != nil {
			t.Fatalf("rasputin-admin login to %s: %v", realm, err)
		}
		defer tok.Destroy()
		return adminAPI{t: t, client: leafHTTP, base: env.KeycloakURL() + "/admin/realms/" + realm, token: string(tok.Reveal())}
	}
	rig := newRealmRig(t, env, client, baselineRealm)

	t.Run("TC-981-10 the features check on the real pin", func(t *testing.T) {
		shipped, err := os.ReadFile(filepath.Join("..", "..", "..", "identity", "keycloak-build.conf"))
		if err != nil {
			t.Fatal(err)
		}
		check := func(conf []byte) *converge.FeatureCheck {
			fc, err := converge.NewFeatureCheck(rig.admin.inner, func() ([]byte, error) { return conf, nil }, env.log)
			if err != nil {
				t.Fatal(err)
			}
			return fc
		}
		// Through the identity client, within its body cap: an error here
		// is serverinfo not fitting the client, or not answering.
		if m, err := check(shipped).Mismatch(t.Context(), ""); err != nil || m {
			t.Fatalf("the shipped conf against the pin: Mismatch = %v, %v; want a match", m, err)
		}
		active := identitystate.Unit{ActiveState: "active", SubState: "running", InvocationID: "0123456789abcdef0123456789abcdef"}
		monitor := func(fc *converge.FeatureCheck) *identitystate.Monitor {
			return newStateMonitor(t, env.h.cfg, stateDeps{
				units: func(context.Context) (identitystate.Units, error) {
					return identitystate.Units{KC: active, DB: active}, nil
				},
				exits:    t.TempDir(),
				health:   client,
				ledger:   openJobs(t),
				features: fc.Mismatch,
			})
		}
		if err := monitor(check(shipped)).Ready(t.Context()); err != nil {
			t.Fatalf("a real Monitor with the shipped conf: Ready = %v, want nil", err)
		}
		// A recorded build that disables a feature the pin runs enabled.
		edited := []byte(strings.Replace(string(shipped), "features-disabled=", "features-disabled=opentelemetry,", 1))
		mon := monitor(check(edited))
		err = mon.Ready(t.Context())
		var nr *identitystate.NotReadyError
		if !errors.As(err, &nr) || nr.State != identitystate.FeaturesMismatch {
			t.Fatalf("the edited conf: Ready = %v, want NotReadyError{features-mismatch}", err)
		}
		a := mon.Alerts(t.Context(), time.Now())
		want := "Sign-in is closed: the sign-in service is not running with the features this release built it with. Update or reinstall this release."
		if len(a) != 1 || a[0].ID != "identity:features-mismatch" || a[0].Severity != proto.AlertCrit || a[0].Title != want {
			t.Errorf("alerts = %+v, want the critical features-mismatch alert", a)
		}
	})

	t.Run("TC-981-01 from empty, then idempotent", func(t *testing.T) {
		fields := rig.converge(t)
		if len(fields) == 0 {
			t.Fatal("the first run repaired nothing from the baseline")
		}
		t.Logf("TC-981-01: the first run repaired %v", fields)
		api := raw(t, baselineRealm)
		checkConverged(t, api)
		if rig.settings.m[converge.HashKey] == "" {
			t.Error("no converge hash stored")
		}
		if a := rig.conv.Alerts(t.Context(), time.Now()); len(a) != 0 {
			t.Errorf("alerts after the first run = %+v, want no drift alert", a)
		}
		before, writes := adminEventCount(t, api), rig.admin.writeCount()
		if again := rig.converge(t); len(again) != 0 {
			t.Errorf("the second run repaired %v, want nothing", again)
		}
		if n := rig.admin.writeCount() - writes; n != 0 {
			t.Errorf("the second run made %d writes, want none", n)
		}
		if after := adminEventCount(t, api); after != before {
			t.Errorf("admin events %d before the second run and %d after, want unchanged", before, after)
		}
	})

	t.Run("TC-981-02 the TS-17 drift fields and the drift alert", func(t *testing.T) {
		api := raw(t, baselineRealm)
		_, out := api.must(http.StatusOK, http.MethodGet, "", nil)
		var rep map[string]any
		if err := json.Unmarshal(out, &rep); err != nil {
			t.Fatal(err)
		}
		policyKeys := []string{"webAuthnPolicyUserVerificationRequirement", "webAuthnPolicyResidentKey", "webAuthnPolicyRequireResidentKey",
			"webAuthnPolicyRpEntityName", "webAuthnPolicyPasswordlessUserVerificationRequirement", "webAuthnPolicyPasswordlessResidentKey",
			"webAuthnPolicyPasswordlessRequireResidentKey", "webAuthnPolicyPasswordlessRpEntityName"}
		beforePolicy := map[string]any{}
		for _, k := range policyKeys {
			beforePolicy[k] = rep[k]
		}
		attrs, _ := rep["attributes"].(map[string]any)
		// Every attribute the realm holds now must survive converge's
		// whole-map write. (CreateDefaultClientScopes is not among them:
		// Keycloak's import removes it, RealmManager.isCreateDefaultClientScopes.)
		var kept []string
		for k := range attrs {
			if k != "frontendUrl" {
				kept = append(kept, k)
			}
		}
		kept = append(kept, migrations.RecordAttr)
		attrs["frontendUrl"] = "https://drift.example"
		attrs[migrations.RecordAttr] = "0"
		rep["webAuthnPolicyRpId"], rep["webAuthnPolicyPasswordlessRpId"] = "drift.example", "drift.example"
		rep["smtpServer"] = map[string]any{"host": "smtp.drift.example", "from": "drift@drift.example"}
		api.must(http.StatusNoContent, http.MethodPut, "", rep)
		// frontendUrl changes the realm's issuer, so the token above no
		// longer validates: take a new one.
		api = raw(t, baselineRealm)
		cliID, cli := api.clientRep("admin-cli")
		cli["enabled"], cli["directAccessGrantsEnabled"] = true, true
		api.must(http.StatusNoContent, http.MethodPut, "/clients/"+cliID, cli)
		got := realmRep(t, api)
		if got["webAuthnPolicyRpId"] != "drift.example" || got["webAuthnPolicyPasswordlessRpId"] != "drift.example" {
			t.Fatalf("the raw drift did not take: RP IDs %v %v", got["webAuthnPolicyRpId"], got["webAuthnPolicyPasswordlessRpId"])
		}
		if code, desc := passwordGrant(t, leafHTTP, env); code != "invalid_grant" {
			_, back := api.clientRep("admin-cli")
			t.Fatalf("admin-cli's password grant with the drift answered %q (%q), want invalid_grant (reached the grant); admin-cli reads back enabled %v, directAccessGrantsEnabled %v, publicClient %v",
				code, desc, back["enabled"], back["directAccessGrantsEnabled"], back["publicClient"])
		}

		fields := rig.converge(t)
		t.Logf("TC-981-02: repaired %v", fields)
		api = raw(t, baselineRealm) // the issuer changed back
		got = realmRep(t, api)
		gotAttrs, _ := got["attributes"].(map[string]any)
		if _, ok := gotAttrs["frontendUrl"]; ok {
			t.Errorf("frontendUrl = %v after converge, want none", gotAttrs["frontendUrl"])
		}
		if got["webAuthnPolicyRpId"] != "" || got["webAuthnPolicyPasswordlessRpId"] != "" {
			t.Errorf("RP IDs = %q %q, want both empty", got["webAuthnPolicyRpId"], got["webAuthnPolicyPasswordlessRpId"])
		}
		for _, k := range policyKeys {
			if fmt.Sprint(got[k]) != fmt.Sprint(beforePolicy[k]) {
				t.Errorf("%s = %v after converge, %v before the drift", k, got[k], beforePolicy[k])
			}
		}
		if smtp, _ := got["smtpServer"].(map[string]any); len(smtp) != 0 {
			t.Errorf("smtpServer = %v, want empty", smtp)
		}
		for _, k := range kept {
			if _, ok := gotAttrs[k]; !ok {
				t.Errorf("attribute %s lost", k)
			}
		}
		_, cli = api.clientRep("admin-cli")
		if cli["enabled"] != false || cli["directAccessGrantsEnabled"] != false {
			t.Errorf("admin-cli enabled %v, direct grants %v; want both off", cli["enabled"], cli["directAccessGrantsEnabled"])
		}
		code, desc := passwordGrant(t, leafHTTP, env)
		t.Logf("T92: admin-cli's password grant after converge answers %q (%q)", code, desc)
		if code == "invalid_grant" || code == "" {
			t.Errorf("admin-cli's password grant after converge answered %q, want it refused for the client", code)
		}
		a := rig.conv.Alerts(t.Context(), time.Now())
		if len(a) != 1 || a[0].ID != converge.DriftAlertID || a[0].Severity != proto.AlertWarn || a[0].RelatedKind != "accounts" ||
			a[0].Title != "A sign-in setting had drifted from Rasputin's and was put back." {
			t.Errorf("alerts after the repair = %+v, want the drift warning", a)
		}
		if again := rig.converge(t); len(again) != 0 {
			t.Errorf("the second run repaired %v", again)
		}
		if a := rig.conv.Alerts(t.Context(), time.Now()); len(a) != 0 {
			t.Errorf("alerts after a clean run = %+v, want none", a)
		}
	})

	t.Run("TC-981-03 every other owned field, the secret untouched", func(t *testing.T) {
		api := raw(t, baselineRealm)
		meshID, _ := api.clientRep(baselineMesh)
		api.must(http.StatusOK, http.MethodPost, "/clients/"+meshID+"/client-secret", nil)
		secretBefore := clientSecret(t, api, meshID)
		rep := realmRep(t, api)
		api.must(http.StatusNoContent, http.MethodPut, "", map[string]any{
			"displayName": "Drifted", "displayNameHtml": "<b>Drifted</b>", "eventsEnabled": false, "adminEventsEnabled": false,
			"eventsListeners": []string{"jboss-logging"},
		})
		for _, id := range []string{"account-console", "broker"} {
			cid, c := api.clientRep(id)
			c["enabled"] = true
			api.must(http.StatusNoContent, http.MethodPut, "/clients/"+cid, c)
		}
		cid, c := api.clientRep(baselineConsole)
		c["redirectUris"] = []string{"https://drift.example/cb"}
		api.must(http.StatusNoContent, http.MethodPut, "/clients/"+cid, c)
		api.must(http.StatusCreated, http.MethodPost, "/components", map[string]any{
			"name": "fallback-HS512", "providerId": "hmac-generated", "providerType": "org.keycloak.keys.KeyProvider",
			"parentId": rep["id"], "config": map[string][]string{"priority": {"-100"}, "algorithm": {"HS512"}},
		})
		if !slices.Contains(keyNames(t, api), "fallback-HS512") {
			t.Fatal("the fallback key provider was not created")
		}

		fields := rig.converge(t)
		t.Logf("TC-981-03: repaired %v", fields)
		api = raw(t, baselineRealm)
		checkConverged(t, api)
		if got := clientSecret(t, api, meshID); got != secretBefore || got == "" {
			t.Error("rasputin-mesh's client secret changed across converge")
		}
	})

	t.Run("TC-981-04 the stored-event settings", func(t *testing.T) {
		api := raw(t, baselineRealm)
		rep := realmRep(t, api)
		attrs, _ := rep["attributes"].(map[string]any)
		attrs["adminEventsExpiration"] = "60"
		api.must(http.StatusNoContent, http.MethodPut, "", map[string]any{
			"enabledEventTypes": []string{"LOGIN"}, "adminEventsDetailsEnabled": true, "eventsExpiration": 60, "attributes": attrs,
		})
		fields := rig.converge(t)
		t.Logf("TC-981-04: repaired %v", fields)
		got := realmRep(t, api)
		_, out := api.must(http.StatusOK, http.MethodGet, "/events/config", nil)
		var ev struct {
			EnabledEventTypes         []string `json:"enabledEventTypes"`
			AdminEventsDetailsEnabled bool     `json:"adminEventsDetailsEnabled"`
			EventsExpiration          int      `json:"eventsExpiration"`
		}
		if err := json.Unmarshal(out, &ev); err != nil {
			t.Fatal(err)
		}
		if !sameStrings(ev.EnabledEventTypes, converge.AuditEventTypes) {
			t.Errorf("enabledEventTypes = %v, want exactly the audit set %v", ev.EnabledEventTypes, converge.AuditEventTypes)
		}
		const thirtyDays = 30 * 24 * 3600
		if ev.AdminEventsDetailsEnabled || ev.EventsExpiration != thirtyDays {
			t.Errorf("events config = %+v, want details off and a 30-day user-event expiry", ev)
		}
		gotAttrs, _ := got["attributes"].(map[string]any)
		if gotAttrs["adminEventsExpiration"] != fmt.Sprint(thirtyDays) {
			t.Errorf("adminEventsExpiration = %v, want %d", gotAttrs["adminEventsExpiration"], thirtyDays)
		}
	})

	t.Run("TC-981-17 one end state over migrations.All then two fixtures", func(t *testing.T) {
		all := append(append([]migrations.Migration{}, migrations.All...), fixtureMigrations(len(migrations.All))...)
		n := len(all)
		names := []string{"tc17-a"}
		for k := 0; k <= n; k++ {
			names = append(names, fmt.Sprintf("tc17-b%d", k))
		}
		importRealms(t, env, names)
		rigs := map[string]*realmRig{}
		imported := map[string][]string{}
		for _, name := range names {
			rigs[name] = newRealmRig(t, env, client, name)
			for k := range realmRep(t, raw(t, name))["attributes"].(map[string]any) {
				imported[name] = append(imported[name], k)
			}
		}
		run := func(r *realmRig, list []migrations.Migration) {
			t.Helper()
			if _, err := r.runner(t, env, list).Run(t.Context()); err != nil {
				t.Fatalf("migrations on %s: %v", r.name, err)
			}
		}
		// A = baseline + all + converge.
		a := rigs["tc17-a"]
		run(a, all)
		a.converge(t)
		// B_k = baseline + the first k + converge + the rest + converge.
		for k := 0; k <= n; k++ {
			b := rigs[fmt.Sprintf("tc17-b%d", k)]
			run(b, all[:k])
			b.converge(t)
			run(b, all)
			b.converge(t)
		}
		exports := exportRealms(t, env)
		want := exports["tc17-a"]
		for k := 0; k <= n; k++ {
			name := fmt.Sprintf("tc17-b%d", k)
			if diffs := jsonDiff("", want, exports[name], nil); len(diffs) > 0 {
				t.Errorf("B_%d's export differs from A's at %d place(s): %v", k, len(diffs), diffs)
			}
		}
		for _, name := range names {
			attrs := realmRep(t, raw(t, name))["attributes"].(map[string]any)
			if attrs[migrations.RecordAttr] != fmt.Sprint(n) {
				t.Errorf("%s: %s = %v, want %d", name, migrations.RecordAttr, attrs[migrations.RecordAttr], n)
			}
			for _, k := range append(imported[name], "rasputin.fixture") {
				if _, ok := attrs[k]; !ok {
					t.Errorf("%s: attribute %s lost", name, k)
				}
			}
		}
	})
}

// checkConverged asserts every owned field reads back as converge wants it,
// with install name convergeInstallName and no redirect URIs.
func checkConverged(t *testing.T, api adminAPI) {
	t.Helper()
	r := realmRep(t, api)
	attrs, _ := r["attributes"].(map[string]any)
	if r["displayName"] != convergeInstallName {
		t.Errorf("displayName = %v", r["displayName"])
	}
	if v, ok := r["displayNameHtml"]; ok && v != "" {
		t.Errorf("displayNameHtml = %v, want empty", v)
	}
	if _, ok := attrs["frontendUrl"]; ok {
		t.Errorf("frontendUrl = %v, want none", attrs["frontendUrl"])
	}
	if r["webAuthnPolicyRpId"] != "" || r["webAuthnPolicyPasswordlessRpId"] != "" {
		t.Errorf("RP IDs = %v %v", r["webAuthnPolicyRpId"], r["webAuthnPolicyPasswordlessRpId"])
	}
	if r["eventsEnabled"] != true || r["adminEventsEnabled"] != true {
		t.Errorf("eventsEnabled %v, adminEventsEnabled %v; want both on", r["eventsEnabled"], r["adminEventsEnabled"])
	}
	if l, _ := r["eventsListeners"].([]any); len(l) != 0 {
		t.Errorf("eventsListeners = %v, want none", l)
	}
	if s, _ := r["smtpServer"].(map[string]any); len(s) != 0 {
		t.Errorf("smtpServer = %v, want empty", s)
	}
	for _, id := range converge.DefaultClients {
		_, c := api.clientRep(id)
		if c["enabled"] != false {
			t.Errorf("%s enabled = %v, want false", id, c["enabled"])
		}
		if id == "admin-cli" && c["directAccessGrantsEnabled"] != false {
			t.Errorf("admin-cli direct grants = %v, want false", c["directAccessGrantsEnabled"])
		}
	}
	for _, id := range converge.RasputinClients {
		_, c := api.clientRep(id)
		if u, _ := c["redirectUris"].([]any); len(u) != 0 {
			t.Errorf("%s redirectUris = %v, want none", id, u)
		}
	}
	keys := keyNames(t, api)
	for _, k := range converge.KeyProviders {
		if !slices.Contains(keys, k) {
			t.Errorf("key provider %s missing: %v", k, keys)
		}
	}
	for _, k := range keys {
		if strings.HasPrefix(k, "fallback-") {
			t.Errorf("fallback key provider %s present", k)
		}
	}
}

func realmRep(t *testing.T, api adminAPI) map[string]any {
	t.Helper()
	_, out := api.must(http.StatusOK, http.MethodGet, "", nil)
	var rep map[string]any
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func keyNames(t *testing.T, api adminAPI) []string {
	t.Helper()
	_, out := api.must(http.StatusOK, http.MethodGet, "/components?type="+url.QueryEscape("org.keycloak.keys.KeyProvider"), nil)
	var comps []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(out, &comps); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range comps {
		names = append(names, c.Name)
	}
	return names
}

func clientSecret(t *testing.T, api adminAPI, id string) string {
	t.Helper()
	_, out := api.must(http.StatusOK, http.MethodGet, "/clients/"+id+"/client-secret", nil)
	defer clear(out)
	var cred struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(out, &cred); err != nil {
		t.Fatal(err)
	}
	return cred.Value
}

func adminEventCount(t *testing.T, api adminAPI) int {
	t.Helper()
	_, out := api.must(http.StatusOK, http.MethodGet, "/admin-events?max=1000", nil)
	var evs []json.RawMessage
	if err := json.Unmarshal(out, &evs); err != nil {
		t.Fatal(err)
	}
	return len(evs)
}

// passwordGrant asks realm rasputin's token endpoint for admin-cli's password
// grant for a user that does not exist, and returns the OAuth error code and
// its description.
func passwordGrant(t *testing.T, c *http.Client, env *Env) (string, string) {
	t.Helper()
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"tc-981-02-nobody"}, "password": {"not-a-password"}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		env.KeycloakURL()+"/realms/"+baselineRealm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("admin-cli password grant: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &e)
	if resp.StatusCode == http.StatusOK {
		t.Errorf("admin-cli's password grant answered 200")
	}
	return e.Error, e.Description
}

func sameStrings(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// fixtureMigrations are two test-only migrations after the shipped ones:
// one adds a realm attribute (writing the whole map, as converge does), one
// sets a realm field converge does not own. Both are idempotent.
func fixtureMigrations(after int) []migrations.Migration {
	path := func(realm string) string { return "/admin/realms/" + url.PathEscape(realm) }
	return []migrations.Migration{
		{ID: after + 1, Name: "test-fixture-attribute", Apply: func(ctx context.Context, a migrations.Admin, realm string) error {
			var rep struct {
				Attributes map[string]json.RawMessage `json:"attributes"`
			}
			if _, err := a.Admin(ctx, http.MethodGet, path(realm), nil, &rep); err != nil {
				return err
			}
			if rep.Attributes == nil {
				rep.Attributes = map[string]json.RawMessage{}
			}
			rep.Attributes["rasputin.fixture"] = json.RawMessage(`"one"`)
			_, err := a.Admin(ctx, http.MethodPut, path(realm), map[string]any{"attributes": rep.Attributes}, nil)
			return err
		}},
		{ID: after + 2, Name: "test-fixture-field", Apply: func(ctx context.Context, a migrations.Admin, realm string) error {
			_, err := a.Admin(ctx, http.MethodPut, path(realm), map[string]any{"accessTokenLifespan": 240}, nil)
			return err
		}},
	}
}

// importRealms imports the repo's baseline once under each name, in one
// kc.sh import.
func importRealms(t *testing.T, env *Env, names []string) {
	t.Helper()
	baseline, err := os.ReadFile(filepath.Join("..", "..", "..", "identity", "realm-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	// UseNumber keeps every number as the baseline writes it.
	dec := json.NewDecoder(bytes.NewReader(baseline))
	dec.UseNumber()
	var realm map[string]any
	if err := dec.Decode(&realm); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(env.root, "tc17-import")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		realm["realm"] = name
		b, err := json.Marshal(realm)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+"-realm.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kcCommand(t, env, "import of the TC-981-17 realms", "import", "--optimized", "--dir", dir)
}

// exportRealms exports every realm with kc.sh export and returns each
// tc17-* realm masked: ids, key material and its own name.
func exportRealms(t *testing.T, env *Env) map[string]any {
	t.Helper()
	dir := filepath.Join(env.root, "tc17-export")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	kcCommand(t, env, "export of the TC-981-17 realms", "export", "--optimized", "--dir", dir, "--users", "skip")
	out := map[string]any{}
	files, err := filepath.Glob(filepath.Join(dir, "tc17-*-realm.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("export wrote no tc17 realm (%v)", err)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), "-realm.json")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		out[name] = mask(v, name)
	}
	return out
}

var uuidShape = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// maskedKeys hold key material, secrets or creation times, which differ by
// realm by construction.
var maskedKeys = map[string]bool{
	"secret": true, "privateKey": true, "certificate": true, "kid": true,
	"client.secret.creation.time": true, "createdTimestamp": true,
}

// mask replaces ids, key material and the realm's name in v, and sorts every
// array, whose order Keycloak does not keep.
func mask(v any, realm string) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if maskedKeys[k] {
				out[k] = "<masked>"
				continue
			}
			out[k] = mask(e, realm)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = mask(e, realm)
		}
		sort.Slice(out, func(i, j int) bool { return canon(out[i]) < canon(out[j]) })
		return out
	case string:
		return uuidShape.ReplaceAllString(strings.ReplaceAll(x, realm, "<realm>"), "<id>")
	}
	return v
}

func canon(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// jsonDiff lists the paths where a and b differ, at most 20.
func jsonDiff(path string, a, b any, out []string) []string {
	if len(out) >= 20 || canon(a) == canon(b) {
		return out
	}
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if !aok || !bok {
		return append(out, fmt.Sprintf("%s: %.200s != %.200s", path, canon(a), canon(b)))
	}
	keys := map[string]bool{}
	for k := range am {
		keys[k] = true
	}
	for k := range bm {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		out = jsonDiff(path+"."+k, am[k], bm[k], out)
	}
	return out
}
