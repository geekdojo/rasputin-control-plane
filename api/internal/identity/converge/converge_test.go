package converge

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// realmPUT is the one realm PUT's body, decoded raw.
func realmPUT(t *testing.T, kc *fakeKC) map[string]json.RawMessage {
	t.Helper()
	var bodies []map[string]json.RawMessage
	for _, c := range kc.writes() {
		if c.method == http.MethodPut && c.path == realmPath {
			var b map[string]json.RawMessage
			if err := json.Unmarshal(c.body, &b); err != nil {
				t.Fatal(err)
			}
			bodies = append(bodies, b)
		}
	}
	if len(bodies) != 1 {
		t.Fatalf("%d realm PUTs, want 1", len(bodies))
	}
	return bodies[0]
}

// TC-981-05: a realm in the desired state yields no diff and Run writes
// nothing. TC-988-41: that realm carries loginTheme rasputin, so a themed
// realm is left alone.
func TestDiff_DesiredRealmHasNone(t *testing.T) {
	r := newRig(t)
	fields, err := r.c.Run(t.Context())
	if err != nil || len(fields) != 0 {
		t.Fatalf("Run = %v, %v; want nothing repaired", fields, err)
	}
	if w := r.kc.writes(); len(w) != 0 {
		t.Fatalf("writes = %+v, want none", w)
	}
}

// TC-981-05: each owned realm field's drift is detected and put back in the
// one realm PUT, with "", {} and [] sent as values; the PUT carries only the
// drifted fields, and no attributes unless an owned attribute changes.
func TestRun_RealmFieldsEachDetected(t *testing.T) {
	for _, c := range []struct {
		name  string // the subtest's name, the field's when ""
		field string
		set   any
		want  string // the field's raw JSON in the PUT
	}{
		{"", "displayName", "Old Name", `"Test Home"`},
		{"", "displayNameHtml", "<b>Home</b>", `""`},
		{"", "eventsEnabled", false, `true`},
		{"", "eventsListeners", []any{"jboss-logging"}, `[]`},
		{"", "enabledEventTypes", []any{"LOGIN"}, ""},
		{"", "eventsExpiration", nil, `2592000`},
		{"", "adminEventsEnabled", false, `true`},
		{"", "adminEventsDetailsEnabled", true, `false`},
		{"", "smtpServer", map[string]any{"host": "mail.example"}, `{}`},
		// TC-988-38: a realm imported from the v2026.11.3 baseline has no
		// loginTheme; an administrator's other theme is put back too.
		{"loginTheme absent", "loginTheme", nil, `"rasputin"`},
		{"loginTheme keycloak.v2", "loginTheme", "keycloak.v2", `"rasputin"`},
	} {
		name := c.name
		if name == "" {
			name = c.field
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			if c.set == nil {
				delete(r.kc.realm, c.field)
			} else {
				r.kc.realm[c.field] = c.set
			}
			fields, err := r.c.Run(t.Context())
			if err != nil || !slices.Equal(fields, []string{"realm." + c.field}) {
				t.Fatalf("Run = %v, %v; want [realm.%s]", fields, err, c.field)
			}
			put := realmPUT(t, r.kc)
			if len(put) != 1 {
				t.Errorf("realm PUT carries %d fields, want only %s: %s", len(put), c.field, mapKeys(put))
			}
			if c.want != "" && string(put[c.field]) != c.want {
				t.Errorf("realm PUT %s = %s, want %s", c.field, put[c.field], c.want)
			}
			if c.field == "enabledEventTypes" {
				var got []string
				_ = json.Unmarshal(put[c.field], &got)
				if !sameSet(got, AuditEventTypes) {
					t.Errorf("enabledEventTypes = %v, want the audit set", got)
				}
			}
		})
	}
}

func mapKeys(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// TC-981-05: attributes is sent only when an owned attribute must change,
// and then as the whole map as read, with only those changes.
func TestRun_AttributesWholeMapOnlyForOwned(t *testing.T) {
	r := newRig(t)
	attrs := r.kc.realm["attributes"].(map[string]any)
	attrs["frontendUrl"] = "https://elsewhere.example"
	delete(attrs, "adminEventsExpiration")
	fields, err := r.c.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fields, []string{"realm.attributes.frontendUrl", "realm.attributes.adminEventsExpiration"}) {
		t.Errorf("fields = %v", fields)
	}
	put := realmPUT(t, r.kc)
	var sent map[string]string
	if err := json.Unmarshal(put["attributes"], &sent); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"CreateDefaultClientScopes": "true", "cibaExpiresIn": "120", "adminEventsExpiration": "2592000"}
	if len(sent) != len(want) {
		t.Errorf("attributes sent = %v, want %v", sent, want)
	}
	for k, v := range want {
		if sent[k] != v {
			t.Errorf("attributes[%s] = %q, want %q", k, sent[k], v)
		}
	}
	if len(put) != 1 {
		t.Errorf("realm PUT carries %v, want attributes alone", mapKeys(put))
	}
	// A drifted scalar alone sends no attributes.
	r = newRig(t)
	r.kc.realm["displayName"] = "Other"
	if _, err := r.c.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := realmPUT(t, r.kc)["attributes"]; ok {
		t.Error("attributes sent with no owned attribute to change")
	}
}

// TC-981-05 (F-981-01): an RP ID that drifted rewrites each WebAuthn policy
// whole, as read, with only its RP ID cleared and its entity name kept.
func TestRun_WebAuthnPoliciesWritten(t *testing.T) {
	r := newRig(t)
	r.kc.realm["webAuthnPolicyRpId"] = "evil.example"
	read := map[string]any{}
	for k, v := range r.kc.realm {
		if strings.HasPrefix(k, "webAuthnPolicy") {
			read[k] = v
		}
	}
	fields, err := r.c.Run(t.Context())
	if err != nil || !slices.Equal(fields, []string{"realm.webAuthnPolicyRpId"}) {
		t.Fatalf("Run = %v, %v", fields, err)
	}
	put := realmPUT(t, r.kc)
	for k, v := range read {
		want, _ := json.Marshal(v)
		if k == "webAuthnPolicyRpId" || k == "webAuthnPolicyPasswordlessRpId" {
			want = []byte(`""`)
		}
		if string(put[k]) != string(want) {
			t.Errorf("PUT %s = %s, want %s", k, put[k], want)
		}
	}
	for k := range put {
		if !strings.HasPrefix(k, "webAuthnPolicy") {
			t.Errorf("PUT carries %s, which is not a WebAuthn policy field", k)
		}
	}
	for _, k := range []string{"webAuthnPolicyRpEntityName", "webAuthnPolicyPasswordlessRpEntityName"} {
		if string(put[k]) == `""` || put[k] == nil {
			t.Errorf("%s = %s, want non-empty", k, put[k])
		}
	}
}

// TC-981-05: each client PUT carries only the owned fields and never secret;
// one DELETE goes per fallback key provider.
func TestRun_ClientsAndFallbackKeys(t *testing.T) {
	r := newRig(t)
	r.inputs.RedirectURIs = map[string][]string{"rasputin-console": {redirectA}}
	admin := r.kc.client("admin-cli")
	admin["enabled"], admin["directAccessGrantsEnabled"] = true, true
	r.kc.client("broker")["enabled"] = true
	r.kc.client("rasputin-mesh")["redirectUris"] = []any{"https://stale.example/cb"}
	r.kc.keys = append(r.kc.keys,
		map[string]any{"id": "fb-1", "name": "fallback-RS256"}, map[string]any{"id": "fb-2", "name": "fallback-HS512"})
	fields, err := r.c.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"client.admin-cli.enabled", "client.admin-cli.directAccessGrantsEnabled", "client.broker.enabled",
		"client.rasputin-console.redirectUris", "client.rasputin-mesh.redirectUris", "keys.fallback-RS256", "keys.fallback-HS512"} {
		if !slices.Contains(fields, f) {
			t.Errorf("fields %v lack %s", fields, f)
		}
	}
	bodies := map[string]string{}
	var deletes []string
	for _, c := range r.kc.writes() {
		switch c.method {
		case http.MethodPut:
			bodies[c.path] = string(c.body)
			if strings.Contains(string(c.body), "secret") {
				t.Errorf("%s carries a secret: %s", c.path, c.body)
			}
		case http.MethodDelete:
			deletes = append(deletes, c.path)
		}
	}
	id := func(clientID string) string { return realmPath + "/clients/" + r.kc.client(clientID)["id"].(string) }
	for path, want := range map[string]string{
		id("admin-cli"):        `{"directAccessGrantsEnabled":false,"enabled":false}`,
		id("broker"):           `{"enabled":false}`,
		id("rasputin-console"): `{"redirectUris":["` + redirectA + `"]}`,
		id("rasputin-mesh"):    `{"redirectUris":[]}`,
	} {
		if bodies[path] != want {
			t.Errorf("PUT %s = %s, want %s", path, bodies[path], want)
		}
	}
	// The console's redirect URI also gives the realm its console origin
	// (geekdojo/geekdojo-brain#988), so the one realm PUT is that attribute.
	if len(bodies) != 5 || !strings.Contains(bodies[realmPath], `"rasputin.console-url":"https://console.home.example"`) {
		t.Errorf("%d PUTs, want 4 client PUTs and the realm PUT of rasputin.console-url: %v", len(bodies), bodies)
	}
	if !slices.Equal(deletes, []string{realmPath + "/components/fb-1", realmPath + "/components/fb-2"}) {
		t.Errorf("deletes = %v", deletes)
	}
	if r.kc.client("rasputin-mesh")["secret"] != secretText {
		t.Error("the mesh client's secret changed")
	}
}

// TC-981-06: a missing key provider is refused with zero writes (a blank
// WebAuthn entity name as read is now repaired: TC-987-40); every failure fails with a fixed sentence and
// stores no hash.
func TestRun_FailurePaths(t *testing.T) {
	down := &idclient.Error{Op: "admin", Path: realmPath, Status: 503, Kind: idclient.ErrUnreachable}
	for _, c := range []struct {
		name   string
		set    func(r *rig)
		want   error
		writes bool
	}{
		{"a key provider missing", func(r *rig) {
			r.kc.realm["displayName"] = "drifted"
			r.kc.keys = r.kc.keys[1:]
		}, errKeyMissing, false},
		{"the inputs unreadable", func(r *rig) {
			r.c.d.Inputs = func(context.Context) (Inputs, error) { return Inputs{}, errors.New("settings db") }
		}, errInputs, false},
		{"the stored hash unreadable", func(r *rig) { r.settings.getErr = errors.New("settings db") }, errSettings, false},
		{"the realm unreadable", func(r *rig) { r.kc.fail["GET "+realmPath] = down }, errRead, false},
		{"a write refused", func(r *rig) {
			r.kc.realm["displayName"] = "drifted"
			r.kc.fail["PUT "+realmPath] = &idclient.Error{Op: "admin", Path: realmPath, Status: 400, Kind: idclient.ErrProtocol}
		}, errWrite, true},
		{"the read-back unreadable", func(r *rig) {
			r.kc.realm["displayName"] = "drifted"
			r.kc.failOn = func(method, path string, n int) error {
				if method == http.MethodGet && path == realmPath && n == 2 {
					return down
				}
				return nil
			}
		}, errRead, true},
		{"the read-back still differs", func(r *rig) {
			r.kc.realm["displayName"] = "drifted"
			r.kc.ignoreWrites = true
		}, errStillDiffers, true},
		{"the hash not stored", func(r *rig) {
			r.settings.setErr = errors.New("settings db")
		}, errHashWrite, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.set(r)
			_, err := r.c.Run(t.Context())
			if !errors.Is(err, c.want) {
				t.Fatalf("Run = %v, want %v", err, c.want)
			}
			if got := len(r.kc.writes()) > 0; got != c.writes {
				t.Errorf("writes made %t, want %t: %+v", got, c.writes, r.kc.writes())
			}
			if _, ok := r.settings.m[HashKey]; ok {
				t.Error("a hash was stored by a failed run")
			}
			if n := len(r.rec.Matching(slog.LevelError, "")); n != 1 {
				t.Errorf("%d ERROR records, want 1:\n%s", n, r.rec.Text())
			}
		})
	}
}

// TC-981-06: the drift alert rises only when repairs are made while the
// stored hash equals the desired one, and clears on the next clean run;
// repairs with no stored hash or a different one are INFO.
func TestRun_DriftAlert(t *testing.T) {
	for _, c := range []struct {
		name   string
		stored func(r *rig)
		alert  bool
		level  slog.Level
	}{
		{"no stored hash", func(*rig) {}, false, slog.LevelInfo},
		{"a different stored hash", func(r *rig) { r.settings.m[HashKey] = "0123" }, false, slog.LevelInfo},
		{"the same stored hash", func(r *rig) { r.storeHash() }, true, slog.LevelWarn},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.stored(r)
			r.kc.realm["displayName"] = "drifted"
			if _, err := r.c.Run(t.Context()); err != nil {
				t.Fatal(err)
			}
			alerts := r.c.Alerts(t.Context(), testNow)
			if got := len(alerts) == 1; got != c.alert {
				t.Fatalf("alerts = %+v, want raised %t", alerts, c.alert)
			}
			if c.alert {
				a := alerts[0]
				if a.ID != DriftAlertID || a.Severity != "warn" || a.Title != driftTitle || a.RelatedKind != "accounts" || !a.Since.Equal(testNow) {
					t.Errorf("alert = %+v", a)
				}
			}
			recs := r.rec.Matching(c.level, "")
			if len(recs) != 1 {
				t.Fatalf("records:\n%s\nwant one at %v", r.rec.Text(), c.level)
			}
			if f, _ := logkittest.Attr(recs[0], "fields"); !strings.Contains(f, "realm.displayName") {
				t.Errorf("fields = %q", f)
			}
			if r.settings.m[HashKey] != NewDesired(r.inputs).Hash() {
				t.Error("the desired hash was not stored")
			}
			// The next clean run clears it.
			if fields, err := r.c.Run(t.Context()); err != nil || len(fields) != 0 {
				t.Fatalf("second Run = %v, %v", fields, err)
			}
			if a := r.c.Alerts(t.Context(), testNow); len(a) != 0 {
				t.Errorf("alerts after a clean run = %+v", a)
			}
		})
	}
}

// TC-981-06: no log record and no job error carries a client secret or a
// redirect URI, on success and on failure.
func TestRun_NoSecretOrRedirectURIInLogs(t *testing.T) {
	r := newRig(t)
	r.storeHash()
	r.inputs.RedirectURIs = map[string][]string{"rasputin-console": {redirectA}}
	r.kc.client("rasputin-console")["redirectUris"] = []any{"https://stale-redirect.example/cb"}
	r.kc.realm["displayName"] = "drifted"
	var errs []string
	if _, err := r.c.Run(t.Context()); err != nil {
		errs = append(errs, err.Error())
	}
	r.kc.client("rasputin-console")["redirectUris"] = []any{"https://stale-redirect.example/cb"}
	r.kc.ignoreWrites = true
	if _, err := r.c.Run(t.Context()); err != nil {
		errs = append(errs, err.Error())
	} else {
		t.Fatal("the run that cannot write succeeded")
	}
	consolePath := realmPath + "/clients/" + r.kc.client("rasputin-console")["id"].(string)
	r.kc.fail["PUT "+consolePath] = &idclient.Error{Op: "admin", Path: consolePath, Status: 400, Kind: idclient.ErrProtocol}
	r.kc.ignoreWrites = false
	if _, err := r.c.Run(t.Context()); err != nil {
		errs = append(errs, err.Error())
	}
	text := r.rec.Text() + strings.Join(errs, "\n")
	for _, v := range []string{secretText, redirectA, "stale-redirect"} {
		if strings.Contains(text, v) {
			t.Errorf("a record or job error carries %q:\n%s", v, text)
		}
	}
}

// TC-981-15 (the converge half): every Admin API call a converge run makes
// is under the realm lock the migrations runner shares.
func TestRun_HoldsTheSharedLock(t *testing.T) {
	r := newRig(t)
	r.kc.realm["displayName"] = "drifted"
	if _, err := r.c.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r.kc.unlocked != 0 || len(r.kc.calls) == 0 {
		t.Fatalf("%d of %d calls without the realm lock", r.kc.unlocked, len(r.kc.calls))
	}
}

// Desired's hash changes exactly when a wanted value does.
func TestDesired_Hash(t *testing.T) {
	a := NewDesired(Inputs{InstallName: "A", RedirectURIs: map[string][]string{"rasputin-console": {"b", "a"}}})
	b := NewDesired(Inputs{InstallName: "A", RedirectURIs: map[string][]string{"rasputin-console": {"a", "b"}, "other": {"x"}}})
	if a.Hash() != b.Hash() {
		t.Error("the same wanted values hash differently")
	}
	if a.Hash() == NewDesired(Inputs{InstallName: "B"}).Hash() {
		t.Error("a different install name hashes the same")
	}
}

// geekdojo/geekdojo-brain#988 (F-988-01): the console's one https origin
// becomes rasputin.console-url; no URI, a non-https URI or two origins hold
// the attribute absent.
func TestNewDesired_ConsoleURL(t *testing.T) {
	for _, c := range []struct {
		name string
		uris []string
		want string
	}{
		{"one https URI", []string{"https://bench.local/api/auth/callback"}, "https://bench.local"},
		{"two URIs, one origin", []string{"https://bench.local/a", "https://bench.local/b"}, "https://bench.local"},
		{"a port is part of the origin", []string{"https://bench.local:8443/cb"}, "https://bench.local:8443"},
		{"none", nil, ""},
		{"not https", []string{"http://bench.local/cb"}, ""},
		{"relative", []string{"/cb"}, ""},
		{"two origins", []string{"https://bench.local/cb", "https://other.local/cb"}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := NewDesired(Inputs{RedirectURIs: map[string][]string{"rasputin-console": c.uris}}).ConsoleURL
			if got != c.want {
				t.Errorf("ConsoleURL = %q, want %q", got, c.want)
			}
		})
	}
}

// geekdojo/geekdojo-brain#988 (F-988-01): a missing or stale
// rasputin.console-url is written in the whole attribute map as read, with
// every other attribute kept, and a stale one is deleted when there is no
// console origin.
func TestRun_ConsoleURLAttribute(t *testing.T) {
	const want = "https://bench.local"
	console := map[string][]string{"rasputin-console": {want + "/api/auth/callback"}}

	attrsSent := func(t *testing.T, r *rig) map[string]string {
		t.Helper()
		var sent map[string]string
		if err := json.Unmarshal(realmPUT(t, r.kc)["attributes"], &sent); err != nil {
			t.Fatal(err)
		}
		return sent
	}

	t.Run("missing is set", func(t *testing.T) {
		r := newRig(t)
		r.inputs.RedirectURIs = console
		setConsoleRedirect(r.kc, console["rasputin-console"])
		fields, err := r.c.Run(t.Context())
		if err != nil || !slices.Equal(fields, []string{"realm.attributes.rasputin.console-url"}) {
			t.Fatalf("Run = %v, %v; want [realm.attributes.rasputin.console-url]", fields, err)
		}
		sent := attrsSent(t, r)
		if sent[attrConsoleURL] != want || sent["CreateDefaultClientScopes"] != "true" || sent["cibaExpiresIn"] != "120" {
			t.Errorf("attributes sent = %v, want the map as read plus %s=%s", sent, attrConsoleURL, want)
		}
	})

	t.Run("stale is rewritten", func(t *testing.T) {
		r := newRig(t)
		r.inputs.RedirectURIs = console
		setConsoleRedirect(r.kc, console["rasputin-console"])
		r.kc.realm["attributes"].(map[string]any)[attrConsoleURL] = "https://old.local"
		if _, err := r.c.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := attrsSent(t, r)[attrConsoleURL]; got != want {
			t.Errorf("%s sent = %q, want %q", attrConsoleURL, got, want)
		}
	})

	t.Run("stale with no console origin is deleted", func(t *testing.T) {
		r := newRig(t)
		r.kc.realm["attributes"].(map[string]any)[attrConsoleURL] = "https://old.local"
		fields, err := r.c.Run(t.Context())
		if err != nil || !slices.Equal(fields, []string{"realm.attributes.rasputin.console-url"}) {
			t.Fatalf("Run = %v, %v", fields, err)
		}
		sent := attrsSent(t, r)
		if _, ok := sent[attrConsoleURL]; ok {
			t.Errorf("attributes sent = %v, want %s left out", sent, attrConsoleURL)
		}
		if sent["CreateDefaultClientScopes"] != "true" {
			t.Errorf("attributes sent = %v, want the other attributes kept", sent)
		}
	})

	t.Run("hash changes with the value", func(t *testing.T) {
		a := NewDesired(Inputs{InstallName: "A", RedirectURIs: console})
		b := NewDesired(Inputs{InstallName: "A", RedirectURIs: map[string][]string{"rasputin-console": {"https://other.local/cb"}}})
		if a.Hash() == b.Hash() || a.Hash() == NewDesired(Inputs{InstallName: "A"}).Hash() {
			t.Error("a different console origin hashes the same")
		}
	})
}

// setConsoleRedirect gives the fake's console client its redirect URIs, so
// only the attribute drifts.
func setConsoleRedirect(kc *fakeKC, uris []string) {
	list := make([]any, len(uris))
	for i, u := range uris {
		list[i] = u
	}
	kc.client("rasputin-console")["redirectUris"] = list
}

// TC-988-37: the desired state owns the login theme: rasputin whatever the
// inputs, in the canonical JSON, and part of the hash, so a cluster holding
// the hash of a build without it is re-armed.
func TestNewDesired_LoginTheme(t *testing.T) {
	if LoginTheme != "rasputin" {
		t.Fatalf("LoginTheme = %q, want rasputin", LoginTheme)
	}
	for _, in := range []Inputs{{}, {InstallName: "Test Home", ClockSynced: true, FirstRun: true,
		RedirectURIs: map[string][]string{"rasputin-console": {redirectA}}}} {
		d := NewDesired(in)
		if d.LoginTheme != LoginTheme {
			t.Errorf("NewDesired(%+v).LoginTheme = %q, want %q", in, d.LoginTheme, LoginTheme)
		}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"loginTheme":"rasputin"`) {
			t.Errorf("canonical JSON carries no loginTheme rasputin: %s", b)
		}
		without := d
		without.LoginTheme = ""
		if without.Hash() == d.Hash() {
			t.Error("a desired state without the login theme hashes the same")
		}
	}
}

// TC-988-39: the first run after an update, on a realm without loginTheme,
// is a repair and not drift: one INFO naming realm.loginTheme, no alert, the
// new hash stored and the control gate open.
func TestRun_LoginThemeFirstRunIsNotDrift(t *testing.T) {
	for _, c := range []struct {
		name   string
		stored func(r *rig)
	}{
		{"no stored hash", func(*rig) {}},
		{"the previous release's hash", func(r *rig) { r.settings.m[HashKey] = "the-previous-release" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.stored(r)
			delete(r.kc.realm, "loginTheme")
			fields, err := r.c.Run(t.Context())
			if err != nil || !slices.Contains(fields, "realm.loginTheme") {
				t.Fatalf("Run = %v, %v; want realm.loginTheme among the fields", fields, err)
			}
			var repaired []slog.Record
			for _, rec := range r.rec.Matching(slog.LevelInfo, "") {
				if e, _ := logkittest.Attr(rec, "event"); e == "identity.converge.repaired" {
					repaired = append(repaired, rec)
				}
			}
			if len(repaired) != 1 {
				t.Fatalf("%d identity.converge.repaired INFO records, want 1:\n%s", len(repaired), r.rec.Text())
			}
			if f, _ := logkittest.Attr(repaired[0], "fields"); !strings.Contains(f, "realm.loginTheme") {
				t.Errorf("fields = %q, want realm.loginTheme", f)
			}
			if n := len(r.rec.AtLevel(slog.LevelWarn)) + len(r.rec.AtLevel(slog.LevelError)); n != 0 {
				t.Errorf("%d WARN or ERROR records, want none:\n%s", n, r.rec.Text())
			}
			if a := r.c.Alerts(t.Context(), testNow); len(a) != 0 {
				t.Errorf("alerts = %+v, want none", a)
			}
			if r.settings.m[HashKey] != NewDesired(r.inputs).Hash() {
				t.Error("the desired hash was not stored")
			}
			if err := r.c.ControlGate(t.Context()); err != nil {
				t.Errorf("ControlGate = %v, want nil", err)
			}
		})
	}
}

// TC-988-40: another login theme set while the stored hash is current is
// drift: put back alone, one WARN, the drift alert at warn, and the control
// gate stays open because the theme is not an integrity field.
func TestRun_LoginThemeDriftPutBack(t *testing.T) {
	r := newRig(t)
	r.storeHash()
	r.kc.realm["loginTheme"] = "keycloak.v2"
	fields, err := r.c.Run(t.Context())
	if err != nil || !slices.Equal(fields, []string{"realm.loginTheme"}) {
		t.Fatalf("Run = %v, %v; want [realm.loginTheme]", fields, err)
	}
	put := realmPUT(t, r.kc)
	if len(put) != 1 || string(put["loginTheme"]) != `"rasputin"` {
		t.Errorf("realm PUT = %v, want loginTheme rasputin alone", mapKeys(put))
	}
	warns := r.rec.Matching(slog.LevelWarn, "")
	if len(warns) != 1 {
		t.Fatalf("%d WARN records, want 1:\n%s", len(warns), r.rec.Text())
	}
	if e, _ := logkittest.Attr(warns[0], "event"); e != "identity.converge.drift" {
		t.Errorf("WARN event = %q, want identity.converge.drift", e)
	}
	if f, _ := logkittest.Attr(warns[0], "fields"); !strings.Contains(f, "realm.loginTheme") {
		t.Errorf("fields = %q, want realm.loginTheme", f)
	}
	alerts := r.c.Alerts(t.Context(), testNow)
	if len(alerts) != 1 || alerts[0].ID != DriftAlertID || alerts[0].Severity != "warn" {
		t.Errorf("alerts = %+v, want %s at warn alone", alerts, DriftAlertID)
	}
	if s := r.c.State(); s != Intact {
		t.Errorf("integrity state = %v, want intact", s)
	}
	if err := r.c.ControlGate(t.Context()); err != nil {
		t.Errorf("ControlGate = %v, want nil", err)
	}
}

// TC-988-42: the new field's failure paths are the existing ones: a theme
// that does not read back, and a realm PUT the identity service refuses,
// each fail with their job error, one ERROR naming the field, and no stored
// hash. No record carries the theme value read.
func TestRun_LoginThemeFailurePaths(t *testing.T) {
	refused := &idclient.Error{Op: "admin", Path: realmPath, Status: 500, Kind: idclient.ErrProtocol}
	for _, c := range []struct {
		name   string
		set    func(r *rig)
		want   error
		detail bool // the ERROR carries the Admin API's status
	}{
		{"the theme does not read back", func(r *rig) {
			delete(r.kc.realm, "loginTheme")
			r.kc.ignoreWrites = true
		}, errStillDiffers, false},
		{"the realm PUT answers 500", func(r *rig) {
			r.kc.realm["loginTheme"] = "keycloak.v2"
			r.kc.fail["PUT "+realmPath] = refused
		}, errWrite, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.set(r)
			_, err := r.c.RunJob(t.Context(), "job-988")
			if !errors.Is(err, c.want) {
				t.Fatalf("RunJob = %v, want %v", err, c.want)
			}
			if _, ok := r.settings.m[HashKey]; ok {
				t.Error("a hash was stored by a failed run")
			}
			errs := r.rec.AtLevel(slog.LevelError)
			if len(errs) != 1 {
				t.Fatalf("%d ERROR records, want 1:\n%s", len(errs), r.rec.Text())
			}
			rec := errs[0]
			if e, _ := logkittest.Attr(rec, "event"); e != "identity.converge.failed" {
				t.Errorf("event = %q, want identity.converge.failed", e)
			}
			if j, _ := logkittest.Attr(rec, "job_id"); j != "job-988" {
				t.Errorf("job_id = %q, want job-988", j)
			}
			if f, _ := logkittest.Attr(rec, "fields"); !strings.Contains(f, "realm.loginTheme") {
				t.Errorf("fields = %q, want realm.loginTheme", f)
			}
			if st, _ := logkittest.Attr(rec, "status"); c.detail && st != "500" {
				t.Errorf("status = %q, want the Admin API's 500", st)
			}
			if text := r.rec.Text() + err.Error(); strings.Contains(text, "keycloak.v2") {
				t.Errorf("a record or the job error carries the theme value read:\n%s", text)
			}
		})
	}
}
