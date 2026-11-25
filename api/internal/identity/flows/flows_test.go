package flows

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// golden compares v's indented JSON with testdata/name.golden.json, or
// rewrites it under -update.
func golden(t *testing.T, name string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", name+".golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to write it)", err)
	}
	if string(got) != string(want) {
		t.Errorf("%s differs from its golden file:\n%s", name, got)
	}
}

// find is the node with the sub-flow alias suffix, depth first.
func find(nodes []Node, suffix string) (Node, bool) {
	for _, n := range nodes {
		if n.IsFlow() && strings.HasSuffix(n.Alias, suffix) {
			return n, true
		}
		if m, ok := find(n.Children, suffix); ok {
			return m, true
		}
	}
	return Node{}, false
}

// branchesOf are the sign-in sub-flow's privileged branches, by suffix.
func branchesOf(t *testing.T, v Variant) map[string]Node {
	t.Helper()
	signIn, ok := find(Flow(v), "-sign-in")
	if !ok {
		t.Fatalf("%s has no sign-in sub-flow", v.Alias())
	}
	out := map[string]Node{}
	for _, n := range signIn.Children {
		if n.IsFlow() && !strings.Contains(n.Alias, "second-step-") {
			out[strings.TrimPrefix(n.Alias, v.Alias()+"-")] = n
		}
	}
	return out
}

// checkLevels walks every level: no ALTERNATIVE beside a REQUIRED or
// CONDITIONAL execution, conditions not counted (F-987-01).
func checkLevels(t *testing.T, where string, nodes []Node) {
	t.Helper()
	strict, alt := false, false
	for _, n := range nodes {
		if strings.HasPrefix(n.Provider, "conditional-") {
			continue
		}
		switch n.Requirement {
		case Required, Conditional:
			strict = true
		case Alternative:
			alt = true
		}
		if n.IsFlow() {
			checkLevels(t, n.Alias, n.Children)
		}
	}
	if strict && alt {
		t.Errorf("%s: an ALTERNATIVE sits beside a REQUIRED or CONDITIONAL execution, which Keycloak would drop", where)
	}
}

// denies are every Deny access node's sentence under nodes.
func denies(nodes []Node) []string {
	var out []string
	for _, n := range nodes {
		if n.Provider == ProviderDeny {
			out = append(out, n.Config[denyMessageKey])
		}
		out = append(out, denies(n.Children)...)
	}
	return out
}

// TC-987-24: each variant's flow equals its golden file; Administering has
// no cookie and one all-account branch; the gates' patterns and the branch
// sets per door are as specified; each Deny holds its own sentence; and no
// level mixes ALTERNATIVE with REQUIRED or CONDITIONAL.
func TestFlow_VariantsAndStructure(t *testing.T) {
	gates := map[Variant][2]string{
		HomeMesh: {appAccessPattern, SentenceNoAppAccess}, AppClients: {appAccessPattern, SentenceNoAppAccess},
		Administering: {appAccessPattern, SentenceNoAppAccess}, AdminsFirst: {appAdminPattern, SentenceAdminsFirst},
		NetworkDevices: {networkAccessPattern, SentenceNoNetworkAccess},
	}
	for _, v := range Variants {
		t.Run(v.Alias(), func(t *testing.T) {
			f := Flow(v)
			golden(t, v.Alias(), f)
			checkLevels(t, v.Alias(), f)
			authenticate := f[0]
			if authenticate.Requirement != Required || !strings.HasSuffix(authenticate.Alias, "-authenticate") {
				t.Fatalf("the top level starts with %+v, want authenticate, REQUIRED", authenticate)
			}
			hasCookie := slices.ContainsFunc(authenticate.Children, func(n Node) bool { return n.Provider == ProviderCookie })
			if hasCookie == (v == Administering) {
				t.Errorf("cookie present %v, want %v", hasCookie, v != Administering)
			}
			gate, gated := gates[v]
			if gated != (len(f) == 2) {
				t.Fatalf("top level holds %d executions, want the gate %v", len(f), gated)
			}
			if gated {
				g := f[1]
				if g.Requirement != Conditional || g.Children[0].Config["attribute_expected_value"] != gate[0] ||
					g.Children[0].Config["not"] != "true" || g.Children[1].Config[denyMessageKey] != gate[1] {
					t.Errorf("the gate is %+v, want pattern %s denying with %q", g, gate[0], gate[1])
				}
				wantAttr := attrAppRole
				if v == NetworkDevices {
					wantAttr = attrNetwork
				}
				if g.Children[0].Config["attribute_name"] != wantAttr {
					t.Errorf("the gate reads %s, want %s", g.Children[0].Config["attribute_name"], wantAttr)
				}
			}
			var want []string
			switch {
			case v == Administering:
				want = []string{"every-account"}
			case v.Door() == DoorHome:
				want = []string{"privileged-admin", "privileged-gear-admin", "privileged-operator"}
			default:
				want = []string{"privileged-admin", "privileged-app-admin", "privileged-gear-admin", "privileged-operator"}
			}
			got := branchesOf(t, v)
			names := slices.Sorted(func(yield func(string) bool) {
				for k := range got {
					if !yield(k) {
						return
					}
				}
			})
			if !slices.Equal(names, want) {
				t.Errorf("branches %v, want %v", names, want)
			}
			for name, b := range got {
				wantSentence := SentencePrivileged
				if v == Administering {
					wantSentence = SentenceAdministering
					if b.Children[0].Provider != ConditionCredential {
						t.Errorf("the administering branch has an account condition %s, want none", b.Children[0].Provider)
					}
				}
				if s := denies(b.Children); len(s) != 1 || s[0] != wantSentence {
					t.Errorf("%s denies with %q, want %q", name, s, wantSentence)
				}
				// Deny only when no passkey was used and neither second step ran.
				var flowsChecked []string
				for _, c := range b.Children {
					if c.Provider == ConditionSubFlowExecuted {
						flowsChecked = append(flowsChecked, c.Config["flow_to_check"])
						if c.Config["check_result"] != "not-executed" {
							t.Errorf("%s checks %v", name, c.Config)
						}
					}
				}
				if !slices.Equal(flowsChecked, []string{v.Alias() + "-second-step-webauthn", v.Alias() + "-second-step-codes"}) {
					t.Errorf("%s checks %v, want both second steps", name, flowsChecked)
				}
			}
			// The two second steps' webauthn-marker conditions are opposite.
			wa, _ := find(f, "-second-step-webauthn")
			co, _ := find(f, "-second-step-codes")
			if wa.Children[2].Config["not"] != "false" || co.Children[2].Config["not"] != "true" ||
				wa.Children[2].Config["attribute_name"] != WebAuthnMarker(v.Door()) {
				t.Errorf("the second steps' door conditions are %v and %v", wa.Children[2].Config, co.Children[2].Config)
			}
			wantMarker := SecondStepMarker(v.Door())
			if v == Administering {
				wantMarker = MarkerSecondStepAny
			}
			if wa.Children[1].Config["attribute_name"] != wantMarker || co.Children[1].Config["attribute_name"] != wantMarker {
				t.Errorf("the second steps read %s and %s, want %s", wa.Children[1].Config["attribute_name"], co.Children[1].Config["attribute_name"], wantMarker)
			}
		})
	}
}

// Every config alias is unique in the realm.
func TestFlow_ConfigAliasesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range Variants {
		for _, s := range Flatten(v.Alias(), Flow(v)) {
			for _, a := range []string{s.ConfigAlias, s.Alias} {
				if a == "" {
					continue
				}
				if seen[a] {
					t.Errorf("%s is used twice", a)
				}
				seen[a] = true
			}
		}
	}
}

// TC-987-25: the realm rules: each lifetime equals its constant, the
// credential actions' max_auth_age the 5-minute one, and the brute-force,
// password, remember-me, offline, WebAuthn and browser-flow fields.
// TC-1145-08: the password policy names the deny list, exactly, and the
// golden file differs from #987's in that one field only.
func TestRealmRules(t *testing.T) {
	in := Inputs{InstallName: "Home"}
	r := RealmRules(in)
	golden(t, "realm-rules", r)
	for k, want := range map[string]any{
		"ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 36000, "offlineSessionIdleTimeout": 2592000,
		"accessCodeLifespanLogin": 1800, "accessCodeLifespanUserAction": 1800, "accessCodeLifespan": 60, "accessTokenLifespan": 300,
		"rememberMe": false, "offlineSessionMaxLifespanEnabled": false,
		"bruteForceProtected": true, "failureFactor": 100, "maxDeltaTimeSeconds": 43200, "quickLoginCheckMilliSeconds": 0,
		"permanentLockout": false, "passwordPolicy": "length(15) and maxLength(128) and notUsername(undefined) and notEmail(undefined) and passwordBlacklist(rasputin-common-passwords.txt)",
		"webAuthnPolicyUserVerificationRequirement": "required", "webAuthnPolicyPasswordlessUserVerificationRequirement": "required",
		"webAuthnPolicyPasswordlessResidentKey": "required", "webAuthnPolicyPasswordlessPasskeysEnabled": true,
		"webAuthnPolicyExtraOrigins": []string{}, "webAuthnPolicyPasswordlessExtraOrigins": []string{},
		"browserFlow": "rasputin-signin-app-clients", "otpPolicyPeriod": 30,
	} {
		if !SameJSON(r[k], want) {
			t.Errorf("%s = %v, want %v", k, r[k], want)
		}
	}
	if _, ok := r["webAuthnPolicyRpId"]; ok {
		t.Error("the RP ID is rendered here; converge owns it")
	}
	for _, a := range RequiredActions(in, nil) {
		reentry := slices.Contains([]string{ActionUpdatePassword, ActionSecurityKey, ActionPasskeyRegister, ActionRecoveryCodes}, a.Alias)
		if got := a.Config[maxAuthAge]; reentry != (got == strconv.Itoa(int(CredentialReentryLifetime.Seconds()))) || CredentialReentryLifetime.Seconds() != 300 {
			t.Errorf("%s max_auth_age = %q, want 300 only on the credential actions", a.Alias, got)
		}
	}
}

// TC-987-26: the four actions enabled, CONFIGURE_TOTP with the clock-sync
// fact, every other listed action (delete_credential included) disabled,
// and defaultAction false, the recovery codes' too once first run is over
// (TC-990-23 below covers first run).
func TestRequiredActions(t *testing.T) {
	listed := []string{"TERMS_AND_CONDITIONS", "UPDATE_PROFILE", "VERIFY_EMAIL", "delete_credential", "CONFIGURE_TOTP", "UPDATE_PASSWORD"}
	for _, synced := range []bool{false, true} {
		got := RequiredActions(Inputs{ClockSynced: synced}, listed)
		golden(t, "required-actions-synced-"+strconv.FormatBool(synced), got)
		for _, a := range got {
			wantOn := slices.Contains([]string{ActionUpdatePassword, ActionPasskeyRegister, ActionSecurityKey, ActionRecoveryCodes}, a.Alias) ||
				(a.Alias == ActionConfigureTOTP && synced)
			if a.Enabled != wantOn {
				t.Errorf("synced %v: %s enabled %v, want %v", synced, a.Alias, a.Enabled, wantOn)
			}
			if a.DefaultAction == nil || *a.DefaultAction {
				t.Errorf("%s defaultAction is not false", a.Alias)
			}
		}
		if !slices.ContainsFunc(got, func(a RequiredAction) bool { return a.Alias == ActionDeleteCredential && !a.Enabled }) {
			t.Error("delete_credential is not disabled")
		}
	}
}

// TC-987-28: the owned parts of the profile, applied over the server's.
func TestApplyProfile(t *testing.T) {
	server := `{"unmanagedAttributePolicy":"ENABLED","attributes":[
	 {"name":"username","validations":{"length":{"min":3,"max":255},"username-prohibited-characters":{},"up-username-not-idn-homograph":{}}},
	 {"name":"email","displayName":"${email}"},
	 {"name":"firstName","displayName":"${firstName}"},
	 {"name":"lastName","displayName":"${lastName}"},
	 {"name":"pet","displayName":"Pet","permissions":{"view":["user"],"edit":["user"]}},
	 {"name":"claim_x","permissions":{"view":["admin","user"],"edit":["admin","user"]}}
	],"groups":[{"name":"g"}]}`
	p, diffs, err := ApplyProfile([]byte(server))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "profile-applied", p)
	if _, ok := p["unmanagedAttributePolicy"]; ok {
		t.Error("unmanagedAttributePolicy kept")
	}
	byName := map[string]map[string]any{}
	for _, a := range p["attributes"].([]any) {
		m := a.(map[string]any)
		byName[m["name"].(string)] = m
	}
	if _, ok := byName["lastName"]; ok {
		t.Error("lastName kept")
	}
	if byName["firstName"]["displayName"] != "Name" {
		t.Errorf("firstName shows %v", byName["firstName"]["displayName"])
	}
	v := byName["username"]["validations"].(map[string]any)
	if !SameJSON(v["length"], map[string]any{"min": 2, "max": 32}) || v["pattern"].(map[string]any)["pattern"] != UsernamePattern ||
		v["username-prohibited-characters"] == nil || v["up-username-not-idn-homograph"] == nil {
		t.Errorf("username validations %v", v)
	}
	for name := range AdminOnlyAttributes {
		if !SameJSON(byName[name]["permissions"], adminOnly()) {
			t.Errorf("%s permissions %v", name, byName[name]["permissions"])
		}
	}
	if byName["pet"] == nil || p["groups"] == nil {
		t.Error("an attribute or the groups the rules do not own was dropped")
	}
	if !SameJSON(byName["claim_x"]["permissions"], adminOnly()) {
		t.Error("claim_x was not made admin-only")
	}
	var integrity []string
	for _, d := range diffs {
		if d.Integrity {
			integrity = append(integrity, d.Field)
		}
	}
	if !slices.Contains(integrity, "profile.claim.claim_x") || !slices.Contains(integrity, "profile.attribute.rasputin_app_role") {
		t.Errorf("integrity differences %v lack claim_x or the app role", integrity)
	}
	// claim_* is checked, never created.
	p2, _, _ := ApplyProfile([]byte(`{"attributes":[]}`))
	for _, a := range p2["attributes"].([]any) {
		if strings.HasPrefix(a.(map[string]any)["name"].(string), "claim_") {
			t.Error("a claim_ attribute was created")
		}
	}
	// Applied twice, nothing differs.
	b, _ := json.Marshal(p)
	if _, again, _ := ApplyProfile(b); len(again) != 0 {
		t.Errorf("a profile already applied still differs: %v", again)
	}
	if _, _, err := ApplyProfile([]byte("null")); err == nil {
		t.Error("an empty profile was accepted")
	}
}

// TC-987-29: which drifted field is an integrity difference.
func TestIsIntegrity(t *testing.T) {
	for f, want := range map[string]bool{
		"flow.rasputin-signin-app-clients":            true,
		"flow.rasputin-signin-home-mesh.missing":      true,
		"realm.browserFlow":                           true,
		"client.rasputin-console.binding":             true,
		"action.CONFIGURE_TOTP.enabled":               true,
		"action.UPDATE_PASSWORD.config":               true,
		"role.rasputin-console.admin":                 true,
		"defaultRoles.offline_access":                 true,
		"client.rasputin-account.scope.default.email": true,
		"client.rasputin-mesh.enabled":                true,
		"client.admin-cli.directAccessGrantsEnabled":  true,
		"profile.attribute.rasputin_second_step_app":  true,
		"profile.claim.claim_x":                       true,
		"realm.ssoSessionIdleTimeout":                 false,
		"realm.accessCodeLifespanUserAction":          false,
		"realm.passwordPolicy":                        false,
		"realm.failureFactor":                         false,
		"realm.webAuthnPolicyRpEntityName":            false,
		"realm.displayName":                           false,
		"client.rasputin-console.redirectUris":        false,
		"client.rasputin-console.missing":             false,
		"profile.lastName":                            false,
		"profile.username.validations":                false,
		"keys.fallback-RS256":                         false,
	} {
		if got := IsIntegrity(f); got != want {
			t.Errorf("IsIntegrity(%q) = %v, want %v", f, got, want)
		}
	}
}

// TC-987-41: the passkey relying-party name is exactly Rasputin for every
// input.
func TestRPName(t *testing.T) {
	for _, in := range []Inputs{{}, {InstallName: "Home"}, {InstallName: "Other", ClockSynced: true}} {
		if got := RPName(in); got != "Rasputin" {
			t.Errorf("RPName(%+v) = %q, want Rasputin", in, got)
		}
	}
	r := RealmRules(Inputs{InstallName: "Home"})
	if r["webAuthnPolicyRpEntityName"] != "Rasputin" || r["webAuthnPolicyPasswordlessRpEntityName"] != "Rasputin" {
		t.Error("the policies do not carry RPName")
	}
}

func TestVariant(t *testing.T) {
	for _, v := range Variants {
		if got, ok := VariantByAlias(v.Alias()); !ok || got != v {
			t.Errorf("VariantByAlias(%s) = %v", v.Alias(), got)
		}
		if v.Stricter() != (v == Administering || v == AdminsFirst || v == NetworkDevices) {
			t.Errorf("%s Stricter %v", v.Alias(), v.Stricter())
		}
	}
	if _, ok := VariantByAlias("nope"); ok || Variant(99).Alias() != "" {
		t.Error("an unknown variant resolved")
	}
	if b := Bindings(map[string]Variant{"x": AdminsFirst}); b["x"] != AdminsFirst || b["rasputin-console"] != HomeConsole {
		t.Errorf("Bindings = %v", b)
	}
	if len(Render(Inputs{}).Flows) != 8 {
		t.Error("Render does not render the seven sign-in flows and the reset flow")
	}
}

func TestSameSteps(t *testing.T) {
	a := Flatten("x", Flow(AppClients))
	b := Flatten("x", Flow(AppClients))
	if !SameSteps(a, b) {
		t.Fatal("equal steps differ")
	}
	b[3].Requirement = Disabled
	if SameSteps(a, b) || SameSteps(a, b[1:]) {
		t.Error("different steps compare equal")
	}
	c := Flatten("x", Flow(AppClients))
	for i := range c {
		if c[i].Config != nil {
			c[i].Config = map[string]string{"other": "1"}
			break
		}
	}
	if SameSteps(a, c) {
		t.Error("a changed config compares equal")
	}
}

// TC-990-23: registration is allowed, and the recovery-codes action is a
// default action exactly while first run holds; every other stays false.
// FirstRun is in the rendered rules, so a claim changes the desired hash.
func TestRequiredActions_TC990_23_DefaultDuringFirstRunOnly(t *testing.T) {
	if RealmRules(Inputs{})["registrationAllowed"] != true {
		t.Error("registrationAllowed is not true")
	}
	listed := []string{"UPDATE_PROFILE", "VERIFY_EMAIL"}
	for _, first := range []bool{true, false} {
		for _, a := range RequiredActions(Inputs{FirstRun: first}, listed) {
			want := first && a.Alias == ActionRecoveryCodes
			if a.DefaultAction == nil || *a.DefaultAction != want {
				t.Errorf("first run %v: %s defaultAction %v, want %v", first, a.Alias, a.DefaultAction, want)
			}
		}
		want := []string{}
		if first {
			want = []string{ActionRecoveryCodes}
		}
		if got := Render(Inputs{FirstRun: first}).DefaultActions; !slices.Equal(got, want) {
			t.Errorf("first run %v: Render's DefaultActions %v, want %v", first, got, want)
		}
	}
}
