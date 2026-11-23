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
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

const appClientsDeny = "rasputin-signin-app-clients-privileged-admin"

// disableDeny disables the app-clients variant's privileged Deny, as an
// Admin API edit would.
func (r *rig) disableDeny() {
	r.kc.mu.Lock()
	defer r.kc.mu.Unlock()
	f := r.kc.rulesState.flows[appClientsDeny]
	f.execs[len(f.execs)-1].requirement = "DISABLED"
}

func (r *rig) rulesAlert() *proto.Alert {
	for _, a := range r.c.Alerts(context.Background(), testNow) {
		if a.ID == SignInRulesAlertID {
			return &a
		}
	}
	return nil
}

// TC-987-30: with the stored hash equal to the desired one, a Recheck that
// sees a difference sets drifted, raises the alert with its exact title,
// logs ERROR identity.integrity.differs once per episode and locks control;
// a run that restores the rules sets intact, clears the alert and logs
// restored; a failed rebuild or write leaves it failed; a Recheck read
// failure leaves the state as it was, with one WARN per outage.
func TestIntegrity_DriftTransitions(t *testing.T) {
	r := newRig(t)
	r.storeHash()
	r.c.Recheck(t.Context())
	if s := r.c.State(); s != Intact {
		t.Fatalf("a converged realm reads %s, want intact", s)
	}
	r.disableDeny()
	r.c.Recheck(t.Context())
	r.c.Recheck(t.Context())
	if s := r.c.State(); s != Drifted {
		t.Fatalf("state %s, want drifted", s)
	}
	a := r.rulesAlert()
	if a == nil || a.Title != "Sign-in rules differ from Rasputin's settings. Administrator tools are locked until they are restored." ||
		a.Severity != proto.AlertCrit {
		t.Fatalf("alert = %+v", a)
	}
	if n := len(r.rec.Matching(slog.LevelError, "")); n != 1 || !strings.Contains(r.rec.Text(), "identity.integrity.differs") {
		t.Errorf("%d ERROR records for one episode, want 1:\n%s", n, r.rec.Text())
	}
	if !errors.Is(r.c.ControlGate(t.Context()), ErrSignInRulesDiffer) {
		t.Error("control is not locked while drifted")
	}
	if _, err := r.c.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r.c.State() != Intact || r.rulesAlert() != nil || r.c.ControlGate(t.Context()) != nil {
		t.Errorf("after the repair: state %s, alert %v", r.c.State(), r.rulesAlert())
	}
	if !strings.Contains(r.rec.Text(), "identity.integrity.restored") {
		t.Error("no restored record")
	}

	// A failed rebuild leaves the state failed with errFlowRebuild.
	r.disableDeny()
	r.kc.failOn = func(method, path string, _ int) error {
		if method == http.MethodPost && strings.Contains(path, "/config") {
			return &idclient.Error{Op: "admin", Path: path, Status: 500, Kind: idclient.ErrProtocol}
		}
		return nil
	}
	if _, err := r.c.Run(t.Context()); !errors.Is(err, errFlowRebuild) {
		t.Fatalf("Run = %v, want errFlowRebuild", err)
	}
	if r.c.State() != Failed || r.rulesAlert() == nil {
		t.Errorf("after a failed rebuild: state %s, alert %v", r.c.State(), r.rulesAlert())
	}
	if !errors.Is(r.c.ControlGate(t.Context()), ErrSignInRulesDiffer) {
		t.Error("control is not locked as differing while failed")
	}
	// A failed write (not a rebuild) is errWrite and failed too.
	r = newRig(t)
	r.storeHash()
	r.kc.realm["browserFlow"] = "browser"
	r.kc.fail["PUT "+realmPath] = &idclient.Error{Op: "admin", Path: realmPath, Status: 400, Kind: idclient.ErrProtocol}
	if _, err := r.c.Run(t.Context()); !errors.Is(err, errWrite) || r.c.State() != Failed {
		t.Fatalf("Run = %v, state %s; want errWrite, failed", err, r.c.State())
	}

	// A Recheck that cannot read leaves the state, with one WARN per outage.
	before := r.c.State()
	r.kc.fail["GET "+realmPath] = &idclient.Error{Op: "admin", Path: realmPath, Status: 503, Kind: idclient.ErrUnreachable}
	r.c.Recheck(t.Context())
	r.c.Recheck(t.Context())
	if r.c.State() != before {
		t.Errorf("a failed Recheck moved the state to %s", r.c.State())
	}
	if n := len(r.rec.Matching(slog.LevelWarn, "The sign-in rules could not be read to check them; their state is unchanged.")); n != 1 {
		t.Errorf("%d recheck WARNs, want 1", n)
	}
}

// TC-987-31: an input change (a first install, the clock syncing, an app's
// binding) is applied without the alert or an ERROR, with INFO, ending
// intact; a failed apply does raise the alert.
func TestIntegrity_ApplyingIsNotDrift(t *testing.T) {
	for name, change := range map[string]func(r *rig){
		"first install": func(*rig) {},
		"clock synced":  func(r *rig) { r.storeHash(); r.inputs.ClockSynced = true },
		"an app's binding": func(r *rig) {
			r.storeHash()
			r.inputs.AppBindings = map[string]flows.Variant{"rasputin-console": flows.Administering}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			if name == "first install" {
				r.disableDeny() // something to apply with no stored hash
			}
			change(r)
			if _, err := r.c.Run(t.Context()); err != nil {
				t.Fatal(err)
			}
			if r.rulesAlert() != nil || len(r.rec.Matching(slog.LevelError, "")) != 0 {
				t.Errorf("alert %v, ERRORs:\n%s", r.rulesAlert(), r.rec.Text())
			}
			if !strings.Contains(r.rec.Text(), "identity.integrity.applying") || r.c.State() != Intact {
				t.Errorf("state %s; log:\n%s", r.c.State(), r.rec.Text())
			}
		})
	}
	r := newRig(t)
	r.inputs.ClockSynced = true
	r.kc.fail["PUT "+realmPath+"/authentication/required-actions/CONFIGURE_TOTP"] = &idclient.Error{Op: "admin", Status: 500, Kind: idclient.ErrProtocol}
	if _, err := r.c.Run(t.Context()); err == nil {
		t.Fatal("the failed apply succeeded")
	}
	if r.rulesAlert() == nil || r.c.State() != Failed {
		t.Errorf("a failed apply: state %s, alert %v", r.c.State(), r.rulesAlert())
	}
}

// TC-987-32: a drifted flow is rebuilt with every execution added DISABLED,
// the gate enabled before authenticate, and a failure part-way leaves
// authenticate disabled.
func TestRebuild_Order(t *testing.T) {
	r := newRig(t)
	r.disableDeny()
	if _, err := r.c.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	top := realmPath + "/authentication/flows/rasputin-signin-app-clients/executions"
	var topPuts []string
	for _, c := range r.kc.writes() {
		if c.method == http.MethodPut && c.path == top {
			var b map[string]any
			_ = json.Unmarshal(c.body, &b)
			topPuts = append(topPuts, b["id"].(string))
		}
		if c.method == http.MethodPost && strings.HasSuffix(c.path, "/execution") && strings.Contains(string(c.body), "requirement") {
			t.Errorf("an execution was added with a requirement: %s", c.body)
		}
	}
	execs := r.kc.rulesState.flows["rasputin-signin-app-clients"].execs
	if len(topPuts) != 2 || topPuts[0] != execs[1].id || topPuts[1] != execs[0].id {
		t.Errorf("top-level enables %v, want the gate %s then authenticate %s", topPuts, execs[1].id, execs[0].id)
	}

	r = newRig(t)
	r.disableDeny()
	n := 0
	r.kc.failOn = func(method, path string, _ int) error {
		if method == http.MethodPost && strings.Contains(path, "/config") {
			if n++; n == 5 {
				return &idclient.Error{Op: "admin", Status: 500, Kind: idclient.ErrProtocol}
			}
		}
		return nil
	}
	if _, err := r.c.Run(t.Context()); !errors.Is(err, errFlowRebuild) {
		t.Fatalf("Run = %v", err)
	}
	for _, e := range r.kc.rulesState.flows["rasputin-signin-app-clients"].execs {
		if e.requirement != "DISABLED" {
			t.Errorf("after a failure part-way, %s is %s", e.sub, e.requirement)
		}
	}
}

// TC-987-33: stricter clients are paused while the state is unknown or
// differs, and none once intact; other clients never.
func TestClientPaused(t *testing.T) {
	r := newRig(t)
	r.kc.clients = append(r.kc.clients, map[string]any{"id": "c-strict", "clientId": "strict"}, map[string]any{"id": "c-plain", "clientId": "plain"})
	r.inputs.AppBindings = map[string]flows.Variant{"strict": flows.AdminsFirst, "plain": flows.AppClients}
	r.c.setBindings(r.inputs.AppBindings)
	if !r.c.ClientPaused("strict") || r.c.ClientPaused("plain") || r.c.ClientPaused("rasputin-console") {
		t.Error("unknown: want only the stricter client paused")
	}
	r.storeHash()
	r.c.Recheck(t.Context()) // the bindings are applied: not intact
	if !r.c.ClientPaused("strict") {
		t.Error("a client whose binding differs is not paused")
	}
	if _, err := r.c.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r.c.ClientPaused("strict") || r.c.ClientPaused("plain") {
		t.Error("intact: a client is paused")
	}
}

// F-987-09: an unknown state locks control once the service is ready, and
// not before. F-987-19: unknown and applying lock as Rasputin applying its
// rules, never as the rules differing.
func TestControlGate_UnknownAndApplying(t *testing.T) {
	r := newRig(t)
	if err := r.c.ControlGate(t.Context()); !errors.Is(err, ErrSignInRulesApplying) || errors.Is(err, ErrSignInRulesDiffer) {
		t.Errorf("unknown with the service ready: gate = %v, want ErrSignInRulesApplying", err)
	}
	r.readyErr = errors.New("not ready")
	if r.c.ControlGate(t.Context()) != nil {
		t.Error("unknown with the service not ready: control locked")
	}
	r = newRig(t)
	r.disableDeny() // a difference with no stored hash: Rasputin's own install
	r.c.Recheck(t.Context())
	if s := r.c.State(); s != Applying {
		t.Fatalf("state %s, want applying", s)
	}
	if err := r.c.ControlGate(t.Context()); !errors.Is(err, ErrSignInRulesApplying) || errors.Is(err, ErrSignInRulesDiffer) {
		t.Errorf("applying: gate = %v, want ErrSignInRulesApplying", err)
	}
}

// TC-987-39: only the listed admin event types mark the pass; PassEnded runs
// one Recheck; a difference changes ConvergeCond's rearm key; none leaves
// it.
func TestRecheck_FromAdminEvents(t *testing.T) {
	r := newRig(t)
	r.storeHash()
	gets := func() int {
		r.kc.mu.Lock()
		defer r.kc.mu.Unlock()
		return r.kc.seen["GET "+realmPath]
	}
	r.c.AdminEvent(t.Context(), events.AdminEvent{ResourceType: "USER"})
	r.c.PassStarted(t.Context(), 1)
	r.c.PassEnded(t.Context(), 1)
	if gets() != 0 {
		t.Fatal("a USER event ran a Recheck")
	}
	cond := ConvergeCond(r.c, laggingNone{})
	_, _, key0, _ := cond(t.Context())
	for _, typ := range recheckTypes {
		r.c.AdminEvent(t.Context(), events.AdminEvent{ResourceType: typ})
	}
	r.c.PassEnded(t.Context(), 2)
	if gets() != 1 {
		t.Fatalf("%d realm reads, want one Recheck", gets())
	}
	if _, _, key, _ := cond(t.Context()); key != key0 {
		t.Errorf("a clean Recheck changed the rearm key to %q", key)
	}
	r.disableDeny()
	r.c.AdminEvent(t.Context(), events.AdminEvent{ResourceType: "AUTH_EXECUTION"})
	r.c.PassEnded(t.Context(), 3)
	due, _, key, _ := cond(t.Context())
	if !due || key == key0 || key == "" {
		t.Errorf("after a difference: due %v, key %q (was %q)", due, key, key0)
	}
}

type laggingNone struct{}

func (laggingNone) Lagging(context.Context) (int, int, error) { return 1, 1, nil }

// TC-987-40: both entity names are rendered RPName, never empty or
// keycloak; each policy is sent whole with only the owned fields changed;
// a blank name as read is repaired, not refused.
func TestWebAuthn_RPName(t *testing.T) {
	for _, c := range []struct {
		install, observed string
	}{{"", "keycloak"}, {"Home", "keycloak"}, {"Home", ""}, {"", ""}} {
		r := newRig(t)
		r.inputs.InstallName = c.install
		r.kc.realm["displayName"] = c.install
		r.kc.realm["webAuthnPolicyRpEntityName"] = c.observed
		r.kc.realm["webAuthnPolicyPasswordlessRpEntityName"] = c.observed
		r.kc.realm["webAuthnPolicyCreateTimeout"] = 7 // a field the rules do not own
		if _, err := r.c.Run(t.Context()); err != nil {
			t.Fatalf("%+v: Run = %v", c, err)
		}
		put := realmPUT(t, r.kc)
		want := `"` + flows.RPName(flows.Inputs{InstallName: c.install}) + `"`
		for _, k := range []string{"webAuthnPolicyRpEntityName", "webAuthnPolicyPasswordlessRpEntityName"} {
			if string(put[k]) != want || want == `""` || want == `"keycloak"` {
				t.Errorf("%+v: %s = %s, want %s", c, k, put[k], want)
			}
		}
		if string(put["webAuthnPolicyCreateTimeout"]) != "7" || string(put["webAuthnPolicyRpId"]) != `""` {
			t.Errorf("%+v: the policy was not sent whole as read: %s", c, mapKeys(put))
		}
		if r.kc.realm["webAuthnPolicyRpEntityName"] != "Rasputin" {
			t.Error("the name was not repaired")
		}
	}
}

// The other rules: a missing owned action is registered, an action and its
// config are put back, the profile, a console role, the default roles, a
// scope and a binding are repaired.
func TestRules_OtherParts(t *testing.T) {
	r := newRig(t)
	st := r.kc.rulesState
	st.actions = slices.DeleteFunc(st.actions, func(a requiredAction) bool { return a.Alias == flows.ActionPasskeyRegister })
	st.unregistered = []map[string]any{{"providerId": flows.ActionPasskeyRegister, "name": "Passkey"}}
	for i := range st.actions {
		switch st.actions[i].Alias {
		case "delete_credential":
			st.actions[i].Enabled = true
		case flows.ActionUpdatePassword:
			st.actions[i].Config = map[string]string{}
			st.actions[i].DefaultAction = true
		}
	}
	st.profile = map[string]any{"attributes": []any{map[string]any{"name": "lastName"}}}
	st.consoleRoles = []string{"admin", "viewer"}
	st.defaultRoles = []role{{ID: "x", Name: "offline_access"}}
	acct := r.kc.client("rasputin-account")
	acct["defaultClientScopes"] = []any{"basic", "profile", "email"}
	r.kc.client("rasputin-console")["authenticationFlowBindingOverrides"] = map[string]any{}
	r.kc.client("rasputin-mesh")["directAccessGrantsEnabled"] = true
	r.storeHash()
	fields, err := r.c.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		"action." + flows.ActionPasskeyRegister + ".registered", "action.delete_credential.enabled",
		"action.UPDATE_PASSWORD.config", "action.UPDATE_PASSWORD.defaultAction", "profile.lastName",
		"role.rasputin-console.operator", "defaultRoles.offline_access", "client.rasputin-account.scope.default.email",
		"client.rasputin-console.binding", "client.rasputin-mesh.directAccessGrantsEnabled",
	} {
		if !slices.Contains(fields, f) {
			t.Errorf("fields %v lack %s", fields, f)
		}
	}
	if _, err := r.c.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r.c.State() != Intact {
		t.Errorf("state %s", r.c.State())
	}
	// An owned action the server neither lists nor offers is reported and
	// fails the run's read-back.
	r = newRig(t)
	r.kc.rulesState.actions = slices.DeleteFunc(r.kc.rulesState.actions, func(a requiredAction) bool { return a.Alias == flows.ActionConfigureTOTP })
	if _, err := r.c.Run(t.Context()); !errors.Is(err, errStillDiffers) {
		t.Errorf("Run = %v, want errStillDiffers", err)
	}
	// An unreadable profile is a difference.
	r = newRig(t)
	r.kc.rulesState.profile = nil
	w := diff(NewDesired(r.inputs), mustObserve(t, r))
	if !slices.Contains(w.fields, "profile.unreadable") {
		t.Errorf("fields %v lack profile.unreadable", w.fields)
	}
}

func mustObserve(t *testing.T, r *rig) observed {
	t.Helper()
	o, err := r.c.observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// Each rules read that fails fails the run as unreadable.
func TestRules_ReadFailures(t *testing.T) {
	for _, p := range []string{
		"/authentication/flows", "/authentication/flows/rasputin-signin-home-console/executions",
		"/authentication/required-actions", "/authentication/unregistered-required-actions", "/users/profile",
		"/client-scopes", "/roles/default-roles-rasputin/composites",
	} {
		r := newRig(t)
		r.kc.fail["GET "+realmPath+p] = &idclient.Error{Op: "admin", Status: 503, Kind: idclient.ErrUnreachable}
		if _, err := r.c.Run(t.Context()); !errors.Is(err, errRead) {
			t.Errorf("%s unreadable: Run = %v", p, err)
		}
	}
	r := newRig(t)
	r.kc.failOn = func(method, path string, _ int) error {
		if method == http.MethodGet && (strings.Contains(path, "/authentication/config/") || strings.HasSuffix(path, "/roles")) {
			return &idclient.Error{Op: "admin", Status: 503, Kind: idclient.ErrUnreachable}
		}
		return nil
	}
	if _, err := r.c.Run(t.Context()); !errors.Is(err, errRead) {
		t.Errorf("a config unreadable: Run = %v", err)
	}
}
