package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// fakeApps is an AppReader over a fixed map, which records each read.
type fakeApps struct {
	facts map[string]AppFacts
	err   error
	reads []string
}

func (f *fakeApps) AppFacts(_ context.Context, kind, appID string) (AppFacts, error) {
	f.reads = append(f.reads, kind+" "+appID)
	if f.err != nil {
		return AppFacts{}, f.err
	}
	fa, ok := f.facts[appID]
	if !ok {
		return AppFacts{}, ErrNoApp
	}
	return fa, nil
}

func newPolicy(t *testing.T, apps AppReader) *KindPolicy {
	t.Helper()
	p, err := NewKindPolicy(apps)
	if err != nil {
		t.Fatalf("NewKindPolicy: %v", err)
	}
	return p
}

// The submitters the matrix is drawn over.
var (
	sysSub      = SystemSubmitter("scheduler")
	adminSub    = Person(Subject{Sub: "s-admin", Roles: []string{"admin"}})
	operatorSub = Person(Subject{Sub: "s-op", Roles: []string{"operator"}})
	viewerSub   = Person(Subject{Sub: "s-A", Roles: []string{"viewer"}})
	noRoleSub   = Person(Subject{Sub: "s-none"})
	unknownSub  = Person(Subject{Sub: "s-root", Roles: []string{"root"}})
	repairSub   = RepairSession()
	bridgeSub   = BridgeGrant("s-A")
	zeroSub     = Submitter{}
)

// code is the refusal code err carries, "" for nil, and a marker for an
// error that is not a KindRefusal.
func code(err error) string {
	if err == nil {
		return ""
	}
	var kr *KindRefusal
	if errors.As(err, &kr) {
		return kr.Code
	}
	return "error: " + err.Error()
}

func acct(id string) []byte { return []byte(`{"accountId":"` + id + `"}`) }

// TC-1001-01: a kind the table does not hold is refused unknown_kind to
// every submitter, the system included.
func TestAuthorize_TC1001_01_UnmappedKind(t *testing.T) {
	p := newPolicy(t, &fakeApps{})
	for name, by := range map[string]Submitter{
		"system": sysSub, "admin": adminSub, "repair": repairSub, "bridge": bridgeSub, "zero": zeroSub,
	} {
		if got := code(p.Authorize(t.Context(), "test.unmapped", nil, by)); got != CodeUnknownKind {
			t.Errorf("%s: %q, want unknown_kind", name, got)
		}
	}
}

// TC-1001-03: a self kind needs the target to be the submitter; a no-role
// account passes for its own account; a missing, non-string or empty target,
// or a spec that is not an object, is no_target.
func TestAuthorize_TC1001_03_SelfKinds(t *testing.T) {
	p := newPolicy(t, &fakeApps{})
	const kind = "accounts.rename_credential"
	if got := code(p.Authorize(t.Context(), kind, acct("s-B"), viewerSub)); got != CodeNotYourAccount {
		t.Errorf("viewer s-A for s-B: %q, want not_your_account", got)
	}
	if err := p.Authorize(t.Context(), kind, acct("s-A"), viewerSub); err != nil {
		t.Errorf("viewer s-A for itself: %v, want allowed", err)
	}
	if err := p.Authorize(t.Context(), kind, acct("s-none"), noRoleSub); err != nil {
		t.Errorf("no-role account for itself: %v, want allowed", err)
	}
	for _, spec := range []string{`{}`, `{"accountId":42}`, `{"accountId":""}`, `[]`, `{"accountId":null}`, ``} {
		if got := code(p.Authorize(t.Context(), kind, []byte(spec), viewerSub)); got != CodeNoTarget {
			t.Errorf("spec %s: %q, want no_target", spec, got)
		}
	}
}

// TC-1001-05: accounts.grant_designated_role passes the system only.
func TestAuthorize_TC1001_05_GrantDesignatedRole(t *testing.T) {
	p := newPolicy(t, &fakeApps{})
	const kind = "accounts.grant_designated_role"
	if err := p.Authorize(t.Context(), kind, acct("s-x"), sysSub); err != nil {
		t.Errorf("system: %v, want allowed", err)
	}
	for name, by := range map[string]Submitter{"admin": adminSub, "operator": operatorSub, "repair": repairSub, "bridge": bridgeSub} {
		if got := code(p.Authorize(t.Context(), kind, acct("s-x"), by)); got != CodeSystemOnly {
			t.Errorf("%s: %q, want system_only", name, got)
		}
	}
}

// TC-1001-06: the OS outcome kinds are refused not_submittable to every
// submitter, the system and an administrator included.
func TestAuthorize_TC1001_06_OSOutcomeKinds(t *testing.T) {
	p := newPolicy(t, &fakeApps{})
	for _, kind := range []string{
		"os.identity_db_init", "os.identity_rollback", "identity.service_exit",
		"os.seal_key", "os.store_init", "os.store_provision", "os.store_rollback", "os.store_migrate",
	} {
		for name, by := range map[string]Submitter{"system": sysSub, "admin": adminSub, "repair": repairSub, "zero": zeroSub} {
			if got := code(p.Authorize(t.Context(), kind, []byte(`{}`), by)); got != CodeNotSubmittable {
				t.Errorf("%s by %s: %q, want not_submittable", kind, name, got)
			}
		}
	}
}

// TC-1001-08: identity.move is the system's; a person is refused
// system_only. A repair session's C9 allowance is TC-1004-17's: with no move
// state wired, its submission is a check that failed.
func TestAuthorize_TC1001_08_IdentityMove(t *testing.T) {
	p := newPolicy(t, &fakeApps{})
	if err := p.Authorize(t.Context(), "identity.move", []byte(`{}`), sysSub); err != nil {
		t.Errorf("system: %v, want allowed", err)
	}
	if got := code(p.Authorize(t.Context(), "identity.move", []byte(`{}`), adminSub)); got != CodeSystemOnly {
		t.Errorf("admin: %q, want system_only", got)
	}
	if err := p.Authorize(t.Context(), "identity.move", []byte(`{}`), repairSub); !errors.Is(err, ErrCheckFailed) {
		t.Errorf("repair with no move state: %v, want ErrCheckFailed", err)
	}
	if got := code(p.Authorize(t.Context(), "identity.move", []byte(`{}`), zeroSub)); got == "" {
		t.Error("zero submitter: allowed, want refused")
	}
}

// TC-1001-09: an unknown tier is refused unknown_tier to an administrator and
// an operator, an upgrade target's included; the empty tier (an install from
// before #522) is routine; a custom app needs apps.host whatever its tier.
func TestAuthorize_TC1001_09_Tiers(t *testing.T) {
	apps := &fakeApps{facts: map[string]AppFacts{
		"super":   {Tiers: []string{"super-trusted"}},
		"upgrade": {Tiers: []string{"routine", "super-trusted"}},
		"old":     {Tiers: []string{""}},
		"custom":  {Custom: true, Tiers: []string{""}},
	}}
	p := newPolicy(t, apps)
	spec := func(id string) []byte { return []byte(`{"appId":"` + id + `"}`) }
	for name, by := range map[string]Submitter{"admin": adminSub, "operator": operatorSub} {
		if got := code(p.Authorize(t.Context(), "app.deploy", spec("super"), by)); got != CodeUnknownTier {
			t.Errorf("%s deploy of an unknown tier: %q, want unknown_tier", name, got)
		}
		if got := code(p.Authorize(t.Context(), "app.upgrade", spec("upgrade"), by)); got != CodeUnknownTier {
			t.Errorf("%s upgrade to an unknown tier: %q, want unknown_tier", name, got)
		}
	}
	if err := p.Authorize(t.Context(), "app.deploy", spec("old"), operatorSub); err != nil {
		t.Errorf("operator deploy of a tier-less tile app: %v, want allowed (routine)", err)
	}
	if got := code(p.Authorize(t.Context(), "app.deploy", spec("custom"), operatorSub)); got != CodeNotPermitted {
		t.Errorf("operator deploy of a custom app: %q, want not_permitted (apps.host)", got)
	}
	if err := p.Authorize(t.Context(), "app.deploy", spec("custom"), adminSub); err != nil {
		t.Errorf("admin deploy of a custom app: %v, want allowed", err)
	}
	if got, refusal := appNeed(AppFacts{Tiers: []string{""}}); got != Apps || refusal != nil {
		t.Errorf("appNeed(tier '') = %v, %v; want apps", got, refusal)
	}
	if got, refusal := appNeed(AppFacts{Custom: true, Tiers: []string{""}}); got != AppsHost || refusal != nil {
		t.Errorf("appNeed(custom, '') = %v, %v; want apps.host", got, refusal)
	}
	// The host-trusting boundary itself (F-1001-19): a host-trusting tile
	// needs apps.host, the tier below it does not.
	if got, refusal := appNeed(AppFacts{Tiers: []string{tileschema.TierHostTrusting}}); got != AppsHost || refusal != nil {
		t.Errorf("appNeed(host-trusting) = %v, %v; want apps.host", got, refusal)
	}
	if got, refusal := appNeed(AppFacts{Tiers: []string{tileschema.TierRoutine, tileschema.TierElevated}}); got != Apps || refusal != nil {
		t.Errorf("appNeed(routine, elevated) = %v, %v; want apps", got, refusal)
	}
}

// TC-1001-10: an unknown role or no role holds no control capability, but a
// self kind on its own account passes; the zero Submitter is refused by every
// shape.
func TestAuthorize_TC1001_10_UnknownRolesAndZero(t *testing.T) {
	apps := &fakeApps{facts: map[string]AppFacts{"a1": {Tiers: []string{"routine"}}}}
	p := newPolicy(t, apps)
	for _, roles := range [][]string{{"Admin"}, {"root"}, {}} {
		by := Person(Subject{Sub: "s-x", Roles: roles})
		for kind, r := range kindTable {
			if r.shape != control {
				continue
			}
			if got := code(p.Authorize(t.Context(), kind, []byte(`{}`), by)); got != CodeNotPermitted {
				t.Errorf("roles %v, %s: %q, want not_permitted", roles, kind, got)
			}
		}
		if got := code(p.Authorize(t.Context(), "app.deploy", []byte(`{"appId":"a1"}`), by)); got != CodeNotPermitted {
			t.Errorf("roles %v, app.deploy: %q, want not_permitted", roles, got)
		}
		if err := p.Authorize(t.Context(), "accounts.rename_credential", acct("s-x"), by); err != nil {
			t.Errorf("roles %v, self on its own account: %v, want allowed", roles, err)
		}
	}
	for _, kind := range shapeKinds() {
		if code(p.Authorize(t.Context(), kind, acct("s-x"), zeroSub)) == "" {
			t.Errorf("zero submitter passed %s", kind)
		}
	}
	if Person(Subject{Roles: []string{"admin"}}) != zeroSub {
		t.Error("Person with an empty Sub is not the zero Submitter")
	}
	if BridgeGrant("") != zeroSub {
		t.Error("BridgeGrant with an empty account is not the zero Submitter")
	}
}

// shapeKinds is one kind of each shape.
func shapeKinds() []string {
	seen := map[shape]bool{}
	var out []string
	for kind, r := range kindTable {
		if !seen[r.shape] {
			seen[r.shape] = true
			out = append(out, kind)
		}
	}
	return out
}

// TC-1001-11 (authz part): a reader that fails is ErrCheckFailed, a missing
// app no_app, a spec without appId no_target.
func TestAuthorize_TC1001_11_AppReads(t *testing.T) {
	down := errors.New("database is locked")
	p := newPolicy(t, &fakeApps{err: down})
	err := p.Authorize(t.Context(), "app.deploy", []byte(`{"appId":"a1"}`), adminSub)
	if !errors.Is(err, ErrCheckFailed) || !errors.Is(err, down) {
		t.Errorf("reader down: %v, want ErrCheckFailed wrapping the cause", err)
	}
	var kr *KindRefusal
	if errors.As(err, &kr) {
		t.Errorf("reader down answered a refusal %v, want a check failure", kr)
	}
	p = newPolicy(t, &fakeApps{})
	if got := code(p.Authorize(t.Context(), "app.deploy", []byte(`{"appId":"gone"}`), adminSub)); got != CodeNoApp {
		t.Errorf("missing app: %q, want no_app", got)
	}
	if got := code(p.Authorize(t.Context(), "app.deploy", []byte(`{}`), adminSub)); got != CodeNoTarget {
		t.Errorf("no appId: %q, want no_target", got)
	}
}

// TC-1001-13 (authz part): NewKindPolicy refuses nil.
func TestNewKindPolicy_TC1001_13_RefusesNil(t *testing.T) {
	if p, err := NewKindPolicy(nil); err == nil || p != nil {
		t.Errorf("NewKindPolicy(nil) = %v, %v; want an error", p, err)
	}
}

// TC-1001-14 (authz part): each constructor's CreatedBy.
func TestSubmitter_TC1001_14_CreatedBy(t *testing.T) {
	for _, tc := range []struct {
		by   Submitter
		want string
		sys  bool
	}{
		{SystemSubmitter("scheduler"), "scheduler", true},
		{Person(Subject{Sub: "s-1", Roles: []string{"admin"}}), "s-1", false},
		{RepairSession(), "break-glass", false},
		{BridgeGrant("s-2"), "s-2", false},
		{Submitter{}, "", false},
	} {
		if got := tc.by.CreatedBy(); got != tc.want {
			t.Errorf("CreatedBy = %q, want %q", got, tc.want)
		}
		if got := tc.by.IsSystem(); got != tc.sys {
			t.Errorf("%q IsSystem = %v, want %v", tc.want, got, tc.sys)
		}
	}
}

// TC-1001-15 (authz part): the decision is on the target the workflow's
// decode reads. A case-folded duplicate or an exact duplicate is no_target,
// never a decision on either value.
func TestSpecTarget_TC1001_15_Duplicates(t *testing.T) {
	p := newPolicy(t, &fakeApps{})
	if got := code(p.Authorize(t.Context(), "accounts.rename_credential", []byte(`{"accountId":"s-A","AccountID":"s-B"}`), viewerSub)); got != CodeNoTarget {
		t.Errorf("case-folded duplicate: %q, want no_target", got)
	}
	for _, spec := range []string{
		`{"accountId":"s-A","AccountID":"s-B"}`,
		`{"accountId":"s-A","accountId":"s-B"}`,
		`{"ACCOUNTID":"s-A","accountid":"s-A"}`,
	} {
		if v, ok := SpecTarget([]byte(spec), "accountId"); ok {
			t.Errorf("SpecTarget(%s) = %q, want no target", spec, v)
		}
	}
	for spec, want := range map[string]string{
		`{"accountId":"s-A"}`:                              "s-A",
		`{"ACCOUNTID":"s-A","other":{"x":[1,2]}}`:          "s-A",
		`{"nested":{"accountId":"s-B"},"accountId":"s-A"}`: "s-A",
	} {
		if v, ok := SpecTarget([]byte(spec), "accountId"); !ok || v != want {
			t.Errorf("SpecTarget(%s) = %q, %v; want %q", spec, v, ok, want)
		}
	}
	for _, spec := range []string{`{"accountId":"s-A"`, `{"accountId":"s-A",}`, `"s-A"`} {
		if v, ok := SpecTarget([]byte(spec), "accountId"); ok {
			t.Errorf("SpecTarget(malformed %s) = %q, want no target", spec, v)
		}
	}
}

// TC-1001-16 (the Appendix E part): every Appendix E kind is in the table
// with the shape its row names; the system passes appTier, so the app
// sign-in relay (app.backchannel_logout) runs.
func TestKindTable_TC1001_16_AppendixE(t *testing.T) {
	want := map[shape][]string{
		others: {"accounts.grant_access", "accounts.revoke_access", "accounts.set_roles", "accounts.set_network",
			"accounts.set_claims", "accounts.set_groups", "accounts.set_email", "accounts.confirm_email",
			"accounts.disable", "accounts.enable", "accounts.delete", "accounts.decline", "accounts.unlock",
			"accounts.reset_password", "accounts.remove_second_steps", "accounts.clear_network_password",
			"accounts.grant_waiting"},
		selfOrOthers: {"accounts.sign_out", "accounts.set_display_name", "accounts.revoke_device_certificate", "accounts.remove_mesh_device"},
		self: {"accounts.remove_credential", "accounts.rename_credential", "accounts.set_network_password",
			"accounts.enrol_gear_code", "accounts.issue_device_certificate"},
		control: {"accounts.define_group", "accounts.delete_group", "accounts.define_claim", "accounts.delete_claim",
			"identity.converge", "identity.clients.add", "identity.clients.edit", "identity.clients.remove",
			"identity.rotate_signing_key", "radius.enable", "radius.disable", "radius.device_add", "radius.device_edit",
			"radius.device_remove", "radius.set_password_wifi", "radius.set_wifi_names"},
		sysOnly: {"accounts.grant_designated_role", "identity.revoke", "identity.arm", "identity.migrate",
			"identity.reference_check", "identity.recover", "identity.recover_admin",
			"radius.converge", "radius.disconnect", "firewall.radius_forward"},
		bridge:     {"accounts.set_first_password"},
		repairOnly: {"accounts.repair_reset", "identity.restore_data"},
		repairOr:   {"identity.restart"},
		move:       {"identity.move"},
		never:      {"os.identity_db_init", "os.identity_rollback", "identity.service_exit"},
		appTier:    {"app.sso_reopen_window", "app.backchannel_logout"},
	}
	for sh, kinds := range want {
		for _, k := range kinds {
			r, ok := kindTable[k]
			switch {
			case !ok:
				t.Errorf("%s is not in the table", k)
			case r.shape != sh:
				t.Errorf("%s has shape %d, want %d", k, r.shape, sh)
			case (sh == control || sh == others || sh == selfOrOthers || sh == repairOr) && r.cap != IAM:
				t.Errorf("%s needs %q, want iam", k, r.cap)
			}
		}
	}
	p := newPolicy(t, &fakeApps{})
	if err := p.Authorize(t.Context(), "app.backchannel_logout", []byte(`{"appId":"a1"}`), sysSub); err != nil {
		t.Errorf("the system's relay of app.backchannel_logout: %v, want allowed", err)
	}
	if !SystemOnly("identity.recover") || SystemOnly("identity.move") || SystemOnly("identity.converge") || SystemOnly("nope") {
		t.Error("SystemOnly disagrees with the table")
	}
	if !SystemOrRepair("identity.move") || SystemOrRepair("identity.recover") || SystemOrRepair("nope") {
		t.Error("SystemOrRepair disagrees with the table")
	}
	if !Known("app.deploy") || Known("nope") {
		t.Error("Known disagrees with the table")
	}
}

// TC-1001-18: the shape by submitter matrix. Each cell is the refusal code,
// "" for allowed.
func TestAuthorize_TC1001_18_Matrix(t *testing.T) {
	apps := &fakeApps{facts: map[string]AppFacts{"a1": {Tiers: []string{"routine"}}}}
	p, err := NewKindPolicy(apps, WithMoveState(&fakeMove{token: "t1", holds: true}))
	if err != nil {
		t.Fatal(err)
	}
	subs := []struct {
		name string
		by   Submitter
	}{
		{"system", sysSub}, {"admin", adminSub}, {"operator", operatorSub}, {"viewer", viewerSub},
		{"norole", noRoleSub}, {"unknownrole", unknownSub}, {"repair", repairSub}, {"bridgeA", bridgeSub}, {"zero", zeroSub},
	}
	const (
		ok  = ""
		np  = CodeNotPermitted
		so  = CodeSystemOnly
		nya = CodeNotYourAccount
		own = CodeOwnAccount
		ns  = CodeNotSubmittable
	)
	rows := []struct {
		name, kind string
		spec       []byte
		want       [9]string // system, admin, operator, viewer, norole, unknownrole, repair, bridgeA, zero
	}{
		{"sysOnly", "apps.reconcile", nil, [9]string{ok, so, so, so, so, so, so, so, np}},
		{"control(updates)", "system.update", nil, [9]string{ok, ok, ok, np, np, np, np, np, np}},
		{"control(nodes)", "node.reboot", nil, [9]string{ok, ok, np, np, np, np, np, np, np}},
		{"control(bmc)", "bmc.power", nil, [9]string{ok, ok, np, np, np, np, np, np, np}},
		{"control(firewall)", "firewall.apply", nil, [9]string{ok, ok, np, np, np, np, np, np, np}},
		{"control(mesh)", "mesh.apply", nil, [9]string{ok, ok, np, np, np, np, np, np, np}},
		{"control(system)", "backup.run", nil, [9]string{ok, ok, np, np, np, np, np, np, np}},
		{"control(iam)", "radius.enable", nil, [9]string{ok, ok, np, np, np, np, np, np, np}},
		// The target is s-A, the viewer's and bridge grant's own account.
		{"self own", "accounts.rename_credential", acct("s-A"), [9]string{np, nya, nya, ok, nya, nya, np, np, np}},
		{"selfOrOthers on s-A", "accounts.sign_out", acct("s-A"), [9]string{ok, ok, np, ok, np, np, np, np, np}},
		{"selfOrOthers on another", "accounts.sign_out", acct("s-B"), [9]string{ok, ok, np, np, np, np, np, np, np}},
		{"others on the admin", "accounts.disable", acct("s-admin"), [9]string{ok, own, np, np, np, np, np, np, np}},
		{"others on s-A", "accounts.disable", acct("s-A"), [9]string{ok, ok, np, own, np, np, np, own, np}},
		{"appTier routine", "app.deploy", []byte(`{"appId":"a1"}`), [9]string{ok, ok, ok, np, np, np, np, np, np}},
		{"repairOnly", "identity.restore_data", nil, [9]string{np, np, np, np, np, np, ok, np, np}},
		{"repairOr(iam)", "identity.restart", nil, [9]string{ok, ok, np, np, np, np, ok, np, np}},
		// A repair session with C9's state holding and the current token is
		// allowed; with none in the spec it is state_changed (TC-1004-17).
		{"move", "identity.move", nil, [9]string{ok, so, so, so, so, so, CodeStateChanged, so, np}},
		{"move with the token", "identity.move", []byte(`{"repair":true,"stateToken":"t1"}`), [9]string{ok, so, so, so, so, so, ok, so, np}},
		{"bridge A to A", "accounts.set_first_password", acct("s-A"), [9]string{np, np, np, np, np, np, np, ok, np}},
		{"bridge A to B", "accounts.set_first_password", acct("s-B"), [9]string{np, np, np, np, np, np, np, nya, np}},
		{"never", "os.store_init", nil, [9]string{ns, ns, ns, ns, ns, ns, ns, ns, ns}},
	}
	for _, row := range rows {
		for i, s := range subs {
			if got := code(p.Authorize(t.Context(), row.kind, row.spec, s.by)); got != row.want[i] {
				t.Errorf("%s (%s) by %s: %q, want %q", row.name, row.kind, s.name, got, row.want[i])
			}
		}
	}
}

// Every code has its own sentence, a capitalised sentence ending in a full
// stop (ERR-MESSAGE), and Error names only the code.
func TestKindRefusal_Sentences(t *testing.T) {
	for _, c := range []string{CodeUnknownKind, CodeSystemOnly, CodeNotSubmittable, CodeNotPermitted,
		CodeNotYourAccount, CodeOwnAccount, CodeNoTarget, CodeNoApp, CodeUnknownTier, CodeMoveState, CodeStateChanged} {
		s := sentences[c]
		if s == "" || !strings.HasSuffix(s, ".") || strings.ToUpper(s[:1]) != s[:1] {
			t.Errorf("%s: sentence %q", c, s)
		}
		if got := refuseKind(c).Error(); got != fmt.Sprintf("authz: job refused: %s", c) {
			t.Errorf("Error() = %q", got)
		}
	}
}

// Capabilities is what a Submitter holds: a repair session Repair alone, the
// zero Submitter nothing (geekdojo/geekdojo-brain#321).
func TestSubmitterCapabilities(t *testing.T) {
	if c := RepairSession().Capabilities(); !c.Has(Repair) || c.Has(View) || c.Has(IAM) {
		t.Errorf("repair session holds %v", c.List())
	}
	if c := (Submitter{}).Capabilities(); len(c.List()) != 0 {
		t.Errorf("the zero Submitter holds %v", c.List())
	}
}

// fakeMove is a MoveState over fixed answers, counting its reads.
type fakeMove struct {
	token string
	holds bool
	err   error
	reads int
}

func (m *fakeMove) RepairToken(context.Context) (string, bool, error) {
	m.reads++
	return m.token, m.holds, m.err
}

// TC-1004-17: identity.move's rule. The system is allowed; a repair session
// only while C9's state holds and the spec's stateToken is current; a state
// that does not hold is move_state, another token state_changed; a state
// read error or no state wired is ErrCheckFailed; every person is
// system_only and the zero submitter is refused. SystemOnly is false for it.
func TestAuthorize_TC1004_17_Move(t *testing.T) {
	spec := func(tok string) []byte { return []byte(`{"repair":true,"stateToken":"` + tok + `"}`) }
	pol := func(m MoveState) *KindPolicy {
		t.Helper()
		p, err := NewKindPolicy(&fakeApps{}, WithMoveState(m))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Run("system", func(t *testing.T) {
		m := &fakeMove{}
		if err := pol(m).Authorize(t.Context(), "identity.move", []byte(`{}`), sysSub); err != nil {
			t.Errorf("system: %v, want allowed", err)
		}
		if m.reads != 0 {
			t.Errorf("the system's submission read the state %d times, want 0", m.reads)
		}
	})
	t.Run("repair, state holds, current token", func(t *testing.T) {
		if err := pol(&fakeMove{token: "abc", holds: true}).Authorize(t.Context(), "identity.move", spec("abc"), repairSub); err != nil {
			t.Errorf("%v, want allowed", err)
		}
	})
	t.Run("repair, state does not hold", func(t *testing.T) {
		if got := code(pol(&fakeMove{token: "abc"}).Authorize(t.Context(), "identity.move", spec("abc"), repairSub)); got != CodeMoveState {
			t.Errorf("%q, want move_state", got)
		}
	})
	t.Run("repair, another token", func(t *testing.T) {
		for _, s := range [][]byte{spec("old"), []byte(`{"repair":true}`), []byte(`{"stateToken":"abc","stateToken":"abc"}`)} {
			if got := code(pol(&fakeMove{token: "abc", holds: true}).Authorize(t.Context(), "identity.move", s, repairSub)); got != CodeStateChanged {
				t.Errorf("%s: %q, want state_changed", s, got)
			}
		}
	})
	t.Run("repair, state read error", func(t *testing.T) {
		err := pol(&fakeMove{err: errors.New("db down")}).Authorize(t.Context(), "identity.move", spec("abc"), repairSub)
		if !errors.Is(err, ErrCheckFailed) {
			t.Errorf("%v, want ErrCheckFailed", err)
		}
	})
	t.Run("no option refuses every repair submission", func(t *testing.T) {
		if err := newPolicy(t, &fakeApps{}).Authorize(t.Context(), "identity.move", spec("abc"), repairSub); !errors.Is(err, ErrCheckFailed) {
			t.Errorf("%v, want ErrCheckFailed", err)
		}
	})
	t.Run("persons and the zero submitter", func(t *testing.T) {
		p := pol(&fakeMove{token: "abc", holds: true})
		for name, by := range map[string]Submitter{"admin": adminSub, "operator": operatorSub, "viewer": viewerSub,
			"norole": noRoleSub, "bridge": bridgeSub} {
			if got := code(p.Authorize(t.Context(), "identity.move", spec("abc"), by)); got != CodeSystemOnly {
				t.Errorf("%s: %q, want system_only", name, got)
			}
		}
		if got := code(p.Authorize(t.Context(), "identity.move", spec("abc"), zeroSub)); got == "" {
			t.Error("zero submitter: allowed, want refused")
		}
	})
	if SystemOnly("identity.move") {
		t.Error(`SystemOnly("identity.move") is true, want false`)
	}
	for _, c := range []string{CodeMoveState, CodeStateChanged} {
		if KindSentence(c) == "" {
			t.Errorf("%s has no sentence", c)
		}
	}
}

// TC-1004-17 (grant_waiting): accounts.grant_waiting is an others kind
// under iam: an administrator on another account, never on their own.
func TestAuthorize_TC1004_GrantWaiting(t *testing.T) {
	p := newPolicy(t, &fakeApps{})
	if err := p.Authorize(t.Context(), "accounts.grant_waiting", acct("s-x"), adminSub); err != nil {
		t.Errorf("admin on another: %v, want allowed", err)
	}
	if got := code(p.Authorize(t.Context(), "accounts.grant_waiting", acct("s-admin"), adminSub)); got != CodeOwnAccount {
		t.Errorf("admin on own: %q, want own_account", got)
	}
	if got := code(p.Authorize(t.Context(), "accounts.grant_waiting", acct("s-x"), operatorSub)); got != CodeNotPermitted {
		t.Errorf("operator: %q, want not_permitted", got)
	}
}
