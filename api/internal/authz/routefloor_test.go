package authz

import (
	"errors"
	"strings"
	"testing"
)

// The capability sets the route floor is decided over (TC-1002-15).
var floorSets = []struct {
	name string
	caps Set
}{
	{"admin", For(Subject{Sub: "s-admin", Roles: []string{"admin"}})},
	{"operator", For(Subject{Sub: "s-op", Roles: []string{"operator"}})},
	{"viewer", For(Subject{Sub: "s-view", Roles: []string{"viewer"}})},
	{"none", For(Subject{Sub: "s-none"})},
	{"repair", Set{}.with(Repair)},
	{"zero", Set{}},
}

// TC-1002-15: PermitsKindRoute decides each kind of rule. Each kind below
// stands for its shape; the want column lists the sets it passes, and every
// refusal carries the kind table's code and sentence.
func TestPermitsKindRoute_TC1002_15_Shapes(t *testing.T) {
	cases := []struct {
		kind   string // a kind of the shape under test
		passes string // the sets that pass, space separated
		code   string // the code every other set is refused with
	}{
		{"diag.ping", "admin", CodeNotPermitted},                                       // control(Nodes)
		{"accounts.grant_access", "admin", CodeNotPermitted},                           // others(IAM)
		{"app.deploy", "admin operator", CodeNotPermitted},                             // appTier
		{"accounts.rename_credential", "admin operator viewer none", CodeNotPermitted}, // self
		{"accounts.sign_out", "admin operator viewer none", CodeNotPermitted},          // selfOrOthers
		{"accounts.repair_reset", "repair", CodeNotPermitted},                          // repairOnly
		{"identity.restart", "admin repair", CodeNotPermitted},                         // repairOr(IAM)
		{"accounts.set_first_password", "", CodeNotPermitted},                          // bridge
		{"identity.migrate", "", CodeSystemOnly},                                       // sysOnly
		{"identity.move", "repair", CodeSystemOnly},                                    // move (TC-321-48)
		{"os.identity_rollback", "", CodeNotSubmittable},                               // never
		{"no.such.kind", "", CodeUnknownKind},                                          // unmapped
	}
	for _, c := range cases {
		pass := map[string]bool{}
		for _, n := range strings.Fields(c.passes) {
			pass[n] = true
		}
		for _, s := range floorSets {
			err := s.caps.PermitsKindRoute(c.kind)
			if pass[s.name] {
				if err != nil {
					t.Errorf("%s for %s: %v, want it to pass", c.kind, s.name, err)
				}
				continue
			}
			var kr *KindRefusal
			if !errors.As(err, &kr) {
				t.Errorf("%s for %s: %v, want a *KindRefusal %s", c.kind, s.name, err, c.code)
				continue
			}
			if kr.Code != c.code || kr.Sentence != sentences[c.code] || kr.Sentence == "" {
				t.Errorf("%s for %s: %+v, want code %s with its sentence", c.kind, s.name, kr, c.code)
			}
		}
	}
	// A shape the switch does not know is refused (ERR-CLOSED).
	admin := floorSets[0].caps
	if got := code(admin.permitsRule(rule{shape: shape(99), cap: IAM})); got != CodeNotPermitted {
		t.Errorf("unknown shape: %q, want not_permitted", got)
	}
	if got := code(admin.permitsRule(rule{})); got != CodeNotPermitted {
		t.Errorf("zero rule: %q, want not_permitted", got)
	}
}

// TC-1002-16: the floor is never stricter than the runner. For every kind in
// the table and every person role, a Person the policy passes on their own
// account, or on a routine non-custom app, passes the route floor.
func TestPermitsKindRoute_TC1002_16_NeverStricterThanTheRunner(t *testing.T) {
	const appID = "app-routine"
	p := newPolicy(t, &fakeApps{facts: map[string]AppFacts{appID: {Tiers: []string{"routine"}}}})
	roles := map[string][]string{"admin": {"admin"}, "operator": {"operator"}, "viewer": {"viewer"}, "none": nil}
	checked, passed := 0, 0
	for kind := range kindTable {
		for name, rs := range roles {
			sub := Subject{Sub: "s-" + name, Roles: rs}
			spec := []byte(`{"accountId":"` + sub.Sub + `","appId":"` + appID + `"}`)
			checked++
			if p.Authorize(t.Context(), kind, spec, Person(sub)) != nil {
				continue
			}
			passed++
			if err := For(sub).PermitsKindRoute(kind); err != nil {
				t.Errorf("%s as %s: the runner passes it, the route floor refuses it: %v", kind, name, err)
			}
		}
	}
	if checked < len(kindTable)*len(roles) || passed == 0 {
		t.Fatalf("checked %d pairs (%d passed), want every kind for every role", checked, passed)
	}
}
