package authz

import "testing"

func roleSet(roles ...string) Set { return For(Subject{Sub: "sub-x", Roles: roles}) }

// TC-1000-01: a viewer lacks apps and never sees Accounts; an operator is
// refused Accounts too; an administrator is permitted it.
func TestTC1000_01_ViewerNeverSeesAccounts(t *testing.T) {
	viewer := roleSet("viewer")
	if viewer.Has(Apps) {
		t.Error("TC-1000-01 viewer holds apps")
	}
	if viewer.Permits(NeedControl(Apps)) {
		t.Error("TC-1000-01 viewer permitted control under apps")
	}
	if !viewer.Permits(NeedView()) {
		t.Error("TC-1000-01 viewer refused view")
	}
	for _, c := range []struct {
		role string
		want bool
	}{{"viewer", false}, {"operator", false}, {"admin", true}} {
		if got := roleSet(c.role).Permits(AccountsRead()); got != c.want {
			t.Errorf("TC-1000-01 %s AccountsRead permitted %v, want %v", c.role, got, c.want)
		}
	}
	if AccountsRead() != NeedControl(IAM) {
		t.Errorf("TC-1000-01 AccountsRead() = %+v, want control under iam", AccountsRead())
	}
}

// TC-1000-10: Permits refuses what it cannot evaluate.
func TestTC1000_10_UnevaluableRequirementsRefused(t *testing.T) {
	admin := roleSet("admin")
	for name, r := range map[string]Requirement{
		"zero":                {},
		"out-of-range class":  {Class: Class(99), Capability: Apps},
		"negative class":      {Class: Class(-1)},
		"control, empty":      NeedControl(""),
		"control, unknown":    NeedControl(Capability("bogus")),
		"control, mis-cased":  NeedControl(Capability("IAM")),
		"control, repair":     NeedControl(Repair),
		"control, view":       NeedControl(View),
		"control, self":       NeedControl(Self),
		"zero class with cap": {Capability: Apps},
	} {
		if admin.Permits(r) {
			t.Errorf("TC-1000-10 %s permitted for an admin", name)
		}
	}
}

// TC-1000-11: role × route class. Columns: admin, operator, viewer, none.
func TestTC1000_11_RoleByRouteClass(t *testing.T) {
	sets := []struct {
		name string
		set  Set
	}{{"admin", roleSet("admin")}, {"operator", roleSet("operator")}, {"viewer", roleSet("viewer")}, {"none", roleSet()}}
	for _, row := range []struct {
		name string
		req  Requirement
		want [4]bool
	}{
		{"view", NeedView(), [4]bool{true, true, true, false}},
		{"self", NeedSelf(), [4]bool{true, true, true, true}},
		{"apps", NeedControl(Apps), [4]bool{true, true, false, false}},
		{"apps.host", NeedControl(AppsHost), [4]bool{true, false, false, false}},
		{"iam", NeedControl(IAM), [4]bool{true, false, false, false}},
		{"AccountsRead", AccountsRead(), [4]bool{true, false, false, false}},
	} {
		for i, s := range sets {
			if got := s.set.Permits(row.req); got != row.want[i] {
				t.Errorf("TC-1000-11 %s × %s = %v, want %v", s.name, row.name, got, row.want[i])
			}
		}
	}
}

// TC-1000-08 (the requirement rows): an empty subject is refused self,
// view and every control requirement.
func TestTC1000_08_EmptySubjectRefusedEverything(t *testing.T) {
	set := For(Subject{Roles: []string{"admin"}})
	if set.Permits(NeedSelf()) || set.Permits(NeedView()) {
		t.Error("TC-1000-08 empty subject permitted self or view")
	}
	for _, c := range Capabilities() {
		if set.Permits(NeedControl(c)) {
			t.Errorf("TC-1000-08 empty subject permitted control under %s", c)
		}
	}
}
