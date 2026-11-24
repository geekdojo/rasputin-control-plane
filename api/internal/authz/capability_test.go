package authz

import (
	"slices"
	"testing"
)

func list(caps ...Capability) []string {
	out := []string{}
	for _, c := range caps {
		out = append(out, string(c))
	}
	return out
}

var (
	adminList    = list(View, Apps, AppsHost, Updates, Secrets, Nodes, Firewall, Mesh, BMC, IAM, System, Self)
	operatorList = list(View, Apps, Updates, Secrets, Self)
	viewerList   = list(View, Self)
	selfList     = list(Self)
)

// TC-1000-06: the §3.2 table, cell by cell: admin holds all but repair;
// operator view, apps, updates, secrets, self; viewer view, self; no role
// self.
func TestTC1000_06_CapabilityTable(t *testing.T) {
	holds := map[string][]Capability{
		"admin":    {View, Apps, AppsHost, Updates, Secrets, Nodes, Firewall, Mesh, BMC, IAM, System, Self},
		"operator": {View, Apps, Updates, Secrets, Self},
		"viewer":   {View, Self},
		"":         {Self},
	}
	if n := len(Capabilities()); n != 13 {
		t.Fatalf("%d capabilities, want the 13 of §3.2", n)
	}
	for role, want := range holds {
		var roles []string
		if role != "" {
			roles = []string{role}
		}
		set := For(Subject{Sub: "sub-x", Roles: roles})
		for _, c := range Capabilities() {
			if got, w := set.Has(c), slices.Contains(want, c); got != w {
				t.Errorf("TC-1000-06 cell role %q × %s: holds %v, want %v", role, c, got, w)
			}
		}
	}
}

// TC-1000-02: a role-less account holds exactly self, for nil and empty
// roles alike.
func TestTC1000_02_RolelessHoldsOnlySelf(t *testing.T) {
	for name, roles := range map[string][]string{"nil": nil, "empty": {}} {
		set := For(Subject{Sub: "sub-x", Roles: roles})
		if got := set.List(); !slices.Equal(got, selfList) {
			t.Errorf("TC-1000-02 %s roles: %v, want [self]", name, got)
		}
		if !set.Permits(NeedSelf()) {
			t.Errorf("TC-1000-02 %s roles: self refused", name)
		}
		if set.Permits(NeedView()) {
			t.Errorf("TC-1000-02 %s roles: view permitted", name)
		}
		for _, c := range Capabilities() {
			if set.Permits(NeedControl(c)) {
				t.Errorf("TC-1000-02 %s roles: control under %s permitted", name, c)
			}
		}
	}
}

// TC-1000-05: operator holds exactly view, apps, updates, secrets, self,
// and lacks apps.host; admin is permitted it.
func TestTC1000_05_OperatorLacksAppsHost(t *testing.T) {
	op := For(Subject{Sub: "sub-x", Roles: []string{"operator"}})
	if got := op.List(); !slices.Equal(got, operatorList) {
		t.Errorf("TC-1000-05 operator = %v, want %v", got, operatorList)
	}
	if op.Has(AppsHost) || op.Permits(NeedControl(AppsHost)) {
		t.Error("TC-1000-05 operator holds apps.host")
	}
	if !For(Subject{Sub: "sub-x", Roles: []string{"admin"}}).Permits(NeedControl(AppsHost)) {
		t.Error("TC-1000-05 admin refused apps.host")
	}
}

// TC-1000-07: an unknown role counts as none (ERR-CLOSED); duplicates are
// harmless.
func TestTC1000_07_UnknownRoleCountsAsNone(t *testing.T) {
	for _, c := range []struct {
		roles []string
		want  []string
	}{
		{[]string{"Admin"}, selfList},
		{[]string{"owner"}, selfList},
		{[]string{""}, selfList},
		{[]string{"admin "}, selfList},
		{[]string{"viewer", "owner"}, viewerList},
		{[]string{"operator", "operator"}, operatorList},
	} {
		if got := For(Subject{Sub: "sub-x", Roles: c.roles}).List(); !slices.Equal(got, c.want) {
			t.Errorf("TC-1000-07 roles %q = %v, want %v", c.roles, got, c.want)
		}
	}
}

// TC-1000-08: an empty subject holds nothing, even with the admin role.
func TestTC1000_08_EmptySubjectHoldsNothing(t *testing.T) {
	set := For(Subject{Sub: "", Roles: []string{"admin"}})
	got := set.List()
	if got == nil || len(got) != 0 {
		t.Errorf("TC-1000-08 List() = %#v, want an empty, non-nil slice", got)
	}
	for _, c := range Capabilities() {
		if set.Has(c) {
			t.Errorf("TC-1000-08 empty subject holds %s", c)
		}
	}
}

// TC-1000-09: the grant seam only narrows; repair is never yielded;
// ParseCapability matches exactly.
func TestTC1000_09_GrantSeam(t *testing.T) {
	admin := []string{"admin"}
	for _, c := range []struct {
		name  string
		roles []string
		grant *Grant
		want  []string
	}{
		{"no grant", admin, nil, adminList},
		{"empty grant", admin, &Grant{Scopes: []string{}}, []string{}},
		{"view", admin, &Grant{Scopes: []string{"view"}}, list(View)},
		{"view and bogus", admin, &Grant{Scopes: []string{"view", "bogus"}}, list(View)},
		{"viewer granted nodes", []string{"viewer"}, &Grant{Scopes: []string{"nodes"}}, []string{}},
		{"admin granted repair", admin, &Grant{Scopes: []string{"repair"}}, []string{}},
		{"admin granted every scope", admin, &Grant{Scopes: list(Capabilities()...)}, adminList},
	} {
		got := For(Subject{Sub: "sub-x", Roles: c.roles, Grant: c.grant}).List()
		if !slices.Equal(got, c.want) {
			t.Errorf("TC-1000-09 %s = %v, want %v", c.name, got, c.want)
		}
	}
	for _, roles := range [][]string{nil, {"viewer"}, {"operator"}, {"admin"}, {"repair"}} {
		for _, g := range []*Grant{nil, {Scopes: []string{"repair"}}, {Scopes: list(Capabilities()...)}} {
			if For(Subject{Sub: "sub-x", Roles: roles, Grant: g}).Has(Repair) {
				t.Errorf("TC-1000-09 roles %v with grant %v yield repair", roles, g)
			}
		}
	}
	if _, ok := ParseCapability("bogus"); ok {
		t.Error("TC-1000-09 ParseCapability(bogus) is true")
	}
	if c, ok := ParseCapability("apps.host"); !ok || c != AppsHost {
		t.Errorf("TC-1000-09 ParseCapability(apps.host) = %q, %v", c, ok)
	}
}

// The role names and the privileged set are the one source flows and
// markers read (ARCH-DRY).
func TestRoleNamesAndPrivileged(t *testing.T) {
	if got := RoleNames(); !slices.Equal(got, []string{"admin", "operator", "viewer"}) {
		t.Errorf("RoleNames() = %v", got)
	}
	for role, want := range map[string]bool{"admin": true, "operator": true, "viewer": false, "": false, "Admin": false} {
		if got := Privileged(role); got != want {
			t.Errorf("Privileged(%q) = %v, want %v", role, got, want)
		}
	}
}
