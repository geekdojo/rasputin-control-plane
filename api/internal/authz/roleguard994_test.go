package authz

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
)

// The guard's account ops of Identity 4.12 (geekdojo/geekdojo-brain#994).

// allOps are every op the guard decides, with a change that names a known
// value for each.
var allOps = []RoleChange{
	{Op: OpSetRole, Role: "viewer"},
	{Op: OpDisable},
	{Op: OpDelete},
	{Op: OpSetAppAccess, AppRole: AppRoleUser},
	{Op: OpSetNetwork, Network: []string{NetworkJoin}},
	{Op: OpRemoveSecondSteps},
}

// readLog wraps a fakeAccounts and records every Facts read, by subject.
type readLog struct {
	*fakeAccounts
	mu    sync.Mutex
	reads []string
}

func (r *readLog) Facts(ctx context.Context, sub string) (AccountFacts, error) {
	r.mu.Lock()
	r.reads = append(r.reads, sub)
	r.mu.Unlock()
	return r.fakeAccounts.Facts(ctx, sub)
}

// TC-994-07: one's own account is refused for every op, with its own code
// and sentence, and apply never runs.
func TestTC994_07_OwnAccount(t *testing.T) {
	want := map[Op][2]string{
		OpSetRole:           {"own_role", "You can't change your own role."},
		OpDisable:           {"own_account_disable", "You can't disable your own account."},
		OpDelete:            {"own_account_delete", "You can't delete your own account."},
		OpSetAppAccess:      {"own_app_access", "You can't change your own app access."},
		OpSetNetwork:        {"own_network", "You can't change your own network access."},
		OpRemoveSecondSteps: {"own_second_steps", "You can't remove your own second steps here."},
	}
	for _, ch := range allOps {
		f := newFake(complete("a", "admin"), complete("b", "admin"))
		ch.Target, ch.Fresh = "a", true
		var rec recorder
		_, err := guard(t, f).Change(t.Context(), "a", ch, rec.apply)
		wantRefusal(t, "TC-994-07", err, want[ch.Op][0], want[ch.Op][1])
		if rec.calls != 0 {
			t.Errorf("TC-994-07 op %d: apply ran %d times", ch.Op, rec.calls)
		}
	}
}

// TC-994-08: the only enabled administrator can't lose admin by a role
// change, a disable, a delete or removing the second steps; app access and
// network changes are not last-administrator changes.
func TestTC994_08_LastAdmin(t *testing.T) {
	one := 1
	for _, ch := range []RoleChange{{Op: OpSetRole, Role: "operator"}, {Op: OpDisable}, {Op: OpDelete}, {Op: OpRemoveSecondSteps}} {
		f := newFake(complete("a", "admin"), complete("t", "admin"))
		f.admins = &one
		ch.Target, ch.Fresh = "t", true
		var rec recorder
		_, err := guard(t, f).Change(t.Context(), "a", ch, rec.apply)
		wantRefusal(t, "TC-994-08", err, "last_admin", "Rasputin needs at least one administrator, so this one can't be removed.")
		if rec.calls != 0 {
			t.Errorf("TC-994-08 op %d: apply ran", ch.Op)
		}
	}
	for _, ch := range []RoleChange{{Op: OpSetAppAccess, AppRole: AppRoleUser}, {Op: OpSetNetwork, Network: []string{NetworkJoin}}} {
		f := newFake(complete("a", "admin"), complete("t", "admin"))
		f.admins = &one
		ch.Target, ch.Fresh = "t", true
		var rec recorder
		if d, err := guard(t, f).Change(t.Context(), "a", ch, rec.apply); err != nil || d.Kind != Apply || rec.calls != 1 {
			t.Errorf("TC-994-08 op %d: %+v, %v, want Apply", ch.Op, d, err)
		}
	}
}

// TC-994-09: the actor is re-read under the lock: one without iam, a
// disabled one and a missing one are not_permitted, a read error is a
// wrapped error, and the target's facts are never read.
func TestTC994_09_ActorReread(t *testing.T) {
	boom := errors.New("identity service down")
	disabled := complete("a", "admin")
	disabled.Enabled = false
	cases := map[string]struct {
		actor   *AccountFacts
		readErr error
	}{
		"no iam":    {actor: &AccountFacts{Sub: "a", Roles: []string{"operator"}, Enabled: true}},
		"disabled":  {actor: &disabled},
		"not found": {},
		"read fails": {
			actor: &AccountFacts{Sub: "a", Roles: []string{"admin"}, Enabled: true}, readErr: boom,
		},
	}
	for name, c := range cases {
		for _, ch := range allOps {
			f := newFake(complete("t", "viewer"))
			if c.actor != nil {
				f.facts["a"] = *c.actor
			}
			if c.readErr != nil {
				f.factsErr["a"] = c.readErr
			}
			rl := &readLog{fakeAccounts: f}
			g, err := NewRoleGuard(rl, &sync.Mutex{})
			if err != nil {
				t.Fatal(err)
			}
			ch.Target, ch.Fresh = "t", true
			var rec recorder
			_, err = g.Change(t.Context(), "a", ch, rec.apply)
			if c.readErr != nil {
				var ref *Refusal
				if !errors.Is(err, boom) || errors.As(err, &ref) {
					t.Errorf("TC-994-09 %s op %d: %v, want the wrapped read error", name, ch.Op, err)
				}
			} else {
				wantRefusal(t, "TC-994-09 "+name, err, "not_permitted", "Only an administrator can change roles.")
			}
			if slices.Contains(rl.reads, "t") || rec.calls != 0 {
				t.Errorf("TC-994-09 %s op %d: reads %v, apply %d", name, ch.Op, rl.reads, rec.calls)
			}
		}
	}
}

// TC-994-10: an unknown role, app level or network grant is refused, with
// nothing applied.
func TestTC994_10_UnknownValues(t *testing.T) {
	for _, c := range []struct {
		ch   RoleChange
		code string
		text string
	}{
		{RoleChange{Op: OpSetRole, Role: "root"}, "unknown_role", "That role doesn't exist."},
		{RoleChange{Op: OpSetAppAccess, AppRole: "owner"}, "unknown_access", "That level of app access doesn't exist."},
		{RoleChange{Op: OpSetAppAccess}, "unknown_access", "That level of app access doesn't exist."},
		{RoleChange{Op: OpSetNetwork, Network: []string{NetworkJoin, "gear-root"}}, "unknown_network", "That network access doesn't exist."},
	} {
		f := newFake(complete("a", "admin"), complete("t", "viewer"))
		c.ch.Target, c.ch.Fresh = "t", true
		var rec recorder
		_, err := guard(t, f).Change(t.Context(), "a", c.ch, rec.apply)
		wantRefusal(t, "TC-994-10", err, c.code, c.text)
		if rec.calls != 0 {
			t.Errorf("TC-994-10 %s: apply ran", c.code)
		}
	}
}

// TC-994-11: RaisesPrivilege's table, and the guard's Decision.Raises
// equals it for every row; a raise without a fresh sign-in is refused.
func TestTC994_11_RaisesPrivilege(t *testing.T) {
	withRole := func(role string) AccountFacts {
		f := complete("t", role)
		return f
	}
	withApp := func(app string) AccountFacts { f := complete("t", ""); f.AppRole = app; return f }
	withNet := func(n ...string) AccountFacts { f := complete("t", ""); f.Network = n; return f }
	rows := []struct {
		name   string
		f      AccountFacts
		ch     RoleChange
		raises bool
	}{
		{"viewer to operator", withRole("viewer"), RoleChange{Op: OpSetRole, Role: "operator"}, true},
		{"operator to admin", withRole("operator"), RoleChange{Op: OpSetRole, Role: "admin"}, true},
		{"admin to viewer", withRole("admin"), RoleChange{Op: OpSetRole, Role: "viewer"}, false},
		{"no access to user", withApp(""), RoleChange{Op: OpSetAppAccess, AppRole: AppRoleUser}, false},
		{"user to admin", withApp(AppRoleUser), RoleChange{Op: OpSetAppAccess, AppRole: AppRoleAdmin}, true},
		{"admin held to admin", withApp(AppRoleAdmin), RoleChange{Op: OpSetAppAccess, AppRole: AppRoleAdmin}, false},
		{"join to join and gear-admin", withNet(NetworkJoin), RoleChange{Op: OpSetNetwork, Network: []string{NetworkJoin, NetworkGearAdmin}}, true},
		{"gear-admin held to gear-admin and join", withNet(NetworkGearAdmin), RoleChange{Op: OpSetNetwork, Network: []string{NetworkGearAdmin, NetworkJoin}}, false},
	}
	for _, r := range rows {
		if got := RaisesPrivilege(r.f, r.ch); got != r.raises {
			t.Errorf("TC-994-11 %s: RaisesPrivilege = %v, want %v", r.name, got, r.raises)
		}
		f := newFake(complete("a", "admin"), complete("b", "admin"), r.f)
		ch := r.ch
		ch.Target, ch.Fresh = "t", true
		var rec recorder
		d, err := guard(t, f).Change(t.Context(), "a", ch, rec.apply)
		if err != nil || d.Raises != r.raises || d.Kind != Apply {
			t.Errorf("TC-994-11 %s: %+v, %v, want Apply with Raises %v", r.name, d, err, r.raises)
		}
		if r.raises {
			ch.Fresh = false
			rec = recorder{}
			_, err := guard(t, f).Change(t.Context(), "a", ch, rec.apply)
			wantRefusal(t, "TC-994-11 "+r.name, err, CodeFreshSignIn,
				"Giving a privileged role needs you to sign in again first. Start it again from Accounts.")
			if rec.calls != 0 {
				t.Errorf("TC-994-11 %s: apply ran without a fresh sign-in", r.name)
			}
		}
	}
}

// TC-994-11 (designation): a raise of app access or the network to an
// account that is not complete is a designation, with Raises.
func TestTC994_11_RaiseDesignates(t *testing.T) {
	for _, ch := range []RoleChange{
		{Op: OpSetAppAccess, AppRole: AppRoleAdmin},
		{Op: OpSetNetwork, Network: []string{NetworkGearAdmin}},
		{Op: OpSetRole, Role: "operator"},
	} {
		f := newFake(complete("a", "admin"), AccountFacts{Sub: "t", Username: "maya", Enabled: true})
		ch.Target, ch.Fresh = "t", true
		var rec recorder
		d, err := guard(t, f).Change(t.Context(), "a", ch, rec.apply)
		if err != nil || d.Kind != Designate || !d.Raises || rec.calls != 1 {
			t.Errorf("op %d: %+v, %v, want Designate", ch.Op, d, err)
		}
	}
}

// PrivilegedLevels is the one definition of privilege (F-994-06).
func TestPrivilegedLevels(t *testing.T) {
	for _, c := range []struct {
		f    AccountFacts
		want Levels
	}{
		{AccountFacts{}, Levels{}},
		{AccountFacts{Roles: []string{"viewer"}, AppRole: AppRoleUser, Network: []string{NetworkJoin, NetworkGearRead}}, Levels{}},
		{AccountFacts{Roles: []string{"viewer", "operator"}}, Levels{Console: "operator"}},
		{AccountFacts{Roles: []string{"admin", "operator", "viewer"}}, Levels{Console: "admin"}},
		{AccountFacts{AppRole: AppRoleAdmin}, Levels{App: true}},
		{AccountFacts{Network: []string{NetworkGearAdmin}}, Levels{Gear: true}},
	} {
		got := PrivilegedLevels(c.f)
		if got != c.want || HoldsPrivilege(c.f) != !c.want.Empty() {
			t.Errorf("PrivilegedLevels(%+v) = %+v, want %+v", c.f, got, c.want)
		}
	}
}
