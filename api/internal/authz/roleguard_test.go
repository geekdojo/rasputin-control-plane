package authz

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeAccounts is an in-memory RoleAccounts. Its own mutex makes it safe
// under -race; the guard's lock is what serializes decisions.
type fakeAccounts struct {
	mu       sync.Mutex
	facts    map[string]AccountFacts
	factsErr map[string]error
	adminErr error
	// admins, when set, overrides the counted enabled administrators.
	admins *int
}

func newFake(accounts ...AccountFacts) *fakeAccounts {
	f := &fakeAccounts{facts: map[string]AccountFacts{}, factsErr: map[string]error{}}
	for _, a := range accounts {
		f.facts[a.Sub] = a
	}
	return f
}

func (f *fakeAccounts) Facts(_ context.Context, sub string) (AccountFacts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.factsErr[sub]; err != nil {
		return AccountFacts{}, err
	}
	a, ok := f.facts[sub]
	if !ok {
		return AccountFacts{}, ErrNoAccount
	}
	a.Roles = slices.Clone(a.Roles)
	return a, nil
}

func (f *fakeAccounts) EnabledAdmins(context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.adminErr != nil {
		return 0, f.adminErr
	}
	if f.admins != nil {
		return *f.admins, nil
	}
	n := 0
	for _, a := range f.facts {
		if a.Enabled && slices.Contains(a.Roles, "admin") {
			n++
		}
	}
	return n, nil
}

// write applies d for ch, so the next read sees it.
func (f *fakeAccounts) write(ch RoleChange, d Decision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.facts[ch.Target]
	switch {
	case ch.Op == OpDelete:
		delete(f.facts, ch.Target)
		return
	case ch.Op == OpDisable:
		a.Enabled = false
	case d.Kind == Apply && d.Role == "":
		a.Roles = nil
	case d.Kind == Apply:
		a.Roles = []string{d.Role}
	}
	f.facts[ch.Target] = a
}

func complete(sub, role string) AccountFacts {
	var roles []string
	if role != "" {
		roles = []string{role}
	}
	return AccountFacts{Sub: sub, Name: sub, Username: sub, Roles: roles, Enabled: true, HoldsSecondStep: true, HoldsRecoveryCodes: true}
}

func guard(t *testing.T, f *fakeAccounts) *RoleGuard {
	t.Helper()
	g, err := NewRoleGuard(f, &sync.Mutex{})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// recorder is an apply func that counts its calls and keeps the last
// Decision.
type recorder struct {
	calls int
	got   Decision
	err   error
}

func (r *recorder) apply(_ context.Context, d Decision) error {
	r.calls++
	r.got = d
	return r.err
}

func wantRefusal(t *testing.T, id string, err error, code, sentence string) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("%s: err = %v, want a *Refusal %s", id, err, code)
	}
	if r.Code != code || r.Sentence != sentence {
		t.Errorf("%s: refusal %q %q, want %q %q", id, r.Code, r.Sentence, code, sentence)
	}
	if strings.Contains(r.Error(), r.Sentence) || !strings.Contains(r.Error(), code) {
		t.Errorf("%s: Error() = %q, want the code and not the sentence", id, r.Error())
	}
}

// TC-1000-03: an administrator cannot change their own role, even with a
// second administrator present.
func TestTC1000_03_OwnRole(t *testing.T) {
	g := guard(t, newFake(complete("a", "admin"), complete("b", "admin")))
	var rec recorder
	d, err := g.Change(t.Context(), "a", RoleChange{Target: "a", Op: OpSetRole, Role: "operator"}, rec.apply)
	wantRefusal(t, "TC-1000-03", err, "own_role", "You can't change your own role.")
	if rec.calls != 0 || d != (Decision{}) {
		t.Errorf("TC-1000-03: apply called %d times, decision %+v", rec.calls, d)
	}
}

// TC-1000-17: self-targeted disable and delete each get their own code
// and sentence, never the role-change one.
func TestTC1000_17_OwnAccountDisableDelete(t *testing.T) {
	g := guard(t, newFake(complete("a", "admin"), complete("b", "admin")))
	for _, c := range []struct {
		op             Op
		code, sentence string
	}{
		{OpDisable, "own_account_disable", "You can't disable your own account."},
		{OpDelete, "own_account_delete", "You can't delete your own account."},
	} {
		var rec recorder
		_, err := g.Change(t.Context(), "a", RoleChange{Target: "a", Op: c.op}, rec.apply)
		wantRefusal(t, "TC-1000-17 "+c.code, err, c.code, c.sentence)
		if rec.calls != 0 {
			t.Errorf("TC-1000-17 %s: apply called", c.code)
		}
	}
}

// TC-1000-12: only an enabled administrator changes roles; an unknown role
// is refused; an unknown change, a missing target. apply never runs.
func TestTC1000_12_GuardRefusals(t *testing.T) {
	disabled := complete("disabled-admin", "admin")
	disabled.Enabled = false
	f := newFake(complete("admin", "admin"), complete("admin2", "admin"), complete("operator", "operator"),
		complete("viewer", "viewer"), complete("none", ""), disabled, complete("target", "viewer"))
	g := guard(t, f)
	const notPermitted = "Only an administrator can change roles."
	for _, c := range []struct {
		name, actor    string
		ch             RoleChange
		code, sentence string
	}{
		{"operator", "operator", RoleChange{Target: "target", Op: OpSetRole, Role: "viewer"}, "not_permitted", notPermitted},
		{"viewer", "viewer", RoleChange{Target: "target", Op: OpSetRole, Role: ""}, "not_permitted", notPermitted},
		{"role-less", "none", RoleChange{Target: "target", Op: OpDisable}, "not_permitted", notPermitted},
		{"disabled admin", "disabled-admin", RoleChange{Target: "target", Op: OpSetRole, Role: "viewer"}, "not_permitted", notPermitted},
		{"missing actor", "gone", RoleChange{Target: "target", Op: OpDelete}, "not_permitted", notPermitted},
		{"unknown role", "admin", RoleChange{Target: "target", Op: OpSetRole, Role: "owner"}, "unknown_role", "That role doesn't exist."},
		{"mis-cased role", "admin", RoleChange{Target: "target", Op: OpSetRole, Role: "Admin"}, "unknown_role", "That role doesn't exist."},
		{"missing target", "admin", RoleChange{Target: "gone", Op: OpSetRole, Role: "viewer"}, "no_account", "That account no longer exists."},
		{"zero op", "admin", RoleChange{Target: "target"}, "unknown_change", "That change isn't supported."},
		{"unknown op", "admin", RoleChange{Target: "target", Op: Op(42)}, "unknown_change", "That change isn't supported."},
		{"unknown op on self", "admin", RoleChange{Target: "admin", Op: Op(42)}, "unknown_change", "That change isn't supported."},
	} {
		var rec recorder
		d, err := g.Change(t.Context(), c.actor, c.ch, rec.apply)
		wantRefusal(t, "TC-1000-12 "+c.name, err, c.code, c.sentence)
		if rec.calls != 0 || d != (Decision{}) {
			t.Errorf("TC-1000-12 %s: apply called %d times, decision %+v", c.name, rec.calls, d)
		}
	}
}

// TC-1000-13: the last enabled administrator cannot be demoted, disabled or
// deleted; with two enabled administrators the same changes apply.
func TestTC1000_13_LastAdmin(t *testing.T) {
	changes := []RoleChange{
		{Target: "t", Op: OpSetRole, Role: "operator"},
		{Target: "t", Op: OpSetRole, Role: "viewer"},
		{Target: "t", Op: OpSetRole, Role: ""},
		{Target: "t", Op: OpDisable},
		{Target: "t", Op: OpDelete},
	}
	for _, admins := range []int{1, 2} {
		for _, ch := range changes {
			off := complete("off", "admin")
			off.Enabled = false
			f := newFake(complete("t", "admin"), complete("a", "admin"), off)
			// The actor's demotion is simulated away: it is not counted.
			f.admins = &admins
			var rec recorder
			d, err := guard(t, f).Change(t.Context(), "a", ch, rec.apply)
			if admins == 1 {
				wantRefusal(t, "TC-1000-13", err, "last_admin", "Rasputin needs at least one administrator, so this one can't be removed.")
				if rec.calls != 0 {
					t.Errorf("TC-1000-13 %+v: apply called", ch)
				}
				continue
			}
			if err != nil || d.Kind != Apply || rec.calls != 1 || rec.got != d {
				t.Errorf("TC-1000-13 %+v with two admins: %+v, %v, apply %d, want Apply", ch, d, err, rec.calls)
			}
		}
	}
	// Setting admin on the last administrator removes nothing.
	one := 1
	f := newFake(complete("t", "admin"), complete("a", "admin"))
	f.admins = &one
	if d, err := guard(t, f).Change(t.Context(), "a", RoleChange{Target: "t", Op: OpSetRole, Role: "admin"}, (&recorder{}).apply); err != nil || d.Kind != Apply {
		t.Errorf("TC-1000-13 admin to admin: %+v, %v, want Apply", d, err)
	}
	// A disabled administrator is not the last one being removed.
	off := complete("t", "admin")
	off.Enabled = false
	f = newFake(off, complete("a", "admin"))
	f.admins = &one
	if d, err := guard(t, f).Change(t.Context(), "a", RoleChange{Target: "t", Op: OpDelete}, (&recorder{}).apply); err != nil || d.Kind != Apply {
		t.Errorf("TC-1000-13 deleting a disabled admin: %+v, %v, want Apply", d, err)
	}
}

// TC-1000-04: an operator grant to an account with neither a second step
// nor codes is a designation with the issue's sentence, and apply gets it.
func TestTC1000_04_DesignationSentence(t *testing.T) {
	maya := AccountFacts{Sub: "maya", Name: "Maya", Username: "maya", Enabled: true}
	f := newFake(complete("a", "admin"), maya)
	var rec recorder
	d, err := guard(t, f).Change(t.Context(), "a", RoleChange{Target: "maya", Op: OpSetRole, Role: "operator", Fresh: true}, rec.apply)
	want := Decision{Kind: Designate, Role: "operator", Raises: true,
		Sentence: "This role starts after Maya adds a passkey, security key or authenticator app and saves recovery codes at the next sign-in.",
		Unnamed:  "This role starts after this person adds a passkey, security key or authenticator app and saves recovery codes at the next sign-in."}
	if err != nil || d != want {
		t.Fatalf("TC-1000-04: %+v, %v, want %+v", d, err, want)
	}
	if rec.calls != 1 || rec.got != want {
		t.Errorf("TC-1000-04: apply got %+v (%d calls), want the Designate decision", rec.got, rec.calls)
	}
	// The guard writes nothing: the role stays as it was until apply does.
	if got, _ := f.Facts(t.Context(), "maya"); len(got.Roles) != 0 {
		t.Errorf("TC-1000-04: Maya's roles are %v", got.Roles)
	}
}

// TC-1000-15: every designation variant, designate only on a raise, and
// DesignationComplete's truth table.
func TestTC1000_15_DesignationVariants(t *testing.T) {
	base := func(role string, second, codes, pending bool) AccountFacts {
		f := AccountFacts{Sub: "t", Username: "maya", Enabled: true, HoldsSecondStep: second, HoldsRecoveryCodes: codes, RequiredActionPending: pending}
		if role != "" {
			f.Roles = []string{role}
		}
		return f
	}
	for _, c := range []struct {
		name     string
		target   AccountFacts
		role     string
		kind     Kind
		sentence string
	}{
		{"second step missing", base("", false, true, false), "operator", Designate,
			"This role starts after maya adds a passkey, security key or authenticator app at the next sign-in."},
		{"codes missing", base("", true, false, false), "operator", Designate,
			"This role starts after maya saves recovery codes at the next sign-in."},
		{"action pending", base("", true, true, true), "operator", Designate,
			"This role starts after maya finishes setting up their account at the next sign-in."},
		{"both missing and pending", base("", false, false, true), "admin", Designate,
			"This role starts after maya adds a passkey, security key or authenticator app and saves recovery codes at the next sign-in."},
		{"complete", base("", true, true, false), "operator", Apply, ""},
		{"operator to admin, codes missing", base("operator", true, false, false), "admin", Designate,
			"This role starts after maya saves recovery codes at the next sign-in."},
		{"viewer grant, nothing held", base("", false, false, false), "viewer", Apply, ""},
		{"admin to operator, nothing held", base("admin", false, false, false), "operator", Apply, ""},
		{"admin to viewer, nothing held", base("admin", false, false, false), "viewer", Apply, ""},
		{"operator to viewer, nothing held", base("operator", false, false, false), "viewer", Apply, ""},
		{"operator to operator, nothing held", base("operator", false, false, false), "operator", Apply, ""},
	} {
		f := newFake(complete("a", "admin"), complete("b", "admin"), c.target)
		var rec recorder
		d, err := guard(t, f).Change(t.Context(), "a", RoleChange{Target: "t", Op: OpSetRole, Role: c.role, Fresh: true}, rec.apply)
		want := Decision{Kind: c.kind, Role: c.role, Sentence: c.sentence, Raises: c.kind == Designate || c.name == "complete",
			Unnamed: strings.Replace(c.sentence, "maya", "this person", 1)}
		if err != nil || d != want || rec.got != want {
			t.Errorf("TC-1000-15 %s: %+v, %v (apply got %+v), want %+v", c.name, d, err, rec.got, want)
		}
	}
	for _, second := range []bool{false, true} {
		for _, codes := range []bool{false, true} {
			for _, pending := range []bool{false, true} {
				want := second && codes && !pending
				if got := DesignationComplete(AccountFacts{HoldsSecondStep: second, HoldsRecoveryCodes: codes, RequiredActionPending: pending}); got != want {
					t.Errorf("TC-1000-15 DesignationComplete(second %v, codes %v, pending %v) = %v", second, codes, pending, got)
				}
			}
		}
	}
	// With no display name and no sign-in name the sentence still reads.
	if got := designationSentence(AccountFacts{}); got != "This role starts after this person adds a passkey, security key or authenticator app and saves recovery codes at the next sign-in." {
		t.Errorf("TC-1000-15 nameless sentence = %q", got)
	}
}

// TC-1000-16: the guard's failure paths.
func TestTC1000_16_FailurePaths(t *testing.T) {
	boom := errors.New("identity service down")
	ch := RoleChange{Target: "t", Op: OpSetRole, Role: "viewer"}
	for name, setup := range map[string]func(*fakeAccounts){
		"actor facts":    func(f *fakeAccounts) { f.factsErr["a"] = boom },
		"target facts":   func(f *fakeAccounts) { f.factsErr["t"] = boom },
		"enabled admins": func(f *fakeAccounts) { f.adminErr = boom },
	} {
		f := newFake(complete("a", "admin"), complete("t", "admin"))
		setup(f)
		var rec recorder
		d, err := guard(t, f).Change(t.Context(), "a", ch, rec.apply)
		if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "authz: role change:") {
			t.Errorf("TC-1000-16 %s: err = %v, want it wrapped", name, err)
		}
		var r *Refusal
		if errors.As(err, &r) || d != (Decision{}) || rec.calls != 0 {
			t.Errorf("TC-1000-16 %s: refusal %v, decision %+v, apply %d", name, r, d, rec.calls)
		}
	}
	rec := recorder{err: boom}
	d, err := guard(t, newFake(complete("a", "admin"), complete("t", "viewer"))).Change(t.Context(), "a", ch, rec.apply)
	if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "authz: role change: apply:") || d != (Decision{}) || rec.calls != 1 {
		t.Errorf("TC-1000-16 apply error: %+v, %v, apply %d", d, err, rec.calls)
	}
	if _, err := guard(t, newFake()).Change(t.Context(), "a", ch, nil); err == nil {
		t.Error("TC-1000-16 a nil apply was accepted")
	}
	if g, err := NewRoleGuard(nil, &sync.Mutex{}); err == nil || g != nil {
		t.Errorf("TC-1000-16 NewRoleGuard(nil accounts) = %v, %v", g, err)
	}
	if g, err := NewRoleGuard(newFake(), nil); err == nil || g != nil {
		t.Errorf("TC-1000-16 NewRoleGuard(nil lock) = %v, %v", g, err)
	}
}

// lockCounter is a sync.Locker that records that the guard took it.
type lockCounter struct {
	sync.Mutex
	locks int
}

func (l *lockCounter) Lock() { l.Mutex.Lock(); l.locks++ }

// The guard holds the injected lock, not one of its own (F-1000-05), and
// holds it while apply runs.
func TestRoleGuardHoldsTheInjectedLock(t *testing.T) {
	l := &lockCounter{}
	g, err := NewRoleGuard(newFake(complete("a", "admin"), complete("t", "viewer")), l)
	if err != nil {
		t.Fatal(err)
	}
	held := false
	_, err = g.Change(t.Context(), "a", RoleChange{Target: "t", Op: OpSetRole, Role: "viewer"}, func(context.Context, Decision) error {
		held = !l.TryLock()
		return nil
	})
	if err != nil || l.locks != 1 || !held {
		t.Errorf("locks %d, held during apply %v, err %v", l.locks, held, err)
	}
	if !l.TryLock() {
		t.Error("the lock is still held after Change")
	}
}

// TC-1000-14 (as the plan amends it, F-1000-04): two administrators acting
// on each other at once. Under the lock the loser re-reads its own facts,
// finds itself demoted, disabled or deleted, and is refused not_permitted.
// Every iteration has one Apply and one not_permitted refusal, and one
// enabled administrator remains. Run under go test -race.
func TestTC1000_14_GuardsUnderConcurrency(t *testing.T) {
	pairs := []struct {
		name string
		aOnB RoleChange
		bOnA RoleChange
	}{
		{name: "demote each other", aOnB: RoleChange{Target: "b", Op: OpSetRole, Role: "operator"}, bOnA: RoleChange{Target: "a", Op: OpSetRole, Role: "operator"}},
		{name: "disable and delete", aOnB: RoleChange{Target: "b", Op: OpDisable}, bOnA: RoleChange{Target: "a", Op: OpDelete}},
	}
	for _, p := range pairs {
		for i := range 200 {
			f := newFake(complete("a", "admin"), complete("b", "admin"))
			g := guard(t, f)
			var (
				wg      sync.WaitGroup
				start   = make(chan struct{})
				results [2]error
				kinds   [2]Kind
			)
			for j, c := range []struct {
				actor string
				ch    RoleChange
			}{{"a", p.aOnB}, {"b", p.bOnA}} {
				wg.Go(func() {
					<-start
					d, err := g.Change(context.Background(), c.actor, c.ch, func(_ context.Context, d Decision) error {
						f.write(c.ch, d)
						return nil
					})
					kinds[j], results[j] = d.Kind, err
				})
			}
			close(start)
			wg.Wait()
			applied, refused := 0, 0
			for j := range 2 {
				var r *Refusal
				switch {
				case results[j] == nil && kinds[j] == Apply:
					applied++
				case errors.As(results[j], &r) && r.Code == "not_permitted":
					refused++
				default:
					t.Errorf("TC-1000-14 %s #%d: goroutine %d got %v, %v", p.name, i, j, kinds[j], results[j])
				}
			}
			n, _ := f.EnabledAdmins(context.Background())
			if applied != 1 || refused != 1 || n != 1 {
				t.Fatalf("TC-1000-14 %s #%d: %d applied, %d refused not_permitted, %d enabled admins; want 1, 1, 1", p.name, i, applied, refused, n)
			}
		}
	}
}
