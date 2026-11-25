package accounts

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// Identity 5.1's moved operators over #994's change harness
// (geekdojo/geekdojo-brain#1004): C25, the waiting entry and its one-action
// grant, on the real Users, guard, designations and grant over the fake
// Admin API.

// addMoved seeds a moved operator as identity.move leaves it: enabled, app
// access user, the recovery-codes action, no second step, designated
// admin/admin moved.
func (c *changeHarness) addMoved(t *testing.T, sub string) {
	t.Helper()
	c.kc.add(person{sub: sub, name: sub, enabled: true, appRole: "user", offlineRole: true,
		creds: []string{"password"}, actions: []any{"CONFIGURE_RECOVERY_AUTHN_CODES"}})
	if err := c.designations.DesignateMoved(t.Context(), sub); err != nil {
		t.Fatal(err)
	}
}

// addWaiting seeds a moved operator whose designation is waiting.
func (c *changeHarness) addWaiting(t *testing.T, sub string) {
	t.Helper()
	c.addMoved(t, sub)
	if err := c.designations.Wait(t.Context(), sub); err != nil {
		t.Fatal(err)
	}
}

// noAdmins disables the world's two administrators, so the realm has none.
func (c *changeHarness) noAdmins() {
	c.kc.mu.Lock()
	defer c.kc.mu.Unlock()
	for _, sub := range []string{adminA, adminB} {
		c.kc.users[sub].rep["enabled"] = false
	}
}

func (c *changeHarness) grantWaiting(t *testing.T, sub string, fresh bool) result {
	t.Helper()
	return c.run(t, adminSubmitter, KindGrantWaiting, AccountSpec{AccountID: sub}, fresh, "")
}

// TC-1004-05 (unit): C25. Two moved accounts completing at once: exactly
// one becomes administrator, the other's designation is waiting and it gets
// no role. A moved account completing while an administrator exists is
// waiting with no role. A waiting account that completes is granted
// nothing, and the Observer submits nothing for it.
func TestGrant_TC1004_05_C25(t *testing.T) {
	t.Run("concurrent: exactly one administrator", func(t *testing.T) {
		c := newChangeHarness(t)
		c.noAdmins()
		c.addMoved(t, "m1")
		c.addMoved(t, "m2")
		c.complete("m1")
		c.complete("m2")
		var ids []string
		for _, sub := range []string{"m1", "m2"} {
			j, err := c.runner.Submit(t.Context(), GrantKind, GrantSpec{AccountID: sub}, grantSubmitter)
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, j.ID)
		}
		c.runner.Wait()
		admins, waiting := 0, 0
		for i, sub := range []string{"m1", "m2"} {
			r := c.result(t, ids[i])
			if r.job.Status != jobs.StatusSucceeded {
				t.Fatalf("%s: job %s %q", sub, r.job.Status, r.job.Error)
			}
			x, found := c.designation(t, sub)
			switch {
			case slices.Contains(c.consoleOf(sub), "admin"):
				admins++
				if found {
					t.Errorf("%s: administrator and still designated %+v", sub, x)
				}
				if c.attr(sub, AttrAppRole) != "admin" {
					t.Errorf("%s: administrator with app access %q", sub, c.attr(sub, AttrAppRole))
				}
			case found && x.Reason == ReasonWaiting:
				waiting++
				if len(c.consoleOf(sub)) != 0 || c.attr(sub, AttrAppRole) != "user" {
					t.Errorf("%s: waiting with console %v, app %q", sub, c.consoleOf(sub), c.attr(sub, AttrAppRole))
				}
			default:
				t.Errorf("%s: neither administrator nor waiting: %+v %v", sub, x, found)
			}
		}
		if admins != 1 || waiting != 1 || len(c.kc.log.only("add-console")) != 1 {
			t.Errorf("admins %d, waiting %d, role writes %v; want one of each and one write", admins, waiting, c.kc.log.only("add-console"))
		}
	})
	t.Run("an administrator exists: waiting, no role", func(t *testing.T) {
		c := newChangeHarness(t)
		c.addMoved(t, "m1")
		c.complete("m1")
		r := c.grant(t, "m1")
		if r.job.Status != jobs.StatusSucceeded || r.outcome(t, StepGrantRole) != outcomeWaitingForAdmin {
			t.Fatalf("job %s %q, grant %q", r.job.Status, r.job.Error, r.outcome(t, StepGrantRole))
		}
		if x, _ := c.designation(t, "m1"); x.Reason != ReasonWaiting || len(c.consoleOf("m1")) != 0 {
			t.Errorf("designation %+v, console %v; want waiting and none", x, c.consoleOf("m1"))
		}
	})
	t.Run("a waiting account gets nothing", func(t *testing.T) {
		c := newChangeHarness(t)
		c.noAdmins()
		c.addWaiting(t, "w1")
		c.complete("w1")
		r := c.grant(t, "w1")
		if r.job.Status != jobs.StatusSucceeded || r.outcome(t, StepCheck) != outcomeWaitingForAdmin || r.step(StepGrantRole).Result != nil &&
			r.outcome(t, StepGrantRole) != outcomeNotNeeded {
			t.Errorf("job %s, check %q, grant %q", r.job.Status, r.outcome(t, StepCheck), r.outcome(t, StepGrantRole))
		}
		if len(c.consoleOf("w1")) != 0 || c.attr("w1", AttrAppRole) != "user" {
			t.Errorf("console %v, app %q; want none and user", c.consoleOf("w1"), c.attr("w1", AttrAppRole))
		}
		sub := &countSubmit{}
		log, _ := logkittest.New()
		o, err := NewObserver(ObserverDeps{Designations: c.designations, Facts: c.ra, Runner: sub, Log: log})
		if err != nil {
			t.Fatal(err)
		}
		o.SignedIn(t.Context(), "w1")
		if sub.n != 0 {
			t.Errorf("the Observer submitted %d grants for a waiting account, want 0", sub.n)
		}
	})
}

// countSubmit counts the grants an Observer submits.
type countSubmit struct {
	mu sync.Mutex
	n  int
}

func (s *countSubmit) Submit(context.Context, string, any, string) (*jobs.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return &jobs.Job{}, nil
}

// TC-1004-05 (unit): an EnabledAdmins read error fails the grant, grants
// nothing and keeps the moved designation.
func TestGrant_TC1004_05_AdminCountError(t *testing.T) {
	r := newGrantRig(t)
	r.des[grantSub] = Designation{Sub: grantSub, ConsoleRole: "admin", AppRole: AppAdmin, Reason: ReasonMoved}
	r.fail["EnabledAdmins"] = errors.New("admin api down")
	_, err := r.run(t, grantSubmitter)
	if err == nil {
		t.Fatal("the grant succeeded with the administrators unread")
	}
	for _, c := range r.log.all() {
		if strings.HasPrefix(c, "AddConsoleRole") || strings.HasPrefix(c, "Access.Grant") || c == "Wait" || c == "WaitMoved" || c == "Clear" {
			t.Errorf("a failed count still called %s", c)
		}
	}
	if x := r.des[grantSub]; x.Reason != ReasonMoved {
		t.Errorf("designation %+v, want moved kept", x)
	}
	// With no administrator, the others are set waiting before the grant.
	r = newGrantRig(t)
	r.des[grantSub] = Designation{Sub: grantSub, ConsoleRole: "admin", AppRole: AppAdmin, Reason: ReasonMoved}
	r.des["other"] = Designation{Sub: "other", ConsoleRole: "admin", AppRole: AppAdmin, Reason: ReasonMoved}
	if _, err := r.run(t, grantSubmitter); err != nil {
		t.Fatal(err)
	}
	calls := r.log.all()
	if i, j := slices.Index(calls, "WaitMoved"), slices.Index(calls, "AddConsoleRole:admin"); i < 0 || j < 0 || i > j {
		t.Errorf("calls %v: want WaitMoved before the role", calls)
	}
	if r.des["other"].Reason != ReasonWaiting {
		t.Errorf("the other moved account is %q, want waiting", r.des["other"].Reason)
	}
}

// TC-1004-14: the one-action grant of a waiting entry (F-1004-01). A
// complete waiting account ends with console admin, app admin and no
// designation. An incomplete one is confirmed, and gets both once its
// setup is complete. A row that is not waiting is refused not_waiting; a
// grant without a fresh sign-in is refused.
func TestGrantWaiting_TC1004_14(t *testing.T) {
	t.Run("complete: both roles, no designation", func(t *testing.T) {
		c := newChangeHarness(t)
		c.addWaiting(t, "w1")
		c.complete("w1")
		r := c.grantWaiting(t, "w1", true)
		if r.job.Status != jobs.StatusSucceeded || r.outcome(t, StepChange) != outcomeApplied {
			t.Fatalf("job %s %q, change %q", r.job.Status, r.job.Error, r.outcome(t, StepChange))
		}
		if !slices.Contains(c.consoleOf("w1"), "admin") || c.attr("w1", AttrAppRole) != "admin" {
			t.Errorf("console %v, app %q; want admin and admin", c.consoleOf("w1"), c.attr("w1", AttrAppRole))
		}
		if x, found := c.designation(t, "w1"); found {
			t.Errorf("designation %+v left", x)
		}
		if !slices.Contains(r.names(), StepMovedRows) {
			t.Errorf("steps %v, want #991's role_change after the change", r.names())
		}
	})
	t.Run("incomplete: confirmed, then both on completion", func(t *testing.T) {
		c := newChangeHarness(t)
		c.addWaiting(t, "w2")
		r := c.grantWaiting(t, "w2", true)
		if r.job.Status != jobs.StatusSucceeded || r.outcome(t, StepChange) != outcomeDesignated {
			t.Fatalf("job %s %q, change %q", r.job.Status, r.job.Error, r.outcome(t, StepChange))
		}
		if x, _ := c.designation(t, "w2"); x.Reason != ReasonPrivileged || x.ConsoleRole != "admin" || x.AppRole != AppAdmin {
			t.Errorf("designation %+v, want grant admin/admin", x)
		}
		if len(c.consoleOf("w2")) != 0 {
			t.Errorf("an incomplete account got console %v", c.consoleOf("w2"))
		}
		c.complete("w2")
		g := c.grant(t, "w2")
		if g.job.Status != jobs.StatusSucceeded || !slices.Contains(c.consoleOf("w2"), "admin") || c.attr("w2", AttrAppRole) != "admin" {
			t.Errorf("after completion: job %s %q, console %v, app %q", g.job.Status, g.job.Error, c.consoleOf("w2"), c.attr("w2", AttrAppRole))
		}
		if _, found := c.designation(t, "w2"); found {
			t.Error("the designation outlived the grant")
		}
	})
	t.Run("not waiting: refused", func(t *testing.T) {
		c := newChangeHarness(t)
		c.addMoved(t, "m1")
		r := c.grantWaiting(t, "m1", true)
		if r.job.Status != jobs.StatusFailed || r.job.Error != sentenceNotWaiting {
			t.Errorf("job %s %q, want failed %q", r.job.Status, r.job.Error, sentenceNotWaiting)
		}
		if rec := c.clog.Records(); !slices.ContainsFunc(rec, func(r slog.Record) bool { v, _ := logkittest.Attr(r, "code"); return v == codeNotWaiting }) {
			t.Error("no record carries code not_waiting")
		}
		if x, _ := c.designation(t, "m1"); x.Reason != ReasonMoved || len(c.consoleOf("m1")) != 0 {
			t.Errorf("a refused grant changed %+v, console %v", x, c.consoleOf("m1"))
		}
	})
	t.Run("no fresh sign-in: refused", func(t *testing.T) {
		c := newChangeHarness(t)
		c.addWaiting(t, "w3")
		c.complete("w3")
		r := c.grantWaiting(t, "w3", false)
		if r.job.Status != jobs.StatusFailed || !strings.Contains(r.job.Error, "sign in again") {
			t.Errorf("job %s %q, want refused for a fresh sign-in", r.job.Status, r.job.Error)
		}
		if x, _ := c.designation(t, "w3"); x.Reason != ReasonWaiting || len(c.consoleOf("w3")) != 0 {
			t.Errorf("a refused grant changed %+v, console %v", x, c.consoleOf("w3"))
		}
	})
}

// TC-1004-15: a lesser grant to an incomplete waiting entry gives only what
// was chosen once its setup completes, never console admin (F-1004-02).
func TestGrantWaiting_TC1004_15_LesserGrant(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    string
		spec    any
		console []string
		app     string
		network string
	}{
		{"app administration", KindGrantAccess, AccessSpec{AccountID: "w", Level: string(AppAdmin)}, nil, "admin", ""},
		{"gear administration", KindSetNetwork, NetworkSpec{AccountID: "w", Grants: []string{authz.NetworkGearAdmin}}, nil, "user", authz.NetworkGearAdmin},
		{"console operator", KindSetRoles, RoleSpec{AccountID: "w", Role: "operator"}, []string{"operator"}, "user", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newChangeHarness(t)
			c.addWaiting(t, "w")
			r := c.run(t, adminSubmitter, tc.kind, tc.spec, true, "")
			if r.job.Status != jobs.StatusSucceeded || r.outcome(t, StepChange) != outcomeDesignated {
				t.Fatalf("job %s %q, change %q", r.job.Status, r.job.Error, r.outcome(t, StepChange))
			}
			c.complete("w")
			g := c.grant(t, "w")
			if g.job.Status != jobs.StatusSucceeded {
				t.Fatalf("grant: %s %q", g.job.Status, g.job.Error)
			}
			if got := c.consoleOf("w"); !slices.Equal(got, tc.console) {
				t.Errorf("console %v, want %v", got, tc.console)
			}
			if got := c.attr("w", AttrAppRole); got != tc.app {
				t.Errorf("app %q, want %q", got, tc.app)
			}
			if got := c.attr("w", AttrNetwork); got != tc.network {
				t.Errorf("network %q, want %q", got, tc.network)
			}
		})
	}
}

// TC-1004-16: the waiting count counts an enabled account with no console
// role and a waiting designation, even with app user; not once it holds a
// console role; never moved, first_admin, reset or grant designations; and
// a read error is an error.
func TestWaiting_TC1004_16(t *testing.T) {
	c := newChangeHarness(t)
	ctx := t.Context()
	w, err := NewWaiting(c.users, c.designations)
	if err != nil {
		t.Fatal(err)
	}
	base, err := w.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.addWaiting(t, "w1")
	c.addMoved(t, "m1")
	for _, r := range []Reason{ReasonFirstAdmin, ReasonReset, ReasonPrivileged} {
		sub := "d-" + string(r)
		c.kc.add(person{sub: sub, name: sub, enabled: true, appRole: "user"})
		if err := c.designations.Designate(ctx, Designation{Sub: sub, ConsoleRole: "admin", Reason: r}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := w.Count(ctx); err != nil || n != base+1 {
		t.Errorf("count %d %v, want %d (the waiting entry only)", n, err, base+1)
	}
	c.kc.mu.Lock()
	c.kc.users["w1"].roles = []string{"viewer"}
	c.kc.mu.Unlock()
	if n, err := w.Count(ctx); err != nil || n != base {
		t.Errorf("with a console role: count %d %v, want %d", n, err, base)
	}
	c.kc.fail = func(string, string) error { return errors.New("down") }
	if n, err := w.Count(ctx); err == nil {
		t.Errorf("count %d with the realm unreadable, want an error", n)
	}
}
