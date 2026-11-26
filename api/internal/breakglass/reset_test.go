package breakglass

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// fakeResets is the repair reset: targets by id, the token each confirms
// with, and Submit's answer. block, when set, holds Submit until closed.
type fakeResets struct {
	mu        sync.Mutex
	targets   []accounts.RepairTarget
	targetErr error
	submitErr error
	submits   int
	block     chan struct{}
	entered   chan struct{}
}

func (f *fakeResets) Targets(context.Context) ([]accounts.RepairTarget, error) {
	return f.targets, f.targetErr
}

func (f *fakeResets) Confirm(_ context.Context, id string) (accounts.RepairTarget, string, error) {
	if f.targetErr != nil {
		return accounts.RepairTarget{}, "", f.targetErr
	}
	for _, t := range f.targets {
		if t.ID == id {
			return t, "tok-" + id, nil
		}
	}
	return accounts.RepairTarget{}, "", accounts.ErrNotRepairTarget
}

func (f *fakeResets) Submit(_ context.Context, _ authz.Submitter, id string, _ secret.Value) (*jobs.Job, error) {
	f.mu.Lock()
	f.submits++
	n, err := f.submits, f.submitErr
	f.mu.Unlock()
	if f.entered != nil {
		f.entered <- struct{}{}
	}
	if f.block != nil {
		<-f.block
	}
	if err != nil {
		return nil, err
	}
	return &jobs.Job{ID: "J-" + id + "-" + string(rune('0'+n)), Kind: accounts.RepairResetKind}, nil
}

func (f *fakeResets) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.submits
}

// fakeMove is C9's state.
type fakeMove struct {
	r   MoveRepair
	err error
}

func (f *fakeMove) Repair(context.Context) (MoveRepair, error) { return f.r, f.err }

// resetRig is a rig with the reset wired and a live session.
func resetRig(t *testing.T) (*rig, *fakeResets, Session) {
	t.Helper()
	r := newRig(t)
	fr := &fakeResets{targets: []accounts.RepairTarget{{ID: "sub-a", Username: "alice"}, {ID: "sub-d", Username: "dora"}}}
	r.svc.d.Resets = fr
	return r, fr, r.session(t)
}

// session opens a session at the console's origin.
func (r *rig) session(t *testing.T) Session {
	t.Helper()
	cookie, err := r.redeem(r.issue(t), consoleOrigin, src)
	if err != nil {
		t.Fatal(err)
	}
	sess, ok := r.svc.Resolve(context.Background(), cookie, consoleOrigin)
	if !ok {
		t.Fatal("the session doesn't resolve")
	}
	return sess
}

func pw(s string) secret.Value { return secret.New([]byte(s)) }

// TC-321-44: once per session, nothing claimed before the confirmed
// password, the claim released on a submit failure, exactly one job from
// two concurrent resets, the WARN record and the alert, and a newer
// session resetting again.
func TestReset_TC321_44(t *testing.T) {
	ctx := context.Background()
	by := Session{}.Submitter()
	r, fr, sess := resetRig(t)

	var rc *ResetConfirm
	for _, tok := range []string{"", "tok-stale"} {
		if _, err := r.svc.Reset(ctx, sess, by, "sub-a", tok, pw("p")); !errors.As(err, &rc) ||
			rc.Target != (Target{ID: "sub-a", Name: "alice"}) || rc.Token != "tok-sub-a" {
			t.Errorf("token %q: %v %+v, want *ResetConfirm naming alice with the current token", tok, err, rc)
		}
	}
	if _, err := r.svc.Reset(ctx, sess, by, "sub-x", "", pw("p")); !errors.Is(err, accounts.ErrNotRepairTarget) {
		t.Errorf("a non-target: %v", err)
	}
	if _, err := r.svc.Reset(ctx, sess, by, "sub-a", "tok-sub-a", secret.Value{}); !errors.Is(err, ErrNoPassword) {
		t.Errorf("no password: %v", err)
	}
	for _, e := range []error{&accounts.PasswordRefused{Rule: "r", Sentence: "s."}, accounts.ErrIdentityUnavailable, errors.New("submit failed")} {
		fr.submitErr = e
		if _, err := r.svc.Reset(ctx, sess, by, "sub-a", "tok-sub-a", pw("p")); !errors.Is(err, e) {
			t.Errorf("submit error %v: %v", e, err)
		}
		if r.svc.resetUsed(sess) {
			t.Errorf("submit error %v left the reset claimed", e)
		}
	}
	fr.submitErr = nil
	if n := fr.count(); n != 3 {
		t.Errorf("%d submits before the first success, want 3 (none before a confirmed password)", n)
	}

	j, err := r.svc.Reset(ctx, sess, by, "sub-a", "tok-sub-a", pw("p"))
	if err != nil || j == nil {
		t.Fatalf("the confirmed reset: %v", err)
	}
	if got := r.svc.sessionJobs(sess); len(got) != 1 || got[0] != j.ID {
		t.Errorf("session jobs %v", got)
	}
	recs := r.events("breakglass.reset_submitted", "")
	if len(recs) != 1 || recs[0].Level != slog.LevelWarn {
		t.Fatalf("reset_submitted records: %d", len(recs))
	}
	if id, _ := logkittest.Attr(recs[0], "job_id"); id != j.ID {
		t.Errorf("job_id %q", id)
	}
	if acc, _ := logkittest.Attr(recs[0], "account_id"); acc != "sub-a" {
		t.Errorf("account_id %q", acc)
	}
	if len(r.alerts.resets) != 1 || !strings.HasSuffix(r.alerts.resets[0], "/sub-a") {
		t.Errorf("reset alerts %v", r.alerts.resets)
	}
	for _, id := range []string{"sub-a", "sub-d", "sub-x"} {
		if _, err := r.svc.Reset(ctx, sess, by, id, "tok-"+id, pw("p")); !errors.Is(err, ErrResetUsed) {
			t.Errorf("a second reset of %s: %v, want ErrResetUsed", id, err)
		}
	}

	// A newer redemption's session resets again.
	sess2 := r.session(t)
	if _, err := r.svc.Reset(ctx, sess2, by, "sub-d", "tok-sub-d", pw("p")); err != nil {
		t.Errorf("a newer session: %v", err)
	}
	// The replaced session is no longer live.
	r.svc.mu.Lock()
	r.svc.sess.reset = false
	r.svc.mu.Unlock()
	if _, err := r.svc.Reset(ctx, sess, by, "sub-d", "tok-sub-d", pw("p")); !errors.Is(err, ErrSessionEnded) {
		t.Errorf("a replaced session: %v, want ErrSessionEnded", err)
	}

	// Unwired.
	off := newRig(t)
	if _, err := off.svc.Reset(ctx, off.session(t), by, "sub-a", "", pw("p")); !errors.Is(err, ErrResetUnavailable) {
		t.Errorf("unwired: %v", err)
	}
}

// TC-321-44: two concurrent confirmed resets in one session make one job.
func TestReset_TC321_44_Concurrent(t *testing.T) {
	r, fr, sess := resetRig(t)
	fr.block, fr.entered = make(chan struct{}), make(chan struct{}, 2)
	by := Session{}.Submitter()
	errs := make(chan error, 2)
	go func() {
		_, err := r.svc.Reset(context.Background(), sess, by, "sub-a", "tok-sub-a", pw("p"))
		errs <- err
	}()
	<-fr.entered // the first holds the claim inside Submit
	_, err := r.svc.Reset(context.Background(), sess, by, "sub-d", "tok-sub-d", pw("p"))
	if !errors.Is(err, ErrResetUsed) {
		t.Errorf("the second: %v, want ErrResetUsed", err)
	}
	close(fr.block)
	if err := <-errs; err != nil {
		t.Errorf("the first: %v", err)
	}
	if fr.count() != 1 {
		t.Errorf("%d submits, want 1", fr.count())
	}
}

// TC-321-44: an alert store that fails leaves the job standing, with one
// ERROR alert=not_raised which=reset.
func TestReset_TC321_44_AlertFails(t *testing.T) {
	r, _, sess := resetRig(t)
	r.alerts.err = errors.New("store down")
	j, err := r.svc.Reset(context.Background(), sess, Session{}.Submitter(), "sub-a", "tok-sub-a", pw("p"))
	if err != nil || j == nil {
		t.Fatalf("reset: %v", err)
	}
	n := 0
	for _, rec := range r.rec.Records() {
		if w, _ := logkittest.Attr(rec, "which"); w == "reset" && rec.Level == slog.LevelError {
			if a, _ := logkittest.Attr(rec, "alert"); a == "not_raised" {
				n++
			}
		}
	}
	if n != 1 {
		t.Errorf("%d ERROR alert=not_raised which=reset records, want 1", n)
	}
}

// actionOf is the listed action id, or nil.
func actionOf(st StateView, id string) *Action {
	for i := range st.Actions {
		if st.Actions[i].ID == id {
			return &st.Actions[i]
		}
	}
	return nil
}

// TC-321-45: the reset is listed whenever wired, disabled with its own
// sentence after a reset, on a failed read (WARN) and with no targets; the
// move only while C9's state holds.
func TestState_TC321_45(t *testing.T) {
	ctx := context.Background()
	r, fr, sess := resetRig(t)
	a := actionOf(r.svc.State(ctx, sess), "reset")
	if a == nil || !a.Enabled || a.Label != "RESET THIS ADMIN'S SIGN-IN" || a.Kind != accounts.RepairResetKind ||
		len(a.Targets) != 2 || a.Targets[0] != (Target{ID: "sub-a", Name: "alice"}) {
		t.Fatalf("reset %+v", a)
	}
	b, _ := json.Marshal(a)
	if !strings.Contains(string(b), `"targets":[{"id":"sub-a","name":"alice"}`) {
		t.Errorf("reset JSON %s", b)
	}

	fr.targetErr = errors.New("identity down")
	a = actionOf(r.svc.State(ctx, sess), "reset")
	if a == nil || a.Enabled || a.Reason != "The accounts couldn't be read, so no sign-in can be reset now. If sign-in isn't running, restart it first." {
		t.Errorf("failed read: %+v", a)
	}
	if len(r.events("breakglass.targets_unread", "")) != 1 {
		t.Error("no WARN for the failed read")
	}
	fr.targetErr, fr.targets = nil, nil
	if a = actionOf(r.svc.State(ctx, sess), "reset"); a == nil || a.Enabled ||
		a.Reason != "No administrator or designated account exists on this cluster, so there is no sign-in to reset." {
		t.Errorf("no targets: %+v", a)
	}
	fr.targets = []accounts.RepairTarget{{ID: "sub-a", Username: "alice"}}
	if _, err := r.svc.Reset(ctx, sess, Session{}.Submitter(), "sub-a", "tok-sub-a", pw("p")); err != nil {
		t.Fatal(err)
	}
	if a = actionOf(r.svc.State(ctx, sess), "reset"); a == nil || a.Enabled ||
		a.Reason != "This repair session has already reset a sign-in. Make a new repair code to reset another." || len(a.Targets) != 0 {
		t.Errorf("after a reset: %+v", a)
	}

	// The move.
	fm := &fakeMove{r: MoveRepair{Holds: true, Accounts: 3, Token: "t"}}
	r.svc.d.Move = fm
	if a = actionOf(r.svc.State(ctx, sess), "move"); a == nil || !a.Enabled || a.Label != "BRING BACK THE ACCOUNTS FROM BEFORE THE UPDATE…" || a.Kind != MoveKind {
		t.Errorf("move holding: %+v", a)
	}
	fm.r.Holds = false
	if a = actionOf(r.svc.State(ctx, sess), "move"); a != nil {
		t.Errorf("move not holding: %+v", a)
	}
	fm.r.Holds, fm.err = true, errors.New("db")
	if a = actionOf(r.svc.State(ctx, sess), "move"); a != nil {
		t.Errorf("move unread: %+v", a)
	}
	if len(r.events("breakglass.move_unread", "")) != 1 {
		t.Error("no WARN for the failed move read")
	}
	if rep, err := r.svc.MoveState(ctx); err == nil {
		t.Errorf("MoveState with a failing read: %+v %v", rep, err)
	}

	off := newRig(t)
	st := off.svc.State(ctx, off.session(t))
	if actionOf(st, "reset") != nil || actionOf(st, "move") != nil {
		t.Errorf("unwired: %+v", st.Actions)
	}
	if _, err := off.svc.MoveState(ctx); !errors.Is(err, ErrMoveUnavailable) {
		t.Errorf("MoveState unwired: %v", err)
	}
	for _, act := range st.Actions {
		if strings.Contains(act.ID, "restore") {
			t.Errorf("restore listed: %+v", act)
		}
	}
}
