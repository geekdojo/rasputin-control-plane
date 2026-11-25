package accounts

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The administrator's password reset re-designates a privileged target
// (geekdojo/geekdojo-brain#992 PR B), over #994's change harness: the real
// Users, designations, grant and runner over the fake Admin API.

const (
	privTarget = "priv"
	resetPw    = "a long temporary passphrase"
)

type redesignateHarness struct {
	*changeHarness
	reclog *logkittest.Recorder
}

func newRedesignateHarness(t *testing.T) *redesignateHarness {
	t.Helper()
	h := &redesignateHarness{changeHarness: newChangeHarness(t)}
	redes, err := NewRedesignator(RedesignatorDeps{Facts: h.factsC, Designations: recDes{inner: h.designations, log: h.log},
		Users: h.users, Lock: h.lock})
	if err != nil {
		t.Fatal(err)
	}
	slogger, rec := logkittest.New()
	h.reclog = rec
	wf, err := ResetPasswordWorkflow(ResetDeps{Users: h.users, Held: h.held, Checker: acceptAll{}, Revoker: h.rev, Redesignate: redes,
		Lock: h.lock, Log: slogger, StepTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	h.runner.Register(wf)
	// An operator who is also an app and gear administrator, with a
	// complete setup (C29) and an offline session.
	h.kc.add(person{sub: privTarget, name: "priv", email: "priv@example.invalid", enabled: true, console: []string{"operator"},
		roles: []string{"operator"}, appRole: "admin", network: []string{"join", "gear-admin"}, actions: []any{},
		creds: completeCreds, offline: map[string][]string{appUUID: {"sp"}}})
	return h
}

func (h *redesignateHarness) reset(t *testing.T, sub string) result {
	t.Helper()
	return h.run(t, adminSubmitter, ResetKind, ResetSpec{AccountID: sub}, false, resetPw)
}

func (h *redesignateHarness) events(ev string) []slog.Record {
	var out []slog.Record
	for _, r := range h.reclog.Records() {
		if got, _ := logkittest.Attr(r, "event"); got == ev {
			out = append(out, r)
		}
	}
	return out
}

// TC-992-41: a privileged target's privileged levels are recorded as its
// designation, reason reset, and taken away (console role off, app admin to
// user, gear-admin out); once its setup is complete,
// accounts.grant_designated_role returns every one and clears the
// designation.
func TestResetRedesignate_TC992_41_PrivilegedTargetDesignatedAndRestored(t *testing.T) {
	h := newRedesignateHarness(t)
	r := h.reset(t, privTarget)
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s %q", r.job.Status, r.job.Error)
	}
	if out := r.out(StepRedesignate); out["outcome"] != outcomeDesignated || out["console"] != "operator" || out["app"] != true || out["gear"] != true {
		t.Errorf("redesignate recorded %v", out)
	}
	x, ok := h.designation(t, privTarget)
	if !ok || x.ConsoleRole != "operator" || x.AppRole != AppAdmin || x.Network != "gear-admin" || x.Reason != ReasonReset {
		t.Errorf("designation %+v (found %v)", x, ok)
	}
	if len(h.consoleOf(privTarget)) != 0 || h.attr(privTarget, AttrAppRole) != "user" || h.attr(privTarget, AttrNetwork) != "join" {
		t.Errorf("not demoted: console %v, app %q, network %q",
			h.consoleOf(privTarget), h.attr(privTarget, AttrAppRole), h.attr(privTarget, AttrNetwork))
	}

	h.complete(privTarget)
	g := h.grant(t, privTarget)
	if g.job.Status != jobs.StatusSucceeded || g.outcome(t, StepGrantRole) != outcomeGranted {
		t.Fatalf("grant %s %q, outcome %q", g.job.Status, g.job.Error, g.outcome(t, StepGrantRole))
	}
	if !slices.Contains(h.consoleOf(privTarget), "operator") || h.attr(privTarget, AttrAppRole) != "admin" ||
		h.attr(privTarget, AttrNetwork) != "join,gear-admin" {
		t.Errorf("not restored: console %v, app %q, network %q",
			h.consoleOf(privTarget), h.attr(privTarget, AttrAppRole), h.attr(privTarget, AttrNetwork))
	}
	if _, ok := h.designation(t, privTarget); ok {
		t.Error("the grant left the designation")
	}
}

// TC-992-42: a target holding no privileged level (a viewer with app
// access) is left alone: redesignate records not_needed, no designation is
// written and no role changes.
func TestResetRedesignate_TC992_42_NonPrivilegedTargetUntouched(t *testing.T) {
	h := newRedesignateHarness(t)
	r := h.reset(t, target)
	if r.job.Status != jobs.StatusSucceeded || r.outcome(t, StepRedesignate) != outcomeNotNeeded {
		t.Fatalf("job %s %q, redesignate %q", r.job.Status, r.job.Error, r.outcome(t, StepRedesignate))
	}
	if _, ok := h.designation(t, target); ok || index(h.log.all(), "designate") >= 0 {
		t.Errorf("a designation was written: %v", h.log.all())
	}
	for _, w := range h.writes() {
		if strings.HasPrefix(w, "remove-console") || strings.HasPrefix(w, "set-attr") || strings.HasPrefix(w, "set-"+AttrNetwork) {
			t.Errorf("a role was written: %v", h.writes())
		}
	}
	if !slices.Equal(h.consoleOf(target), []string{"viewer"}) || h.attr(target, AttrAppRole) != "user" {
		t.Errorf("roles changed: console %v, app %q", h.consoleOf(target), h.attr(target, AttrAppRole))
	}
}

// TC-992-43: the steps run set_temporary, redesignate, then #991's
// sign_out steps; the password is set before the designation is written,
// the designation before any role is taken, and every role is taken before
// the first session ends.
func TestResetRedesignate_TC992_43_StepOrder(t *testing.T) {
	h := newRedesignateHarness(t)
	r := h.reset(t, privTarget)
	want := []string{StepSetTemporary, StepRedesignate}
	for _, s := range h.rev.Steps(SignOut) {
		want = append(want, s.Name)
	}
	if !slices.Equal(r.names(), want) {
		t.Errorf("steps %v, want %v", r.names(), want)
	}
	calls := h.log.all()
	order := []string{"reset-password", "designate", "remove-console:operator", "set-attr:user", "set-" + AttrNetwork, "logout", "offline-delete:sp", "console"}
	last := -1
	for _, c := range order {
		i := index(calls, c)
		if i <= last {
			t.Errorf("%s at %d, not after the previous call (%d): %v", c, i, last, calls)
		}
		last = i
	}
}

// TC-992-44: redesignate's failure stops the job with its sentence and an
// ERROR reset.redesignate_failed record carrying the job id and the error
// kind, never the account. The temporary password stays set and no session
// is ended. A facts read that fails records and takes nothing; a demotion
// that fails part way leaves the designation recorded and the roles not
// yet taken still held.
func TestResetRedesignate_TC992_44_FailureLeavesDesignationAndSessions(t *testing.T) {
	h := newRedesignateHarness(t)
	h.factsC.err = errors.New("facts unavailable")
	r := h.reset(t, privTarget)
	if r.job.Status != jobs.StatusFailed || r.job.Error != sentenceRedesignate {
		t.Fatalf("facts failure: job %s %q", r.job.Status, r.job.Error)
	}
	if _, ok := h.designation(t, privTarget); ok || len(h.consoleOf(privTarget)) != 1 {
		t.Errorf("facts failure changed something: designation %v, console %v", ok, h.consoleOf(privTarget))
	}

	h = newRedesignateHarness(t)
	h.kc.fail = func(method, path string) error {
		if method == http.MethodPut && strings.HasSuffix(path, "/users/"+privTarget) {
			return errors.New("the attribute write failed")
		}
		return nil
	}
	r = h.reset(t, privTarget)
	if r.job.Status != jobs.StatusFailed || r.job.Error != sentenceRedesignate {
		t.Fatalf("demotion failure: job %s %q", r.job.Status, r.job.Error)
	}
	if index(h.log.all(), "reset-password") < 0 {
		t.Error("the temporary password was not set")
	}
	if got := h.log.only("logout", "offline-delete", "console"); len(got) != 0 {
		t.Errorf("sessions ended after a failed redesignate: %v", got)
	}
	if x, ok := h.designation(t, privTarget); !ok || x.ConsoleRole != "operator" || x.AppRole != AppAdmin || x.Network != "gear-admin" {
		t.Errorf("designation %+v (found %v)", x, ok)
	}
	if len(h.consoleOf(privTarget)) != 0 || h.attr(privTarget, AttrAppRole) != "admin" {
		t.Errorf("console %v, app %q: want the console role taken and app admin still held", h.consoleOf(privTarget), h.attr(privTarget, AttrAppRole))
	}
	recs := h.events("reset.redesignate_failed")
	if len(recs) != 1 || recs[0].Level != slog.LevelError {
		t.Fatalf("records %v", recs)
	}
	if id, _ := logkittest.Attr(recs[0], "job_id"); id != r.job.ID {
		t.Errorf("job_id %q, want %q", id, r.job.ID)
	}
	if k, ok := logkittest.Attr(recs[0], "kind"); !ok || k == "" {
		t.Error("no kind on the record")
	}
	recs[0].Attrs(func(a slog.Attr) bool {
		if strings.Contains(a.Value.String(), privTarget) {
			t.Errorf("the record names the account: %s=%s", a.Key, a.Value)
		}
		return true
	})
}

// TC-992-45: redesignate is safe to run again. The runner never retries it
// (Retries 0) and Recover fails a job rather than resuming it, so a retry
// is a second reset: after a part-way failure it takes what is left with
// the designation unchanged; on a target already set aside it records
// not_needed and keeps the designation.
func TestResetRedesignate_TC992_45_IdempotentOnRetry(t *testing.T) {
	h := newRedesignateHarness(t)
	h.kc.fail = func(method, path string) error {
		if method == http.MethodPut && strings.HasSuffix(path, "/users/"+privTarget) {
			return errors.New("the attribute write failed")
		}
		return nil
	}
	if r := h.reset(t, privTarget); r.job.Status != jobs.StatusFailed {
		t.Fatalf("first reset %s", r.job.Status)
	}
	first, _ := h.designation(t, privTarget)
	h.kc.mu.Lock()
	h.kc.fail = nil
	h.kc.mu.Unlock()

	r := h.reset(t, privTarget)
	if r.job.Status != jobs.StatusSucceeded || r.outcome(t, StepRedesignate) != outcomeDesignated {
		t.Fatalf("second reset %s %q, redesignate %q", r.job.Status, r.job.Error, r.outcome(t, StepRedesignate))
	}
	if x, _ := h.designation(t, privTarget); x != first {
		t.Errorf("designation changed on retry: %+v, was %+v", x, first)
	}
	if len(h.consoleOf(privTarget)) != 0 || h.attr(privTarget, AttrAppRole) != "user" || h.attr(privTarget, AttrNetwork) != "join" {
		t.Errorf("not demoted: console %v, app %q, network %q",
			h.consoleOf(privTarget), h.attr(privTarget, AttrAppRole), h.attr(privTarget, AttrNetwork))
	}

	r = h.reset(t, privTarget)
	if r.job.Status != jobs.StatusSucceeded || r.outcome(t, StepRedesignate) != outcomeNotNeeded {
		t.Fatalf("third reset %s %q, redesignate %q", r.job.Status, r.job.Error, r.outcome(t, StepRedesignate))
	}
	if x, ok := h.designation(t, privTarget); !ok || x != first {
		t.Errorf("designation after a reset of a set-aside account: %+v (found %v), want %+v", x, ok, first)
	}
}

// NewRedesignator and ResetPasswordWorkflow refuse a missing collaborator.
func TestNewRedesignator_RefusesNil(t *testing.T) {
	if _, err := NewRedesignator(RedesignatorDeps{}); err == nil {
		t.Error("NewRedesignator accepted no collaborators")
	}
	h := newRedesignateHarness(t)
	if _, err := ResetPasswordWorkflow(ResetDeps{Users: h.users, Held: h.held, Checker: acceptAll{}, Revoker: h.rev, Lock: h.lock,
		Log: slog.New(slog.DiscardHandler), StepTimeout: time.Minute}); err == nil {
		t.Error("ResetPasswordWorkflow accepted no Redesignate")
	}
}
