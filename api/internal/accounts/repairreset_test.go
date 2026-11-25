package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/pwpolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The break-glass repair reset (geekdojo/geekdojo-brain#321, C1) over the
// changes harness: the real Users, markers writer, designations and revoker
// over the fake Admin API, on a runner the kind table decides.

const repairSub = "adm"

// repairSubmitter is the repair session as a job's submitter.
var repairSubmitter = authz.RepairSession()

type repairHarness struct {
	*changeHarness
	checker *pwpolicy.Checker
	wf      jobs.Workflow
}

func newRepairHarness(t *testing.T) *repairHarness {
	t.Helper()
	h := &repairHarness{changeHarness: newChangeHarness(t)}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, flows.DenylistFile), []byte(listedPw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	if h.checker, err = pwpolicy.New(dir, flows.PasswordPolicy); err != nil {
		t.Fatal(err)
	}
	if h.wf, err = h.changes.RepairResetWorkflow(h.users, h.checker); err != nil {
		t.Fatal(err)
	}
	h.runner.Register(h.wf)
	// An administrator holding the console's admin role, app admin,
	// gear-admin, an authenticator app, a passkey, recovery codes and a
	// password, with an offline session.
	h.kc.add(person{sub: repairSub, name: "adm", email: "adm@example.invalid", enabled: true, console: []string{"admin"}, directAdmin: true,
		appRole: "admin", network: []string{"join", "gear-admin"}, actions: []any{},
		creds: []string{"password", "otp", "webauthn", "recovery-authn-codes"}, offline: map[string][]string{appUUID: {"so"}}})
	return h
}

// reset runs accounts.repair_reset for sub with the temporary password pw
// held ("" holds nothing).
func (h *repairHarness) reset(t *testing.T, sub, pw string) result {
	t.Helper()
	return h.run(t, repairSubmitter, RepairResetKind, ResetSpec{AccountID: sub}, false, pw)
}

// credsOf is sub's credential types in the fake.
func (h *repairHarness) credsOf(sub string) []string {
	h.kc.mu.Lock()
	defer h.kc.mu.Unlock()
	return slices.Clone(h.kc.users[sub].creds)
}

// actionsOf is sub's required actions in the fake.
func (h *repairHarness) actionsOf(sub string) []any {
	h.kc.mu.Lock()
	defer h.kc.mu.Unlock()
	ra, _ := h.kc.users[sub].rep["requiredActions"].([]any)
	return slices.Clone(ra)
}

// clearFailures are the clear_failed records.
func (h *repairHarness) clearFailures() []slog.Record {
	var out []slog.Record
	for _, r := range h.clog.Records() {
		if ev, _ := logkittest.Attr(r, "event"); ev == "repair_reset.clear_failed" {
			out = append(out, r)
		}
	}
	return out
}

const repairPw = "a long unlisted repair passphrase"

// TC-321-39: the steps in order, and what each leaves on the account.
func TestRepairReset_TC321_39_OrderAndEffects(t *testing.T) {
	h := newRepairHarness(t)
	r := h.reset(t, repairSub, repairPw)
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s: %s", r.job.Status, r.job.Error)
	}
	names := r.names()
	want := []string{StepClearSecondSteps, StepSetTemporary}
	for _, s := range h.rev.Steps(SecondStepsRemoved) {
		want = append(want, s.Name)
	}
	if !slices.Equal(names, want) {
		t.Errorf("steps %v, want %v", names, want)
	}
	x, ok := h.designation(t, repairSub)
	if !ok || x.ConsoleRole != "admin" || x.AppRole != AppAdmin || x.Network != authz.NetworkGearAdmin || x.Reason != ReasonRepair {
		t.Errorf("designation %+v %v", x, ok)
	}
	if got := h.credsOf(repairSub); !slices.Equal(got, []string{"password"}) {
		t.Errorf("credentials left %v, want the password alone", got)
	}
	if got := h.actionsOf(repairSub); !slices.Contains(got, any(flows.ActionRecoveryCodes)) {
		t.Errorf("required actions %v", got)
	}
	if len(h.consoleOf(repairSub)) != 0 || h.attr(repairSub, AttrAppRole) != "user" || h.attr(repairSub, AttrNetwork) != "join" {
		t.Errorf("not demoted: console %v, app %q, network %q", h.consoleOf(repairSub), h.attr(repairSub, AttrAppRole), h.attr(repairSub, AttrNetwork))
	}
	calls := h.log.all()
	des, del, after, actions, demote := index(calls, "designate"), index(calls, "delete-credential"), index(calls, "after-removal"),
		index(calls, "set-actions"), index(calls, "remove-console:admin")
	reset, logout := index(calls, "reset-password"), index(calls, "logout")
	if des < 0 || !(des < del && del < after && after < actions && actions < demote && demote < reset && reset < logout) {
		t.Errorf("order: designate %d, delete %d, markers %d, action %d, demote %d, reset-password %d, logout %d: %v",
			des, del, after, actions, demote, reset, logout, calls)
	}
	for _, e := range []string{"offline-delete:so", "console", "moved", StepApps} {
		if index(calls[reset:], e) < 0 {
			t.Errorf("%s did not follow the temporary password: %v", e, calls[reset:])
		}
	}
	if out := r.out(StepClearSecondSteps); out["outcome"] != outcomeCleared || out["credentials"] != float64(3) {
		t.Errorf("clear outcome %v", out)
	}
	if h.held.size() != 0 {
		t.Error("the password is still held")
	}
	if _, err := h.changes.RepairResetWorkflow(nil, h.checker); err == nil {
		t.Error("RepairResetWorkflow accepted no users")
	}
}

// failing fails the n-th call (1-based) matching method and path.
func failing(method, path string, n int) func(string, string) error {
	seen := 0
	return func(m, p string) error {
		if m != method || p != path {
			return nil
		}
		seen++
		if seen == n {
			return &idclient.Error{Op: "admin", Path: p, Status: http.StatusServiceUnavailable, Kind: idclient.ErrUnreachable}
		}
		return nil
	}
}

// TC-321-40 (F-321-27): each write in clear_second_steps failing in turn
// fails the job there, before set_temporary, with every level not yet
// taken still recorded and the sentence true at that stop; set_temporary's
// and the sessions' failures say what was already removed; nothing stays
// held, on success, failure and Recover alike.
func TestRepairReset_TC321_40_PartWayFailures(t *testing.T) {
	user := "/users/" + repairSub
	for _, c := range []struct {
		kind       string
		fail       func(string, string) error
		notStarted bool
	}{
		{clearFacts, failing(http.MethodGet, user+"/role-mappings/clients/"+consoleUUID+"/composite", 1), true},
		{clearCredentials, failing(http.MethodGet, user+"/credentials", 2), false},
		{clearCredentials, failing(http.MethodDelete, user+"/credentials/id-webauthn-2", 1), false},
		{clearMarkers, failing(http.MethodPut, user, 1), false},
		{clearRequiredAction, failing(http.MethodPut, user, 2), false},
		{clearDemote, failing(http.MethodDelete, user+"/role-mappings/clients/"+consoleUUID, 1), false},
		{clearDemote, failing(http.MethodPut, user, 3), false},
		{clearDemote, failing(http.MethodPut, user, 4), false},
	} {
		h := newRepairHarness(t)
		h.kc.fail = c.fail
		r := h.reset(t, repairSub, repairPw)
		want := sentenceRepairStopped
		if c.notStarted {
			want = sentenceRepairNotStarted
		}
		if r.job.Status != jobs.StatusFailed || r.job.Error != want || r.step(StepSetTemporary) != nil {
			t.Errorf("%s: job %s %q, set_temporary ran %v", c.kind, r.job.Status, r.job.Error, r.step(StepSetTemporary) != nil)
		}
		if index(h.log.all(), "reset-password") >= 0 {
			t.Errorf("%s: the temporary password was set", c.kind)
		}
		recs := h.clearFailures()
		if len(recs) != 1 || recs[0].Level != slog.LevelError {
			t.Fatalf("%s: %d clear_failed records", c.kind, len(recs))
		}
		if k, _ := logkittest.Attr(recs[0], "kind"); k != c.kind {
			t.Errorf("%s: kind %q", c.kind, k)
		}
		if !c.notStarted {
			x, ok := h.designation(t, repairSub)
			if !ok || x.Reason != ReasonRepair || x.ConsoleRole != "admin" || x.AppRole != AppAdmin || x.Network != authz.NetworkGearAdmin {
				t.Errorf("%s: designation %+v %v", c.kind, x, ok)
			}
		} else if _, ok := h.designation(t, repairSub); ok || index(h.log.all(), "delete-credential") >= 0 {
			t.Errorf("%s: something was written before the failure", c.kind)
		}
		if h.held.size() != 0 {
			t.Errorf("%s: the password is still held", c.kind)
		}
		if strings.Contains(h.clog.Text(), repairPw) {
			t.Errorf("%s: the password is in a record", c.kind)
		}
	}

	// The designation write.
	h := newRepairHarness(t)
	if err := h.designations.Close(); err != nil {
		t.Fatal(err)
	}
	if r := h.reset(t, repairSub, repairPw); r.job.Error != sentenceRepairNotStarted || index(h.log.all(), "delete-credential") >= 0 {
		t.Errorf("designation: %q", r.job.Error)
	}
	if recs := h.clearFailures(); len(recs) != 1 {
		t.Errorf("designation: %d records", len(recs))
	} else if k, _ := logkittest.Attr(recs[0], "kind"); k != clearDesignation {
		t.Errorf("designation: kind %q", k)
	}

	// set_temporary and the sessions.
	never := []string{"Nothing was changed.", "Start the reset again.", "Try again."}
	check := func(what string, r result, want string) {
		t.Helper()
		if r.job.Status != jobs.StatusFailed || r.job.Error != want {
			t.Errorf("%s: %s %q, want %q", what, r.job.Status, r.job.Error, want)
		}
		for _, n := range never {
			if strings.Contains(r.job.Error, n) {
				t.Errorf("%s: says %q", what, n)
			}
		}
	}
	status := func(code int) func(string, string) error {
		return func(_, p string) error {
			if strings.HasSuffix(p, "/reset-password") {
				return &idclient.Error{Op: "admin", Path: p, Status: code, Kind: idclient.ErrProtocol}
			}
			return nil
		}
	}
	h = newRepairHarness(t)
	h.kc.fail = status(http.StatusBadRequest)
	check("a fault", h.reset(t, repairSub, repairPw), sentenceRepairNotSet)
	h = newRepairHarness(t)
	h.kc.fail = status(http.StatusInternalServerError)
	check("a policy 500", h.reset(t, repairSub, listedPw),
		"This person's second steps, recovery codes and roles were removed, but the temporary password was refused: "+
			"That password is too common. Choose another. Make a new repair code and reset their sign-in again with another password.")
	h = newRepairHarness(t)
	check("nothing held", h.reset(t, repairSub, ""), sentenceRepairNotSet)
	h = newRepairHarness(t)
	h.kc.fail = func(_, p string) error {
		if strings.HasSuffix(p, "/logout") {
			return &idclient.Error{Op: "admin", Path: p, Status: 503, Kind: idclient.ErrUnreachable}
		}
		return nil
	}
	check("the sessions", h.reset(t, repairSub, repairPw), sentenceRepairSessions)

	// Recover drops what an orphaned job held.
	orphan := &jobs.Job{ID: "orphan-r", Kind: RepairResetKind, Spec: json.RawMessage(`{"accountId":"adm"}`), Status: jobs.StatusRunning,
		CreatedBy: "break-glass", CreatedAt: time.Now().UTC()}
	if err := h.jobs.CreateJob(t.Context(), orphan); err != nil {
		t.Fatal(err)
	}
	v := secret.New([]byte("orphaned"))
	h.held.Put(orphan.ID, v)
	if err := h.runner.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v.Len() != 0 || h.held.size() != 0 {
		t.Error("Recover left the orphan's password held")
	}
}

// TC-321-41: a row already at the same or a higher level keeps its reason
// and levels; an account with no privileged level gets no row. (Reason
// reset for remove_second_steps and accounts.reset_password: TC-994-02 and
// TC-992-41, unchanged but for the reason argument.)
func TestRepairReset_TC321_41_KeepTheHigher(t *testing.T) {
	for _, reason := range []Reason{ReasonWaiting, ReasonMoved} {
		h := newRepairHarness(t)
		prior := Designation{Sub: repairSub, ConsoleRole: "admin", AppRole: AppAdmin, Network: authz.NetworkGearAdmin, Reason: reason}
		if err := h.designations.Designate(t.Context(), prior); err != nil {
			t.Fatal(err)
		}
		if r := h.reset(t, repairSub, repairPw); r.job.Status != jobs.StatusSucceeded {
			t.Fatalf("%s: %s", reason, r.job.Error)
		}
		x, _ := h.designation(t, repairSub)
		if x.Reason != reason || x.ConsoleRole != "admin" || x.AppRole != AppAdmin || x.Network != authz.NetworkGearAdmin {
			t.Errorf("%s: %+v", reason, x)
		}
	}
	h := newRepairHarness(t)
	if r := h.reset(t, target, repairPw); r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("no levels: %s", r.job.Error)
	}
	if _, ok := h.designation(t, target); ok {
		t.Error("an account holding no privileged level was designated")
	}
}

// resets builds RepairResets over the harness, submitting through sub.
func (h *repairHarness) resets(t *testing.T, sub Submitter, checker PasswordChecker) *RepairResets {
	t.Helper()
	r, err := NewRepairResets(RepairResetsDeps{Admins: h.users, Designations: h.designations, Users: h.users, Checker: checker,
		Runner: sub, Held: h.held, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TC-321-42: Targets is the administrators and the designated accounts,
// each once, without an id the realm lacks, by sign-in name; a failed read
// is an error, never a shorter list.
func TestRepairResets_TC321_42_Targets(t *testing.T) {
	h := newRepairHarness(t)
	h.kc.add(person{sub: "admin-c", name: "adminc", email: "c@example.invalid", enabled: false, console: []string{"admin"}, directAdmin: true})
	for _, sub := range []string{"gone", adminA, target} {
		if err := h.designations.Designate(t.Context(), Designation{Sub: sub, ConsoleRole: "operator", Reason: ReasonMoved}); err != nil {
			t.Fatal(err)
		}
	}
	rs := h.resets(t, h.runner, h.checker)
	got, err := rs.Targets(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range got {
		names = append(names, x.Username+"="+x.ID)
	}
	want := []string{"adm=adm", "admina=admin-a", "adminb=admin-b", "adminc=admin-c", "targetname=target-sub"}
	if !slices.Equal(names, want) {
		t.Errorf("targets %v, want %v", names, want)
	}
	for what, fail := range map[string]func(string, string) error{
		"the administrators":   failing(http.MethodGet, "/clients/"+consoleUUID+"/roles/admin/users?briefRepresentation=false&first=0&max=1000", 1),
		"a designated account": failing(http.MethodGet, "/users/"+target, 1),
	} {
		h.kc.fail = fail
		if got, err := rs.Targets(t.Context()); err == nil {
			t.Errorf("%s failing: %v, want an error", what, got)
		}
	}
	h.kc.fail = nil
	h.kc.fail = failing(http.MethodGet, "/clients/"+consoleUUID+"/roles/admin/users?briefRepresentation=false&first=0&max=1000", 1)
	if _, _, err := rs.Confirm(t.Context(), adminA); !errors.Is(err, ErrIdentityUnavailable) {
		t.Errorf("Confirm over a failed read: %v", err)
	}
	if _, err := NewRepairResets(RepairResetsDeps{}); err == nil {
		t.Error("NewRepairResets accepted no collaborators")
	}
}

// TC-321-43: Confirm's token; Submit's policy refusals, the exact spec, the
// held copy, and nothing held after a failed submit.
func TestRepairResets_TC321_43_ConfirmAndSubmit(t *testing.T) {
	h := newRepairHarness(t)
	var gotKind string
	var gotSpec []byte
	var gotBy authz.Submitter
	var submitErr error
	sub := submitterFunc(func(_ context.Context, by authz.Submitter, kind string, spec any, prepare func(string) error) (*jobs.Job, error) {
		gotKind, gotBy = kind, by
		gotSpec, _ = json.Marshal(spec)
		if err := prepare("job-1"); err != nil {
			return nil, err
		}
		if submitErr != nil {
			return nil, submitErr
		}
		return &jobs.Job{ID: "job-1"}, nil
	})
	rs := h.resets(t, sub, h.checker)
	tg, tok, err := rs.Confirm(t.Context(), repairSub)
	if err != nil || tg != (RepairTarget{ID: repairSub, Username: "adm"}) ||
		tok != repairToken(RepairTarget{ID: repairSub, Username: "adm"}) || len(tok) != 64 {
		t.Errorf("Confirm: %+v %q %v", tg, tok, err)
	}
	if _, _, err := rs.Confirm(t.Context(), target); !errors.Is(err, ErrNotRepairTarget) {
		t.Errorf("a non-target: %v", err)
	}

	var refused *PasswordRefused
	if _, err := rs.Submit(t.Context(), repairSubmitter, repairSub, secret.New([]byte(listedPw))); !errors.As(err, &refused) ||
		refused.Sentence != "That password is too common. Choose another." || gotKind != "" || h.held.size() != 0 {
		t.Errorf("a refused password: %v, submitted %q, held %d", err, gotKind, h.held.size())
	}
	unread, err := pwpolicy.New(t.TempDir(), flows.PasswordPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resets(t, sub, unread).Submit(t.Context(), repairSubmitter, repairSub, secret.New([]byte(repairPw))); !errors.Is(err, ErrPasswordCheckUnavailable) {
		t.Errorf("an unreadable list: %v", err)
	}
	if _, err := rs.Submit(t.Context(), repairSubmitter, "nobody", secret.New([]byte(repairPw))); !errors.Is(err, ErrNotRepairTarget) {
		t.Errorf("no such account: %v", err)
	}
	h.kc.fail = failing(http.MethodGet, "/users/"+repairSub, 1)
	if _, err := rs.Submit(t.Context(), repairSubmitter, repairSub, secret.New([]byte(repairPw))); !errors.Is(err, ErrIdentityUnavailable) {
		t.Errorf("identity down: %v", err)
	}
	h.kc.fail = nil

	j, err := rs.Submit(t.Context(), repairSubmitter, repairSub, secret.New([]byte(repairPw)))
	if err != nil || j.ID != "job-1" {
		t.Fatalf("Submit: %v", err)
	}
	if gotKind != RepairResetKind || string(gotSpec) != `{"accountId":"adm"}` || gotBy.CreatedBy() != "break-glass" {
		t.Errorf("submitted %s %s by %s", gotKind, gotSpec, gotBy.CreatedBy())
	}
	if v, ok := h.held.Take("job-1"); !ok || string(v.Reveal()) != repairPw {
		t.Error("the password is not held under the job")
	}
	submitErr = errors.New("ledger down")
	if _, err := rs.Submit(t.Context(), repairSubmitter, repairSub, secret.New([]byte(repairPw))); err == nil || h.held.size() != 0 {
		t.Errorf("a failed submit: %v, held %d", err, h.held.size())
	}
}

// TC-321-53 (the new part): Administrators reads every admin holder with
// its name and state; EnabledAdmins counts the enabled ones over it; a full
// page is an error. AddRequiredAction leaves a pending action alone.
func TestUsers_TC321_53_AdministratorsAndRequiredAction(t *testing.T) {
	h := newRepairHarness(t)
	h.kc.add(person{sub: "admin-c", name: "adminc", email: "c@example.invalid", enabled: false, console: []string{"admin"}, directAdmin: true})
	admins, err := h.users.Administrators(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(admins, func(a, b Account) int { return strings.Compare(a.ID, b.ID) })
	var got []string
	for _, a := range admins {
		got = append(got, a.ID+"/"+a.Username+"/"+map[bool]string{true: "on", false: "off"}[a.Enabled])
	}
	if want := []string{"adm/adm/on", "admin-a/admina/on", "admin-b/adminb/on", "admin-c/adminc/off"}; !slices.Equal(got, want) {
		t.Errorf("administrators %v, want %v", got, want)
	}
	if n, err := h.users.EnabledAdmins(t.Context()); err != nil || n != 3 {
		t.Errorf("EnabledAdmins = %d, %v; want 3", n, err)
	}
	h.kc.fullPage = true
	if _, err := h.users.Administrators(t.Context()); err == nil {
		t.Error("a full page read as a list")
	}
	if _, err := h.users.EnabledAdmins(t.Context()); err == nil {
		t.Error("a full page read as a count")
	}
	h.kc.fullPage = false

	if err := h.users.AddRequiredAction(t.Context(), repairSub, flows.ActionRecoveryCodes); err != nil {
		t.Fatal(err)
	}
	before := len(h.log.only("set-actions"))
	if err := h.users.AddRequiredAction(t.Context(), repairSub, flows.ActionRecoveryCodes); err != nil || len(h.log.only("set-actions")) != before {
		t.Errorf("a pending action was written again: %v", err)
	}
	if err := h.users.AddRequiredAction(t.Context(), repairSub, ""); err == nil {
		t.Error("an empty action was accepted")
	}
	h.kc.keepNothing = true
	h.kc.mu.Lock()
	h.kc.users[target].rep["requiredActions"] = []any{}
	h.kc.mu.Unlock()
	h.kc.fail = failing(http.MethodPut, "/users/"+target, 1)
	if err := h.users.AddRequiredAction(t.Context(), target, flows.ActionRecoveryCodes); err == nil {
		t.Error("a failed write was not an error")
	}
}
