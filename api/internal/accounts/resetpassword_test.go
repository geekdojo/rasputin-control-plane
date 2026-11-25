package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/pwpolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	resetTarget = "sub-bob"
	resetAdmin  = "sub-alice"
	goodPw      = "a long unlisted passphrase"
	listedPw    = "correcthorsebatterystaple"
)

type noApps struct{}

func (noApps) AppFacts(context.Context, string, string) (authz.AppFacts, error) {
	return authz.AppFacts{}, errors.New("no apps here")
}

// resetHarness is the accounts harness with the reset registered on an
// authorized runner (the kind table decides SubmitFor), a real policy
// checker over a staged list, and Held.
type resetHarness struct {
	*harness
	held    *Held
	checker *pwpolicy.Checker
	runner  *jobs.Runner
	wf      jobs.Workflow
	rlog    *logkittest.Recorder
	action  *ResetAction
}

func newResetHarness(t *testing.T) *resetHarness {
	t.Helper()
	h := &resetHarness{harness: newHarness(t), held: NewHeld()}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, flows.DenylistFile), []byte(listedPw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	if h.checker, err = pwpolicy.New(dir, flows.PasswordPolicy); err != nil {
		t.Fatal(err)
	}
	kp, err := authz.NewKindPolicy(noApps{})
	if err != nil {
		t.Fatal(err)
	}
	slogger, rec := logkittest.New()
	h.rlog = rec
	if h.wf, err = ResetPasswordWorkflow(ResetDeps{Users: h.users, Held: h.held, Checker: h.checker, Revoker: h.rev,
		Log: slogger, StepTimeout: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if h.runner, err = jobs.NewAuthorizedRunner(h.jobs, h.nc, kp); err != nil {
		t.Fatal(err)
	}
	h.runner.Register(h.wf)
	if h.action, err = NewResetAction(h.runner, h.held); err != nil {
		t.Fatal(err)
	}
	h.kc.add(person{sub: resetTarget, name: "bob-longname", email: "bob@example.org", enabled: true,
		offline: map[string][]string{appUUID: {"off-1"}}})
	h.kc.add(person{sub: resetAdmin, name: "alice", email: "alice@example.org", enabled: true, console: []string{"admin"}})
	return h
}

func admin() auth.Principal {
	return auth.Principal{Sub: resetAdmin, Name: "alice", Roles: []string{"admin"}}
}

// runReset submits the reset through the action, as the fresh sign-in's
// return does, and waits for it.
func (h *resetHarness) runReset(t *testing.T, pw string) result {
	t.Helper()
	pl := &ResetPayload{Target: resetTarget, Password: secret.New([]byte(pw))}
	next, err := h.action.Run(t.Context(), admin(), pl)
	pl.Destroy()
	if err != nil || !strings.HasPrefix(next, "/tasks?id=") {
		t.Fatalf("Run = %q, %v", next, err)
	}
	h.runner.Wait()
	return h.result(t, strings.TrimPrefix(next, "/tasks?id="))
}

func (h *resetHarness) resets() int {
	n := 0
	for _, c := range h.log.all() {
		if c == "reset-password" {
			n++
		}
	}
	return n
}

func (h *resetHarness) event(ev string) []slog.Record {
	var out []slog.Record
	for _, r := range h.rlog.Records() {
		if got, _ := logkittest.Attr(r, "event"); got == ev {
			out = append(out, r)
		}
	}
	return out
}

// TC-992-19: the submitted spec is exactly {"accountId":"<id>"}; the
// password is in Held under the job id until set_temporary takes it, and
// the ledger's stored spec never holds it.
func TestResetAction_TC992_19_SpecHoldsNoPassword(t *testing.T) {
	h := newResetHarness(t)
	var heldAtPrepare string
	spy := submitterFunc(func(ctx context.Context, by authz.Submitter, kind string, spec any, prepare func(string) error) (*jobs.Job, error) {
		return h.runner.SubmitFor(ctx, by, kind, spec, func(id string) error {
			err := prepare(id)
			h.held.mu.Lock()
			v := h.held.m[id]
			h.held.mu.Unlock()
			heldAtPrepare = string(v.Reveal())
			return err
		})
	})
	a, _ := NewResetAction(spy, h.held)
	pl := &ResetPayload{Target: resetTarget, Password: secret.New([]byte(goodPw))}
	next, err := a.Run(t.Context(), admin(), pl)
	if err != nil {
		t.Fatal(err)
	}
	pl.Destroy() // the sign-in destroys the payload after Run; Held keeps its own copy
	h.runner.Wait()
	if heldAtPrepare != goodPw {
		t.Errorf("held at prepare %q", heldAtPrepare)
	}
	r := h.result(t, strings.TrimPrefix(next, "/tasks?id="))
	if string(r.job.Spec) != `{"accountId":"`+resetTarget+`"}` {
		t.Errorf("spec %s", r.job.Spec)
	}
	if r.job.Status != jobs.StatusSucceeded || h.resets() != 1 {
		t.Fatalf("job %s (%s), resets %d", r.job.Status, r.job.Error, h.resets())
	}
	for _, req := range h.kc.reqs {
		if strings.HasSuffix(req.path, "/reset-password") {
			var b map[string]any
			_ = json.Unmarshal(req.body, &b)
			if b["value"] != goodPw || b["temporary"] != true || b["type"] != "password" {
				t.Errorf("reset-password body %v", b)
			}
		}
	}
	// r.job is read back from the ledger: its Spec is the stored bytes.
	if strings.Contains(string(r.job.Spec), goodPw) || strings.Contains(h.rlog.Text(), goodPw) || strings.Contains(h.rec.Text(), goodPw) {
		t.Error("the password reached the ledger or a log")
	}
	if h.held.size() != 0 {
		t.Errorf("%d values still held", h.held.size())
	}
}

type submitterFunc func(ctx context.Context, by authz.Submitter, kind string, spec any, prepare func(string) error) (*jobs.Job, error)

func (f submitterFunc) SubmitFor(ctx context.Context, by authz.Submitter, kind string, spec any, prepare func(string) error) (*jobs.Job, error) {
	return f(ctx, by, kind, spec, prepare)
}

// TC-992-20: set_temporary's outcomes, each tried once.
func TestSetTemporary_TC992_20_Outcomes(t *testing.T) {
	// status fails reset-password with code, counting each attempt in the
	// call log as the fake's own reset does.
	var h *resetHarness
	status := func(code int) func(method, path string) error {
		return func(method, path string) error {
			if strings.HasSuffix(path, "/reset-password") {
				h.log.add("reset-password")
				kind := idclient.ErrProtocol
				if code >= 500 {
					kind = idclient.ErrUnreachable
				}
				return &idclient.Error{Op: "admin", Path: path, Status: code, Kind: kind}
			}
			return nil
		}
	}
	t.Run("204 moves on", func(t *testing.T) {
		h := newResetHarness(t)
		r := h.runReset(t, goodPw)
		if r.job.Status != jobs.StatusSucceeded || r.step(StepSetTemporary).Status != jobs.StepSucceeded || r.step(StepOnlineSessions) == nil {
			t.Errorf("job %s %s", r.job.Status, r.job.Error)
		}
	})
	t.Run("500 with a policy rule", func(t *testing.T) {
		h2 := newResetHarness(t)
		h = h2
		h2.kc.fail = status(500)
		r := h2.runReset(t, listedPw)
		if r.job.Status != jobs.StatusFailed || r.job.Error != "That password is too common. Choose another." || h2.resets() != 1 {
			t.Errorf("job %s %q resets %d", r.job.Status, r.job.Error, h2.resets())
		}
		recs := h2.event("reset.refused_by_policy")
		if len(recs) != 1 || recs[0].Level != slog.LevelWarn {
			t.Errorf("log %s", h2.rlog.Text())
		}
		if r.step(StepOnlineSessions) != nil {
			t.Error("the sessions steps ran after a refusal")
		}
	})
	t.Run("500 with no rule", func(t *testing.T) {
		h = newResetHarness(t)
		h.kc.fail = status(500)
		r := h.runReset(t, goodPw)
		if r.job.Error != "The sign-in service couldn't set the temporary password. Nothing was changed." || h.resets() != 1 {
			t.Errorf("job %q resets %d", r.job.Error, h.resets())
		}
		recs := h.event("reset.set_failed")
		if len(recs) != 1 || recs[0].Level != slog.LevelError {
			t.Fatalf("log %s", h.rlog.Text())
		}
		if s, _ := logkittest.Attr(recs[0], "status"); s != "500" {
			t.Errorf("status %s", s)
		}
	})
	t.Run("another status", func(t *testing.T) {
		h = newResetHarness(t)
		h.kc.fail = status(http.StatusBadRequest)
		r := h.runReset(t, goodPw)
		if r.job.Error != sentenceSetFailed || h.resets() != 1 {
			t.Errorf("job %q resets %d", r.job.Error, h.resets())
		}
		if recs := h.event("reset.set_failed"); len(recs) != 1 || recs[0].Level != slog.LevelError {
			t.Errorf("log %s", h.rlog.Text())
		}
	})
	t.Run("nothing held", func(t *testing.T) {
		h := newResetHarness(t)
		j, err := h.runner.SubmitFor(t.Context(), admin().Submitter(), ResetKind, ResetSpec{AccountID: resetTarget}, nil)
		if err != nil {
			t.Fatal(err)
		}
		h.runner.Wait()
		r := h.result(t, j.ID)
		if r.job.Error != "The temporary password is no longer held. Start the reset again." || h.resets() != 0 {
			t.Errorf("job %q resets %d", r.job.Error, h.resets())
		}
	})
	for _, s := range []int{0, 204, 400} {
		if statusText(s) == "" {
			t.Errorf("statusText(%d) is empty", s)
		}
	}
}

// TC-992-21: the embedded sign_out steps end the target's online and
// offline identity sessions and its console sessions, in #991's order, and
// their failure is #991's sentence; the terminal hook destroys a held value
// on success, failure and Recover.
func TestResetWorkflow_TC992_21_EndSessionsAndCleanup(t *testing.T) {
	h := newResetHarness(t)
	if _, err := h.console.Create(t.Context(), auth.Principal{Sub: resetTarget, Session: auth.SessionRef{SID: "sid-b"}}); err != nil {
		t.Fatal(err)
	}
	r := h.runReset(t, goodPw)
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s %q", r.job.Status, r.job.Error)
	}
	got := h.log.only("reset-password", "logout", "offline-delete", "console")
	want := []string{"reset-password", "logout", "offline-delete:off-1", "console"}
	if len(got) != len(want) {
		t.Fatalf("effects %v, want %v", got, want)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("effects %v, want %v", got, want)
		}
	}
	if n, _ := h.console.EndBySub(t.Context(), resetTarget); n != 0 {
		t.Errorf("%d console sessions left", n)
	}

	h2 := newResetHarness(t)
	h2.kc.fail = func(method, path string) error {
		if strings.HasSuffix(path, "/logout") {
			return &idclient.Error{Op: "admin", Path: path, Status: 503, Kind: idclient.ErrUnreachable}
		}
		return nil
	}
	if r := h2.runReset(t, goodPw); r.job.Error != SentenceSessions {
		t.Errorf("a failed session end: %q, want %q", r.job.Error, SentenceSessions)
	}

	// The hook: success and failure leave nothing held, and Recover
	// destroys what an orphaned job held.
	for _, ok := range []bool{true, false} {
		v := secret.New([]byte("x"))
		h.held.Put("j-"+map[bool]string{true: "ok", false: "fail"}[ok], v)
		h.wf.OnTerminal(t.Context(), "j-"+map[bool]string{true: "ok", false: "fail"}[ok], ok, "")
		if v.Len() != 0 {
			t.Errorf("success %v: the held value survived the hook", ok)
		}
	}
	orphan := &jobs.Job{ID: "orphan-1", Kind: ResetKind, Spec: json.RawMessage(`{"accountId":"x"}`), Status: jobs.StatusRunning,
		CreatedBy: resetAdmin, CreatedAt: time.Now().UTC()}
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
	if _, err := ResetPasswordWorkflow(ResetDeps{}); err == nil {
		t.Error("ResetPasswordWorkflow accepted no collaborators")
	}
	d := ResetDeps{Users: h.users, Held: h.held, Checker: h.checker, Revoker: h.rev, Log: slog.New(slog.DiscardHandler)}
	if _, err := ResetPasswordWorkflow(d); err == nil {
		t.Error("ResetPasswordWorkflow accepted no step timeout")
	}
}

// Resetter.Check's order and answers (the endpoint half is TC-992-18).
func TestResetter_Check(t *testing.T) {
	h := newResetHarness(t)
	kp, _ := authz.NewKindPolicy(noApps{})
	log, rec := logkittest.New()
	rs, err := NewResetter(ResetterDeps{Authorizer: kp, Users: h.users, Checker: h.checker, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	by := admin().Submitter()
	pw := func(s string) secret.Value { return secret.New([]byte(s)) }
	var kr *authz.KindRefusal
	if err := rs.Check(t.Context(), by, resetAdmin, pw(goodPw)); !errors.As(err, &kr) || kr.Code != authz.CodeOwnAccount {
		t.Errorf("own account: %v", err)
	}
	viewer := auth.Principal{Sub: "sub-v", Roles: []string{"viewer"}}.Submitter()
	if err := rs.Check(t.Context(), viewer, resetTarget, pw(goodPw)); !errors.As(err, &kr) {
		t.Errorf("a viewer: %v", err)
	}
	if err := rs.Check(t.Context(), by, "sub-nobody", pw(goodPw)); !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("no account: %v", err)
	}
	var pr *PasswordRefused
	if err := rs.Check(t.Context(), by, resetTarget, pw("short")); !errors.As(err, &pr) || pr.Sentence != "Use at least 15 characters." {
		t.Errorf("short: %v", err)
	}
	if err := rs.Check(t.Context(), by, resetTarget, pw("BOB-LONGNAME-XYZ")); err != nil {
		t.Errorf("a name-like password: %v", err)
	}
	if err := rs.Check(t.Context(), by, resetTarget, pw(goodPw)); err != nil {
		t.Errorf("a good password: %v", err)
	}
	h.kc.fail = func(string, string) error {
		return &idclient.Error{Op: "admin", Status: 503, Kind: idclient.ErrUnreachable}
	}
	if err := rs.Check(t.Context(), by, resetTarget, pw(goodPw)); !errors.Is(err, ErrIdentityUnavailable) {
		t.Errorf("identity down: %v", err)
	}
	h.kc.fail = nil
	broken, _ := pwpolicy.New(t.TempDir(), flows.PasswordPolicy)
	rs2, _ := NewResetter(ResetterDeps{Authorizer: kp, Users: h.users, Checker: broken, Log: log})
	if err := rs2.Check(t.Context(), by, resetTarget, pw(goodPw)); !errors.Is(err, ErrPasswordCheckUnavailable) {
		t.Errorf("no list: %v", err)
	}
	found := false
	for _, r := range rec.Records() {
		if ev, _ := logkittest.Attr(r, "event"); ev == "pwpolicy.list_unreadable" && r.Level == slog.LevelError {
			found = true
		}
	}
	if !found || strings.Contains(rec.Text(), goodPw) {
		t.Errorf("log %s", rec.Text())
	}
	if _, err := NewResetter(ResetterDeps{}); err == nil {
		t.Error("NewResetter accepted nothing")
	}
	if _, err := NewResetAction(nil, nil); err == nil {
		t.Error("NewResetAction accepted nothing")
	}
	if _, err := h.action.Run(t.Context(), admin(), nil); err == nil {
		t.Error("Run accepted no payload")
	}
	if _, err := h.users.SetTemporaryPassword(t.Context(), "", pw(goodPw)); err == nil {
		t.Error("SetTemporaryPassword accepted no account")
	}
}

// The credential body escapes the password as JSON and refuses bytes that
// are not UTF-8.
func TestTemporaryPassword_JSON(t *testing.T) {
	in := "q\"uo\\te\n é😀"
	b, err := json.Marshal(temporaryPassword{pw: secret.New([]byte(in))})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Type      string `json:"type"`
		Temporary bool   `json:"temporary"`
		Value     string `json:"value"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Value != in || !out.Temporary || out.Type != "password" {
		t.Errorf("round trip %s: %+v %v", b, out, err)
	}
	if _, err := json.Marshal(temporaryPassword{pw: secret.New([]byte{0xff, 'a'})}); err == nil {
		t.Error("invalid UTF-8 encoded")
	}
}
