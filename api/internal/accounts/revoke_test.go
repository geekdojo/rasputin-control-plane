package accounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

var allSteps = []string{StepAuthorize, StepOnlineSessions, StepOfflineSessions, StepChange, StepConsoleSessions,
	StepMovedRows, StepDevices, StepApps, StepNetwork}

var sessionCalls = []string{"logout", "offline-delete:s1", "offline-delete:s2"}

func cat(parts ...[]string) []string { return slices.Concat(parts...) }

// TC-991-01: each kind runs its steps in the plan's order, every step
// records one outcome, and a step the kind doesn't need records
// not_needed.
func TestRevoke_StepOrderEveryKind(t *testing.T) {
	cases := []struct {
		spec    Spec
		want    []string
		skipped []string
	}{
		{Spec{Kind: SignOut}, cat(sessionCalls, []string{"console", StepApps}),
			[]string{StepAuthorize, StepChange, StepMovedRows, StepDevices, StepNetwork}},
		{Spec{Kind: Privileged}, sessionCalls,
			[]string{StepAuthorize, StepChange, StepConsoleSessions, StepMovedRows, StepDevices, StepApps, StepNetwork}},
		{Spec{Kind: RoleChange, AccessChanged: true}, cat(sessionCalls, []string{"console", "moved"}),
			[]string{StepAuthorize, StepChange, StepDevices, StepApps, StepNetwork}},
		{Spec{Kind: RoleChange}, []string{"console", "moved"},
			[]string{StepAuthorize, StepOnlineSessions, StepOfflineSessions, StepChange, StepDevices, StepApps, StepNetwork}},
		{Spec{Kind: RemoveAccess}, cat(sessionCalls, []string{"remove-attr", "remove-offline", "console", StepDevices, StepApps, StepNetwork}),
			[]string{StepAuthorize, StepMovedRows}},
		{Spec{Kind: Disable}, cat([]string{"guard"}, sessionCalls, []string{"guard", "disable", "console", "moved", StepDevices, StepApps, StepNetwork}),
			nil},
		{Spec{Kind: Delete}, cat([]string{"guard"}, sessionCalls, []string{"guard", "list", "delete-user", "console", "moved", StepDevices, StepApps, StepNetwork}),
			nil},
	}
	for _, c := range cases {
		t.Run(string(c.spec.Kind), func(t *testing.T) {
			h := newHarness(t)
			h.world()
			c.spec.AccountID = target
			r := h.run(t, c.spec, adminA)
			if r.job.Status != jobs.StatusSucceeded {
				t.Fatalf("job %s: %s", r.job.Status, r.job.Error)
			}
			if got := h.effects(); !slices.Equal(got, c.want) {
				t.Errorf("calls\n got %v\nwant %v", got, c.want)
			}
			var names []string
			for _, s := range r.steps {
				names = append(names, s.Name)
				if s.Status != jobs.StepSucceeded || len(s.Result) == 0 {
					t.Errorf("step %s: %s, result %s", s.Name, s.Status, s.Result)
				}
			}
			if !slices.Equal(names, allSteps) {
				t.Errorf("ledger steps %v", names)
			}
			for _, s := range allSteps {
				skipped := slices.Contains(c.skipped, s)
				if got := r.outcome(t, s); (got == outcomeNotNeeded) != skipped {
					t.Errorf("step %s recorded %q; not needed = %v", s, got, skipped)
				}
			}
		})
	}
}

// TC-991-02: when the online-session call, or an offline-session call,
// fails, the job fails at that step with the sessions sentence, the cause
// names the step, and no change is made.
func TestRevoke_SessionsEndBeforeTheChange(t *testing.T) {
	fails := map[string]func(m, p string) error{
		StepOnlineSessions: func(m, p string) error {
			if strings.HasSuffix(p, "/logout") {
				return &idclient.Error{Op: "admin", Status: 503, Kind: idclient.ErrUnreachable}
			}
			return nil
		},
		StepOfflineSessions: func(m, p string) error {
			if strings.HasPrefix(p, "/sessions/s2") {
				return &idclient.Error{Op: "admin", Status: 503, Kind: idclient.ErrUnreachable}
			}
			return nil
		},
	}
	for step, fail := range fails {
		for _, kind := range []RevokeKind{Disable, Delete, RemoveAccess} {
			t.Run(step+"/"+string(kind), func(t *testing.T) {
				h := newHarness(t)
				h.world()
				h.kc.fail = fail
				r := h.run(t, Spec{AccountID: target, Kind: kind}, adminA)
				if r.job.Status != jobs.StatusFailed || r.job.Error != SentenceSessions {
					t.Errorf("job %s %q", r.job.Status, r.job.Error)
				}
				if s := r.step(step); s == nil || s.Status != jobs.StepFailed || s.Error != SentenceSessions {
					t.Errorf("step %s: %+v", step, s)
				}
				if got := h.log.only("disable", "delete-user", "remove-attr", "remove-offline", "list"); len(got) != 0 {
					t.Errorf("changes made after a session failure: %v", got)
				}
				if !h.kc.exists(target) || !h.kc.enabled(target) {
					t.Error("the account changed")
				}
				// The cause names the step.
				_, err := stepByName(h.rev.Workflow(), step).Do(stepCtx(t, Spec{AccountID: target, Kind: kind}, adminA))
				var se *StepError
				if !errors.As(err, &se) || se.Step != step || !strings.Contains(errors.Unwrap(err).Error(), step) ||
					!errors.Is(err, idclient.ErrUnreachable) {
					t.Errorf("the step's error %v does not name %s", err, step)
				}
			})
		}
	}
}

func stepByName(w jobs.Workflow, name string) jobs.WorkflowStep {
	for _, s := range w.Steps {
		if s.Name == name {
			return s
		}
	}
	panic("no step " + name)
}

func stepCtx(t *testing.T, spec Spec, by string) *jobs.StepCtx {
	b, _ := json.Marshal(spec)
	return &jobs.StepCtx{Ctx: t.Context(), JobID: "J1", Spec: b, CreatedBy: by, PriorResults: map[string]json.RawMessage{}}
}

// TC-991-03: an administrator's disable and delete of their own account
// are refused at step 1 with the guard's sentence, and nothing ends.
func TestRevoke_OwnAccountRefusedFirst(t *testing.T) {
	for kind, sentence := range map[RevokeKind]string{
		Disable: "You can't disable your own account.", Delete: "You can't delete your own account.",
	} {
		h := newHarness(t)
		h.world()
		r := h.run(t, Spec{AccountID: adminA, Kind: kind}, adminA)
		if r.job.Status != jobs.StatusFailed || r.job.Error != sentence {
			t.Errorf("%s: job %s %q", kind, r.job.Status, r.job.Error)
		}
		if s := r.step(StepAuthorize); s == nil || s.Error != sentence {
			t.Errorf("%s: authorize step %+v", kind, s)
		}
		if got := h.effects(); !slices.Equal(got, []string{"guard"}) {
			t.Errorf("%s: calls %v", kind, got)
		}
	}
}

// TC-991-04: deleting an enabled administrator when the administrator
// count is 1 is refused with the last-administrator sentence, and no
// session ends. The actor holds admin through a composite, so the count is
// the target's alone.
func TestRevoke_LastAdministratorStays(t *testing.T) {
	h := newHarness(t)
	h.kc.add(person{sub: adminA, name: "admina", enabled: true, console: []string{"admin"}})
	h.kc.add(person{sub: target, name: "t", enabled: true, console: []string{"admin"}, directAdmin: true})
	r := h.run(t, Spec{AccountID: target, Kind: Delete}, adminA)
	const want = "Rasputin needs at least one administrator, so this one can't be removed."
	if r.job.Status != jobs.StatusFailed || r.job.Error != want {
		t.Errorf("job %s %q", r.job.Status, r.job.Error)
	}
	if got := h.effects(); !slices.Equal(got, []string{"guard"}) {
		t.Errorf("calls %v", got)
	}
	if !h.kc.exists(target) {
		t.Error("the last administrator was deleted")
	}
}

// TC-991-05: two administrators disabling each other at once, under the
// real guard and the one mutex: exactly one disable applies, the other job
// fails with a guard sentence, and one enabled administrator remains.
func TestRevoke_LastAdministratorUnderConcurrency(t *testing.T) {
	for range 20 {
		h := newHarness(t)
		h.kc.add(person{sub: adminA, name: "a", enabled: true, console: []string{"admin"}, directAdmin: true})
		h.kc.add(person{sub: adminB, name: "b", enabled: true, console: []string{"admin"}, directAdmin: true})
		ja := h.submit(t, Spec{AccountID: adminB, Kind: Disable}, adminA)
		jb := h.submit(t, Spec{AccountID: adminA, Kind: Disable}, adminB)
		h.runner.Wait()
		ra, rb := h.result(t, ja), h.result(t, jb)
		ok := 0
		for _, r := range []result{ra, rb} {
			switch r.job.Status {
			case jobs.StatusSucceeded:
				ok++
			case jobs.StatusFailed:
				if r.job.Error != "Only an administrator can change roles." &&
					r.job.Error != "Rasputin needs at least one administrator, so this one can't be removed." {
					t.Errorf("the refused job's error %q is not a guard sentence", r.job.Error)
				}
			}
		}
		enabled := 0
		for _, s := range []string{adminA, adminB} {
			if h.kc.enabled(s) {
				enabled++
			}
		}
		if ok != 1 || enabled != 1 || len(h.log.only("disable")) != 1 {
			t.Fatalf("succeeded %d, enabled %d, disables %v", ok, enabled, h.log.only("disable"))
		}
	}
}

// TC-991-06: a job a subsystem submitted can't disable or delete anyone:
// step 1 refuses with not_permitted, and no session or change call is made.
func TestRevoke_SubsystemRefused(t *testing.T) {
	for _, kind := range []RevokeKind{Disable, Delete} {
		h := newHarness(t)
		h.world()
		r := h.run(t, Spec{AccountID: target, Kind: kind}, "scheduler")
		if r.job.Status != jobs.StatusFailed || r.job.Error != "Only an administrator can change roles." {
			t.Errorf("%s: job %s %q", kind, r.job.Status, r.job.Error)
		}
		warn := h.rec.Matching(slog.LevelWarn, "")
		if len(warn) != 1 {
			t.Fatalf("%s: records\n%s", kind, h.rec.Text())
		}
		if code, _ := logkittest.Attr(warn[0], "code"); code != "not_permitted" {
			t.Errorf("%s: refusal code %q", kind, code)
		}
		if got := h.effects(); !slices.Equal(got, []string{"guard"}) {
			t.Errorf("%s: calls %v", kind, got)
		}
	}
}

// TC-991-07: when the administrators read fills a page, the guard can't
// count, the step fails with a wrapped error, and the disable never
// applies.
func TestRevoke_FullAdministratorPageRefuses(t *testing.T) {
	h := newHarness(t)
	h.world()
	h.kc.add(person{sub: target, name: "t", enabled: true, console: []string{"admin"}, directAdmin: true})
	h.kc.fullPage = true
	r := h.run(t, Spec{AccountID: target, Kind: Disable}, adminA)
	if r.job.Status != jobs.StatusFailed || r.job.Error != sentenceCheck {
		t.Errorf("job %s %q", r.job.Status, r.job.Error)
	}
	_, err := stepByName(h.rev.Workflow(), StepAuthorize).Do(stepCtx(t, Spec{AccountID: target, Kind: Disable}, adminA))
	if err == nil || !strings.Contains(errors.Unwrap(err).Error(), "fill a page") {
		t.Errorf("the step's cause %v", err)
	}
	if len(h.log.only("disable")) != 0 || !h.kc.enabled(target) {
		t.Error("the disable applied")
	}
	// F-991-16: the page that was refused held exactly adminPage rows, so
	// the boundary itself (not an overfull page) is what refuses.
	h.kc.mu.Lock()
	rows := h.kc.adminRows
	h.kc.mu.Unlock()
	if rows != adminPage {
		t.Errorf("the administrators read answered %d rows, want exactly %d", rows, adminPage)
	}
}

// TC-991-08: a delete of an account that held app access records its name
// and email before the delete; a failed record fails the step and deletes
// nothing. F-991-03: the attribute alone, with no fact row, counts. F-991-04:
// a re-run after the account is gone records already_deleted and finishes
// steps 5 to 9.
func TestRevoke_DeleteListsBeforeDeleting(t *testing.T) {
	t.Run("the fact", func(t *testing.T) {
		h := newHarness(t)
		h.world()
		h.kc.add(person{sub: target, name: "heldname", email: "held@example.invalid", enabled: true, console: []string{"viewer"}})
		if err := h.removed.Facts().Record(t.Context(), target); err != nil {
			t.Fatal(err)
		}
		r := h.run(t, Spec{AccountID: target, Kind: Delete}, adminA)
		if r.job.Status != jobs.StatusSucceeded {
			t.Fatalf("job %s", r.job.Error)
		}
		got := h.log.only("list", "delete-user")
		if !slices.Equal(got, []string{"list", "delete-user"}) {
			t.Errorf("order %v", got)
		}
		if found, err := h.removed.Removed(t.Context(), "HeldName", "held@example.invalid"); err != nil || !found {
			t.Errorf("Removed = %v, %v", found, err)
		}
	})
	t.Run("the attribute without the fact (F-991-03)", func(t *testing.T) {
		h := newHarness(t)
		h.world() // the target carries rasputin_app_role and no fact row
		h.run(t, Spec{AccountID: target, Kind: Delete}, adminA)
		if found, err := h.removed.Removed(t.Context(), "targetname", ""); err != nil || !found {
			t.Errorf("Removed = %v, %v", found, err)
		}
	})
	t.Run("a failed record deletes nothing", func(t *testing.T) {
		h := newHarness(t)
		h.world()
		h.list.err = errors.New("disk full")
		r := h.run(t, Spec{AccountID: target, Kind: Delete}, adminA)
		if r.job.Status != jobs.StatusFailed || r.job.Error != sentenceList {
			t.Errorf("job %s %q", r.job.Status, r.job.Error)
		}
		if s := r.step(StepChange); s == nil || s.Status != jobs.StepFailed {
			t.Errorf("change step %+v", s)
		}
		if len(h.log.only("delete-user")) != 0 || !h.kc.exists(target) {
			t.Error("the account was deleted")
		}
	})
	t.Run("a re-run after the account is gone (F-991-04)", func(t *testing.T) {
		h := newHarness(t)
		h.world()
		r := h.run(t, Spec{AccountID: target, Kind: Delete}, adminA)
		if r.job.Status != jobs.StatusSucceeded {
			t.Fatal(r.job.Error)
		}
		h.log.calls = nil
		again := h.run(t, Spec{AccountID: target, Kind: Delete}, adminA)
		if again.job.Status != jobs.StatusSucceeded {
			t.Fatalf("the re-run: %s", again.job.Error)
		}
		want := map[string]string{StepAuthorize: outcomeAlreadyDeleted, StepOnlineSessions: outcomeNotNeeded,
			StepOfflineSessions: outcomeNotNeeded, StepChange: outcomeNotNeeded, StepConsoleSessions: outcomeEnded,
			StepMovedRows: outcomeRemoved, StepDevices: "done", StepApps: "done", StepNetwork: "done"}
		for s, w := range want {
			if got := again.outcome(t, s); got != w {
				t.Errorf("re-run %s = %q, want %q", s, got, w)
			}
		}
		if got := h.effects(); !slices.Equal(got, []string{"guard", "console", "moved", StepDevices, StepApps, StepNetwork}) {
			t.Errorf("re-run calls %v", got)
		}
	})
}

// TC-991-12: a delete of an account with no app-access fact and no app
// attribute records nothing, and its name and email stay free.
func TestRevoke_DeleteWithoutAccessReleasesTheName(t *testing.T) {
	h := newHarness(t)
	h.world()
	h.kc.add(person{sub: target, name: "declined", email: "declined@example.invalid", enabled: true})
	r := h.run(t, Spec{AccountID: target, Kind: Delete}, adminA)
	if r.job.Status != jobs.StatusSucceeded || h.kc.exists(target) {
		t.Fatalf("job %s %q", r.job.Status, r.job.Error)
	}
	if len(h.log.only("list")) != 0 {
		t.Error("the name was recorded")
	}
	if found, err := h.removed.Removed(t.Context(), "declined", "declined@example.invalid"); err != nil || found {
		t.Errorf("Removed = %v, %v", found, err)
	}
}

// TC-991-17: the spec carries ids only: its keys are exactly accountId and
// kind, and the account's name and email appear nowhere in it.
func TestSpec_IDsOnly(t *testing.T) {
	h := newHarness(t)
	h.world()
	b, err := json.Marshal(Spec{AccountID: target, Kind: Delete})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	})
	if !slices.Equal(keys, []string{"accountId", "kind"}) {
		t.Errorf("keys %v", keys)
	}
	for _, s := range []string{"targetname", "target@example.invalid"} {
		if bytes.Contains(b, []byte(s)) {
			t.Errorf("the spec carries %q", s)
		}
	}
	r := h.run(t, Spec{AccountID: target, Kind: Delete}, adminA)
	if !bytes.Equal(r.job.Spec, b) {
		t.Errorf("the ledger's spec %s", r.job.Spec)
	}
}

// TC-991-18: neither on success nor on an Admin API failure does a slog
// record, a job-log line or a step outcome hold the name, the email, the
// account id, an HMAC or the key; every slog record carries
// component=accounts, event, job_id and step.
func TestRevoke_NothingPersonalInLogsOrOutcomes(t *testing.T) {
	const sub = "sentinel-sub-7f3a"
	for _, failing := range []bool{false, true} {
		h := newHarness(t)
		h.world()
		h.kc.add(person{sub: sub, name: "sentinelname", email: "sentinel@example.invalid", enabled: true, appRole: "user",
			offline: map[string][]string{appUUID: {"s9"}}})
		if failing {
			h.kc.fail = func(m, p string) error {
				if m == "DELETE" && p == "/users/"+sub {
					return &idclient.Error{Op: "admin", Path: "/admin/realms/rasputin/users/" + sub, Status: 500, Kind: idclient.ErrUnreachable}
				}
				return nil
			}
		}
		r := h.run(t, Spec{AccountID: sub, Kind: Delete}, adminA)
		if failing != (r.job.Status == jobs.StatusFailed) {
			t.Fatalf("failing %v: job %s", failing, r.job.Status)
		}
		events, err := h.jobs.ListEvents(context.Background(), r.job.ID)
		if err != nil {
			t.Fatal(err)
		}
		var hay strings.Builder
		hay.WriteString(h.rec.Text())
		hay.WriteString(r.job.Error)
		for _, s := range r.steps {
			hay.Write(s.Result)
			hay.WriteString(s.Error)
		}
		logLines := 0
		for _, e := range events {
			// The job-log lines; the spec in the created event carries the
			// account id by design (TC-991-17).
			if e.Type == "log" {
				hay.Write(e.Data)
				logLines++
			}
		}
		if logLines == 0 {
			t.Fatal("no job-log lines")
		}
		needles := []string{"sentinelname", "sentinel@example.invalid", sub, testKey,
			h.mac.Sum("removed-name.name", []byte("sentinelname")), h.mac.Sum("removed-name.email", []byte("sentinel@example.invalid"))}
		for _, n := range needles {
			if strings.Contains(hay.String(), n) {
				t.Errorf("failing %v: %q appears in a record, line or outcome", failing, n)
			}
		}
		if len(h.rec.Records()) == 0 {
			t.Fatal("no records")
		}
		for _, rec := range h.rec.Records() {
			for _, k := range []string{"component", "event", "job_id", "step"} {
				if v, ok := logkittest.Attr(rec, k); !ok || v == "" {
					t.Errorf("failing %v: record %q lacks %s", failing, rec.Message, k)
				}
			}
			if c, _ := logkittest.Attr(rec, "component"); c != "accounts" {
				t.Errorf("component %q", c)
			}
		}
	}
}

// TC-991-21: a role change runs the moved-rows step for a moved person who
// no longer holds admin, and not for one who still does; sign_out never
// runs it.
func TestRevoke_MovedRowsWhichKinds(t *testing.T) {
	handle := bytes.Repeat([]byte{0x42}, 16)
	moved := auth.MovedAccountID(handle)
	seed := func(t *testing.T, roles []string) *harness {
		h := newHarness(t)
		h.world()
		h.kc.add(person{sub: moved, name: "moved", enabled: true, console: roles})
		if err := h.auth.CreateUser(t.Context(), &auth.User{ID: handle, Name: "moved", DisplayName: "Moved", CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if err := h.auth.CreateSession(t.Context(), &auth.Session{Token: "tok", UserID: handle, CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour), LastActiveAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		return h
	}
	h := seed(t, []string{"viewer"})
	r := h.run(t, Spec{AccountID: moved, Kind: RoleChange}, adminA)
	var out struct{ Sessions int64 }
	_ = json.Unmarshal(r.step(StepMovedRows).Result, &out)
	if len(h.log.only("moved")) != 1 || out.Sessions != 1 {
		t.Errorf("a demoted moved person: calls %v, outcome %s", h.log.only("moved"), r.step(StepMovedRows).Result)
	}
	h = seed(t, []string{"admin"})
	h.run(t, Spec{AccountID: moved, Kind: RoleChange}, adminA)
	h.run(t, Spec{AccountID: moved, Kind: SignOut}, adminA)
	if got := h.log.only("moved"); len(got) != 0 {
		t.Errorf("an administrator or a sign-out removed rows: %v", got)
	}
}

// TC-991-23 (the privileged kind): privileged runs only the online and
// offline session steps, and records each step.
func TestRevoke_PrivilegedOnlyEndsIdentitySessions(t *testing.T) {
	h := newHarness(t)
	h.world()
	r := h.run(t, Spec{AccountID: target, Kind: Privileged}, "accounts")
	if r.job.Status != jobs.StatusSucceeded || !slices.Equal(h.effects(), sessionCalls) {
		t.Errorf("job %s, calls %v", r.job.Status, h.effects())
	}
	if r.outcome(t, StepOnlineSessions) != outcomeEnded || r.outcome(t, StepOfflineSessions) != outcomeEnded {
		t.Error("the session steps' outcomes")
	}
}

// TC-991-24: with NoHook wired, each hook step a kind needs records
// not_built and what it is; a hook's unreachable targets are outcomes and
// the step succeeds; a hook that errors fails its step, which is recorded.
func TestRevoke_Hooks(t *testing.T) {
	h := newHarness(t)
	h.world()
	h.rev.d.Devices, h.rev.d.Apps, h.rev.d.Network = NoHook{What: "devices"}, NoHook{What: "apps"}, NoHook{What: "network"}
	h.runner.Register(h.rev.Workflow())
	r := h.run(t, Spec{AccountID: target, Kind: RemoveAccess}, adminA)
	for step, what := range map[string]string{StepDevices: "devices", StepApps: "apps", StepNetwork: "network"} {
		var o Outcome
		_ = json.Unmarshal(r.step(step).Result, &o)
		if o.Outcome != "not_built" || o.What != what {
			t.Errorf("%s: %s", step, r.step(step).Result)
		}
	}

	h = newHarness(t)
	h.world()
	h.hooks[StepApps].out = Outcome{Outcome: "done", Targets: []TargetResult{{Target: "immich", Result: Unreachable}, {Target: "romm", Result: Delivered}}}
	r = h.run(t, Spec{AccountID: target, Kind: SignOut}, adminA)
	if r.job.Status != jobs.StatusSucceeded || !strings.Contains(string(r.step(StepApps).Result), `"result":"unreachable"`) {
		t.Errorf("unreachable target: job %s, outcome %s", r.job.Status, r.step(StepApps).Result)
	}

	h = newHarness(t)
	h.world()
	h.hooks[StepDevices].err = errors.New("the device store can't be read")
	r = h.run(t, Spec{AccountID: target, Kind: Disable}, adminA)
	if s := r.step(StepDevices); r.job.Status != jobs.StatusFailed || s == nil || s.Status != jobs.StepFailed || s.Error != hookSentence[StepDevices] {
		t.Errorf("hook error: job %s, step %+v", r.job.Status, s)
	}
	if r.step(StepApps) != nil {
		t.Error("a step after the failed hook ran")
	}
}

// A spec naming no account or an unknown kind fails before anything.
func TestRevoke_BadSpec(t *testing.T) {
	h := newHarness(t)
	h.world()
	for _, spec := range []Spec{{Kind: Disable}, {AccountID: target, Kind: "explode"}} {
		r := h.run(t, spec, adminA)
		if r.job.Status != jobs.StatusFailed || r.job.Error != sentenceSpec {
			t.Errorf("%+v: %s %q", spec, r.job.Status, r.job.Error)
		}
	}
	if len(h.effects()) != 0 {
		t.Errorf("calls %v", h.effects())
	}
}

// Steps(kind) fixes the kind for an embedding workflow whose spec carries
// only the account.
func TestSteps_FixedKind(t *testing.T) {
	h := newHarness(t)
	h.world()
	h.runner.Register(jobs.Workflow{Kind: "accounts.test_sign_out", Steps: h.rev.Steps(SignOut)})
	j, err := h.runner.Submit(t.Context(), "accounts.test_sign_out", map[string]string{"accountId": target}, adminA)
	if err != nil {
		t.Fatal(err)
	}
	h.runner.Wait()
	if r := h.result(t, j.ID); r.job.Status != jobs.StatusSucceeded || !slices.Equal(h.effects(), cat(sessionCalls, []string{"console", StepApps})) {
		t.Errorf("job %s, calls %v", r.job.Status, h.effects())
	}
}

// The constructors refuse a missing collaborator.
func TestConstructorsRefuseNil(t *testing.T) {
	if _, err := NewRevoker(RevokerDeps{}); err == nil {
		t.Error("NewRevoker with nothing")
	}
	h := newHarness(t)
	d := h.rev.d
	d.StepTimeout = 0
	if _, err := NewRevoker(d); err == nil {
		t.Error("NewRevoker with no timeout")
	}
	if _, err := NewAccess(AccessDeps{}); err == nil {
		t.Error("NewAccess with nothing")
	}
	if _, err := NewUsers(UsersDeps{Admin: h.kc}); err == nil {
		t.Error("NewUsers with no realm")
	}
	if _, err := NewUsers(UsersDeps{}); err == nil {
		t.Error("NewUsers with no admin")
	}
	if _, err := NewRoleAccounts(nil); err == nil {
		t.Error("NewRoleAccounts(nil)")
	}
	if f, err := (RoleAccounts{users: h.users}).Facts(t.Context(), ""); !errors.Is(err, authz.ErrNoAccount) {
		t.Errorf("Facts of no id: %+v, %v", f, err)
	}
}
