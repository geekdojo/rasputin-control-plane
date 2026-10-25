package storerecover

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

const (
	testDir  = "/data"
	testUnit = "openbao.service"
	fullAt   = uint64(1 << 30)
)

// facts is what the fakes report, and how often each was asked.
type facts struct {
	mu         sync.Mutex
	free       uint64
	freeErr    error
	state      string
	stateErr   error
	held       bool
	restoring  bool
	restartErr error

	freeCalls, stateCalls, heldCalls, restoreCalls, restartCalls int
}

func (f *facts) set(fn func(*facts)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *facts) counts() (free, state, held, restore, restart int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.freeCalls, f.stateCalls, f.heldCalls, f.restoreCalls, f.restartCalls
}

type fixture struct {
	f   *facts
	rec *logkittest.Recorder
	r   *Recoverer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &facts{free: 0, state: stateFailed}
	log, rec := logkittest.New()
	r, err := New(Deps{
		Dir: testDir,
		Free: func(dir string) (uint64, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.freeCalls++
			if dir != testDir {
				t.Errorf("Free(%q), want %q", dir, testDir)
			}
			return f.free, f.freeErr
		},
		FullBelow: fullAt,
		Unit:      testUnit,
		UnitState: func(context.Context) (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.stateCalls++
			return f.state, f.stateErr
		},
		Held: func(context.Context) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.heldCalls++
			return f.held
		},
		Restoring: func() (string, bool) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.restoreCalls++
			if f.restoring {
				return "(not yet submitted)", true
			}
			return "", false
		},
		Restart: func(context.Context) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.restartCalls++
			return f.restartErr
		},
		Log:         log,
		StepTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{f: f, rec: rec, r: r}
}

func (x *fixture) due(t *testing.T) (bool, string) {
	t.Helper()
	return x.r.Due(t.Context())
}

// armed puts the fixture in the armed state through a full-and-failed reading.
func (x *fixture) armed(t *testing.T) {
	t.Helper()
	x.f.set(func(f *facts) { f.free, f.state = 0, stateFailed })
	if due, _ := x.due(t); due {
		t.Fatal("a full reading was due")
	}
	if !x.r.isArmed() {
		t.Fatal("a full-and-failed reading did not arm")
	}
}

func (x *fixture) room(state string) {
	x.f.set(func(f *facts) { f.free, f.state = fullAt, state })
}

func attr(t *testing.T, r slog.Record, key string) string {
	t.Helper()
	v, ok := logkittest.Attr(r, key)
	if !ok {
		t.Errorf("record %q has no %s", r.Message, key)
	}
	return v
}

// TC-874-01: while full, the first reading arms and logs once; no reading is
// due and Restart is never called.
func TestDue_FullNeverFires(t *testing.T) {
	x := newFixture(t)
	x.f.set(func(f *facts) { f.free = 12345 })
	for i := range 10 {
		if due, reason := x.due(t); due || reason != "" {
			t.Fatalf("reading %d = %v, %q, want false with no reason", i, due, reason)
		}
	}
	if _, _, _, _, restarts := x.f.counts(); restarts != 0 {
		t.Errorf("Restart called %d times while full", restarts)
	}
	armed := x.rec.Matching(slog.LevelInfo, "secret store failed while the data partition was full")
	if len(armed) != 1 {
		t.Fatalf("%d armed records over ten readings, want 1", len(armed))
	}
	for key, want := range map[string]string{
		"event": "secretstore.recover_armed", "free_bytes": "12345", "unit": testUnit,
		"state": stateFailed, "component": "secretstore",
	} {
		if got := attr(t, armed[0], key); got != want {
			t.Errorf("armed %s = %q, want %q", key, got, want)
		}
	}
}

// TC-874-02: armed, the first reading with room and a failed, unheld,
// unrestored unit is due once with a reason naming the MiB and the unit; the
// next is not.
func TestDue_OneRecoveryOnRoom(t *testing.T) {
	x := newFixture(t)
	x.armed(t)
	x.room(stateFailed)
	due, reason := x.due(t)
	if !due {
		t.Fatalf("Due with room = false, %q", reason)
	}
	if want := "the data partition has 1024 MiB free and the store unit is failed"; reason != want {
		t.Errorf("reason = %q, want %q", reason, want)
	}
	if due, reason := x.due(t); due || reason != "" {
		t.Errorf("second Due = %v, %q, want false with no reason", due, reason)
	}
}

// TC-874-03: an unarmed Recoverer with room and a failed unit is never due,
// and the unit is never read.
func TestDue_FailedWithRoomNotArmed(t *testing.T) {
	x := newFixture(t)
	x.room(stateFailed)
	for range 5 {
		if due, _ := x.due(t); due {
			t.Fatal("an unarmed Recoverer was due")
		}
	}
	x.r.Arm(t.Context())
	if _, state, _, _, _ := x.f.counts(); state != 0 {
		t.Errorf("UnitState called %d times, want 0", state)
	}
}

// TC-874-04: armed, a unit read inactive or active with room disarms with a
// record of its state and is never due until a new full-and-failed reading;
// activating stays armed and is due on the next failed reading.
func TestDue_DisarmsOnOtherState(t *testing.T) {
	for _, state := range []string{"inactive", "active"} {
		t.Run(state, func(t *testing.T) {
			x := newFixture(t)
			x.armed(t)
			x.room(state)
			if due, _ := x.due(t); due {
				t.Fatal("due on a unit that is not failed")
			}
			rec := x.rec.Matching(slog.LevelInfo, "secret store is no longer failed; no recovery needed")
			if len(rec) != 1 {
				t.Fatalf("%d disarm records, want 1", len(rec))
			}
			if got := attr(t, rec[0], "event"); got != "secretstore.recover_disarmed" {
				t.Errorf("event = %q", got)
			}
			if got := attr(t, rec[0], "state"); got != state {
				t.Errorf("state = %q, want %q", got, state)
			}
			x.room(stateFailed)
			for range 3 {
				if due, _ := x.due(t); due {
					t.Fatal("due after disarm without a new full reading")
				}
			}
			x.armed(t)
			x.room(stateFailed)
			if due, _ := x.due(t); !due {
				t.Error("not due after re-arming")
			}
		})
	}
	t.Run("activating", func(t *testing.T) {
		x := newFixture(t)
		x.armed(t)
		x.room(stateActivating)
		if due, reason := x.due(t); due || reason != "" {
			t.Fatalf("Due on activating = %v, %q", due, reason)
		}
		if n := len(x.rec.Matching(slog.LevelInfo, "no recovery needed")); n != 0 {
			t.Errorf("%d disarm records on activating, want 0", n)
		}
		x.room(stateFailed)
		if due, _ := x.due(t); !due {
			t.Error("not due on the failed reading after activating")
		}
	})
}

// TC-874-05: a quiesce hold blocks recovery with its reason and keeps it
// armed; once released the next reading is due.
func TestDue_HeldBlocks(t *testing.T) {
	x := newFixture(t)
	x.armed(t)
	x.room(stateFailed)
	x.f.set(func(f *facts) { f.held = true })
	for range 2 {
		if due, reason := x.due(t); due || reason != "a job holds the secret store" {
			t.Fatalf("Due while held = %v, %q", due, reason)
		}
	}
	x.f.set(func(f *facts) { f.held = false })
	if due, _ := x.due(t); !due {
		t.Error("not due after the hold ended")
	}
}

// TC-874-06: a restore in progress, bound or not yet submitted, blocks
// recovery and keeps it armed; after it closes the next reading is due.
func TestDue_RestoreBlocks(t *testing.T) {
	for _, id := range []string{"job-restore", "(not yet submitted)"} {
		t.Run(id, func(t *testing.T) {
			x := newFixture(t)
			var active bool
			x.r.d.Restoring = func() (string, bool) { return id, active }
			x.armed(t)
			x.room(stateFailed)
			active = true
			if due, reason := x.due(t); due || reason != "a restore is in progress" {
				t.Fatalf("Due while restoring = %v, %q", due, reason)
			}
			active = false
			if due, _ := x.due(t); !due {
				t.Error("not due after the restore closed")
			}
		})
	}
}

// TC-874-07: free space or the unit state unreadable refuses with a WARN
// carrying its fields, from either state, and leaves armed as it was.
func TestDue_UnreadableRefuses(t *testing.T) {
	for _, armed := range []bool{false, true} {
		name := "unarmed"
		if armed {
			name = "armed"
		}
		t.Run(name+"/free", func(t *testing.T) {
			x := newFixture(t)
			if armed {
				x.armed(t)
			}
			x.f.set(func(f *facts) { f.freeErr = errors.New("statfs: EIO") })
			if due, _ := x.due(t); due {
				t.Fatal("due on an unreadable free space")
			}
			w := x.rec.Matching(slog.LevelWarn, "free space could not be read; no store recovery checked")
			if len(w) != 1 {
				t.Fatalf("%d WARN records, want 1", len(w))
			}
			for key, want := range map[string]string{"component": "secretstore", "dir": testDir, "err": "statfs: EIO"} {
				if got := attr(t, w[0], key); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			x.f.set(func(f *facts) { f.freeErr = nil })
			x.room(stateFailed)
			if due, _ := x.due(t); due != armed {
				t.Errorf("next good reading due = %v, want %v (armed unchanged)", due, armed)
			}
		})
		t.Run(name+"/unit", func(t *testing.T) {
			x := newFixture(t)
			if armed {
				x.armed(t)
				x.room(stateFailed)
			}
			x.f.set(func(f *facts) { f.stateErr = errors.New("dbus: timeout") })
			if due, _ := x.due(t); due {
				t.Fatal("due on an unreadable unit state")
			}
			w := x.rec.Matching(slog.LevelWarn, "secret store unit state could not be read")
			if len(w) != 1 {
				t.Fatalf("%d WARN records, want 1", len(w))
			}
			for key, want := range map[string]string{"component": "secretstore", "unit": testUnit, "err": "dbus: timeout"} {
				if got := attr(t, w[0], key); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			if x.r.isArmed() != armed {
				t.Errorf("armed = %v after the refusal, want %v", x.r.isArmed(), armed)
			}
			x.f.set(func(f *facts) { f.stateErr = nil })
			x.room(stateFailed)
			if due, _ := x.due(t); due != armed {
				t.Errorf("next good reading due = %v, want %v (armed unchanged)", due, armed)
			}
		})
	}
}

// TC-874-08: FullBelow N arms at N-1 and is due at exactly N.
func TestDue_Boundary(t *testing.T) {
	x := newFixture(t)
	x.f.set(func(f *facts) { f.free, f.state = fullAt-1, stateFailed })
	if due, _ := x.due(t); due || !x.r.isArmed() {
		t.Fatalf("N-1: due %v armed %v, want armed and not due", due, x.r.isArmed())
	}
	x.f.set(func(f *facts) { f.free = fullAt })
	if due, _ := x.due(t); !due {
		t.Error("N: not due")
	}
}

// TC-874-09: a second full-and-failed episode after a recovery arms again and
// is due exactly once again.
func TestDue_SecondEpisode(t *testing.T) {
	x := newFixture(t)
	trues := 0
	for range 2 {
		x.armed(t)
		x.room(stateFailed)
		for range 3 {
			if due, _ := x.due(t); due {
				trues++
			}
		}
	}
	if trues != 2 {
		t.Errorf("%d due readings over two episodes, want 2", trues)
	}
	if n := len(x.rec.Matching(slog.LevelInfo, "secret store failed while the data partition was full")); n != 2 {
		t.Errorf("%d armed records, want 2", n)
	}
}

// stepLine is one line the job's step log received.
type stepLine struct{ level, msg string }

func runStep(t *testing.T, x *fixture) (json.RawMessage, []stepLine, error) {
	t.Helper()
	var lines []stepLine
	sc := &jobs.StepCtx{Ctx: t.Context(), JobID: "job-rec", Log: func(level, msg string) {
		lines = append(lines, stepLine{level, msg})
	}}
	steps := x.r.Workflow().Steps
	if len(steps) != 1 {
		t.Fatalf("%d steps", len(steps))
	}
	out, err := steps[0].Do(sc)
	return out, lines, err
}

// TC-874-10: the restart step re-reads the unit, the holds and the restore;
// it restarts only a still-failed, unheld, unrestored store, and otherwise
// succeeds with restarted:false naming the cause.
func TestRestartStep_Rechecks(t *testing.T) {
	t.Run("restarts", func(t *testing.T) {
		x := newFixture(t)
		x.room(stateFailed)
		out, _, err := runStep(t, x)
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != `{"restarted":true}` {
			t.Errorf("result = %s", out)
		}
		if _, _, _, _, n := x.f.counts(); n != 1 {
			t.Errorf("Restart called %d times, want 1", n)
		}
		r := x.rec.Matching(slog.LevelInfo, "secret store restarting after the data partition was freed")
		if len(r) != 1 {
			t.Fatalf("%d restart records, want 1", len(r))
		}
		for key, want := range map[string]string{"event": "secretstore.recover_restart", "job_id": "job-rec", "unit": testUnit, "free_bytes": "1073741824"} {
			if got := attr(t, r[0], key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
	})
	for _, tc := range []struct {
		name   string
		set    func(*facts)
		reason string
	}{
		{"no longer failed", func(f *facts) { f.state = "active" }, "the store unit is active, not failed"},
		{"held", func(f *facts) { f.held = true }, "a job holds the secret store"},
		{"restoring", func(f *facts) { f.restoring = true }, "a restore is in progress"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newFixture(t)
			x.room(stateFailed)
			x.f.set(tc.set)
			out, _, err := runStep(t, x)
			if err != nil {
				t.Fatalf("step err = %v, want success", err)
			}
			var res result
			if err := json.Unmarshal(out, &res); err != nil {
				t.Fatal(err)
			}
			if res.Restarted || res.Reason != tc.reason {
				t.Errorf("result = %+v, want restarted:false reason %q", res, tc.reason)
			}
			if _, _, _, _, n := x.f.counts(); n != 0 {
				t.Errorf("Restart called %d times, want 0", n)
			}
		})
	}
	t.Run("state unreadable", func(t *testing.T) {
		x := newFixture(t)
		x.f.set(func(f *facts) { f.stateErr = errors.New("dbus: gone") })
		if _, _, err := runStep(t, x); !errors.Is(err, errStateUnread) {
			t.Errorf("err = %v, want the unread sentence", err)
		}
		if _, _, _, _, n := x.f.counts(); n != 0 {
			t.Errorf("Restart called %d times, want 0", n)
		}
	})
}

// exitErr is a real *exec.ExitError with code 1.
func exitErr(t *testing.T) error {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("sh: %v", err)
	}
	err = exec.Command(sh, "-c", "exit 1").Run()
	if err == nil {
		t.Fatal("exit 1 succeeded")
	}
	return err
}

// TC-874-11: a failed restart fails the step with a sentence that points at
// nothing the feed lacks; the step log carries the safe exit-status line and
// an ERROR record carries job_id and err. The workflow never retries.
func TestRestartStep_FailureSurfaces(t *testing.T) {
	x := newFixture(t)
	x.room(stateFailed)
	cause := exitErr(t)
	x.f.set(func(f *facts) {
		f.restartErr = errors.Join(errors.New("systemctl restart openbao.service: output: secret-token-xyz"), cause)
	})
	_, lines, err := runStep(t, x)
	if err == nil {
		t.Fatal("step succeeded on a failed restart")
	}
	msg := err.Error()
	if msg != "The secret store could not be restarted after the data partition was freed, so it is still down." {
		t.Errorf("sentence = %q", msg)
	}
	if !strings.HasSuffix(msg, ".") || strings.ToUpper(msg[:1]) != msg[:1] {
		t.Errorf("sentence %q is not capitalised and full-stopped", msg)
	}
	for _, bad := range []string{"log", "feed", "secret-token"} {
		if strings.Contains(strings.ToLower(msg), bad) {
			t.Errorf("sentence %q contains %q", msg, bad)
		}
	}
	wantLine := stepLine{"error", "systemctl restart of the secret store unit failed (exit status 1)."}
	found := false
	for _, l := range lines {
		if strings.Contains(l.msg, "secret-token") {
			t.Errorf("step log line %q carries command output", l.msg)
		}
		if l == wantLine {
			found = true
		}
	}
	if !found {
		t.Errorf("step log %+v, want %+v", lines, wantLine)
	}
	e := x.rec.Matching(slog.LevelError, "systemctl restart of the secret store unit failed")
	if len(e) != 1 {
		t.Fatalf("%d ERROR records, want 1", len(e))
	}
	if got := attr(t, e[0], "event"); got != "secretstore.recover_restart_failed" {
		t.Errorf("event = %q", got)
	}
	if got := attr(t, e[0], "job_id"); got != "job-rec" {
		t.Errorf("job_id = %q", got)
	}
	if got := attr(t, e[0], "err"); !strings.Contains(got, "exit status 1") {
		t.Errorf("err = %q, want the cause", got)
	}
	w := x.r.Workflow()
	if w.Kind != Kind || w.Steps[0].Name != "restart" || w.Steps[0].Retries != 0 || w.Steps[0].Timeout != 30*time.Second {
		t.Errorf("workflow = %+v", w)
	}
	t.Run("not an exit status", func(t *testing.T) {
		if got := restartFailedLine(errors.New("no systemctl")); got != "systemctl restart of the secret store unit failed." {
			t.Errorf("line = %q", got)
		}
	})
}

// TC-874-12: the start-time Arm arms on full plus failed or activating with no
// scheduler interval elapsed, and the next reading with room is due.
func TestArm_AtStart(t *testing.T) {
	for _, state := range []string{stateFailed, stateActivating} {
		t.Run(state, func(t *testing.T) {
			x := newFixture(t)
			x.f.set(func(f *facts) { f.free, f.state = 0, state })
			x.r.Arm(t.Context())
			if n := len(x.rec.Matching(slog.LevelInfo, "secret store failed while the data partition was full")); n != 1 {
				t.Fatalf("%d armed records from Arm, want 1", n)
			}
			x.room(stateFailed)
			if due, _ := x.due(t); !due {
				t.Error("the first reading with room after Arm was not due")
			}
		})
	}
	t.Run("room never arms or restarts", func(t *testing.T) {
		x := newFixture(t)
		x.room(stateFailed)
		x.r.Arm(t.Context())
		if x.r.isArmed() {
			t.Error("Arm with room armed")
		}
		// Arm with room while armed does not fire either.
		x.armed(t)
		x.room(stateFailed)
		x.r.Arm(t.Context())
		if !x.r.isArmed() {
			t.Error("Arm with room cleared armed")
		}
		if _, _, _, _, n := x.f.counts(); n != 0 {
			t.Errorf("Restart called %d times", n)
		}
	})
}

// TC-874-16: unarmed with room, every reading is false with an empty reason
// and reads only Free.
func TestDue_QuietSteadyState(t *testing.T) {
	x := newFixture(t)
	x.room(stateFailed)
	for range 5 {
		if due, reason := x.due(t); due || reason != "" {
			t.Fatalf("Due = %v, %q", due, reason)
		}
	}
	free, state, held, restore, restart := x.f.counts()
	if free != 5 || state != 0 || held != 0 || restore != 0 || restart != 0 {
		t.Errorf("calls free=%d state=%d held=%d restore=%d restart=%d, want 5/0/0/0/0", free, state, held, restore, restart)
	}
	if n := len(x.rec.Records()); n != 0 {
		t.Errorf("%d log records in the steady state, want 0", n)
	}
}

// TC-874-15 (New's half): New refuses each missing collaborator and a zero
// FullBelow.
func TestNew_Refuses(t *testing.T) {
	log, _ := logkittest.New()
	ok := func() Deps {
		return Deps{
			Dir: testDir, Free: func(string) (uint64, error) { return 0, nil }, FullBelow: fullAt, Unit: testUnit,
			UnitState: func(context.Context) (string, error) { return "", nil },
			Held:      func(context.Context) bool { return false },
			Restoring: func() (string, bool) { return "", false },
			Restart:   func(context.Context) error { return nil },
			Log:       log,
		}
	}
	if _, err := New(ok()); err != nil {
		t.Fatalf("New(ok) = %v", err)
	}
	for name, mut := range map[string]func(*Deps){
		"Dir": func(d *Deps) { d.Dir = "" }, "Free": func(d *Deps) { d.Free = nil },
		"FullBelow": func(d *Deps) { d.FullBelow = 0 }, "Unit": func(d *Deps) { d.Unit = "" },
		"UnitState": func(d *Deps) { d.UnitState = nil }, "Held": func(d *Deps) { d.Held = nil },
		"Restoring": func(d *Deps) { d.Restoring = nil }, "Restart": func(d *Deps) { d.Restart = nil },
		"Log": func(d *Deps) { d.Log = nil },
	} {
		d := ok()
		mut(&d)
		if _, err := New(d); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("New without %s = %v, want a refusal naming it", name, err)
		}
	}
}
