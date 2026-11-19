package storemigrate

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
)

// fakeReady is the readiness monitor's first-ready contract, synchronous:
// callbacks wait for ready(), and once it has fired a new one runs at once.
type fakeReady struct {
	mu    sync.Mutex
	seen  bool
	fns   []func(context.Context)
	reads int
}

func (r *fakeReady) OnFirstReady(ctx context.Context, fn func(context.Context)) {
	r.mu.Lock()
	if !r.seen {
		r.fns = append(r.fns, fn)
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	fn(ctx)
}

func (r *fakeReady) State(context.Context) (storestate.State, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads++
	return storestate.Sealed, nil
}

// ready is the first Ready reading.
func (r *fakeReady) ready() {
	r.mu.Lock()
	r.seen = true
	fns := r.fns
	r.fns = nil
	r.mu.Unlock()
	for _, fn := range fns {
		fn(context.Background())
	}
}

// fakeRunner records what was submitted, in order.
type fakeRunner struct {
	mu        sync.Mutex
	submitted []string
	err       error
}

func (r *fakeRunner) Submit(_ context.Context, kind string, _ any, _ string) (*jobs.Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	r.submitted = append(r.submitted, kind)
	return &jobs.Job{ID: "j", Kind: kind}, nil
}

func (r *fakeRunner) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.submitted...)
}

const checkKind = "store.reference_check"

// newTrigger builds a trigger over settings, with the last provision record
// rec (none when nil). Its check submits checkKind.
func newTrigger(t *testing.T, settings *fakeSettings, boot string, rec *osoutcome.Record) (*Trigger, *fakeReady, *fakeRunner) {
	t.Helper()
	ready, runner := &fakeReady{}, &fakeRunner{}
	last := &LastRecord{}
	if rec != nil {
		last.Observe(context.Background(), *rec)
	}
	tr, err := NewTrigger(TriggerDeps{
		Ready: ready, Runner: runner, Settings: settings,
		BootID:    func() (string, error) { return boot, nil },
		Provision: last.Last,
		Check:     func(ctx context.Context) { _, _ = runner.Submit(ctx, checkKind, nil, CreatedBy) },
		Log:       slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tr, ready, runner
}

func provisionRec(outcome, author, boot string) *osoutcome.Record {
	return &osoutcome.Record{Outcome: outcome, BootID: boot, RunID: runBefore, Reason: "r.", Author: author}
}

// TC-1132-21 (F-1132-07, F-1132-09): with this boot's provision record
// saying author=absent, first-ready submits exactly one migration. Nothing
// is submitted for present, for -, for a failed outcome, for another boot's
// record or with no record; the reference check is submitted instead. Once
// the bound names this boot (the job wrote it before anything else, and a
// job runner.Recover failed leaves it there), a new api process submits no
// migration. On a new boot it submits again.
func TestTrigger_SubmitsOnTheFact(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  *osoutcome.Record
		want string
	}{
		{"absent, applied", provisionRec("applied", osoutcome.AuthorAbsent, thisBoot), Kind},
		{"absent, unchanged", provisionRec("unchanged", osoutcome.AuthorAbsent, thisBoot), Kind},
		{"present", provisionRec("applied", osoutcome.AuthorPresent, thisBoot), checkKind},
		{"unknown", provisionRec("applied", osoutcome.AuthorUnknown, thisBoot), checkKind},
		{"failed", provisionRec("failed", osoutcome.AuthorAbsent, thisBoot), checkKind},
		{"another boot", provisionRec("applied", osoutcome.AuthorAbsent, otherBoot), checkKind},
		{"no record", nil, checkKind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, ready, runner := newTrigger(t, &fakeSettings{kv: map[string]string{}}, thisBoot, tc.rec)
			tr.Arm(context.Background())
			if ready.reads != 1 || len(runner.list()) != 0 {
				t.Fatalf("Arm: %d readings, submitted %v; want one reading and nothing before ready", ready.reads, runner.list())
			}
			ready.ready()
			if got := runner.list(); len(got) != 1 || got[0] != tc.want {
				t.Fatalf("submitted %v, want [%s]", got, tc.want)
			}
		})
	}

	// The bound: after an attempt in this boot, a new process submits no
	// migration, only the check; on a new boot it migrates again.
	settings := &fakeSettings{kv: map[string]string{KeyAttemptBootID: thisBoot}}
	tr, ready, runner := newTrigger(t, settings, thisBoot, provisionRec("applied", osoutcome.AuthorAbsent, thisBoot))
	tr.Arm(context.Background())
	ready.ready()
	if got := runner.list(); len(got) != 1 || got[0] != checkKind {
		t.Fatalf("after an attempt this boot: submitted %v, want only the check", got)
	}
	tr, ready, runner = newTrigger(t, settings, otherBoot, provisionRec("applied", osoutcome.AuthorAbsent, otherBoot))
	tr.Arm(context.Background())
	ready.ready()
	if got := runner.list(); len(got) != 1 || got[0] != Kind {
		t.Fatalf("on a new boot: submitted %v, want the migration", got)
	}

	// An unreadable bound, and a refused submit, fail toward no migration
	// and still run the check.
	tr, ready, runner = newTrigger(t, &fakeSettings{kv: map[string]string{}, getErr: errBoom}, thisBoot,
		provisionRec("applied", osoutcome.AuthorAbsent, thisBoot))
	tr.Arm(context.Background())
	ready.ready()
	if got := runner.list(); len(got) != 1 || got[0] != checkKind {
		t.Fatalf("unreadable bound: submitted %v", got)
	}
	tr, ready, runner = newTrigger(t, &fakeSettings{kv: map[string]string{}}, thisBoot,
		provisionRec("applied", osoutcome.AuthorAbsent, thisBoot))
	runner.err = errors.New("database is locked")
	tr.Arm(context.Background())
	ready.ready()
	if _, err := NewTrigger(TriggerDeps{}); err == nil {
		t.Error("nil collaborators accepted")
	}
}

// TC-1132-23 (F-1132-05): with a migration triggered, first-ready submits
// the migration and not the check; the check is submitted only when the
// migration job ends (its terminal hook calls ReferenceCheck), and once per
// process: a second terminal call, as runner.Recover's after the trigger,
// submits nothing more. With no migration, the check is submitted on
// first-ready as before.
func TestTrigger_ReferenceCheckAfterTheMigration(t *testing.T) {
	tr, ready, runner := newTrigger(t, &fakeSettings{kv: map[string]string{}}, thisBoot,
		provisionRec("applied", osoutcome.AuthorAbsent, thisBoot))
	tr.Arm(context.Background())
	ready.ready()
	if got := runner.list(); len(got) != 1 || got[0] != Kind {
		t.Fatalf("first-ready submitted %v, want only the migration", got)
	}
	// The migration's terminal hook.
	tr.ReferenceCheck(context.Background())
	tr.ReferenceCheck(context.Background())
	if got := runner.list(); len(got) != 2 || got[1] != checkKind {
		t.Fatalf("after the migration ended: submitted %v, want the check once after it", got)
	}

	// runner.Recover failing an orphaned migration at start fires the hook
	// before the store is ready: the check waits for the first ready reading.
	tr, ready, runner = newTrigger(t, &fakeSettings{kv: map[string]string{KeyAttemptBootID: thisBoot}}, thisBoot,
		provisionRec("applied", osoutcome.AuthorAbsent, thisBoot))
	tr.ReferenceCheck(context.Background())
	if got := runner.list(); len(got) != 0 {
		t.Fatalf("the check ran before the store was ready: %v", got)
	}
	tr.Arm(context.Background())
	ready.ready()
	if got := runner.list(); len(got) != 1 || got[0] != checkKind {
		t.Fatalf("submitted %v, want one check", got)
	}
}

// sealClean is a seal directory whose fragment is Clean.
type sealClean struct{}

func (sealClean) State() (sealrotate.Tree, error) {
	return sealrotate.Tree{Fragment: sealrotate.Fragment{Shape: sealrotate.Clean}}, nil
}

// TC-1132-25: the migration holds the real capture gate. While it does, a
// seal-key rotation's TryAcquire is refused, and a backup's Acquire and an
// OS update's AcquireForUpdate wait; neither gets the gate, so neither can
// stop or start the store, until the migration releases it.
func TestMigrate_SerialisedOnTheRealGate(t *testing.T) {
	gate, err := sealrotate.NewGate(sealClean{}, func(context.Context, string) (bool, error) { return true, nil },
		slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	f := newFx(t)
	f.m.d.Lock = gate
	backup, update := make(chan error, 1), make(chan error, 1)
	duringHold := false
	f.ctl.onStart = func() {
		f.rootStep()
		if duringHold {
			return
		}
		duringHold = true
		if err := gate.TryAcquire("rotation"); err == nil {
			t.Error("a rotation took the gate during the migration")
		}
		go func() { backup <- gate.Acquire(context.Background(), "backup") }()
		go func() { update <- gate.AcquireForUpdate(context.Background(), "update") }()
		select {
		case <-backup:
			t.Error("a backup took the gate during the migration")
		case <-update:
			t.Error("an OS update took the gate during the migration")
		default:
		}
	}
	if err := f.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Released at the commit: one waiter gets it, then the other.
	select {
	case err := <-backup:
		if err != nil {
			t.Fatal(err)
		}
		gate.Release("backup")
		if err := <-update; err != nil {
			t.Fatal(err)
		}
	case err := <-update:
		if err != nil {
			t.Fatal(err)
		}
		gate.Release("update")
		if err := <-backup; err != nil {
			t.Fatal(err)
		}
	}
}
