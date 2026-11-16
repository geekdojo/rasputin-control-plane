package identitystate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fixedNow is the fixture's clock. It never advances: no reading depends on
// it beyond stamping Since.
var fixedNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

// The unit tuples the tests use.
var (
	kcActive      = Unit{ActiveState: "active", SubState: "running", InvocationID: id(100)}
	kcStartPre    = Unit{ActiveState: "activating", SubState: "start-pre", InvocationID: id(101)}
	kcStart       = Unit{ActiveState: "activating", SubState: "start", InvocationID: id(101)}
	kcStartPost   = Unit{ActiveState: "activating", SubState: "start-post", InvocationID: id(101)}
	kcAutoRestart = Unit{ActiveState: "activating", SubState: "auto-restart", InvocationID: id(102)}
	kcFailed      = Unit{ActiveState: "failed", SubState: "failed", InvocationID: id(103)}
	kcInactive    = Unit{ActiveState: "inactive", SubState: "dead"}
	dbActive      = Unit{ActiveState: "active", SubState: "running", InvocationID: id(200)}
)

// id is a 32-character invocation ID.
func id(n int) string { return fmt.Sprintf("%032x", n) }

// healthDown is a 503 report naming the database check DOWN.
var healthDown = idclient.HealthReport{Status: "DOWN", Checks: []idclient.HealthCheck{{Name: dbCheck, Status: "DOWN"}}}

// fakeLedger is the job ledger, in memory, with an error to inject.
type fakeLedger struct {
	mu        sync.Mutex
	jobs      map[string]*jobs.Job
	order     []string
	recordErr error // returned once by the next RecordFinishedJob
	listErr   error
	records   int
}

func newFakeLedger() *fakeLedger { return &fakeLedger{jobs: map[string]*jobs.Job{}} }

func (l *fakeLedger) RecordFinishedJob(_ context.Context, j *jobs.Job) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records++
	if err := l.recordErr; err != nil {
		l.recordErr = nil
		return false, err
	}
	if _, ok := l.jobs[j.ID]; ok {
		return false, nil
	}
	l.jobs[j.ID] = j
	l.order = append(l.order, j.ID)
	return true, nil
}

func (l *fakeLedger) ListJobsByKind(_ context.Context, kind string, limit int) ([]*jobs.Job, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listErr != nil {
		return nil, l.listErr
	}
	var out []*jobs.Job
	for i := len(l.order) - 1; i >= 0 && len(out) < limit; i-- {
		if j := l.jobs[l.order[i]]; j.Kind == kind {
			out = append(out, j)
		}
	}
	return out, nil
}

// rollback adds an os.identity_rollback job with outcome and reason.
func (l *fakeLedger) rollback(t *testing.T, outcome, reason string) {
	t.Helper()
	spec, err := json.Marshal(osoutcome.Spec{Source: RollbackKind, Outcome: outcome, Reason: reason})
	if err != nil {
		t.Fatal(err)
	}
	st := jobs.StatusSucceeded
	if outcome != "current" {
		st = jobs.StatusFailed
	}
	j := &jobs.Job{ID: "rb-" + fmt.Sprint(len(l.order)), Kind: RollbackKind, Spec: spec, Status: st, Error: reason}
	if _, err := l.RecordFinishedJob(t.Context(), j); err != nil {
		t.Fatal(err)
	}
}

func (l *fakeLedger) byKind(kind string) []*jobs.Job {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []*jobs.Job
	for _, k := range l.order {
		if l.jobs[k].Kind == kind {
			out = append(out, l.jobs[k])
		}
	}
	return out
}

// world is what the fakes report, and how often each was asked.
type world struct {
	mu sync.Mutex

	units    Units
	unitsErr error

	health    idclient.HealthReport
	healthErr error

	startHold    StartHold
	startHoldErr error

	marker    string
	markerErr error

	stored     string
	getErr     error
	setErr     error
	jobRunning map[string]bool
	runningErr error

	blank, appsPaused, historyBehind          bool
	blankErr, appsPausedErr, historyBehindErr error

	unitsCalls, healthCalls, readRecordsCalls, setCalls, removes int
}

func (w *world) set(fn func(*world)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fn(w)
}

// fixture is a Monitor over the world's fakes, a real exits directory and a
// ledger.
type fixture struct {
	w      *world
	ledger *fakeLedger
	dir    string // the exits directory
	rec    *logkittest.Recorder
	m      *Monitor
}

// newFixture starts in the ready world: both units active, health UP, no
// record, no hold, marker equal to the stored version.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	w := &world{
		units:  Units{KC: kcActive, DB: dbActive},
		health: idclient.HealthReport{Status: "UP"},
		marker: "26.8.2", stored: "26.8.2",
		jobRunning: map[string]bool{},
	}
	x := &fixture{w: w, ledger: newFakeLedger(), dir: filepath.Join(t.TempDir(), "exits")}
	if err := os.Mkdir(x.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	log, rec := logkittest.New()
	x.rec = rec
	m, err := New(x.deps(log, x.ledger))
	if err != nil {
		t.Fatal(err)
	}
	x.m = m
	return x
}

// deps are the fixture's Deps with ledger.
func (x *fixture) deps(log *slog.Logger, ledger Ledger) Deps {
	w := x.w
	fact := func(v *bool, e *error) Fact {
		return func(context.Context) (bool, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			return *v, *e
		}
	}
	return Deps{
		Units: func(context.Context) (Units, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.unitsCalls++
			return w.units, w.unitsErr
		},
		Exits: ExitRecords(os.DirFS("/"), x.dir),
		RemoveExit: RemoveExitRecord(func(name string) error {
			w.mu.Lock()
			w.removes++
			w.mu.Unlock()
			return os.Remove(name)
		}, x.dir),
		Health: healthFunc(func(context.Context) (idclient.HealthReport, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.healthCalls++
			return w.health, w.healthErr
		}),
		Ledger: ledger,
		ReadRecords: func(context.Context) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.readRecordsCalls++
		},
		StartHold: func(context.Context) (StartHold, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			return w.startHold, w.startHoldErr
		},
		Marker: func(context.Context) (string, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			return w.marker, w.markerErr
		},
		Settings: settingsFake{w},
		JobRunning: func(_ context.Context, jobID string) (bool, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			return w.jobRunning[jobID], w.runningErr
		},
		Blank:         fact(&w.blank, &w.blankErr),
		AppsPaused:    fact(&w.appsPaused, &w.appsPausedErr),
		HistoryBehind: fact(&w.historyBehind, &w.historyBehindErr),
		Now:           func() time.Time { return fixedNow },
		Log:           log,
	}
}

type healthFunc func(context.Context) (idclient.HealthReport, error)

func (f healthFunc) Health(ctx context.Context) (idclient.HealthReport, error) { return f(ctx) }

type settingsFake struct{ w *world }

func (s settingsFake) Get(context.Context, string) (string, error) {
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	return s.w.stored, s.w.getErr
}

func (s settingsFake) Set(_ context.Context, key, value string) error {
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	s.w.setCalls++
	if s.w.setErr != nil {
		return s.w.setErr
	}
	if key != VersionReadyKey {
		return errors.New("unexpected key " + key)
	}
	s.w.stored = value
	return nil
}

// state reads once and fails the test on an error.
func (x *fixture) state(t *testing.T) State {
	t.Helper()
	st, err := x.m.State(t.Context())
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	return st
}

// record writes one exit record into the fixture's directory, with mtime at.
func (x *fixture) record(t *testing.T, invocation, outcome, code, status string, at time.Time) {
	t.Helper()
	writeRecord(t, x.dir, invocation, outcome, code, status, at)
}

func writeRecord(t *testing.T, dir, invocation, outcome, code, status string, at time.Time) {
	t.Helper()
	p := filepath.Join(dir, invocation)
	body := "outcome=" + outcome + "\ninvocation_id=" + invocation + "\nexit_code=" + code + "\nexit_status=" + status + "\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, at, at); err != nil {
		t.Fatal(err)
	}
}

// last points `last` at invocation.
func (x *fixture) last(t *testing.T, invocation string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(x.dir, lastName), []byte(invocation+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// oom writes an exit-3 record and points `last` at it.
func (x *fixture) oom(t *testing.T, invocation string) {
	t.Helper()
	x.record(t, invocation, "exit-code", "exited", "3", fixedNow)
	x.last(t, invocation)
}

// names lists the exits directory.
func (x *fixture) names(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(x.dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}
