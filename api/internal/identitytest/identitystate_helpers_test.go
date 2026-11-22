package identitytest

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// stateDeps are the parts of an identity state monitor a functional test
// supplies; the rest are the production adapters, or stand-ins for the facts
// these tests do not exercise (no hold, no marker change, no injected fact).
type stateDeps struct {
	units  func(context.Context) (identitystate.Units, error)
	exits  string // the exits directory
	health identitystate.Health
	ledger identitystate.Ledger
	// features is the features check; nil stands in a matching one.
	features func(ctx context.Context, kcInvocation string) (bool, error)
}

// memSettings is the settings store in memory.
type memSettings struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memSettings) Get(_ context.Context, k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k], nil
}

func (s *memSettings) Set(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}

// recordingHealth keeps the last report and error the service answered.
type recordingHealth struct {
	inner identitystate.Health
	mu    sync.Mutex
	rep   idclient.HealthReport
	err   error
}

func (r *recordingHealth) Health(ctx context.Context) (idclient.HealthReport, error) {
	rep, err := r.inner.Health(ctx)
	r.mu.Lock()
	r.rep, r.err = rep, err
	r.mu.Unlock()
	return rep, err
}

func (r *recordingHealth) last() (idclient.HealthReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rep, r.err
}

// noHealth is the health stand-in for a test that must never ask.
type noHealth struct{ t *testing.T }

func (n noHealth) Health(context.Context) (idclient.HealthReport, error) {
	n.t.Error("the monitor asked /health/ready while the unit was not active")
	return idclient.HealthReport{}, &idclient.Error{Op: "health", Kind: idclient.ErrUnreachable}
}

// newStateMonitor is an identity state monitor over d. The marker and the
// stored ready version agree, so it never reads upgrading.
func newStateMonitor(t *testing.T, cfg Config, d stateDeps) *identitystate.Monitor {
	t.Helper()
	never := func(context.Context) (bool, error) { return false, nil }
	features := d.features
	if features == nil {
		features = func(context.Context, string) (bool, error) { return false, nil }
	}
	m, err := identitystate.New(identitystate.Deps{
		Units:       d.units,
		Exits:       identitystate.ExitRecords(os.DirFS("/"), d.exits),
		RemoveExit:  identitystate.RemoveExitRecord(os.Remove, d.exits),
		Health:      d.health,
		Ledger:      d.ledger,
		ReadRecords: func(context.Context) {},
		StartHold:   identitystate.StartHoldRecord(os.DirFS("/"), filepath.Join(d.exits, "no-start-hold")),
		Marker:      func(context.Context) (string, error) { return "26.8.2", nil },
		Settings:    &memSettings{m: map[string]string{identitystate.VersionReadyKey: "26.8.2"}},
		JobRunning:  func(context.Context, string) (bool, error) { return false, nil },
		Blank:       never, AppsPaused: never, HistoryBehind: never,
		Features: features,
		Now:      time.Now,
		Log:      cfg.Logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// openJobs is a real job store on temporary SQLite.
func openJobs(t *testing.T) *jobs.Store {
	t.Helper()
	js, err := jobs.OpenStore(context.Background(), filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	return js
}
