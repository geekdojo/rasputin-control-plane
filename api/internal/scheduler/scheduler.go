// Package scheduler fires registered jobs on a periodic interval. It's a
// thin wrapper around the jobs.Runner: each Entry says "submit a job of
// kind X every Y duration"; the scheduler owns one goroutine per entry.
//
// Design choices:
//   - In-memory schedule. The cadence is derived from main on every
//     restart; we don't persist when each entry last fired. Restart-replay
//     is honest (per architecture §6.4) and the schedule resumes from
//     "now + interval", not "from the last persisted fire time". For
//     reconcile cadences, a few-minute drift on restart is fine.
//   - One goroutine per entry. Simple, no shared ticker contention; the
//     overhead at our scale (3-5 entries) is negligible.
//   - Failures are logged, not panicked. The next tick still fires.
//   - Optional InitialDelay so we don't stampede every entry at startup.
package scheduler

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// Entry registers one periodic job.
type Entry struct {
	// Kind is the workflow kind, e.g. "firewall.reconcile".
	Kind string
	// Spec is the JSON body passed to Runner.Submit. Empty {} for sagas
	// that don't take parameters.
	Spec json.RawMessage
	// Interval between fires. Minimum 30s — anything shorter would
	// hammer the bus for no benefit.
	Interval time.Duration
	// InitialDelay is the wait before the first fire. Useful to stagger
	// startup. Defaults to Interval if zero.
	InitialDelay time.Duration
	// CreatedBy is the value persisted as the job's creator. Defaults to
	// "scheduler" if empty.
	CreatedBy string
}

// Scheduler owns the periodic goroutines for a set of Entries. Start
// returns immediately; Stop blocks until all goroutines exit.
type Scheduler struct {
	runner  *jobs.Runner
	entries []Entry

	mu      sync.Mutex
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
}

func New(runner *jobs.Runner, entries []Entry) *Scheduler {
	return &Scheduler{runner: runner, entries: entries}
}

// Start kicks off one goroutine per entry. Safe to call once; subsequent
// calls are no-ops.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return
	}
	s.started = true
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	for _, e := range s.entries {
		e := e // capture
		s.wg.Add(1)
		go s.runEntry(runCtx, e)
	}
	log.Printf("scheduler: started %d entries", len(s.entries))
}

// Stop signals all entry goroutines to exit and waits for them.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

func (s *Scheduler) runEntry(ctx context.Context, e Entry) {
	defer s.wg.Done()
	interval := e.Interval
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	initial := e.InitialDelay
	if initial <= 0 {
		initial = interval
	}
	createdBy := e.CreatedBy
	if createdBy == "" {
		createdBy = "scheduler"
	}
	spec := e.Spec
	if len(spec) == 0 {
		spec = json.RawMessage("{}")
	}

	log.Printf("scheduler: %s every %s (first in %s)", e.Kind, interval, initial)

	// Initial wait — staggered.
	select {
	case <-ctx.Done():
		return
	case <-time.After(initial):
	}
	s.fire(ctx, e.Kind, spec, createdBy)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.fire(ctx, e.Kind, spec, createdBy)
		}
	}
}

func (s *Scheduler) fire(ctx context.Context, kind string, spec json.RawMessage, createdBy string) {
	// Use a short submission timeout — the Submit call itself only does
	// the create-job-row work; the saga then runs in its own goroutine.
	subCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := s.runner.Submit(subCtx, kind, spec, createdBy); err != nil {
		log.Printf("scheduler: submit %s: %v", kind, err)
	}
}
