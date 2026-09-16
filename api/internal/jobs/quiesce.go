package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Quiescing: stopping job intake so the api can restart without a job in
// flight, and without losing a job someone submits while it does.
//
// The only caller today is the bus TLS switch to TLS-required
// (geekdojo/geekdojo-brain#448): nats-server cannot drop plaintext on a reload,
// so the api restarts, and a restart ends whatever the runner is doing the way
// Recover describes — "control plane restarted mid-job". So the switch waits for
// a runner with nothing to do, and it must stay that way until the process
// exits.
//
// The ordering that guarantees it, in one lock:
//
//  1. every submit takes an intake slot under intakeMu, and is refused with
//     ErrQuiesced once the runner is closed — before anything is persisted,
//     so a refused submit is an error its caller sees, never a job row that
//     silently fails at the next start;
//  2. QuiesceIfIdle, under the same lock, checks there is no job in this
//     process (intake slots held, runs not finished) AND no queued or running
//     job in the ledger (a self-update deferred across a restart runs outside
//     this runner), and only then closes intake.
//
// There is no reopen on success: the caller restarts the process. Reopen
// exists for the one path that decides not to restart after closing (it could
// not persist its decision).

// ErrQuiesced is returned by every submit once intake is closed for a restart.
var ErrQuiesced = errors.New("jobs: the control plane is restarting and not accepting new jobs; retry once it is back")

type intake struct {
	mu     sync.Mutex
	active int
	closed bool
}

// acquire takes an intake slot for one job, or refuses when closed.
func (r *Runner) acquire() error {
	r.intake.mu.Lock()
	defer r.intake.mu.Unlock()
	if r.intake.closed {
		return ErrQuiesced
	}
	r.intake.active++
	return nil
}

// release gives the slot back when the job's run ends (or was never started).
func (r *Runner) release() {
	r.intake.mu.Lock()
	defer r.intake.mu.Unlock()
	r.intake.active--
}

// QuiesceIfIdle closes job intake when, and only when, nothing is in flight.
// ok=false carries the reasons (job ids and kinds) for a status page. An error
// reading the ledger leaves intake open.
func (r *Runner) QuiesceIfIdle(ctx context.Context) (ok bool, inFlight []string, err error) {
	r.intake.mu.Lock()
	defer r.intake.mu.Unlock()
	if r.intake.closed {
		return true, nil, nil
	}
	inFlight, err = InFlight(ctx, r.store)
	if err != nil {
		return false, nil, err
	}
	if r.intake.active > 0 && len(inFlight) == 0 {
		// A submit holds a slot but has not written its row yet.
		inFlight = append(inFlight, fmt.Sprintf("%d job(s) being submitted", r.intake.active))
	}
	if len(inFlight) > 0 {
		return false, inFlight, nil
	}
	r.intake.closed = true
	return true, nil, nil
}

// Reopen undoes QuiesceIfIdle for a caller that decided not to restart.
func (r *Runner) Reopen() {
	r.intake.mu.Lock()
	defer r.intake.mu.Unlock()
	r.intake.closed = false
}

// InFlight lists the ledger's queued and running jobs as "kind id".
func InFlight(ctx context.Context, store *Store) ([]string, error) {
	jobs, err := store.ListJobsByStatus(ctx, []Status{StatusQueued, StatusRunning})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, fmt.Sprintf("%s %s", j.Kind, j.ID))
	}
	return out, nil
}
