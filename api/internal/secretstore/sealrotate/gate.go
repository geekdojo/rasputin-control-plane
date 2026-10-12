package sealrotate

import (
	"context"
	"errors"
	"log/slog"
	"sync"
)

// stateReader is the one Files call the Gate makes (ARCH-ISP).
type stateReader interface {
	State() (Tree, error)
}

// Gate is the backup capture lock (AC4). One holder at a time: the rotation
// takes it with TryAcquire and never waits; a backup takes it with Acquire,
// which waits for a rotation to release it. A backup is refused at once when
// the seal files are not Clean and no rotation holds the gate, because an
// archive captured in the middle of a rotation could hold a key that does
// not open it.
type Gate struct {
	state      stateReader
	jobRunning func(ctx context.Context, jobID string) (bool, error)
	log        *slog.Logger

	mu         sync.Mutex
	holder     string
	byRotation bool
	// free is closed when the holder releases; a waiter re-checks then.
	free chan struct{}
}

// NewGate returns a Gate over the seal files, the job ledger's running fact
// and the logger. None may be nil.
func NewGate(state stateReader, jobRunning func(ctx context.Context, jobID string) (bool, error), log *slog.Logger) (*Gate, error) {
	switch {
	case state == nil:
		return nil, errors.New("sealrotate: the gate's seal files are nil")
	case jobRunning == nil:
		return nil, errors.New("sealrotate: the gate's JobRunning is nil")
	case log == nil:
		return nil, errors.New("sealrotate: the gate's logger is nil")
	}
	return &Gate{state: state, jobRunning: jobRunning, log: log}, nil
}

// TryAcquire takes the gate for the rotation jobID, or refuses at once with
// the sentence naming who holds it.
func (g *Gate) TryAcquire(jobID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case g.holder == jobID:
		return nil
	case g.holder != "" && g.byRotation:
		return errAnotherRotation
	case g.holder != "":
		return errBackupHolds
	}
	g.take(jobID, true)
	return nil
}

// take records jobID as the holder. The caller holds mu.
func (g *Gate) take(jobID string, byRotation bool) {
	g.holder, g.byRotation, g.free = jobID, byRotation, make(chan struct{})
}

// Acquire takes the gate for the backup jobID. While another job holds it,
// Acquire waits for the release, unless that job is no longer running, whose
// hold is dropped. Once free, the seal files must read Clean, or Acquire
// refuses with a sentence; it returns ctx's error when ctx ends first.
func (g *Gate) Acquire(ctx context.Context, jobID string) error {
	for {
		g.mu.Lock()
		if g.holder == "" || g.holder == jobID {
			defer g.mu.Unlock()
			tree, err := g.state.State()
			if err != nil {
				g.log.WarnContext(ctx, "backup refused: the seal files could not be checked",
					"component", "secretstore", "event", "secretstore.seal_rotate.capture_refused", "job_id", jobID, "err", err.Error())
				return errBackupSealUnreadable
			}
			if tree.Fragment.Shape != Clean {
				g.log.WarnContext(ctx, "backup refused: a seal-key rotation has not finished",
					"component", "secretstore", "event", "secretstore.seal_rotate.capture_refused", "job_id", jobID,
					"shape", tree.Fragment.Shape.String(), "key_id", tree.Fragment.Current.String())
				return errBackupRotationIncomplete
			}
			g.take(jobID, false)
			return nil
		}
		holder, free := g.holder, g.free
		g.mu.Unlock()

		if running, err := g.jobRunning(ctx, holder); err == nil && !running {
			g.Release(holder)
			continue
		}
		select {
		case <-free:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Release frees the gate when jobID holds it. It is idempotent, and a job
// that does not hold the gate releases nothing.
func (g *Gate) Release(jobID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if jobID == "" || g.holder != jobID {
		return
	}
	close(g.free)
	g.holder, g.byRotation, g.free = "", false, nil
}

// RotationHolder is the rotation job holding the gate, or "".
func (g *Gate) RotationHolder() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.byRotation {
		return ""
	}
	return g.holder
}
