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

// Gate is the store capture lock (AC4). One holder at a time: the rotation
// takes it with TryAcquire and never waits; a backup takes it with Acquire,
// and an OS update's pre-update copy with AcquireForUpdate
// (geekdojo/geekdojo-brain#800), both of which wait for the holder to
// release it. A capture is refused at once when the seal files are not Clean
// and no rotation holds the gate, because a copy taken in the middle of a
// rotation could hold a key that does not open it. The gate records whether
// a non-rotation holder is a backup or an OS update, so every refusal names
// the job the reader started (ERR-MESSAGE).
type Gate struct {
	state      stateReader
	jobRunning func(ctx context.Context, jobID string) (bool, error)
	log        *slog.Logger

	mu         sync.Mutex
	holder     string
	byRotation bool
	// byUpdate is set while an OS update's pre-update copy holds the gate.
	byUpdate bool
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
	case g.holder != "" && g.byUpdate:
		return errUpdateHolds
	case g.holder != "":
		return errBackupHolds
	}
	g.take(jobID, true, false)
	return nil
}

// take records jobID as the holder. The caller holds mu.
func (g *Gate) take(jobID string, byRotation, byUpdate bool) {
	g.holder, g.byRotation, g.byUpdate, g.free = jobID, byRotation, byUpdate, make(chan struct{})
}

// capturePurpose is who a waiting capture is: its refusal sentences and the
// words of its WARN record.
type capturePurpose struct {
	byUpdate                           bool
	refused                            string
	rotationIncomplete, sealUnreadable error
}

var (
	backupCapture = capturePurpose{refused: "backup refused",
		rotationIncomplete: errBackupRotationIncomplete, sealUnreadable: errBackupSealUnreadable}
	updateCapture = capturePurpose{byUpdate: true, refused: "os update refused",
		rotationIncomplete: errUpdateRotationIncomplete, sealUnreadable: errUpdateSealUnreadable}
)

// Acquire takes the gate for the backup jobID. While another job holds it,
// Acquire waits for the release, unless that job is no longer running, whose
// hold is dropped. Once free, the seal files must read Clean, or Acquire
// refuses with a sentence; it returns ctx's error when ctx ends first.
func (g *Gate) Acquire(ctx context.Context, jobID string) error {
	return g.acquire(ctx, jobID, backupCapture)
}

// AcquireForUpdate is Acquire for an OS update's pre-update copy of the
// store, jobID being the node.update job (geekdojo/geekdojo-brain#800). Its
// refusals name the OS update, and a rotation tried while it holds the gate
// is told an update is copying the store.
func (g *Gate) AcquireForUpdate(ctx context.Context, jobID string) error {
	return g.acquire(ctx, jobID, updateCapture)
}

// acquire is the wait loop Acquire and AcquireForUpdate share.
func (g *Gate) acquire(ctx context.Context, jobID string, p capturePurpose) error {
	for {
		g.mu.Lock()
		if g.holder == "" || g.holder == jobID {
			defer g.mu.Unlock()
			tree, err := g.state.State()
			if err != nil {
				g.log.WarnContext(ctx, p.refused+": the seal files could not be checked",
					"component", "secretstore", "event", "secretstore.seal_rotate.capture_refused", "job_id", jobID, "err", err.Error())
				return p.sealUnreadable
			}
			if tree.Fragment.Shape != Clean {
				g.log.WarnContext(ctx, p.refused+": a seal-key rotation has not finished",
					"component", "secretstore", "event", "secretstore.seal_rotate.capture_refused", "job_id", jobID,
					"shape", tree.Fragment.Shape.String(), "key_id", tree.Fragment.Current.String())
				return p.rotationIncomplete
			}
			g.take(jobID, false, p.byUpdate)
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
	g.holder, g.byRotation, g.byUpdate, g.free = "", false, false, nil
}

// CheckRestore refuses a restore with a sentence while a rotation holds the
// gate, or while the seal files are not Clean or cannot be read, and returns
// nil otherwise (geekdojo/geekdojo-brain#765, AC8). A restore staged in the
// middle of a rotation could put back a key that does not open the store the
// rotation leaves behind. It waits for nothing and changes nothing; the
// defect behind a refusal goes to the log, never into the sentence.
func (g *Gate) CheckRestore() error {
	g.mu.Lock()
	rotating := g.holder != "" && g.byRotation
	holder := g.holder
	g.mu.Unlock()
	if rotating {
		g.log.Warn("restore refused: a seal-key rotation is running",
			"component", "secretstore", "event", "secretstore.seal_rotate.restore_refused", "job_id", holder)
		return errRestoreRotation
	}
	tree, err := g.state.State()
	if err != nil {
		g.log.Warn("restore refused: the seal files could not be checked",
			"component", "secretstore", "event", "secretstore.seal_rotate.restore_refused", "err", err.Error())
		return errRestoreSealUnreadable
	}
	if tree.Fragment.Shape != Clean {
		g.log.Warn("restore refused: a seal-key rotation has not finished",
			"component", "secretstore", "event", "secretstore.seal_rotate.restore_refused",
			"shape", tree.Fragment.Shape.String(), "key_id", tree.Fragment.Current.String())
		return errRestoreRotationIncomplete
	}
	return nil
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
