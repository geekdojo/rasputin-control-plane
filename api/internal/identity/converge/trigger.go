package converge

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// readiness is whether the identity service is ready
// (identitystate.Monitor.Ready).
type readiness interface {
	Ready(ctx context.Context) error
}

// ledger is the job ledger as a trigger reads it (*jobs.Store).
type ledger interface {
	ListJobsByKind(ctx context.Context, kind string, limit int) ([]*jobs.Job, error)
}

// Cond is a trigger's own condition, read only while the service is ready.
// due is whether its job is wanted, reason the sentence logged when it is
// submitted, and rearm a key: a non-empty one the trigger has not seen
// before re-arms its latch.
type Cond func(ctx context.Context) (due bool, reason, rearm string, err error)

// TriggerDeps is everything a Trigger needs. NewTrigger refuses an
// incomplete one.
type TriggerDeps struct {
	// Kind is the job kind the trigger submits and latches on.
	Kind   string
	Ready  readiness
	Ledger ledger
	Cond   Cond
	// CondErrLevel is the level of the one record per outage a failing Cond
	// writes.
	CondErrLevel slog.Level
	Log          *slog.Logger
}

// Trigger decides, on each scheduler check, whether its job is due: the
// service is ready AND Cond holds, latched on the job ledger. When the latch
// arms it notes the newest job of its kind, and the job is due only while
// that is still the newest, so one job is submitted per arming and a failed
// submit, which leaves no row, is tried again on the next check. The latch
// re-arms on each not-ready to ready transition the checks observe, and on a
// new rearm key from Cond.
type Trigger struct {
	d   TriggerDeps
	log *slog.Logger

	mu       sync.Mutex
	wasReady bool
	armed    bool
	armedAt  string // the newest job's id when armed, "" for none
	lastKey  string
	// The once-per-outage flags.
	notReady, condDown, ledgerDown bool
}

// NewTrigger checks d and returns a Trigger. It does no I/O.
func NewTrigger(d TriggerDeps) (*Trigger, error) {
	if d.Kind == "" || d.Ready == nil || d.Ledger == nil || d.Cond == nil || d.Log == nil {
		return nil, errors.New("converge: a trigger collaborator is nil")
	}
	return &Trigger{d: d, log: d.Log.With("component", "identity", "kind", d.Kind)}, nil
}

// Due is one reading. Every check it could not make is not due.
func (t *Trigger) Due(ctx context.Context) (bool, string) {
	if err := t.d.Ready.Ready(ctx); err != nil {
		t.outage(ctx, &t.notReady, err, slog.LevelWarn, "The identity service is not ready; its job is not checked.")
		t.mu.Lock()
		t.wasReady = false
		t.mu.Unlock()
		return false, ""
	}
	t.outage(ctx, &t.notReady, nil, slog.LevelWarn, "")
	t.mu.Lock()
	if !t.wasReady {
		// A new readiness episode.
		t.wasReady, t.armed = true, false
	}
	t.mu.Unlock()

	due, reason, key, err := t.d.Cond(ctx)
	t.outage(ctx, &t.condDown, err, t.d.CondErrLevel, "The identity job's condition could not be read; it is not due.")
	if err != nil || !due {
		return false, ""
	}
	newest, err := t.d.Ledger.ListJobsByKind(ctx, t.d.Kind, 1)
	t.outage(ctx, &t.ledgerDown, err, slog.LevelWarn, "The job ledger could not be read; the identity job is not due.")
	if err != nil {
		return false, ""
	}
	newestID := ""
	if len(newest) > 0 {
		newestID = newest[0].ID
	}
	t.mu.Lock()
	if key != "" && key != t.lastKey {
		t.armed = false
	}
	t.lastKey = key
	if !t.armed {
		t.armed, t.armedAt = true, newestID
	}
	due = newestID == t.armedAt
	t.mu.Unlock()
	if due {
		t.log.LogAttrs(ctx, slog.LevelInfo, "An identity job is due.",
			slog.String("event", t.d.Kind+".due"), slog.String("reason", reason))
	}
	return due, reason
}

// outage writes msg once per run of errors on flag, and clears the flag on a
// nil err.
func (t *Trigger) outage(ctx context.Context, flag *bool, err error, level slog.Level, msg string) {
	t.mu.Lock()
	first := err != nil && !*flag
	*flag = err != nil
	t.mu.Unlock()
	if first {
		t.log.LogAttrs(ctx, level, msg, slog.String("err", err.Error()))
	}
}

// lagging is the migrations runner's record read (migrations.Runner).
type lagging interface {
	Lagging(ctx context.Context) (applied, want int, err error)
}

// ConvergeCond is identity.converge's condition: the realm has every shipped
// migration, and it is wanted on each readiness episode; a desired state
// whose hash differs from the stored one re-arms it.
func ConvergeCond(c *Converger, mig lagging) Cond {
	return func(ctx context.Context) (bool, string, string, error) {
		applied, want, err := mig.Lagging(ctx)
		if err != nil {
			return false, "", "", err
		}
		if applied < want {
			return false, "", "", nil
		}
		desired, stored, err := c.Pending(ctx)
		if err != nil {
			return false, "", "", err
		}
		if desired != stored {
			return true, "the sign-in settings Rasputin wants are not yet applied", desired, nil
		}
		return true, "the identity service became ready", "", nil
	}
}

// MigrateCond is identity.migrate's condition: the realm lacks a shipped
// migration.
func MigrateCond(mig lagging) Cond {
	return func(ctx context.Context) (bool, string, string, error) {
		applied, want, err := mig.Lagging(ctx)
		if err != nil {
			return false, "", "", err
		}
		return applied < want, "the sign-in realm lacks a shipped migration", "", nil
	}
}

// ArmCond is identity.arm's condition: no realm id recorded, or the armed
// marker absent.
func ArmCond(a *Armer) Cond {
	return func(ctx context.Context) (bool, string, string, error) {
		pending, err := a.Pending(ctx)
		if err != nil {
			return false, "", "", err
		}
		return pending, "the sign-in realm is not armed", "", nil
	}
}
