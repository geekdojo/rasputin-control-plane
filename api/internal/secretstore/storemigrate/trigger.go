package storemigrate

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
)

// CreatedBy is who the migration job names as its submitter.
const CreatedBy = "store-ready"

// Ready is the readiness monitor as the trigger uses it.
type Ready interface {
	OnFirstReady(ctx context.Context, fn func(context.Context))
	State(ctx context.Context) (storestate.State, error)
}

// Submitter is the job runner as the trigger uses it.
type Submitter interface {
	Submit(ctx context.Context, kind string, spec any, createdBy string) (*jobs.Job, error)
}

// TriggerDeps are the trigger's collaborators. NewTrigger refuses a nil one.
type TriggerDeps struct {
	Ready    Ready
	Runner   Submitter
	Settings Settings
	BootID   func() (string, error)
	// Provision is the last os.store_provision record observed
	// (LastRecord.Last).
	Provision func() (osoutcome.Record, bool)
	// Check submits the store's reference check (#800).
	Check func(ctx context.Context)
	Log   *slog.Logger
}

// Trigger is the store's one first-ready coordinator (F-1132-05). On the
// first reading of this process that finds the store ready, it submits the
// migration when this boot's provision record says the author role is
// absent and no attempt was made in this boot; then the reference check
// waits for the migration's end (ReferenceCheck from the job's terminal
// hook). Otherwise it submits the reference check as before. There is no
// timer: the reading and the record are the facts.
type Trigger struct {
	d    TriggerDeps
	once sync.Once
}

// NewTrigger checks d and returns a Trigger. It does no I/O.
func NewTrigger(d TriggerDeps) (*Trigger, error) {
	if d.Ready == nil || d.Runner == nil || d.Settings == nil || d.BootID == nil || d.Provision == nil || d.Check == nil || d.Log == nil {
		return nil, errors.New("storemigrate: a trigger collaborator is nil")
	}
	return &Trigger{d: d}, nil
}

// Arm runs the trigger on the first ready reading, and takes one reading
// now, under the client's own per-call bound: a store already ready runs it
// at once; otherwise the next ready reading by any reader does. main runs it
// after the start-time outcome read, so the provision record is observed.
func (t *Trigger) Arm(ctx context.Context) {
	t.d.Ready.OnFirstReady(ctx, t.fire)
	if _, err := t.d.Ready.State(ctx); err != nil {
		t.d.Log.WarnContext(ctx, "secret store readiness not read at start; the next reading arms the store's checks",
			"component", "secretstore", "err", err.Error())
	}
}

// fire decides between the migration and the reference check.
func (t *Trigger) fire(ctx context.Context) {
	if t.wanted(ctx) {
		_, err := t.d.Runner.Submit(ctx, Kind, nil, CreatedBy)
		if err == nil {
			return
		}
		t.d.Log.ErrorContext(ctx, "secret store migration not submitted; the reference check runs instead",
			"component", "secretstore", "event", "secretstore.migrate_submit_failed", "err", err.Error())
	}
	t.ReferenceCheck(ctx)
}

// wanted reports whether this boot's provision record asks for the
// migration and none was attempted in this boot. Anything it cannot read is
// no migration (ERR-CLOSED), logged.
func (t *Trigger) wanted(ctx context.Context) bool {
	rec, ok := t.d.Provision()
	if !ok || !triggerOutcomes[rec.Outcome] || rec.Author != osoutcome.AuthorAbsent {
		return false
	}
	boot, err := t.d.BootID()
	if err != nil {
		t.d.Log.WarnContext(ctx, "secret store migration not considered: this boot's id is unreadable",
			"component", "secretstore", "event", "secretstore.migrate_not_considered", "err", err.Error())
		return false
	}
	if rec.BootID != boot {
		return false
	}
	attempted, err := t.d.Settings.Get(ctx, KeyAttemptBootID)
	if err != nil {
		t.d.Log.WarnContext(ctx, "secret store migration not considered: its attempt bound is unreadable",
			"component", "secretstore", "event", "secretstore.migrate_not_considered", "err", err.Error())
		return false
	}
	return attempted != boot
}

// ReferenceCheck submits the reference check once per process, on the first
// ready reading (now, when there was one). The migration's terminal hook
// calls it, so the check runs on the store that is live and never inside the
// Hold.
func (t *Trigger) ReferenceCheck(ctx context.Context) {
	t.once.Do(func() { t.d.Ready.OnFirstReady(ctx, t.d.Check) })
}
