// Package storerecover restarts the secret store once after a sustained full
// disk failed it and the data partition has room again
// (geekdojo/geekdojo-brain#874).
//
// A full data partition makes the store's unit crash-loop on compaction
// ENOSPC into failed, where systemd leaves it. Freeing space changes nothing
// systemd watches, so the store stays down until someone resets it. No step
// that changes the cause runs (ADR-0010 "The store unit"), and Linux raises no
// event when free blocks go up: statfs is a query.
//
// So the Recoverer arms on the fact "the unit failed while the partition was
// full", read once at the api's start (Arm) and on each scheduler check
// (Due), and on the first check with room it is due exactly once. The
// restart job re-reads the unit, the quiesce holds and the restore before it
// acts. A unit that failed with room, which the rollback gate (#801) or a
// missing seal key leave on purpose, never arms, so it is never retried.
//
// The armed flag is in memory and resets when the api restarts; the start-time
// reading arms it again while the disk is still full.
package storerecover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// Kind is the recovery job's workflow kind.
const Kind = "secretstore.recover"

// The unit states the Recoverer acts on, as systemd's ActiveState names them.
const (
	stateFailed = "failed"
	// stateActivating is the crash loop still running: systemd reports it
	// during the auto-restart delay, before the start limit is hit.
	stateActivating = "activating"
)

// The reasons Due and the step give when the store is not restarted.
const (
	reasonHeld      = "a job holds the secret store"
	reasonRestoring = "a restore is in progress"
)

// Deps are the Recoverer's collaborators. New refuses a nil function, an
// empty string and a zero FullBelow.
type Deps struct {
	// Dir is the data partition's directory, read by Free.
	Dir string
	// Free reports the bytes available on dir (production: storage.FreeBytes).
	Free func(dir string) (uint64, error)
	// FullBelow is the free space below which the partition reads as full
	// (production: storeaudit.FreeCritBelow).
	FullBelow uint64
	// Unit names the store's unit in log fields.
	Unit string
	// UnitState reads the store unit's systemd ActiveState.
	UnitState func(ctx context.Context) (string, error)
	// Held reports whether a job holds the store quiesced, with an unreadable
	// hold counted as held (storestate.Monitor.Held).
	Held func(ctx context.Context) bool
	// Restoring reports the restore in progress, if any
	// (storage.RestoreSessions.Active).
	Restoring func() (jobID string, ok bool)
	// Restart resets the failed unit and restarts it.
	Restart func(ctx context.Context) error
	Log     *slog.Logger
	// StepTimeout bounds the restart step.
	StepTimeout time.Duration
}

// Recoverer decides when the store is restarted after a full disk, and runs
// the restart as a job.
type Recoverer struct {
	d   Deps
	log *slog.Logger

	mu sync.Mutex
	// armed is set by a reading that found the partition full and the unit
	// failed or activating, and cleared when Due fires or the unit is found
	// neither failed nor activating with room.
	armed bool
}

// New checks d and returns a Recoverer. It does no I/O.
func New(d Deps) (*Recoverer, error) {
	switch {
	case d.Dir == "":
		return nil, errors.New("storerecover: Deps.Dir is empty")
	case d.Free == nil:
		return nil, errors.New("storerecover: Deps.Free is nil")
	case d.FullBelow == 0:
		return nil, errors.New("storerecover: Deps.FullBelow is zero")
	case d.Unit == "":
		return nil, errors.New("storerecover: Deps.Unit is empty")
	case d.UnitState == nil:
		return nil, errors.New("storerecover: Deps.UnitState is nil")
	case d.Held == nil:
		return nil, errors.New("storerecover: Deps.Held is nil")
	case d.Restoring == nil:
		return nil, errors.New("storerecover: Deps.Restoring is nil")
	case d.Restart == nil:
		return nil, errors.New("storerecover: Deps.Restart is nil")
	case d.Log == nil:
		return nil, errors.New("storerecover: Deps.Log is nil")
	}
	return &Recoverer{d: d, log: d.Log.With("component", "secretstore")}, nil
}

// Workflow is the recovery job: one restart step, never retried. A failed
// restart fails the job, which raises the job-failed alert.
func (r *Recoverer) Workflow() jobs.Workflow {
	return jobs.Workflow{Kind: Kind, Steps: []jobs.WorkflowStep{
		{Name: "restart", Do: r.restartStep, Timeout: r.d.StepTimeout, Retries: 0},
	}}
}

// Arm is the reading taken on the fact of the api's start. It only arms: a
// Recoverer that finds room is not armed, so Arm never restarts anything.
// After a reboot while full the store crash-loops before the api starts, so
// this reading sees it.
func (r *Recoverer) Arm(ctx context.Context) {
	r.reading(ctx, false)
}

// Due is the scheduler's gate. It arms like Arm, and when armed with free
// space at or above FullBelow it is true once for a failed unit that no job
// holds and no restore is using. Every return but the firing one, and the
// refusals, carries an empty reason, so a steady state logs nothing.
func (r *Recoverer) Due(ctx context.Context) (bool, string) {
	return r.reading(ctx, true)
}

func (r *Recoverer) isArmed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.armed
}

// reading is one reading of the facts. fire is false for Arm.
func (r *Recoverer) reading(ctx context.Context, fire bool) (bool, string) {
	free, err := r.d.Free(r.d.Dir)
	if err != nil {
		r.log.WarnContext(ctx, "free space could not be read; no store recovery checked", "dir", r.d.Dir, "err", err.Error())
		return false, "the free space on the data partition could not be read"
	}
	full := free < r.d.FullBelow
	armed := r.isArmed()
	switch {
	case full && armed, !full && !armed, !full && !fire:
		return false, ""
	}
	state, err := r.d.UnitState(ctx)
	if err != nil {
		r.log.WarnContext(ctx, "secret store unit state could not be read; no store recovery checked", "unit", r.d.Unit, "err", err.Error())
		return false, "the secret store unit's state could not be read"
	}
	if full {
		if state == stateFailed || state == stateActivating {
			r.arm(ctx, free, state)
		}
		return false, ""
	}
	switch state {
	case stateFailed:
		if r.d.Held(ctx) {
			return false, reasonHeld
		}
		if _, ok := r.d.Restoring(); ok {
			return false, reasonRestoring
		}
		if !r.setArmed(false) {
			return false, ""
		}
		return true, fmt.Sprintf("the data partition has %d MiB free and the store unit is failed", free>>20)
	case stateActivating:
		return false, ""
	}
	if r.setArmed(false) {
		r.log.InfoContext(ctx, "secret store is no longer failed; no recovery needed",
			"event", "secretstore.recover_disarmed", "unit", r.d.Unit, "state", state)
	}
	return false, ""
}

// arm sets armed and logs it once per arming.
func (r *Recoverer) arm(ctx context.Context, free uint64, state string) {
	if r.setArmed(true) {
		r.log.InfoContext(ctx, "secret store failed while the data partition was full; it will be restarted once there is room",
			"event", "secretstore.recover_armed", "free_bytes", free, "unit", r.d.Unit, "state", state)
	}
}

// setArmed sets armed to v and reports whether it changed.
func (r *Recoverer) setArmed(v bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := r.armed != v
	r.armed = v
	return changed
}

// stepError is a failure sentence a person reads: the runner stores a failed
// step's err.Error() as the job's error and as its job-failed alert's detail.
// It never carries a command's output or an OS error; those go to the logger
// under the job's id.
type stepError string

func (e stepError) Error() string { return string(e) }

const (
	errStateUnread stepError = "The secret store's unit state could not be read, so it was not restarted."
	errRestart     stepError = "The secret store could not be restarted after the data partition was freed, so it is still down."
)

// result is the step's recorded outcome.
type result struct {
	Restarted bool   `json:"restarted"`
	Reason    string `json:"reason,omitempty"`
}

// restartStep re-reads the unit, the holds and the restore, and restarts the
// store only when it is still failed with nothing using it.
func (r *Recoverer) restartStep(sc *jobs.StepCtx) (json.RawMessage, error) {
	state, err := r.d.UnitState(sc.Ctx)
	if err != nil {
		jobs.LogStep(r.log, sc, slog.LevelError, "The secret store's unit state could not be read.",
			"event", "secretstore.recover_restart_failed", "unit", r.d.Unit, "err", err.Error())
		return nil, errStateUnread
	}
	switch {
	case state != stateFailed:
		return skipped("the store unit is " + state + ", not failed")
	case r.d.Held(sc.Ctx):
		return skipped(reasonHeld)
	}
	if _, ok := r.d.Restoring(); ok {
		return skipped(reasonRestoring)
	}
	attrs := []any{"event", "secretstore.recover_restart", "unit", r.d.Unit}
	if free, err := r.d.Free(r.d.Dir); err == nil {
		attrs = append(attrs, "free_bytes", free)
	}
	jobs.LogStep(r.log, sc, slog.LevelInfo, "secret store restarting after the data partition was freed", attrs...)
	if err := r.d.Restart(sc.Ctx); err != nil {
		jobs.LogStep(r.log, sc, slog.LevelError, restartFailedLine(err),
			"event", "secretstore.recover_restart_failed", "unit", r.d.Unit, "err", err.Error())
		return nil, errRestart
	}
	return json.Marshal(result{Restarted: true})
}

func skipped(reason string) (json.RawMessage, error) {
	return json.Marshal(result{Restarted: false, Reason: reason})
}

// restartFailedLine is the step log's safe cause: the command's exit status,
// never its output.
func restartFailedLine(err error) string {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Sprintf("systemctl restart of the secret store unit failed (exit status %d).", exitErr.ExitCode())
	}
	return "systemctl restart of the secret store unit failed."
}
