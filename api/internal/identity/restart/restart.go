// Package restart is identity.restart (geekdojo/geekdojo-brain#321): the
// sign-in service's pair restarted on a person's or a repair session's
// request, the break-glass repair page's RESTART.
//
// It runs one step. The step first applies identity.recover's two guards
// (unitrecover): a job that holds the service quiesced, and a restore in
// progress. While either holds, the step fails with a sentence and touches
// nothing. Otherwise it runs systemctl reset-failed on the pair, so a unit
// left failed after a crash loop can start, then systemctl restart on the
// identity service's unit (sysunit.RestartUnits). The unit's Requires= brings
// its database up, and the restart re-arms the unit's start hold.
//
// The kind table decides who may submit it (authz: repairOr under IAM); the
// workflow decides nothing about the submitter.
package restart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/sysunit"
)

// Kind is the workflow's job kind.
const Kind = "identity.restart"

// BusySentence is what a person reads while a guard holds: the step's
// failure, and the repair page's reason RESTART is disabled.
const BusySentence = "The sign-in service wasn't restarted, because a restore or another job is using it. Try again when it finishes."

// Deps are the workflow's collaborators. New refuses a nil function, an
// empty unit name and a zero StepTimeout.
type Deps struct {
	// Run runs one command (execrun.CombinedOutput).
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Held reports whether a job holds the identity service quiesced, with an
	// unreadable hold counted as held (identitystate.Monitor.Held).
	Held func(ctx context.Context) bool
	// Restoring reports the restore in progress, if any
	// (storage.RestoreSessions.Active).
	Restoring func() (jobID string, ok bool)
	// DBUnit and Unit are the pair's units: the database's, which is reset,
	// and the service's, which is reset and restarted.
	DBUnit, Unit string
	Log          *slog.Logger
	// StepTimeout bounds the step far outside the service's measured start
	// (11 to 80 s on the bench). It only marks the job dead.
	StepTimeout time.Duration
}

// Restarter is identity.restart.
type Restarter struct {
	d   Deps
	log *slog.Logger
}

// New checks d. It does no I/O.
func New(d Deps) (*Restarter, error) {
	switch {
	case d.Run == nil:
		return nil, errors.New("identity restart: Deps.Run is nil")
	case d.Held == nil:
		return nil, errors.New("identity restart: Deps.Held is nil")
	case d.Restoring == nil:
		return nil, errors.New("identity restart: Deps.Restoring is nil")
	case d.DBUnit == "" || d.Unit == "":
		return nil, errors.New("identity restart: a unit name is empty")
	case d.Log == nil:
		return nil, errors.New("identity restart: Deps.Log is nil")
	case d.StepTimeout <= 0:
		return nil, errors.New("identity restart: Deps.StepTimeout is not positive")
	}
	return &Restarter{d: d, log: d.Log.With("component", "identity")}, nil
}

// Workflow is the job: one restart step, never retried.
func (r *Restarter) Workflow() jobs.Workflow {
	return jobs.Workflow{Kind: Kind, Steps: []jobs.WorkflowStep{
		{Name: "restart", Do: r.step, Timeout: r.d.StepTimeout, Retries: 0},
	}}
}

// Busy reports whether a guard holds now, with the sentence a person reads.
// The repair page's state and the step read the same guards through it.
func (r *Restarter) Busy(ctx context.Context) (string, bool) {
	if r.d.Held(ctx) {
		return BusySentence, true
	}
	if _, ok := r.d.Restoring(); ok {
		return BusySentence, true
	}
	return "", false
}

// stepError is a failure sentence a person reads: the runner stores a failed
// step's err.Error() as the job's error. It never carries a command's
// output; that goes to the logger under the job's id.
type stepError string

func (e stepError) Error() string { return string(e) }

// result is the step's recorded outcome.
type result struct {
	Restarted bool `json:"restarted"`
}

func (r *Restarter) step(sc *jobs.StepCtx) (json.RawMessage, error) {
	if reason, busy := r.Busy(sc.Ctx); busy {
		jobs.LogStep(r.log, sc, slog.LevelWarn, "The sign-in service was not restarted: a restore or another job is using it.",
			"event", "identity.restart_refused", "unit", r.d.Unit)
		return nil, stepError(reason)
	}
	jobs.LogStep(r.log, sc, slog.LevelInfo, "Restarting the sign-in service.",
		"event", "identity.restart", "unit", r.d.Unit, "created_by", sc.CreatedBy)
	if err := sysunit.RestartUnits(sc.Ctx, r.d.Run, []string{r.d.DBUnit, r.d.Unit}, r.d.Unit); err != nil {
		jobs.LogStep(r.log, sc, slog.LevelError, "The sign-in service could not be restarted.",
			"event", "identity.restart_failed", "unit", r.d.Unit, "err", err.Error())
		return nil, failed(err)
	}
	return json.Marshal(result{Restarted: true})
}

// failed is the job's error for a failed systemctl: its exit status, never
// its output.
func failed(err error) stepError {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stepError(fmt.Sprintf("The sign-in service couldn't be restarted: systemctl exited with status %d.", exitErr.ExitCode()))
	}
	return stepError("The sign-in service couldn't be restarted.")
}
