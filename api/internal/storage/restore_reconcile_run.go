package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// restoredRunLedger is the slice of the backup_runs ledger the reconciler
// reads and writes. *Store satisfies it.
type restoredRunLedger interface {
	GetRun(ctx context.Context, jobID string) (*BackupRun, error)
	FinishRun(ctx context.Context, jobID string, res RunResult) error
	MarkRunRetention(ctx context.Context, jobID string, res RunResult) error
	FailRun(ctx context.Context, jobID, errMsg string, at time.Time) error
}

// restoredJobLedger is the slice of the job ledger the reconciler reads and
// writes. *jobs.Store satisfies it.
type restoredJobLedger interface {
	GetJob(ctx context.Context, id string) (*jobs.Job, error)
	ListSteps(ctx context.Context, jobID string) ([]*jobs.JobStep, error)
	CreateStep(ctx context.Context, st *jobs.JobStep) error
	MarkStepSucceeded(ctx context.Context, jobID string, seq, attempt int, result json.RawMessage, ts time.Time) error
	MarkJobSucceeded(ctx context.Context, id string, ts time.Time) error
	MarkJobFailed(ctx context.Context, id, errMsg string, ts time.Time) error
	AppendEvent(ctx context.Context, jobID, eventType string, data json.RawMessage, ts time.Time) error
}

// RestoredRunReconciler settles, on the restore boot, the backup run that
// wrote the restored generation (#903).
//
// The database a generation carries was snapshotted while its own run was
// still in flight, so the restored ledger holds that run `running`. Left
// alone, the jobs runner's Recover fails it as "restarted mid-job" and every
// app it captured reads OVERDUE. The generation's manifest is the record of
// what that run did, so the run is settled from it: the verdict the run
// itself would have reached, finished at the manifest's createdAt.
type RestoredRunReconciler struct {
	runs restoredRunLedger
	jobs restoredJobLedger
	log  *slog.Logger
	now  func() time.Time
}

// NewRestoredRunReconciler wires the reconciler to the two ledgers, the
// logger and the clock. The clock stamps only the reconcile's own log event;
// every recorded finish time comes from the manifest.
func NewRestoredRunReconciler(runs restoredRunLedger, jobLedger restoredJobLedger, log *slog.Logger, now func() time.Time) *RestoredRunReconciler {
	return &RestoredRunReconciler{runs: runs, jobs: jobLedger, log: log, now: now}
}

// Reconcile settles the run that wrote rep's generation. A report that names
// no run, or a restored database that holds none, records nothing and says
// why; a run already settled is left alone. A store error is returned, and
// the caller carries on: the worst outcome is Recover's loud failure.
func (r *RestoredRunReconciler) Reconcile(ctx context.Context, rep *RestoreReport) error {
	if rep == nil || rep.GenerationJobID == "" || rep.GenerationAppVolumes == nil {
		r.log.WarnContext(ctx, "restored generation's manifest names no backup job; no run reconciled", reportAttrs(rep)...)
		return nil
	}
	jobID := rep.GenerationJobID
	attrs := reportAttrs(rep)

	run, err := r.runs.GetRun(ctx, jobID)
	if err != nil {
		return fmt.Errorf("reconcile restored run %s: %w", jobID, err)
	}
	job, err := r.jobs.GetJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("reconcile restored run %s: %w", jobID, err)
	}
	if reason := unmatchedReason(run, job); reason != "" {
		r.log.WarnContext(ctx, "restored database holds no backup run for the generation's job; nothing reconciled",
			append(attrs, "reason", reason)...)
		return nil
	}
	jobOpen := job.Status == jobs.StatusQueued || job.Status == jobs.StatusRunning
	if run.Status != RunRunning && !jobOpen {
		r.log.InfoContext(ctx, "backup run already settled; nothing to reconcile", attrs...)
		return nil
	}

	out := volumeOutcome(*rep.GenerationAppVolumes, rep.Complete)
	errMsg, warning := runVerdict(out)
	note := fmt.Sprintf("Reconciled at restore %s from the manifest of generation %s: the generation was written to the backup target, "+
		"but whether this run's retention prune afterwards succeeded is not recorded.", rep.ID, rep.GenerationID)
	at := rep.GenerationCreatedAt
	verdict := "succeeded"
	if errMsg != "" {
		verdict = "failed"
	}

	if run.Status == RunRunning {
		res := RunResult{
			GenerationID:       rep.GenerationID,
			Digest:             rep.SealedDigest,
			SizeBytes:          rep.SealedBytes,
			AppVolumesCaptured: out.AppVolumesCaptured,
			AppVolumesSkipped:  out.AppVolumesSkipped,
			AppVolumesFailed:   out.AppVolumesFailed,
			Scope:              rep.Scope,
			Complete:           out.Complete,
			At:                 at,
		}
		if errMsg != "" {
			res.Warning = withNote(errMsg, note)
			if err := r.runs.MarkRunRetention(ctx, jobID, res); err != nil {
				return fmt.Errorf("reconcile restored run %s: %w", jobID, err)
			}
			if err := r.runs.FailRun(ctx, jobID, errMsg, at); err != nil {
				return fmt.Errorf("reconcile restored run %s: %w", jobID, err)
			}
		} else {
			res.Warning = withNote(warning, note)
			if err := r.runs.FinishRun(ctx, jobID, res); err != nil {
				return fmt.Errorf("reconcile restored run %s: %w", jobID, err)
			}
		}
	}

	if err := r.settleSteps(ctx, jobID, *rep.GenerationAppVolumes, at); err != nil {
		return fmt.Errorf("reconcile restored run %s: %w", jobID, err)
	}

	if jobOpen {
		if errMsg != "" {
			err = r.jobs.MarkJobFailed(ctx, jobID, errMsg, at)
		} else {
			err = r.jobs.MarkJobSucceeded(ctx, jobID, at)
		}
		if err != nil {
			return fmt.Errorf("reconcile restored run %s: %w", jobID, err)
		}
		data, err := json.Marshal(proto.LogEventData{Level: "info", Message: note})
		if err != nil {
			return fmt.Errorf("reconcile restored run %s: %w", jobID, err)
		}
		if err := r.jobs.AppendEvent(ctx, jobID, string(proto.JobLog), data, r.now()); err != nil {
			return fmt.Errorf("reconcile restored run %s: %w", jobID, err)
		}
	}

	r.log.InfoContext(ctx, "reconciled the backup run that wrote the restored generation", append(attrs, "verdict", verdict)...)
	return nil
}

// settleSteps closes the step the snapshot caught running (its output is the
// database this boot runs on) and records the fan-out step from the manifest,
// which is the record both readers of a run's per-volume outcome look for by
// name.
func (r *RestoredRunReconciler) settleSteps(ctx context.Context, jobID string, report AppVolumeReport, at time.Time) error {
	steps, err := r.jobs.ListSteps(ctx, jobID)
	if err != nil {
		return err
	}
	maxSeq, hasFanOut := -1, false
	for _, st := range steps {
		maxSeq = max(maxSeq, st.Seq)
		hasFanOut = hasFanOut || st.Name == "fan_out"
		if st.Status == jobs.StepRunning {
			if err := r.jobs.MarkStepSucceeded(ctx, jobID, st.Seq, max(st.Attempt, 1), nil, at); err != nil {
				return err
			}
		}
	}
	if hasFanOut {
		return nil
	}
	result, err := json.Marshal(runFanOutResult{Report: report})
	if err != nil {
		return err
	}
	seq := maxSeq + 1
	if err := r.jobs.CreateStep(ctx, &jobs.JobStep{JobID: jobID, Seq: seq, Name: "fan_out", Status: jobs.StepRunning, Attempt: 1}); err != nil {
		return err
	}
	return r.jobs.MarkStepSucceeded(ctx, jobID, seq, 1, result, at)
}

// unmatchedReason says why the restored ledger holds no backup run to settle,
// or "" when it holds one.
func unmatchedReason(run *BackupRun, job *jobs.Job) string {
	switch {
	case run == nil:
		return "no backup_runs row for the job"
	case job == nil:
		return "no job row for the run"
	case job.Kind != RunJobKind:
		return fmt.Sprintf("the job is a %s, not a %s", job.Kind, RunJobKind)
	}
	return ""
}

// reportAttrs is the log fields every reconcile record carries.
func reportAttrs(rep *RestoreReport) []any {
	if rep == nil {
		return nil
	}
	return []any{"restore_id", rep.ID, "job_id", rep.GenerationJobID, "generation_id", rep.GenerationID}
}

// withNote appends the reconcile note to a run's own verdict text.
func withNote(text, note string) string {
	if text == "" {
		return note
	}
	return text + "\n" + note
}
