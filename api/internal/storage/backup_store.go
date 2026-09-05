package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// The backup_runs ledger — design/storage.md §4.1's producer, recorded.
//
// Two readers, and they want opposite things. The Tasks feed and the Backups
// view want the LIST, failures included, because §4.4's "failure is loud"
// starts with a run that is visibly there and visibly red. The OVERDUE app tile
// and the alert path (#298, not built here) want exactly one number: when a
// backup last actually SUCCEEDED. LastSuccess is that number, and it exists now
// so #298 has something to read rather than a reason to re-derive it from step
// results.

// RunStatus is the rollup for one backup run.
//
// Every value except RunRunning is TERMINAL, and a row still `running` after
// its job has finished is the #53 bug — a failed run rendering as one still in
// progress. The workflow's OnTerminal hook is what stops it, exactly as
// finalizeTargetRow does for backup_targets.
type RunStatus string

const (
	RunRunning   RunStatus = "running"
	RunSucceeded RunStatus = "succeeded"
	RunFailed    RunStatus = "failed"
)

// BackupRun is one row of the backup_runs ledger.
type BackupRun struct {
	JobID string `json:"jobId"`
	// TargetJobID is the backup_targets row this run wrote to. The target's own
	// identity is PartUUID; this is the claim that produced it.
	TargetJobID string `json:"targetJobId,omitempty"`
	PartUUID    string `json:"partUuid,omitempty"`
	NodeID      string `json:"nodeId,omitempty"`
	// Reason is "scheduled" or "manual" — §4.1 has both producers and an
	// operator looking at a 3 a.m. failure wants to know which one it was.
	Reason string `json:"reason,omitempty"`
	// Scope is proto.BackupScopeFull for everything this build writes — the
	// generation's REACH, every node.
	//
	// Marshalled on every row, deliberately, so no view can render a run
	// without having been handed the fact that it did not reach the cluster.
	Scope        string `json:"scope,omitempty"`
	GenerationID string `json:"generationId,omitempty"`
	KeyID        string `json:"keyId,omitempty"`
	// Digest is the SHA-256 over the SEALED archive. Not key material, and the
	// only thing that can verify a generation without a custody secret.
	Digest    string `json:"digest,omitempty"`
	SizeBytes uint64 `json:"sizeBytes,omitempty"`
	// AppVolumesCaptured and AppVolumesSkipped are the two halves of what the
	// fan-out did, and both are always marshalled: "2 captured" alone is not an
	// answer, and "no volumes" must never be indistinguishable from "the field
	// was never populated".
	AppVolumesCaptured int `json:"appVolumesCaptured"`
	AppVolumesSkipped  int `json:"appVolumesSkipped"`
	// AppVolumesFailed is how many of the skipped ones the run TRIED to take
	// and could not — an offline node, a refusal, an upload that did not land.
	// §4.4's failed-not-skipped; non-zero is a failed run with the volumes
	// named in Error.
	AppVolumesFailed int `json:"appVolumesFailed"`
	// Complete is true only when every classified volume in the cluster was
	// captured.
	Complete bool `json:"complete"`
	// Warning is a caveat on a row that is NOT failed — volumes that were
	// skipped, or an app the backup left down. Distinct from Error, which is
	// why the run died.
	Warning           string `json:"warning,omitempty"`
	GenerationsKept   int    `json:"generationsKept,omitempty"`
	GenerationsPruned int    `json:"generationsPruned,omitempty"`
	// Preflight is the target-side estimate step 2 sent — the identity set,
	// the app volumes (with the ones no earlier generation had sized named),
	// and the margin. Recorded BEFORE the agent answers, so a run refused for
	// space carries the numbers it was refused on. Nil on rows from builds
	// that estimated the identity set alone.
	Preflight  *TargetEstimate `json:"preflight,omitempty"`
	Status     RunStatus       `json:"status"`
	StartedAt  time.Time       `json:"startedAt"`
	FinishedAt *time.Time      `json:"finishedAt,omitempty"`
	Error      string          `json:"error,omitempty"`
}

const runCols = `job_id, target_job_id, part_uuid, node_id, reason, scope, generation_id,
        key_id, digest, size_bytes, app_volumes_captured, app_volumes_skipped, app_volumes_failed,
        complete, warning, generations_kept,
        generations_pruned, preflight, status, started_at, finished_at, error`

// StartRun records a run at step 1, before anything has been snapshotted.
//
// Early for the same reason CreatePending is early: a run that fails at
// validate must still appear, or the only evidence an operator has that their
// weekly backup did not happen is its absence — and absence is exactly what a
// backup that never ran looks like anyway.
func (s *Store) StartRun(ctx context.Context, jobID, reason, scope string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO backup_runs (job_id, reason, scope, status, started_at)
        VALUES (?, ?, ?, ?, ?)`,
		jobID, reason, scope, string(RunRunning), ms(now))
	return err
}

// BindRunTarget records which target a run resolved to, once step 1 knows.
func (s *Store) BindRunTarget(ctx context.Context, jobID, targetJobID, partUUID, nodeID, keyID string) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE backup_runs SET target_job_id = ?, part_uuid = ?, node_id = ?, key_id = ?
        WHERE job_id = ?`,
		targetJobID, partUUID, nodeID, keyID, jobID)
	return err
}

// MarkRunGeneration records the generation the moment the agent confirms it
// landed, BEFORE the run as a whole has finished.
//
// The split from FinishRun is a matter of honesty, not tidiness. Step 7 (prune)
// runs after the write, so a prune failure ends the job as `failed` — and
// without this, that row would name no generation at all, while a complete,
// fresh archive sat on the target. An operator reading "failed, no generation"
// would reasonably conclude they had no backup from that night. They do.
//
// It deliberately does not touch `status`: a run whose retention did not
// converge has not finished, and this is not the call that decides it has.
func (s *Store) MarkRunGeneration(ctx context.Context, jobID, generationID, digest string, sizeBytes uint64, appVolumes, appVolumesSkipped, appVolumesFailed int) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE backup_runs
        SET generation_id = ?, digest = ?, size_bytes = ?, app_volumes_captured = ?, app_volumes_skipped = ?, app_volumes_failed = ?
        WHERE job_id = ?`,
		generationID, digest, sizeForDB(sizeBytes), appVolumes, appVolumesSkipped, appVolumesFailed, jobID)
	return err
}

// MarkRunPreflight records the target-side estimate a run sent at step 2.
//
// Written before the agent is asked, on purpose: a run the target refuses for
// space is the run whose numbers an operator most needs to see, and a record
// written only on success would be missing from exactly that row.
func (s *Store) MarkRunPreflight(ctx context.Context, jobID string, est TargetEstimate) error {
	raw, err := json.Marshal(est)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE backup_runs SET preflight = ? WHERE job_id = ?`, string(raw), jobID)
	return err
}

// RunResult is what a completed run recorded. A struct rather than nine
// positional arguments, for the same reason ClaimResult is one.
type RunResult struct {
	GenerationID       string
	Digest             string
	SizeBytes          uint64
	AppVolumesCaptured int
	AppVolumesSkipped  int
	AppVolumesFailed   int
	Scope              string
	Complete           bool
	// Warning is the caveat a SUCCEEDED row still has to carry — volumes that
	// were not captured. It is not an error and it is not silence.
	Warning           string
	GenerationsKept   int
	GenerationsPruned int
	At                time.Time
}

// FinishRun moves a running row to `succeeded`.
//
// The status guard keeps this from resurrecting a row OnTerminal already
// failed, in the window where the last step's write and the terminal hook could
// both be in flight — the same guard, for the same reason, as MarkClaimed's.
func (s *Store) FinishRun(ctx context.Context, jobID string, res RunResult) error {
	out, err := s.db.ExecContext(ctx, `
        UPDATE backup_runs
        SET generation_id = ?, digest = ?, size_bytes = ?, app_volumes_captured = ?,
            app_volumes_skipped = ?, app_volumes_failed = ?, complete = ?, warning = ?,
            generations_kept = ?, generations_pruned = ?, status = ?, finished_at = ?, error = ''
        WHERE job_id = ? AND status = ?`,
		res.GenerationID, res.Digest, sizeForDB(res.SizeBytes), res.AppVolumesCaptured,
		res.AppVolumesSkipped, res.AppVolumesFailed, boolForDB(res.Complete), res.Warning,
		res.GenerationsKept, res.GenerationsPruned, string(RunSucceeded), ms(res.At),
		jobID, string(RunRunning))
	if err != nil {
		return err
	}
	if n, _ := out.RowsAffected(); n == 0 {
		return errors.New("no running backup_runs row for this job")
	}
	return nil
}

// MarkRunRetention records everything a finished run knows WITHOUT giving the
// row a verdict.
//
// It exists for exactly one caller: a run whose archive landed and whose
// retention converged, and which is about to fail anyway because the fan-out
// left an app down. The generation, the counts and the warning belong on the
// row — an operator must be able to see that tonight's archive IS on the disk —
// and the verdict belongs to the terminal hook, which will mark it `failed`
// with the app named.
//
// Deliberately NOT a variant of FinishRun with a status argument. "Record the
// facts" and "declare the run over" are two decisions, and a single function
// taking a status is one typo away from marking a red run green.
func (s *Store) MarkRunRetention(ctx context.Context, jobID string, res RunResult) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE backup_runs
        SET generation_id = ?, digest = ?, size_bytes = ?, app_volumes_captured = ?,
            app_volumes_skipped = ?, app_volumes_failed = ?, complete = ?, warning = ?,
            generations_kept = ?, generations_pruned = ?
        WHERE job_id = ?`,
		res.GenerationID, res.Digest, sizeForDB(res.SizeBytes), res.AppVolumesCaptured,
		res.AppVolumesSkipped, res.AppVolumesFailed, boolForDB(res.Complete), res.Warning,
		res.GenerationsKept, res.GenerationsPruned, jobID)
	return err
}

// boolForDB stores a boolean as SQLite's 0/1. One helper rather than an inline
// ternary at each site, so `complete` can never be written as the string
// "false" — which SQLite would happily accept and every reader would treat as
// truthy.
func boolForDB(b bool) int {
	if b {
		return 1
	}
	return 0
}

// FailRun gives a still-running row a terminal status. A no-op on a row that
// already has a verdict.
func (s *Store) FailRun(ctx context.Context, jobID, errMsg string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE backup_runs SET status = ?, error = ?, finished_at = ?
        WHERE job_id = ? AND status = ?`,
		string(RunFailed), errMsg, ms(at), jobID, string(RunRunning))
	return err
}

// GetRun returns one run, or nil when the job never made one.
func (s *Store) GetRun(ctx context.Context, jobID string) (*BackupRun, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+runCols+` FROM backup_runs WHERE job_id = ?`, jobID)
	return scanRun(row.Scan)
}

// ListRuns returns runs newest first, capped at limit (0 = 100).
func (s *Store) ListRuns(ctx context.Context, limit int) ([]*BackupRun, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.queryRuns(ctx, `SELECT `+runCols+` FROM backup_runs ORDER BY started_at DESC LIMIT ?`, limit)
}

// ListRunning returns runs still in flight.
//
// Two callers. The startup sweep finalizes rows stranded by a process that died
// mid-saga, and step 1 refuses to start a second run while one is already
// going: the weekly schedule and an operator's "Back up now" can otherwise
// collide, and two runs staging archives at once is exactly the disk-pressure
// failure §4.7 warns about.
func (s *Store) ListRunning(ctx context.Context) ([]*BackupRun, error) {
	return s.queryRuns(ctx, `SELECT `+runCols+`
        FROM backup_runs WHERE status = ? ORDER BY started_at DESC`, string(RunRunning))
}

// LastSuccess returns the most recent successful run, or nil when there has
// never been one.
//
// This is the number §4.4's OVERDUE tile and alert path are about (#298, not
// built here). Nil is a real and important answer — "no backup has ever
// succeeded" is not the same as "the last one was a while ago", and a caller
// that conflated them would render a brand-new installation as overdue.
func (s *Store) LastSuccess(ctx context.Context) (*BackupRun, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+runCols+`
        FROM backup_runs WHERE status = ? ORDER BY finished_at DESC LIMIT 1`, string(RunSucceeded))
	return scanRun(row.Scan)
}

func (s *Store) queryRuns(ctx context.Context, q string, args ...any) ([]*BackupRun, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*BackupRun
	for rows.Next() {
		r, err := scanRun(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanRun(scan func(...any) error) (*BackupRun, error) {
	var (
		r          BackupRun
		sizeBytes  int64
		complete   int64
		preflight  string
		status     string
		startedAt  int64
		finishedAt sql.NullInt64
	)
	if err := scan(&r.JobID, &r.TargetJobID, &r.PartUUID, &r.NodeID, &r.Reason, &r.Scope,
		&r.GenerationID, &r.KeyID, &r.Digest, &sizeBytes, &r.AppVolumesCaptured,
		&r.AppVolumesSkipped, &r.AppVolumesFailed, &complete, &r.Warning,
		&r.GenerationsKept, &r.GenerationsPruned, &preflight, &status, &startedAt, &finishedAt,
		&r.Error); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if sizeBytes > 0 {
		r.SizeBytes = uint64(sizeBytes)
	}
	r.Complete = complete != 0
	if preflight != "" {
		var est TargetEstimate
		// A column this process wrote and cannot parse is a row worth serving
		// without it, not a listing worth failing: the run's status, error and
		// generation are the answers an operator is reading for.
		if json.Unmarshal([]byte(preflight), &est) == nil {
			r.Preflight = &est
		}
	}
	r.Status = RunStatus(status)
	r.StartedAt = fromMs(startedAt)
	if finishedAt.Valid {
		ts := fromMs(finishedAt.Int64)
		r.FinishedAt = &ts
	}
	return &r, nil
}
