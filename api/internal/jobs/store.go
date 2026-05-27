package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed durable ledger for jobs, steps, and events.
type Store struct {
	db *sql.DB
}

// OpenStore opens (and migrates) the SQLite database at path.
func OpenStore(ctx context.Context, path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("jobs: open sqlite: %w", err)
	}
	// SQLite is single-writer; cap connections so we serialize writes.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("jobs: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func tsMillis(t time.Time) int64 { return t.UnixMilli() }
func fromMillis(ms int64) time.Time {
	return time.UnixMilli(ms).UTC()
}
func fromNullMillis(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := fromMillis(n.Int64)
	return &t
}

// ----- Jobs ---------------------------------------------------------------

func (s *Store) CreateJob(ctx context.Context, j *Job) error {
	var parent any
	if j.ParentID != nil && *j.ParentID != "" {
		parent = *j.ParentID
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO jobs (id, kind, spec, status, created_by, created_at, parent_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		j.ID, j.Kind, string(j.Spec), string(j.Status), j.CreatedBy, tsMillis(j.CreatedAt), parent)
	return err
}

// ListChildJobs returns every job whose parent_id matches parentID, ordered
// by creation time ascending. Used by the api's GET /api/jobs?parentId
// filter and by the system update UI for the per-node rollup view.
func (s *Store) ListChildJobs(ctx context.Context, parentID string) ([]*Job, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, kind, spec, status, created_by, created_at, started_at, finished_at, parent_id, error
        FROM jobs WHERE parent_id = ? ORDER BY created_at ASC`, parentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) MarkJobStarted(ctx context.Context, id string, ts time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET status=?, started_at=? WHERE id=?`,
		string(StatusRunning), tsMillis(ts), id)
	return err
}

func (s *Store) MarkJobSucceeded(ctx context.Context, id string, ts time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET status=?, finished_at=? WHERE id=?`,
		string(StatusSucceeded), tsMillis(ts), id)
	return err
}

func (s *Store) MarkJobFailed(ctx context.Context, id, errMsg string, ts time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET status=?, finished_at=?, error=? WHERE id=?`,
		string(StatusFailed), tsMillis(ts), errMsg, id)
	return err
}

func (s *Store) GetJob(ctx context.Context, id string) (*Job, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, kind, spec, status, created_by, created_at, started_at, finished_at, parent_id, error
        FROM jobs WHERE id = ?`, id)
	return scanJob(row.Scan)
}

// ListJobsByStatus returns every job whose status is in `statuses`. Used by
// Runner.Recover to find jobs that were in-flight when the api last died.
func (s *Store) ListJobsByStatus(ctx context.Context, statuses []Status) ([]*Job, error) {
	if len(statuses) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(statuses)), ",")
	args := make([]any, len(statuses))
	for i, st := range statuses {
		args[i] = string(st)
	}
	q := fmt.Sprintf(`
        SELECT id, kind, spec, status, created_by, created_at, started_at, finished_at, parent_id, error
        FROM jobs WHERE status IN (%s) ORDER BY created_at ASC`, placeholders)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) ListJobs(ctx context.Context, limit int) ([]*Job, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, kind, spec, status, created_by, created_at, started_at, finished_at, parent_id, error
        FROM jobs ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

type scanner func(...any) error

func scanJob(scan scanner) (*Job, error) {
	var (
		j          Job
		spec       string
		createdAt  int64
		startedAt  sql.NullInt64
		finishedAt sql.NullInt64
		parentID   sql.NullString
		errMsg     sql.NullString
	)
	if err := scan(&j.ID, &j.Kind, &spec, &j.Status, &j.CreatedBy,
		&createdAt, &startedAt, &finishedAt, &parentID, &errMsg); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	j.Spec = json.RawMessage(spec)
	j.CreatedAt = fromMillis(createdAt)
	j.StartedAt = fromNullMillis(startedAt)
	j.FinishedAt = fromNullMillis(finishedAt)
	if parentID.Valid {
		s := parentID.String
		j.ParentID = &s
	}
	if errMsg.Valid {
		j.Error = errMsg.String
	}
	return &j, nil
}

// ----- Steps --------------------------------------------------------------

func (s *Store) CreateStep(ctx context.Context, st *JobStep) error {
	var started any
	if st.StartedAt != nil {
		started = tsMillis(*st.StartedAt)
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO job_steps (job_id, seq, name, status, started_at, attempt)
        VALUES (?, ?, ?, ?, ?, ?)`,
		st.JobID, st.Seq, st.Name, string(st.Status), started, st.Attempt)
	return err
}

func (s *Store) MarkStepSucceeded(ctx context.Context, jobID string, seq, attempt int, result json.RawMessage, ts time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE job_steps SET status=?, finished_at=?, attempt=?, result=?
        WHERE job_id=? AND seq=?`,
		string(StepSucceeded), tsMillis(ts), attempt, string(result), jobID, seq)
	return err
}

func (s *Store) MarkStepFailed(ctx context.Context, jobID string, seq int, errMsg string, ts time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE job_steps SET status=?, finished_at=?, error=?
        WHERE job_id=? AND seq=?`,
		string(StepFailed), tsMillis(ts), errMsg, jobID, seq)
	return err
}

func (s *Store) ListSteps(ctx context.Context, jobID string) ([]*JobStep, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT job_id, seq, name, status, started_at, finished_at, attempt, result, error
        FROM job_steps WHERE job_id=? ORDER BY seq ASC`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*JobStep
	for rows.Next() {
		var (
			st         JobStep
			started    sql.NullInt64
			finished   sql.NullInt64
			result     sql.NullString
			errMsg     sql.NullString
			statusText string
		)
		if err := rows.Scan(&st.JobID, &st.Seq, &st.Name, &statusText,
			&started, &finished, &st.Attempt, &result, &errMsg); err != nil {
			return nil, err
		}
		st.Status = StepStatus(statusText)
		st.StartedAt = fromNullMillis(started)
		st.FinishedAt = fromNullMillis(finished)
		if result.Valid {
			st.Result = json.RawMessage(result.String)
		}
		if errMsg.Valid {
			st.Error = errMsg.String
		}
		out = append(out, &st)
	}
	return out, rows.Err()
}

// ----- Events -------------------------------------------------------------

func (s *Store) AppendEvent(ctx context.Context, jobID, eventType string, data json.RawMessage, ts time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO job_events (job_id, ts, type, data)
        VALUES (?, ?, ?, ?)`, jobID, tsMillis(ts), eventType, string(data))
	return err
}

func (s *Store) ListEvents(ctx context.Context, jobID string) ([]*JobEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, job_id, ts, type, data
        FROM job_events WHERE job_id=? ORDER BY id ASC`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*JobEvent
	for rows.Next() {
		var (
			ev   JobEvent
			ts   int64
			data sql.NullString
		)
		if err := rows.Scan(&ev.ID, &ev.JobID, &ts, &ev.Type, &data); err != nil {
			return nil, err
		}
		ev.Ts = fromMillis(ts)
		if data.Valid {
			ev.Data = json.RawMessage(data.String)
		}
		out = append(out, &ev)
	}
	return out, rows.Err()
}
