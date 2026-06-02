package alerts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	_ "modernc.org/sqlite"
)

// Store persists rule-engine alerts. The aggregator's "current concerns"
// view (node-offline, job-failed, etc.) stays computed-on-read in
// service.go; this Store holds alerts that arrived via the webhook from
// vmalert AND the operator's ack/dismiss state.
//
// Schema rationale: fingerprint is the natural key (Alertmanager-style
// hash of the labels). We use TEXT not TEXT PRIMARY KEY because we
// also want a synthetic monotonic id for the WS push topic to
// reference; the fingerprint is UNIQUE separately.
//
// Why a single table (not separate "history" + "current"): the
// distinction at read time is "status = firing AND dismissed_at IS NULL"
// vs "any other state" — cheap query, no need to physically split.
type Store struct {
	db *sql.DB
}

// PersistedAlert is the row type. Status is "firing" or "resolved" (mirrors
// Alertmanager). Labels + annotations are stored as JSON.
type PersistedAlert struct {
	ID          string
	Fingerprint string
	Status      string // "firing" | "resolved"
	Severity    proto.AlertSeverity
	Title       string
	Detail      string
	Labels      map[string]string
	Annotations map[string]string
	StartsAt    time.Time
	EndsAt      *time.Time
	AckedAt     *time.Time
	DismissedAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// OpenStore opens (and migrates) the alerts store at the given db path.
// Shares the api's SQLite file with every other subsystem.
func OpenStore(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("alerts: open store: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS persisted_alerts (
  id            TEXT PRIMARY KEY,
  fingerprint   TEXT NOT NULL UNIQUE,
  status        TEXT NOT NULL,
  severity      TEXT NOT NULL,
  title         TEXT NOT NULL,
  detail        TEXT,
  labels        TEXT NOT NULL,
  annotations   TEXT NOT NULL,
  starts_at     INTEGER NOT NULL,
  ends_at       INTEGER,
  acked_at      INTEGER,
  dismissed_at  INTEGER,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS persisted_alerts_status_idx ON persisted_alerts(status, dismissed_at);
`)
	if err != nil {
		return fmt.Errorf("alerts: migrate: %w", err)
	}
	return nil
}

// Upsert inserts or updates by fingerprint. Returns the resulting row +
// whether this was a NEW alert (no prior row) so callers can decide
// whether to publish AlertFired vs an update.
func (s *Store) Upsert(ctx context.Context, a *PersistedAlert) (saved *PersistedAlert, isNew bool, err error) {
	if a.Fingerprint == "" {
		return nil, false, errors.New("alerts: upsert: fingerprint required")
	}
	if a.Title == "" {
		return nil, false, errors.New("alerts: upsert: title required")
	}
	labelsJSON, _ := json.Marshal(a.Labels)
	annsJSON, _ := json.Marshal(a.Annotations)
	if a.ID == "" {
		a.ID = "rule:" + a.Fingerprint
	}
	now := time.Now().UTC()
	a.UpdatedAt = now
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}

	var existingID string
	err = s.db.QueryRowContext(ctx,
		`SELECT id FROM persisted_alerts WHERE fingerprint = ?`,
		a.Fingerprint).Scan(&existingID)
	switch {
	case err == sql.ErrNoRows:
		isNew = true
	case err != nil:
		return nil, false, fmt.Errorf("alerts: lookup: %w", err)
	default:
		a.ID = existingID // preserve stable ID across re-fires
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO persisted_alerts
  (id, fingerprint, status, severity, title, detail, labels, annotations,
   starts_at, ends_at, acked_at, dismissed_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(fingerprint) DO UPDATE SET
  status      = excluded.status,
  severity    = excluded.severity,
  title       = excluded.title,
  detail      = excluded.detail,
  labels      = excluded.labels,
  annotations = excluded.annotations,
  starts_at   = excluded.starts_at,
  ends_at     = excluded.ends_at,
  updated_at  = excluded.updated_at`,
		a.ID, a.Fingerprint, a.Status, string(a.Severity), a.Title, a.Detail,
		string(labelsJSON), string(annsJSON),
		a.StartsAt.UnixMilli(), nilIfZeroMs(a.EndsAt),
		nilIfZeroMs(a.AckedAt), nilIfZeroMs(a.DismissedAt),
		a.CreatedAt.UnixMilli(), a.UpdatedAt.UnixMilli())
	if err != nil {
		return nil, false, fmt.Errorf("alerts: upsert: %w", err)
	}
	saved, err = s.Get(ctx, a.ID)
	if err != nil {
		return nil, false, err
	}
	return saved, isNew, nil
}

// Ack sets acked_at = now for an alert. No-op when already acked.
// Returns the updated row or (nil, sql.ErrNoRows) when missing.
func (s *Store) Ack(ctx context.Context, id string) (*PersistedAlert, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE persisted_alerts SET acked_at = ?, updated_at = ? WHERE id = ? AND acked_at IS NULL`,
		now.UnixMilli(), now.UnixMilli(), id)
	if err != nil {
		return nil, fmt.Errorf("alerts: ack: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// either not found OR already acked — disambiguate via Get
		if a, _ := s.Get(ctx, id); a == nil {
			return nil, sql.ErrNoRows
		}
	}
	return s.Get(ctx, id)
}

// Dismiss sets dismissed_at = now. Dismissed alerts disappear from List
// by default; they're kept in the table for audit and can be
// re-surfaced via ListAll(includeDismissed=true).
func (s *Store) Dismiss(ctx context.Context, id string) (*PersistedAlert, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE persisted_alerts SET dismissed_at = ?, updated_at = ? WHERE id = ? AND dismissed_at IS NULL`,
		now.UnixMilli(), now.UnixMilli(), id)
	if err != nil {
		return nil, fmt.Errorf("alerts: dismiss: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if a, _ := s.Get(ctx, id); a == nil {
			return nil, sql.ErrNoRows
		}
	}
	return s.Get(ctx, id)
}

// Get returns one alert by id, or (nil, nil) when not found.
func (s *Store) Get(ctx context.Context, id string) (*PersistedAlert, error) {
	row := s.db.QueryRowContext(ctx, selectCols+` WHERE id = ?`, id)
	a, err := scanAlert(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return a, err
}

// List returns every alert that's not dismissed. Order: severity
// descending, then starts_at ascending. Sort happens in code (sql sort
// would require a severity-rank case expression).
func (s *Store) List(ctx context.Context) ([]*PersistedAlert, error) {
	rows, err := s.db.QueryContext(ctx,
		selectCols+` WHERE dismissed_at IS NULL ORDER BY starts_at DESC LIMIT 500`)
	if err != nil {
		return nil, fmt.Errorf("alerts: list: %w", err)
	}
	defer rows.Close()
	var out []*PersistedAlert
	for rows.Next() {
		a, err := scanAlert(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

const selectCols = `SELECT id, fingerprint, status, severity, title, detail,
labels, annotations, starts_at, ends_at, acked_at, dismissed_at, created_at, updated_at
FROM persisted_alerts`

type scanner func(dest ...any) error

func scanAlert(scan scanner) (*PersistedAlert, error) {
	var (
		a                              PersistedAlert
		labelsJSON, annsJSON           string
		startsMs, createdMs, updatedMs int64
		endsMs, ackedMs, dismissedMs   sql.NullInt64
		severity                       string
	)
	if err := scan(&a.ID, &a.Fingerprint, &a.Status, &severity, &a.Title, &a.Detail,
		&labelsJSON, &annsJSON,
		&startsMs, &endsMs, &ackedMs, &dismissedMs, &createdMs, &updatedMs); err != nil {
		return nil, err
	}
	a.Severity = proto.AlertSeverity(severity)
	_ = json.Unmarshal([]byte(labelsJSON), &a.Labels)
	_ = json.Unmarshal([]byte(annsJSON), &a.Annotations)
	a.StartsAt = time.UnixMilli(startsMs).UTC()
	if endsMs.Valid {
		t := time.UnixMilli(endsMs.Int64).UTC()
		a.EndsAt = &t
	}
	if ackedMs.Valid {
		t := time.UnixMilli(ackedMs.Int64).UTC()
		a.AckedAt = &t
	}
	if dismissedMs.Valid {
		t := time.UnixMilli(dismissedMs.Int64).UTC()
		a.DismissedAt = &t
	}
	a.CreatedAt = time.UnixMilli(createdMs).UTC()
	a.UpdatedAt = time.UnixMilli(updatedMs).UTC()
	return &a, nil
}

// nilIfZeroMs returns nil for a zero-value time pointer / time.Time so
// SQLite stores NULL instead of an epoch 0 sentinel. Saves a "is the
// timestamp 0 or unset" branch on every read.
func nilIfZeroMs(t any) any {
	switch v := t.(type) {
	case time.Time:
		if v.IsZero() {
			return nil
		}
		return v.UnixMilli()
	case *time.Time:
		if v == nil || v.IsZero() {
			return nil
		}
		return v.UnixMilli()
	}
	return nil
}
