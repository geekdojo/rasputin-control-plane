package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// The restore_reports ledger: one row per restore this cluster came back
// from. Written by the start that applied the restore, into the database it
// restored — so the record lives with the identity it describes and survives
// the same backups.

// RecordRestore inserts a report. A report already present (by id) is left
// as it is: the apply writes it once and the record is not a thing to
// overwrite.
func (s *Store) RecordRestore(ctx context.Context, r *RestoreReport) error {
	if r == nil {
		return errors.New("no report")
	}
	now := time.Now().UTC()
	r.RecordedAt = &now
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var applied any
	if r.AppliedAt != nil {
		applied = ms(*r.AppliedAt)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT OR IGNORE INTO restore_reports
            (id, phase, generation_id, cluster_id, key_id, scope, complete, part_uuid,
             prepared_at, applied_at, recorded_at, report)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Phase, r.GenerationID, r.ClusterID, r.KeyID, r.Scope, boolInt(r.Complete), r.PartUUID,
		ms(r.PreparedAt), applied, ms(now), string(b))
	return err
}

// ListRestores returns every restore this cluster came back from, newest
// first.
func (s *Store) ListRestores(ctx context.Context) ([]*RestoreReport, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT report FROM restore_reports ORDER BY recorded_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*RestoreReport
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var r RestoreReport
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// LatestRestore is the most recent restore, or nil when this cluster was
// never restored.
func (s *Store) LatestRestore(ctx context.Context) (*RestoreReport, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT report FROM restore_reports ORDER BY recorded_at DESC, id DESC LIMIT 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r RestoreReport
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
