package updater

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed ledger for bundles + per-node update history.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("updater: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("updater: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

// ----- Bundles ------------------------------------------------------------

func (s *Store) CreateBundle(ctx context.Context, b *Bundle) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO bundles
        (sha256, version, compatible, architecture, description, build_date, size_bytes, signed_by, storage_path, uploaded_at, uploaded_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		b.SHA256, b.Version, b.Compatible, b.Architecture, b.Description, b.BuildDate,
		b.SizeBytes, b.SignedBy, b.StoragePath, ms(b.UploadedAt), b.UploadedBy)
	return err
}

func (s *Store) GetBundle(ctx context.Context, sha string) (*Bundle, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT sha256, version, compatible, architecture, description, build_date,
               size_bytes, signed_by, storage_path, uploaded_at, uploaded_by
        FROM bundles WHERE sha256 = ?`, sha)
	return scanBundle(row.Scan)
}

func (s *Store) ListBundles(ctx context.Context) ([]*Bundle, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT sha256, version, compatible, architecture, description, build_date,
               size_bytes, signed_by, storage_path, uploaded_at, uploaded_by
        FROM bundles ORDER BY uploaded_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Bundle
	for rows.Next() {
		b, err := scanBundle(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) DeleteBundle(ctx context.Context, sha string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM bundles WHERE sha256 = ?`, sha)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanBundle(scan func(...any) error) (*Bundle, error) {
	var (
		b          Bundle
		uploadedAt int64
	)
	if err := scan(&b.SHA256, &b.Version, &b.Compatible, &b.Architecture,
		&b.Description, &b.BuildDate, &b.SizeBytes, &b.SignedBy,
		&b.StoragePath, &uploadedAt, &b.UploadedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	b.UploadedAt = fromMs(uploadedAt)
	return &b, nil
}

// ----- NodeUpdate history -------------------------------------------------

func (s *Store) CreateNodeUpdate(ctx context.Context, u *NodeUpdate) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO node_updates
        (job_id, node_id, bundle_sha256, from_slot, to_slot, from_version, to_version, status, started_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.JobID, u.NodeID, u.BundleSHA256,
		string(u.FromSlot), string(u.ToSlot),
		u.FromVersion, u.ToVersion,
		string(u.Status), ms(u.StartedAt))
	return err
}

// UpdateNodeUpdate writes the post-update outcome row.
func (s *Store) UpdateNodeUpdate(ctx context.Context, jobID string, status NodeUpdateStatus, toSlot proto.UpdateSlot, toVersion, errMsg string, finishedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE node_updates
        SET status = ?, to_slot = ?, to_version = ?, error = ?, finished_at = ?
        WHERE job_id = ?`,
		string(status), string(toSlot), toVersion, errMsg, ms(finishedAt), jobID)
	return err
}

// SetNodeUpdateSlots records the from/to slot and version once known
// (after install). Called from the install step.
func (s *Store) SetNodeUpdateSlots(ctx context.Context, jobID string, from, to proto.UpdateSlot, fromVersion, toVersion string) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE node_updates
        SET from_slot = ?, to_slot = ?, from_version = ?, to_version = ?
        WHERE job_id = ?`,
		string(from), string(to), fromVersion, toVersion, jobID)
	return err
}

func (s *Store) GetNodeUpdate(ctx context.Context, jobID string) (*NodeUpdate, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT job_id, node_id, bundle_sha256, from_slot, to_slot, from_version, to_version,
               status, started_at, finished_at, error
        FROM node_updates WHERE job_id = ?`, jobID)
	return scanNodeUpdate(row.Scan)
}

// ListNodeUpdates returns the most-recent update history for one node (or
// all nodes if nodeID is empty). Limit is the number of rows returned.
func (s *Store) ListNodeUpdates(ctx context.Context, nodeID string, limit int) ([]*NodeUpdate, error) {
	if limit <= 0 {
		limit = 50
	}
	var (
		rows *sql.Rows
		err  error
	)
	if nodeID != "" {
		rows, err = s.db.QueryContext(ctx, `
            SELECT job_id, node_id, bundle_sha256, from_slot, to_slot, from_version, to_version,
                   status, started_at, finished_at, error
            FROM node_updates WHERE node_id = ? ORDER BY started_at DESC LIMIT ?`, nodeID, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
            SELECT job_id, node_id, bundle_sha256, from_slot, to_slot, from_version, to_version,
                   status, started_at, finished_at, error
            FROM node_updates ORDER BY started_at DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*NodeUpdate
	for rows.Next() {
		u, err := scanNodeUpdate(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// LatestNodeUpdate returns the most recent NodeUpdate for nodeID, or
// (nil, nil) if the node has never been updated through the control plane.
func (s *Store) LatestNodeUpdate(ctx context.Context, nodeID string) (*NodeUpdate, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT job_id, node_id, bundle_sha256, from_slot, to_slot, from_version, to_version,
               status, started_at, finished_at, error
        FROM node_updates WHERE node_id = ? ORDER BY started_at DESC LIMIT 1`, nodeID)
	return scanNodeUpdate(row.Scan)
}

func scanNodeUpdate(scan func(...any) error) (*NodeUpdate, error) {
	var (
		u                              NodeUpdate
		fromSlot, toSlot, statusRaw    string
		startedAt                      int64
		finishedAt                     sql.NullInt64
	)
	if err := scan(&u.JobID, &u.NodeID, &u.BundleSHA256, &fromSlot, &toSlot,
		&u.FromVersion, &u.ToVersion, &statusRaw, &startedAt, &finishedAt, &u.Error); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	u.FromSlot = proto.UpdateSlot(fromSlot)
	u.ToSlot = proto.UpdateSlot(toSlot)
	u.Status = NodeUpdateStatus(statusRaw)
	u.StartedAt = fromMs(startedAt)
	if finishedAt.Valid {
		t := fromMs(finishedAt.Int64)
		u.FinishedAt = &t
	}
	return &u, nil
}
