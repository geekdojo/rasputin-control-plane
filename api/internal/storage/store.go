package storage

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"math"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
)

// Store is the SQLite-backed backup_targets ledger.
type Store struct {
	db *sql.DB
}

// OpenStore opens (and creates) the ledger at path. Shares the cluster's one
// SQLite file with every other store — see dbutil.Open.
func OpenStore(ctx context.Context, path string) (*Store, error) {
	db, err := dbutil.Open(ctx, path, schema, "storage")
	if err != nil {
		return nil, err
	}
	applyMigrations(ctx, db)
	return &Store{db: db}, nil
}

// applyMigrations runs the forward-only DDL in schema.go, tolerating the column
// already being there — which is the normal case on every open after the first.
func applyMigrations(ctx context.Context, db *sql.DB) {
	for _, stmt := range migrations {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			msg := err.Error()
			if strings.Contains(msg, "duplicate column name") ||
				strings.Contains(msg, "already exists") {
				continue // expected: column already present
			}
			log.Printf("storage: migration %q: %v", stmt, err)
		}
	}
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

const targetCols = `job_id, node_id, label, part_uuid, device_path, mount_path, fs_type,
        size_bytes, fingerprint, key_id, key_alg, wrapped_by_passphrase,
        wrapped_by_recovery_code, adopted, wiped, status, created_at, claimed_at, error`

// CreatePending records the start of a claim attempt. Called by step 1, before
// anything on the disk has been touched, so the Backup view shows the attempt
// from the moment it exists rather than from the moment it succeeds.
func (s *Store) CreatePending(ctx context.Context, jobID, nodeID, devicePath, label string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO backup_targets (job_id, node_id, label, device_path, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?)`,
		jobID, nodeID, label, devicePath, string(TargetPending), ms(now))
	return err
}

// ClaimResult is everything step 5 records about a successful claim. A struct
// rather than fourteen positional arguments: this is the one write in the
// package that must not silently transpose two strings.
type ClaimResult struct {
	PartUUID    string
	DevicePath  string
	MountPath   string
	FSType      string
	SizeBytes   uint64
	Fingerprint string
	Adopted     bool
	// Wiped records that this claim destroyed an existing Rasputin backup set —
	// §4.8's second, separate choice. Mutually exclusive with Adopted.
	Wiped bool
	// Key is the already-wrapped §4.6 material, or nil when the target was
	// claimed before encryption was configured. Never plaintext.
	Key *ArchiveKey
	// KeyIDOverride, when non-empty, is the KeyID to record regardless of Key —
	// the adopt path, where the disk's own marker is the authority on which key
	// its existing generations are under.
	KeyIDOverride string
	At            time.Time
}

// MarkClaimed moves a pending row to `claimed` and records the target.
//
// The status guard is not decoration: it is what keeps this write from
// resurrecting a row that OnTerminal already failed, in the window where a
// step-5 write and a terminal hook could both be in flight.
func (s *Store) MarkClaimed(ctx context.Context, jobID string, res ClaimResult) error {
	keyID, keyAlg, wrappedPass, wrappedRecovery := res.KeyIDOverride, "", "", ""
	if res.Key != nil {
		if keyID == "" {
			keyID = res.Key.KeyID
		}
		keyAlg = res.Key.Alg
		wrappedPass = res.Key.WrappedByPassphrase
		wrappedRecovery = res.Key.WrappedByRecoveryCode
	}
	adopted, wiped := 0, 0
	if res.Adopted {
		adopted = 1
	}
	if res.Wiped {
		wiped = 1
	}
	out, err := s.db.ExecContext(ctx, `
        UPDATE backup_targets
        SET part_uuid = ?, device_path = ?, mount_path = ?, fs_type = ?, size_bytes = ?,
            fingerprint = ?, key_id = ?, key_alg = ?, wrapped_by_passphrase = ?,
            wrapped_by_recovery_code = ?, adopted = ?, wiped = ?, status = ?, claimed_at = ?, error = ''
        WHERE job_id = ? AND status = ?`,
		res.PartUUID, res.DevicePath, res.MountPath, res.FSType, sizeForDB(res.SizeBytes),
		res.Fingerprint, keyID, keyAlg, wrappedPass, wrappedRecovery, adopted, wiped,
		string(TargetClaimed), ms(res.At), jobID, string(TargetPending))
	if err != nil {
		return err
	}
	if n, _ := out.RowsAffected(); n == 0 {
		return errors.New("no pending backup target row for this job")
	}
	return nil
}

// MarkFailed gives a still-pending row a terminal status. A no-op on a row that
// already has a verdict — MarkClaimed's result is a record of what happened and
// this must never overwrite it.
func (s *Store) MarkFailed(ctx context.Context, jobID, errMsg string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE backup_targets SET status = ?, error = ?, claimed_at = ?
        WHERE job_id = ? AND status = ?`,
		string(TargetFailed), errMsg, ms(at), jobID, string(TargetPending))
	return err
}

// MarkReplaced supersedes a claimed target. Used by step 5 when the operator
// confirmed `replace`; the row survives because the disk it names does.
func (s *Store) MarkReplaced(ctx context.Context, jobID string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE backup_targets SET status = ?, claimed_at = COALESCE(claimed_at, ?)
        WHERE job_id = ? AND status = ?`,
		string(TargetReplaced), ms(at), jobID, string(TargetClaimed))
	return err
}

// GetByJob returns one attempt's row, or nil when the job never made one.
func (s *Store) GetByJob(ctx context.Context, jobID string) (*BackupTarget, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+targetCols+` FROM backup_targets WHERE job_id = ?`, jobID)
	return scanTarget(row.Scan)
}

// GetByPartUUID resolves a target by the only identifier that survives a
// reboot. nil when nothing with that partition UUID was ever recorded — which
// is exactly the case an adopt exists to fix.
func (s *Store) GetByPartUUID(ctx context.Context, partUUID string) (*BackupTarget, error) {
	if partUUID == "" {
		return nil, nil
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+targetCols+`
        FROM backup_targets WHERE part_uuid = ? AND status = ? ORDER BY created_at DESC LIMIT 1`,
		partUUID, string(TargetClaimed))
	return scanTarget(row.Scan)
}

// ListTargets returns every attempt, newest first.
func (s *Store) ListTargets(ctx context.Context) ([]*BackupTarget, error) {
	return s.query(ctx, `SELECT `+targetCols+` FROM backup_targets ORDER BY created_at DESC`)
}

// ListClaimed returns the targets currently in service. More than one is not
// an error today — §4.8 does not forbid a second disk — but it is what step 1
// checks `replace` against.
func (s *Store) ListClaimed(ctx context.Context) ([]*BackupTarget, error) {
	return s.query(ctx, `SELECT `+targetCols+`
        FROM backup_targets WHERE status = ? ORDER BY created_at DESC`, string(TargetClaimed))
}

// ListPending returns claim attempts still in flight. Used by the startup sweep
// that finalizes rows stranded by a process that died between failing the job
// and firing OnTerminal.
func (s *Store) ListPending(ctx context.Context) ([]*BackupTarget, error) {
	return s.query(ctx, `SELECT `+targetCols+`
        FROM backup_targets WHERE status = ? ORDER BY created_at DESC`, string(TargetPending))
}

// GetWrappedKeys returns the stored §4.6 wrappings for a target. Both are
// opaque ciphertext; neither is the data key.
//
// A separate call rather than a field on BackupTarget so that reaching key
// material is always a deliberate act with its own call site, and never
// something a handler does by returning a struct it happened to have.
func (s *Store) GetWrappedKeys(ctx context.Context, jobID string) (byPassphrase, byRecoveryCode string, err error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT wrapped_by_passphrase, wrapped_by_recovery_code FROM backup_targets WHERE job_id = ?`, jobID)
	if err := row.Scan(&byPassphrase, &byRecoveryCode); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", nil
		}
		return "", "", err
	}
	return byPassphrase, byRecoveryCode, nil
}

func (s *Store) query(ctx context.Context, q string, args ...any) ([]*BackupTarget, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*BackupTarget
	for rows.Next() {
		t, err := scanTarget(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// sizeForDB narrows a disk size for SQLite's signed 64-bit INTEGER column.
//
// The clamp, rather than a bare conversion: a value above MaxInt64 would wrap
// to a NEGATIVE size, and a negative size is worse than a wrong one — it reads
// as a corrupt row and it would come back through scanTarget's `> 0` guard as
// zero, i.e. as "we do not know how big this disk is". No such disk exists
// today; the point is that the failure mode if one ever did is silent.
func sizeForDB(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

func scanTarget(scan func(...any) error) (*BackupTarget, error) {
	var (
		t         BackupTarget
		sizeBytes int64
		adopted   int
		wiped     int
		status    string
		createdAt int64
		claimedAt sql.NullInt64
	)
	if err := scan(&t.JobID, &t.NodeID, &t.Label, &t.PartUUID, &t.DevicePath, &t.MountPath,
		&t.FSType, &sizeBytes, &t.Fingerprint, &t.KeyID, &t.KeyAlg,
		&t.wrappedByPassphrase, &t.wrappedByRecoveryCode, &adopted, &wiped, &status,
		&createdAt, &claimedAt, &t.Error); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if sizeBytes > 0 {
		t.SizeBytes = uint64(sizeBytes)
	}
	t.Adopted = adopted == 1
	t.Wiped = wiped == 1
	t.Status = TargetStatus(status)
	t.CreatedAt = fromMs(createdAt)
	if claimedAt.Valid {
		ts := fromMs(claimedAt.Int64)
		t.ClaimedAt = &ts
	}
	t.HasWrappedKeys = t.wrappedByPassphrase != "" && t.wrappedByRecoveryCode != ""
	return &t, nil
}
