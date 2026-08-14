package updater

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Store is the SQLite-backed ledger for bundles + per-node update history.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	db, err := dbutil.Open(ctx, path, schema, "updater")
	if err != nil {
		return nil, err
	}
	applyMigrations(ctx, db)
	return &Store{db: db}, nil
}

// applyMigrations runs the forward-only DDL in schema.go. A "duplicate column"
// / "already exists" failure is the expected result on a fresh install, where
// CREATE TABLE already produced the final shape; anything else is logged and
// skipped rather than fatal, because a store that will not open takes the whole
// api down for what is usually one additive column.
func applyMigrations(ctx context.Context, db *sql.DB) {
	for _, stmt := range migrations {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			msg := err.Error()
			if strings.Contains(msg, "duplicate column name") || strings.Contains(msg, "already exists") {
				continue
			}
			log.Printf("updater: migration %q: %v", stmt, err)
		}
	}
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

// SetNodeUpdateVerifyGaps records which conjuncts of the verify contract could
// not be evaluated for this update (ADR-0005 Decision 3). Written once, when
// verify completes, so the per-node report can say that a green row rests on
// fewer than all four checks.
//
// A separate call rather than more arguments on UpdateNodeUpdate because the
// two are written at different moments by different steps — verify knows the
// gaps, the terminal status is decided later — and threading them through would
// mean carrying the values across a step boundary just to write them together.
func (s *Store) SetNodeUpdateVerifyGaps(ctx context.Context, jobID string, unverifiedBoot, unverifiedVersion bool) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE node_updates
        SET unverified_boot = :unverified_boot, unverified_version = :unverified_version
        WHERE job_id = :job_id`,
		sql.Named("unverified_boot", unverifiedBoot),
		sql.Named("unverified_version", unverifiedVersion),
		sql.Named("job_id", jobID))
	return err
}

// SetNodeUpdateSlots records the from/to slot and version once known
// (after install). Called from the install step.
//
// ⚠️ THE VERSIONS REFINE, THEY NEVER ERASE — that is what the COALESCE is for,
// and it is the whole of #86's real fix.
//
// The api already knows the version it is installing: step 1 writes
// `to_version = bundle.Version` straight from the release manifest, before the
// node has been asked to do anything. This statement then ran with the AGENT's
// echo and overwrote it unconditionally. On RAUC that was invisible, because
// `rauc info` returns the same string. On openwrt-ab the raw squashfs carries
// no manifest, so the echo is "" — and a good manifest version was replaced
// with nothing on every single firewall update.
//
// The consequence was not cosmetic. verify's conjunct (c) reads this column as
// the EXPECTED side (`classifyVersion(expected.ToVersion, …)`), so blanking it
// made the check permanently unevaluable on that backend. #86 was originally
// filed against the agent — it used to return the bundle's sha256 here, which
// verify then compared against a real CalVer and failed every firewall update —
// and #111 fixed that by returning "" so the three-valued conjunct would
// degrade rather than fail. That was right as far as it went, and it went one
// step short: degrading was never necessary, because the api held the answer
// the whole time and was throwing it away here.
//
// ⚠️ AMENDED for #92 — THE ECHO FILLS A GAP, IT DOES NOT REFINE.
//
// The original fix guarded only the EMPTY echo (NULLIF on the bind param),
// on the reasoning that an agent which knows better may refine the value. A
// pre-#111 agent does not return nothing — it returns the bundle's SHA256,
// which is non-empty, sails through that guard, and replaces a good manifest
// version with a string that is not a version at all. The firewall's agent is
// pinned separately (`rasputin-openwrt-firewall/agent-version.txt`) on its own
// cadence, so it lagged into exactly that state and EVERY firewall update
// failed `version_mismatch` on `e3bench` 2026-08-14.
//
// The asymmetry below is the point, and it follows from who holds the answer:
//
//   - to_version   — the api ALREADY KNOWS IT (step 1 wrote bundle.Version from
//     the signed manifest before the node was asked anything). The
//     existing value therefore WINS, and the agent's echo can only
//     fill the column when it is still empty.
//   - from_version — the api knows NOTHING (step 1 leaves it empty; only the
//     node can say what it was running). The echo stays authoritative.
//
// "Refinement" bought nothing to weigh against that: on RAUC the two strings
// are identical, and on openwrt-ab the agent has no better source than the
// manifest the api is already holding. What it cost was letting a node
// overwrite the EXPECTED side of the check that grades it.
//
// Done in SQL rather than read-modify-write so it stays a single atomic
// statement; a concurrent writer cannot interleave between the read and the
// decision.
func (s *Store) SetNodeUpdateSlots(ctx context.Context, jobID string, from, to proto.UpdateSlot, fromVersion, toVersion string) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE node_updates
        SET from_slot    = :from_slot,
            to_slot      = :to_slot,
            from_version = COALESCE(NULLIF(:from_version, ''), from_version),
            to_version   = COALESCE(NULLIF(to_version, ''), NULLIF(:to_version, ''))
        WHERE job_id = :job_id`,
		sql.Named("from_slot", string(from)),
		sql.Named("to_slot", string(to)),
		sql.Named("from_version", fromVersion),
		sql.Named("to_version", toVersion),
		sql.Named("job_id", jobID))
	return err
}

func (s *Store) GetNodeUpdate(ctx context.Context, jobID string) (*NodeUpdate, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT job_id, node_id, bundle_sha256, from_slot, to_slot, from_version, to_version,
               unverified_boot, unverified_version,
               status, started_at, finished_at, error
        FROM node_updates WHERE job_id = ?`, jobID)
	return scanNodeUpdate(row.Scan)
}

// ListInProgressNodeUpdates returns every row still reading in_progress,
// oldest first. Used by ReconcileStrandedRows at api start to clear rows whose
// job has already reached a terminal state — see #53.
//
// Unbounded on purpose: this runs once per process against a table with one row
// per node per update, and a LIMIT here would silently leave the oldest strays
// behind, which is the exact failure being cleaned up.
func (s *Store) ListInProgressNodeUpdates(ctx context.Context) ([]*NodeUpdate, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT job_id, node_id, bundle_sha256, from_slot, to_slot, from_version, to_version,
               unverified_boot, unverified_version,
               status, started_at, finished_at, error
        FROM node_updates WHERE status = ? ORDER BY started_at ASC`, string(NodeUpdateInProgress))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*NodeUpdate
	for rows.Next() {
		nu, err := scanNodeUpdate(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, nu)
	}
	return out, rows.Err()
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
               unverified_boot, unverified_version,
                   status, started_at, finished_at, error
            FROM node_updates WHERE node_id = ? ORDER BY started_at DESC LIMIT ?`, nodeID, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
            SELECT job_id, node_id, bundle_sha256, from_slot, to_slot, from_version, to_version,
               unverified_boot, unverified_version,
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
               unverified_boot, unverified_version,
               status, started_at, finished_at, error
        FROM node_updates WHERE node_id = ? ORDER BY started_at DESC LIMIT 1`, nodeID)
	return scanNodeUpdate(row.Scan)
}

func scanNodeUpdate(scan func(...any) error) (*NodeUpdate, error) {
	var (
		u                           NodeUpdate
		fromSlot, toSlot, statusRaw string
		startedAt                   int64
		finishedAt                  sql.NullInt64
	)
	if err := scan(&u.JobID, &u.NodeID, &u.BundleSHA256, &fromSlot, &toSlot,
		&u.FromVersion, &u.ToVersion, &u.UnverifiedBoot, &u.UnverifiedVersion,
		&statusRaw, &startedAt, &finishedAt, &u.Error); err != nil {
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
