package apps

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Store is the SQLite-backed ledger of declared apps.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	db, err := dbutil.Open(ctx, path, schema, "apps")
	if err != nil {
		return nil, err
	}
	applyMigrations(ctx, db)
	if err := backfillComposeHash(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// ComposeHash is the hex sha256 of a compose file's exact bytes. It is how an
// installed app and its catalog tile are compared (#409): install copies the
// tile's compose verbatim, so the same bytes mean the same compose, and any
// change to the tile — an image digest, an env var, a comment — is a
// difference the owner gets to look at before taking it. Deliberately not a
// normalized or semantic comparison: deciding which changes "don't count" is a
// judgement, and this is a fact.
func ComposeHash(composeYAML string) string {
	sum := sha256.Sum256([]byte(composeYAML))
	return hex.EncodeToString(sum[:])
}

// backfillComposeHash stamps compose_sha256 on every row that has none — every
// app installed before the column existed. It runs on every open and touches
// only blank rows, so after the first open it finds nothing to do.
//
// Unlike the ALTERs it fails the open. A blank hash is not a harmless default:
// it differs from every tile's hash, so every catalog app would read as having
// an upgrade available that nobody published, and an owner who took it would
// be "upgrading" to whatever the catalog holds today from a state nothing
// recorded.
func backfillComposeHash(ctx context.Context, db *sql.DB) error {
	type pending struct{ id, hash string }
	// Read everything, and close the cursor, before the first UPDATE: the pool
	// is one connection, so writing while the cursor still holds it would
	// deadlock.
	todo, err := func() ([]pending, error) {
		rows, err := db.QueryContext(ctx, `SELECT id, compose_yaml FROM apps WHERE compose_sha256 = ''`)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		var out []pending
		for rows.Next() {
			var id, compose string
			if err := rows.Scan(&id, &compose); err != nil {
				return nil, err
			}
			out = append(out, pending{id, ComposeHash(compose)})
		}
		return out, rows.Err()
	}()
	if err != nil {
		return fmt.Errorf("apps: backfill compose hash: %w", err)
	}
	for _, p := range todo {
		if _, err := db.ExecContext(ctx, `UPDATE apps SET compose_sha256 = ? WHERE id = ? AND compose_sha256 = ''`, p.hash, p.id); err != nil {
			return fmt.Errorf("apps: backfill compose hash for %s: %w", p.id, err)
		}
	}
	return nil
}

func applyMigrations(ctx context.Context, db *sql.DB) {
	for _, stmt := range migrations {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			msg := err.Error()
			if strings.Contains(msg, "duplicate column name") ||
				strings.Contains(msg, "already exists") {
				continue // expected: column already present
			}
			log.Printf("apps: migration %q: %v", stmt, err)
		}
	}
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

// Create inserts a new app. It stamps a.ComposeSHA256 from a.ComposeYAML rather
// than trusting the field, so the hash an upgrade check reads is always the
// hash of what was actually stored.
func (s *Store) Create(ctx context.Context, a *App) error {
	a.ComposeSHA256 = ComposeHash(a.ComposeYAML)
	var ackAt sql.NullInt64
	ackBy := ""
	if a.BackupAck != nil {
		ackAt = sql.NullInt64{Int64: ms(a.BackupAck.At), Valid: true}
		ackBy = a.BackupAck.By
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO apps (id, name, compose_yaml, target_node, published_port,
                          source_tile, deploy_budget_s, expose_lan, web_tls, last_status, created_at, updated_at,
                          backup_ack_at, backup_ack_by, compose_sha256, compose_catalog_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, a.ComposeYAML, a.TargetNode, a.PublishedPort,
		a.SourceTile, a.DeployBudgetSeconds, a.ExposeLAN, a.WebTLS, string(a.LastStatus), ms(a.CreatedAt), ms(a.UpdatedAt),
		ackAt, ackBy, a.ComposeSHA256, a.ComposeCatalogVersion)
	return err
}

// There is deliberately no general Update.
//
// There was one, and nothing in the api ever called it — its only callers were
// its own tests. It wrote name, compose_yaml and target_node and silently
// dropped every other column, which is exactly the shape of trap that costs an
// afternoon: a test seeded an app, called Update to set a published port, and
// passed for the wrong reason because the port was never written and the
// assertion happened to hold anyway.
//
// Mutations here are narrow and named for what they do — SetExposeLAN,
// RecordStatus — so a caller cannot accidentally rewrite an installed app's
// compose while flipping one flag, and so a column added later cannot be
// silently forgotten by a method whose name promises to write everything. If an
// edit-app feature lands it should add its own narrow method the same way, as
// the catalog upgrade did (UpgradeCompose, #409).

// SetExposeLAN flips an app's LAN-exposure opt-in in place.
//
// It exists because the grant had no reverse edge (#197): ExposeLAN was set
// once from the create payload and never updated, so withdrawing LAN
// reachability meant DELETING the app — for any tile with volumes, a choice
// between leaving it on the LAN and destroying its data. The default was right
// and the grant path was well built; the asymmetry was the defect.
//
// Deliberately narrow rather than folded into Update: Update rewrites name,
// compose and target node, and an exposure toggle should not be able to touch
// the compose that was signed and installed.
func (s *Store) SetExposeLAN(ctx context.Context, id string, expose bool, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `
        UPDATE apps SET expose_lan = ?, updated_at = ? WHERE id = ?`,
		expose, ms(now), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ComposeUpgrade is everything an in-place upgrade writes (#409): the tile's
// compose and the catalog version it came from, plus the three install-time
// fields install copies from the tile and an upgrade must therefore re-copy.
// Nothing else. The app's identity and the owner's choices — ID, Name,
// TargetNode, ExposeLAN, BackupAck — are not in this struct, so UpgradeCompose
// cannot change them: the ULID is the Compose project and the volume
// namespace, and a new one is a reinstall that starts the app empty.
type ComposeUpgrade struct {
	ComposeYAML         string
	CatalogVersion      int
	PublishedPort       int
	WebTLS              bool
	DeployBudgetSeconds int
}

// ErrComposeChanged is UpgradeCompose refusing because the installed compose
// is no longer the one the caller read.
var ErrComposeChanged = errors.New("apps: the installed compose changed since it was read")

// UpgradeCompose replaces an installed app's compose with a catalog tile's, in
// place, keeping the one it replaces in previous_compose_yaml.
//
// fromHash is the compose_sha256 the caller read, and the write is conditional
// on it. Two upgrades racing, or an upgrade racing any later compose edit,
// would otherwise both succeed and the second would shift the FIRST upgrade's
// compose into previous_compose_yaml — losing the only copy of the compose
// that was actually running before either began. A mismatch is
// ErrComposeChanged; an unknown id is sql.ErrNoRows.
func (s *Store) UpgradeCompose(ctx context.Context, id, fromHash string, up ComposeUpgrade, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `
        UPDATE apps SET previous_compose_yaml = compose_yaml,
                        compose_yaml = ?, compose_sha256 = ?, compose_catalog_version = ?,
                        published_port = ?, web_tls = ?, deploy_budget_s = ?, updated_at = ?
        WHERE id = ? AND compose_sha256 = ?`,
		up.ComposeYAML, ComposeHash(up.ComposeYAML), up.CatalogVersion,
		up.PublishedPort, up.WebTLS, up.DeployBudgetSeconds, ms(now),
		id, fromHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var exists int
	switch err := s.db.QueryRowContext(ctx, `SELECT 1 FROM apps WHERE id = ?`, id).Scan(&exists); {
	case errors.Is(err, sql.ErrNoRows):
		return sql.ErrNoRows
	case err != nil:
		return err
	}
	return ErrComposeChanged
}

// RecordStatus persists the agent-reported status for an app. status is the
// new value; detail is an optional human-readable message; deployed/stopped
// timestamps are updated when status transitions into/out of running.
func (s *Store) RecordStatus(ctx context.Context, appID string, status proto.AppStatus, detail string, now time.Time) error {
	cols := []string{"last_status = ?", "last_detail = ?", "last_status_at = ?", "updated_at = ?"}
	args := []any{string(status), detail, ms(now), ms(now)}

	switch status {
	case proto.AppStatusRunning:
		cols = append(cols, "last_deployed = ?")
		args = append(args, ms(now))
	case proto.AppStatusStopped:
		cols = append(cols, "last_stopped = ?")
		args = append(args, ms(now))
	}
	args = append(args, appID)

	q := "UPDATE apps SET " + joinCols(cols) + " WHERE id = ?"
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func joinCols(cols []string) string {
	out := ""
	for i, c := range cols {
		if i > 0 {
			out += ", "
		}
		out += c
	}
	return out
}

func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM apps WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteByTargetNode removes every apps row whose target_node matches the
// given id, returning the ids of the deleted rows so the caller can emit
// per-app change events.
//
// Contract: this removes *deployments* targeting the node — never a shared
// catalog entry. In today's schema each apps row IS both the catalog
// definition and the deployment (target_node is on the same row, name is
// UNIQUE), so deleting by target_node and "removing the deployment" are
// the same operation. When the catalog/deployments split lands, this
// method should be ported to operate on the deployments table; the
// contract (one node's deployments, never shared catalog rows) is
// unchanged.
func (s *Store) DeleteByTargetNode(ctx context.Context, nodeID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM apps WHERE target_node = ?`, nodeID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(ids) == 0 {
		return nil, nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM apps WHERE target_node = ?`, nodeID); err != nil {
		return nil, err
	}
	return ids, nil
}

func (s *Store) Get(ctx context.Context, id string) (*App, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, name, compose_yaml, target_node, published_port, source_tile, deploy_budget_s, expose_lan, web_tls, last_status, last_detail,
               last_deployed, last_stopped, last_status_at, created_at, updated_at, backup_ack_at, backup_ack_by,
               compose_sha256, compose_catalog_version, previous_compose_yaml
        FROM apps WHERE id = ?`, id)
	return scanApp(row.Scan)
}

func (s *Store) GetByName(ctx context.Context, name string) (*App, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, name, compose_yaml, target_node, published_port, source_tile, deploy_budget_s, expose_lan, web_tls, last_status, last_detail,
               last_deployed, last_stopped, last_status_at, created_at, updated_at, backup_ack_at, backup_ack_by,
               compose_sha256, compose_catalog_version, previous_compose_yaml
        FROM apps WHERE name = ?`, name)
	return scanApp(row.Scan)
}

func (s *Store) List(ctx context.Context) ([]*App, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, name, compose_yaml, target_node, published_port, source_tile, deploy_budget_s, expose_lan, web_tls, last_status, last_detail,
               last_deployed, last_stopped, last_status_at, created_at, updated_at, backup_ack_at, backup_ack_by,
               compose_sha256, compose_catalog_version, previous_compose_yaml
        FROM apps ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*App
	for rows.Next() {
		a, err := scanApp(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func scanApp(scan func(...any) error) (*App, error) {
	var (
		a            App
		status       string
		lastDeployed sql.NullInt64
		lastStopped  sql.NullInt64
		lastStatusAt sql.NullInt64
		createdAt    int64
		updatedAt    int64
		ackAt        sql.NullInt64
		ackBy        string
	)
	if err := scan(&a.ID, &a.Name, &a.ComposeYAML, &a.TargetNode, &a.PublishedPort,
		&a.SourceTile, &a.DeployBudgetSeconds, &a.ExposeLAN, &a.WebTLS, &status, &a.LastDetail, &lastDeployed, &lastStopped, &lastStatusAt,
		&createdAt, &updatedAt, &ackAt, &ackBy,
		&a.ComposeSHA256, &a.ComposeCatalogVersion, &a.PreviousComposeYAML); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	a.LastStatus = proto.AppStatus(status)
	if lastDeployed.Valid {
		t := fromMs(lastDeployed.Int64)
		a.LastDeployed = &t
	}
	if lastStopped.Valid {
		t := fromMs(lastStopped.Int64)
		a.LastStopped = &t
	}
	if lastStatusAt.Valid {
		t := fromMs(lastStatusAt.Int64)
		a.LastStatusAt = &t
	}
	a.CreatedAt = fromMs(createdAt)
	a.UpdatedAt = fromMs(updatedAt)
	if ackAt.Valid {
		a.BackupAck = &BackupAck{At: fromMs(ackAt.Int64), By: ackBy}
	}
	return &a, nil
}
