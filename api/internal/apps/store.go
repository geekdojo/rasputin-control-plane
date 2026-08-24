package apps

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
	return &Store{db: db}, nil
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

func (s *Store) Create(ctx context.Context, a *App) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO apps (id, name, compose_yaml, target_node, published_port,
                          source_tile, deploy_budget_s, expose_lan, last_status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, a.ComposeYAML, a.TargetNode, a.PublishedPort,
		a.SourceTile, a.DeployBudgetSeconds, a.ExposeLAN, string(a.LastStatus), ms(a.CreatedAt), ms(a.UpdatedAt))
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
// edit-app feature lands it should add its own narrow method the same way.

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
        SELECT id, name, compose_yaml, target_node, published_port, source_tile, deploy_budget_s, expose_lan, last_status, last_detail,
               last_deployed, last_stopped, last_status_at, created_at, updated_at
        FROM apps WHERE id = ?`, id)
	return scanApp(row.Scan)
}

func (s *Store) GetByName(ctx context.Context, name string) (*App, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, name, compose_yaml, target_node, published_port, source_tile, deploy_budget_s, expose_lan, last_status, last_detail,
               last_deployed, last_stopped, last_status_at, created_at, updated_at
        FROM apps WHERE name = ?`, name)
	return scanApp(row.Scan)
}

func (s *Store) List(ctx context.Context) ([]*App, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, name, compose_yaml, target_node, published_port, source_tile, deploy_budget_s, expose_lan, last_status, last_detail,
               last_deployed, last_stopped, last_status_at, created_at, updated_at
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
	)
	if err := scan(&a.ID, &a.Name, &a.ComposeYAML, &a.TargetNode, &a.PublishedPort,
		&a.SourceTile, &a.DeployBudgetSeconds, &a.ExposeLAN, &status, &a.LastDetail, &lastDeployed, &lastStopped, &lastStatusAt,
		&createdAt, &updatedAt); err != nil {
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
	return &a, nil
}
