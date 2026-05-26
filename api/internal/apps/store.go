package apps

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed ledger of declared apps.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("apps: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apps: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64    { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

func (s *Store) Create(ctx context.Context, a *App) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO apps (id, name, compose_yaml, target_node, last_status,
                          created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, a.ComposeYAML, a.TargetNode, string(a.LastStatus),
		ms(a.CreatedAt), ms(a.UpdatedAt))
	return err
}

func (s *Store) Update(ctx context.Context, a *App) error {
	res, err := s.db.ExecContext(ctx, `
        UPDATE apps
        SET name = ?, compose_yaml = ?, target_node = ?, updated_at = ?
        WHERE id = ?`,
		a.Name, a.ComposeYAML, a.TargetNode, ms(a.UpdatedAt), a.ID)
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

func (s *Store) Get(ctx context.Context, id string) (*App, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, name, compose_yaml, target_node, last_status, last_detail,
               last_deployed, last_stopped, last_status_at, created_at, updated_at
        FROM apps WHERE id = ?`, id)
	return scanApp(row.Scan)
}

func (s *Store) GetByName(ctx context.Context, name string) (*App, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, name, compose_yaml, target_node, last_status, last_detail,
               last_deployed, last_stopped, last_status_at, created_at, updated_at
        FROM apps WHERE name = ?`, name)
	return scanApp(row.Scan)
}

func (s *Store) List(ctx context.Context) ([]*App, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, name, compose_yaml, target_node, last_status, last_detail,
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
	if err := scan(&a.ID, &a.Name, &a.ComposeYAML, &a.TargetNode, &status,
		&a.LastDetail, &lastDeployed, &lastStopped, &lastStatusAt,
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
