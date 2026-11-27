package move

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
)

// schema is the move's record in rasputin.db: one row per moved operator,
// written last, so a row means the account was imported and read back.
const schema = `
CREATE TABLE IF NOT EXISTS identity_move (
    handle     BLOB PRIMARY KEY,          -- the old user's 16-byte handle
    account_id TEXT NOT NULL UNIQUE,      -- auth.MovedAccountID(handle)
    old_name   TEXT NOT NULL,             -- the pre-update sign-in name
    new_name   TEXT NOT NULL,             -- the identity service's sign-in name
    moved_at   INTEGER NOT NULL           -- unix milliseconds
);

-- The bridge's password fact (geekdojo/geekdojo-brain#1005): a moved
-- account that holds a password. It only hides /login's bridge offer;
-- the bridge itself asks the identity service.
CREATE TABLE IF NOT EXISTS identity_bridge (
    account_id  TEXT PRIMARY KEY,
    password_at INTEGER NOT NULL          -- unix milliseconds
);
`

// Row is one moved operator's record.
type Row struct {
	Handle    []byte
	AccountID string
	OldName   string
	NewName   string
	MovedAt   time.Time
}

// Records is the move's record as the job and the state read it (*Store).
type Records interface {
	Recorded(ctx context.Context) (bool, error)
	Record(ctx context.Context, rows []Row) error
	// Rows is every row; a repair re-run maps each recorded account to its
	// recorded new name.
	Rows(ctx context.Context) ([]Row, error)
}

// Store is the identity_move table.
type Store struct{ db *sql.DB }

var _ Records = (*Store)(nil)

// OpenStore opens the table in the database at dbPath, creating it when
// absent.
func OpenStore(ctx context.Context, dbPath string) (*Store, error) {
	db, err := dbutil.Open(ctx, dbPath, schema, "identity_move")
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Recorded reports whether any move row exists.
func (s *Store) Recorded(ctx context.Context) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM identity_move)`).Scan(&n); err != nil {
		return false, fmt.Errorf("move: read the move record: %w", err)
	}
	return n == 1, nil
}

// Record writes rows in one transaction. A row already there is kept as it
// is (INSERT OR IGNORE). The recorded accounts' password facts are deleted
// in the same transaction, so a repair re-run (C9) offers their bridge
// again.
func (s *Store) Record(ctx context.Context, rows []Row) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("move: record: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO identity_move (handle, account_id, old_name, new_name, moved_at) VALUES (?, ?, ?, ?, ?)`,
			r.Handle, r.AccountID, r.OldName, r.NewName, r.MovedAt.UnixMilli()); err != nil {
			return fmt.Errorf("move: record: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM identity_bridge WHERE account_id = ?`, r.AccountID); err != nil {
			return fmt.Errorf("move: record: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("move: record: %w", err)
	}
	return nil
}

// Rows returns every row, by handle.
func (s *Store) Rows(ctx context.Context) ([]Row, error) {
	rs, err := s.db.QueryContext(ctx, `SELECT handle, account_id, old_name, new_name, moved_at FROM identity_move ORDER BY handle`)
	if err != nil {
		return nil, fmt.Errorf("move: read the rows: %w", err)
	}
	defer func() { _ = rs.Close() }()
	var out []Row
	for rs.Next() {
		var r Row
		var at int64
		if err := rs.Scan(&r.Handle, &r.AccountID, &r.OldName, &r.NewName, &at); err != nil {
			return nil, fmt.Errorf("move: read the rows: %w", err)
		}
		r.MovedAt = time.UnixMilli(at).UTC()
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("move: read the rows: %w", err)
	}
	return out, nil
}

// Account returns the move row of the old user handle, and false when it
// has none.
func (s *Store) Account(ctx context.Context, handle []byte) (Row, bool, error) {
	var r Row
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT handle, account_id, old_name, new_name, moved_at FROM identity_move WHERE handle = ?`, handle).
		Scan(&r.Handle, &r.AccountID, &r.OldName, &r.NewName, &at)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Row{}, false, nil
	case err != nil:
		return Row{}, false, fmt.Errorf("move: read a move row: %w", err)
	}
	r.MovedAt = time.UnixMilli(at).UTC()
	return r, true, nil
}

// PasswordSet reports whether the account's password fact is recorded.
func (s *Store) PasswordSet(ctx context.Context, sub string) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM identity_bridge WHERE account_id = ?)`, sub).Scan(&n); err != nil {
		return false, fmt.Errorf("move: read the password fact: %w", err)
	}
	return n == 1, nil
}

// RecordPasswordSet records that the account holds a password. Recording
// it again keeps the first time. password_at is the database's own time:
// it is for a person reading the table and decides nothing.
func (s *Store) RecordPasswordSet(ctx context.Context, sub string) error {
	if sub == "" {
		return errors.New("move: a password fact needs an account")
	}
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO identity_bridge (account_id, password_at) VALUES (?, CAST(strftime('%s','now') AS INTEGER) * 1000)`, sub); err != nil {
		return fmt.Errorf("move: record the password fact: %w", err)
	}
	return nil
}
