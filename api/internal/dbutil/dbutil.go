// Package dbutil centralizes how every store package opens its SQLite
// database. Each ledger (auth, jobs, apps, …) used to inline the same DSN
// pragma string and open sequence; keeping it in one place means a pragma
// change (WAL, busy timeout, foreign keys) happens once, not once per store.
package dbutil

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Open opens the SQLite database at path with Rasputin's standard pragmas
// (WAL journal, a 5s busy timeout, foreign keys on) and caps the pool at a
// single connection — SQLite is single-writer, so this serializes writes. It
// applies schema (the caller's CREATE TABLE DDL) before returning the ready
// *sql.DB. name prefixes error messages so callers can tell which store
// failed to open. On any error the partially-opened handle is closed.
func Open(ctx context.Context, path, schema, name string) (*sql.DB, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("%s: open sqlite: %w", name, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%s: apply schema: %w", name, err)
	}
	return db, nil
}
