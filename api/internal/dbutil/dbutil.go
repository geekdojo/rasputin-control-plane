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

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
)

// Open opens the SQLite database at path with Rasputin's standard pragmas
// (WAL journal, a 5s busy timeout, foreign keys on) and caps the pool at a
// single connection — SQLite is single-writer, so this serializes writes. It
// applies schema (the caller's CREATE TABLE DDL) before returning the ready
// *sql.DB. name prefixes error messages so callers can tell which store
// failed to open. On any error the partially-opened handle is closed.
//
// The database holds session tokens, passkey credentials and the bus-token
// store, so it is owner-only: the file is pre-created 0600 before SQLite
// opens it (SQLite would create it 0644 less the umask), an existing one is
// tightened to 0600, and so are the -wal and -shm files, both before the open
// (a pair left behind by an older api keeps its old mode) and after it.
// SQLite gives a new -wal or -shm the database's own mode, so a 0600 database
// keeps them 0600 from then on.
func Open(ctx context.Context, path, schema, name string) (*sql.DB, error) {
	if err := secureFiles(path); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
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
	// The schema statement ran in WAL mode, so -wal and -shm exist now.
	if err := secureSidecars(path); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return db, nil
}

// secureFiles makes the database file exist at 0600 and tightens any -wal and
// -shm beside it.
func secureFiles(path string) error {
	if err := atrest.EnsureSecretFile(path); err != nil {
		return fmt.Errorf("database file mode: %w", err)
	}
	return secureSidecars(path)
}

// secureSidecars tightens the database's -wal and -shm files, when present.
func secureSidecars(path string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := atrest.TightenIfExists(path + suffix); err != nil {
			return fmt.Errorf("database file mode: %w", err)
		}
	}
	return nil
}
