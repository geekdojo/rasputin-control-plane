// Package setuptest is test support for code that reads the settings store.
package setuptest

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// UnreadableKey makes one key of the settings database at path fail to read
// while every other key still reads and writes: setup.Store.Get on key then
// returns an error, never "" (which is how the store reports an absent key).
//
// It rebuilds the settings table so its value column admits NULL and stores
// NULL under key; Get cannot scan NULL into a string. The store open on path
// keeps working, because SQLite re-prepares its statements after the schema
// change.
func UnreadableKey(t testing.TB, path, key string) {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("setuptest: open %s: %v", path, err)
	}
	defer func() { _ = db.Close() }()
	for _, stmt := range []string{
		`CREATE TABLE settings_nullable (key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER NOT NULL)`,
		`INSERT INTO settings_nullable SELECT key, value, updated_at FROM settings`,
		`DROP TABLE settings`,
		`ALTER TABLE settings_nullable RENAME TO settings`,
	} {
		if _, err := db.ExecContext(context.Background(), stmt); err != nil {
			t.Fatalf("setuptest: %s: %v", stmt, err)
		}
	}
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO settings (key, value, updated_at) VALUES (?, NULL, 0)
		 ON CONFLICT(key) DO UPDATE SET value = NULL`, key); err != nil {
		t.Fatalf("setuptest: null %s: %v", key, err)
	}
}
