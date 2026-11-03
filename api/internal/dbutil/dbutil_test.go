//go:build unix

package dbutil

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const testSchema = `CREATE TABLE IF NOT EXISTS t (x TEXT)`

// An existing install's database, -wal and -shm, left 0644 by an older api,
// are 0600 once Open returns. (The table of every secret file the api writes
// is api/internal/atrest TestAtRestModes; this pins Open itself.)
func TestOpen_TightensAnExistingInstall(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rasputin.db")
	for _, s := range []string{"", "-wal", "-shm"} {
		if err := os.WriteFile(p+s, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p+s, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	db, err := Open(context.Background(), p, testSchema, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, s := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(p + s)
		if err != nil {
			t.Fatalf("%s: %v", p+s, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("rasputin.db%s: mode %#o, want 0600", s, got)
		}
	}
}

// A symlink where the database or a sidecar should be is refused before
// SQLite opens anything: the mode fix never follows a link onto another file.
func TestOpen_RefusesASymlink(t *testing.T) {
	for _, s := range []string{"", "-wal", "-shm"} {
		t.Run("rasputin.db"+s, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "rasputin.db")
			victim := filepath.Join(dir, "victim")
			if err := os.WriteFile(victim, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(victim, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, p+s); err != nil {
				t.Fatal(err)
			}
			db, err := Open(context.Background(), p, testSchema, "test")
			if err == nil {
				_ = db.Close()
				t.Fatal("Open succeeded over a symlink")
			}
			info, _ := os.Stat(victim)
			if got := info.Mode().Perm(); got != 0o644 {
				t.Errorf("the link's target was changed to %#o", got)
			}
		})
	}
}

// geekdojo/geekdojo-brain#1059: a write transaction takes the write lock at
// BEGIN, so a transaction that reads and then writes can never find, at its
// write, that another pool on the same file committed (SQLITE_BUSY_SNAPSHOT,
// 517) or is mid-write (SQLITE_BUSY, 5) since its read. Pool A is the code
// under test; pool B's only connection gets busy_timeout 0, so its refusal is
// immediate rather than after five seconds. No sleeps and no goroutines: every
// step runs in order on this goroutine.
func TestOpen_WriteTransactionTakesTheLockAtBegin(t *testing.T) {
	ctx := context.Background()
	open := func(t *testing.T) (a, b *sql.DB) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "rasputin.db")
		var err error
		if a, err = Open(ctx, p, testSchema, "a"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close() })
		if b, err = Open(ctx, p, testSchema, "b"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.Close() })
		if _, err := b.ExecContext(ctx, `PRAGMA busy_timeout = 0`); err != nil {
			t.Fatal(err)
		}
		if _, err := a.ExecContext(ctx, `INSERT INTO t (x) VALUES ('seed')`); err != nil {
			t.Fatal(err)
		}
		return a, b
	}
	// readThenWrite runs A's transaction: BEGIN and a SELECT, then between
	// does whatever B does, then a DELETE and Commit, which must succeed.
	readThenWrite := func(t *testing.T, a *sql.DB, between func()) {
		t.Helper()
		tx, err := a.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("A: begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM t`).Scan(&n); err != nil {
			t.Fatalf("A: select: %v", err)
		}
		between()
		if _, err := tx.ExecContext(ctx, `DELETE FROM t WHERE x = 'seed'`); err != nil {
			t.Fatalf("A: delete after its read: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("A: commit: %v", err)
		}
	}

	// TC-1059-01: B commits an INSERT between A's read and A's write.
	t.Run("another pool commits between the read and the write", func(t *testing.T) {
		a, b := open(t)
		readThenWrite(t, a, func() {
			_, err := b.ExecContext(ctx, `INSERT INTO t (x) VALUES ('b')`)
			requireBusy(t, "B: insert while A's transaction is open", err)
		})
		var n int
		if err := a.QueryRowContext(ctx, `SELECT count(*) FROM t WHERE x = 'b'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("B's row is present (%d); its insert should have been refused", n)
		}
	})

	// TC-1059-02: B begins and INSERTs and holds its transaction open between
	// A's read and A's write (the rack's code-5 shape), then commits if it
	// began.
	t.Run("another pool is mid-write between the read and the write", func(t *testing.T) {
		a, b := open(t)
		var held *sql.Tx
		readThenWrite(t, a, func() {
			tx, err := b.BeginTx(ctx, nil)
			if err == nil {
				held = tx
				_, err = tx.ExecContext(ctx, `INSERT INTO t (x) VALUES ('b')`)
			}
			requireBusy(t, "B: begin and insert while A's transaction is open", err)
		})
		if held != nil {
			_ = held.Commit()
		}
	})
}

// requireBusy fails t unless err is SQLite's SQLITE_BUSY (any extended code).
func requireBusy(t *testing.T, what string, err error) {
	t.Helper()
	var se *sqlite.Error
	if !errors.As(err, &se) || se.Code()&0xff != sqlite3.SQLITE_BUSY {
		t.Errorf("%s: err = %v; want SQLITE_BUSY", what, err)
	}
}
