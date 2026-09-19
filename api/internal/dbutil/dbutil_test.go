//go:build unix

package dbutil

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
