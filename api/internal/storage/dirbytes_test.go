package storage

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func writeSized(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TC-939-13: DirBytes sums regular files in nested directories, refuses a
// root it cannot read, and counts an unreadable subtree as zero. treeBytes,
// which backup sizing uses, still maps every failure to a number.
func TestDirBytes_TC_939_13(t *testing.T) {
	t.Run("nested regular files", func(t *testing.T) {
		root := t.TempDir()
		writeSized(t, filepath.Join(root, "a"), 100)
		writeSized(t, filepath.Join(root, "x", "b"), 200)
		writeSized(t, filepath.Join(root, "x", "y", "c"), 300)
		if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		got, err := DirBytes(root)
		if err != nil || got != 600 {
			t.Fatalf("DirBytes = %d, %v; want 600, nil (the symlink is not a regular file)", got, err)
		}
		if tb := treeBytes(root); tb != 600 {
			t.Errorf("treeBytes = %d, want 600", tb)
		}
	})

	t.Run("missing root", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope")
		got, err := DirBytes(missing)
		if !errors.Is(err, fs.ErrNotExist) || got != 0 {
			t.Fatalf("DirBytes = %d, %v; want 0 and an fs.ErrNotExist error", got, err)
		}
		if tb := treeBytes(missing); tb != 0 {
			t.Errorf("treeBytes = %d, want 0", tb)
		}
	})

	t.Run("unreadable subtree", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a 0000 directory; the permission case needs an unprivileged user")
		}
		root := t.TempDir()
		writeSized(t, filepath.Join(root, "a"), 100)
		locked := filepath.Join(root, "locked")
		writeSized(t, filepath.Join(locked, "hidden"), 500)
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
		got, err := DirBytes(root)
		if err != nil || got != 100 {
			t.Fatalf("DirBytes = %d, %v; want 100, nil", got, err)
		}
	})

	t.Run("unreadable root", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a 0000 directory; the permission case needs an unprivileged user")
		}
		root := t.TempDir()
		writeSized(t, filepath.Join(root, "a"), 100)
		if err := os.Chmod(root, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
		got, err := DirBytes(root)
		if !errors.Is(err, fs.ErrPermission) || got != 0 {
			t.Fatalf("DirBytes = %d, %v; want 0 and a permission error", got, err)
		}
		if tb := treeBytes(root); tb != 0 {
			t.Errorf("treeBytes = %d, want 0", tb)
		}
	})
}
