//go:build unix

package fsat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The primitives refuse a symlink at every position, and never open a path.

func TestOpenDirRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if d, err := OpenDir(root, "real"); err != nil {
		t.Fatalf("real dir: %v", err)
	} else {
		_ = d.Close()
	}
	if _, err := OpenDir(root, "link"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink dir opened: err=%v", err)
	}
	if _, err := MkdirOpen(root, "link"); err == nil {
		t.Fatal("MkdirOpen went through a symlink")
	}
}

func TestOpenFileRefusesSymlinkAndNonRegular(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "f"), filepath.Join(dir, "lf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if f, err := OpenFile(root, "f"); err != nil {
		t.Fatalf("regular file: %v", err)
	} else {
		_ = f.Close()
	}
	if _, err := OpenFile(root, "lf"); err == nil {
		t.Fatal("symlink to a file opened")
	}
	if _, err := OpenFile(root, "d"); err == nil {
		t.Fatal("directory opened as a file")
	}
}

func TestCreateExclusiveRefusesAnExistingNameOfAnyKind(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "taken"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, "planted")); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := CreateExclusive(root, "taken"); err == nil {
		t.Fatal("overwrote an existing file")
	}
	if _, err := CreateExclusive(root, "planted"); err == nil {
		t.Fatal("wrote through a planted symlink")
	}
	f, err := CreateExclusive(root, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	st, err := os.Lstat(filepath.Join(dir, "fresh"))
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		t.Fatalf("fresh: %v %v", st, err)
	}
	if ok, err := Exists(root, "fresh"); err != nil || !ok {
		t.Fatalf("Exists(fresh) = %v, %v", ok, err)
	}
	if ok, err := Exists(root, "planted"); err != nil || !ok {
		t.Fatalf("Exists(planted symlink) = %v, %v — a dangling symlink still occupies the name", ok, err)
	}
	if ok, err := Exists(root, "absent"); err != nil || ok {
		t.Fatalf("Exists(absent) = %v, %v", ok, err)
	}
}

func TestRenameAndUnlink(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	f, err := CreateExclusive(root, "a")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := Rename(root, "a", "b"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "b")); err != nil {
		t.Fatal("rename did not happen")
	}
	if err := Unlink(root, "b"); err != nil {
		t.Fatal(err)
	}
	if err := Unlink(root, "b"); err != nil {
		t.Fatalf("second unlink is not an error: %v", err)
	}
}

func TestOpenRootRefusesAFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRoot(p); err == nil {
		t.Fatal("a file opened as a root")
	}
}
