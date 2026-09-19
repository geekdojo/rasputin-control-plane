//go:build unix

package atrest

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// withUmask runs fn with the process umask set to mask. The widest umask (0)
// is the one that would expose a secret written with a loose create mode, and
// the narrowest (077) the one that would hide a public file from another uid;
// the helpers must give the same modes under both. No test in this package
// runs in parallel, so the process-wide umask is safe to change here.
func withUmask(t *testing.T, mask int, fn func()) {
	t.Helper()
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	fn()
}

func perm(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

var umasks = []int{0o000, 0o022, 0o077}

func TestWriteSecretFile_ModeIgnoresUmask(t *testing.T) {
	for _, mask := range umasks {
		withUmask(t, mask, func() {
			dir := t.TempDir()
			p := filepath.Join(dir, "new", "secret")
			if err := WriteSecretFile(p, []byte("s3cret")); err != nil {
				t.Fatalf("umask %#o: %v", mask, err)
			}
			if got := perm(t, p); got != 0o600 {
				t.Errorf("umask %#o: file mode %#o, want 0600", mask, got)
			}
			if got := perm(t, filepath.Dir(p)); got&0o077 != 0 {
				t.Errorf("umask %#o: created parent mode %#o has group/other bits", mask, got)
			}
			if b, _ := os.ReadFile(p); string(b) != "s3cret" {
				t.Errorf("umask %#o: content %q", mask, b)
			}
		})
	}
}

func TestWriteSecretFile_TightensAReplacedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecretFile(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, p); got != 0o600 {
		t.Errorf("mode %#o, want 0600: os.WriteFile would have kept the old mode", got)
	}
}

func TestWriteSecretFile_ReplacesASymlinkRatherThanWritingThroughIt(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "secret")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecretFile(link, []byte("s3cret")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Errorf("wrote through the symlink: victim now %q", b)
	}
	if got := perm(t, victim); got != 0o644 {
		t.Errorf("victim mode changed to %#o", got)
	}
	if info, _ := os.Lstat(link); info.Mode()&fs.ModeSymlink != 0 {
		t.Error("the symlink is still in place")
	}
}

func TestWriteSecretFile_LeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSecretFile(filepath.Join(dir, "secret"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("directory holds %d entries, want only the file: %v", len(ents), ents)
	}
}

func TestWritePublicFile_ModeIgnoresUmask(t *testing.T) {
	for _, mask := range umasks {
		withUmask(t, mask, func() {
			p := filepath.Join(t.TempDir(), "config")
			if err := WritePublicFile(p, []byte("cfg")); err != nil {
				t.Fatalf("umask %#o: %v", mask, err)
			}
			if got := perm(t, p); got != 0o644 {
				t.Errorf("umask %#o: mode %#o, want 0644", mask, got)
			}
		})
	}
}

func TestCreateSecretFile(t *testing.T) {
	withUmask(t, 0, func() {
		p := filepath.Join(t.TempDir(), "key")
		if err := CreateSecretFile(p, []byte("first")); err != nil {
			t.Fatal(err)
		}
		if got := perm(t, p); got != 0o600 {
			t.Errorf("mode %#o, want 0600", got)
		}
		err := CreateSecretFile(p, []byte("second"))
		if !errors.Is(err, fs.ErrExist) {
			t.Fatalf("second create: %v, want fs.ErrExist", err)
		}
		if b, _ := os.ReadFile(p); string(b) != "first" {
			t.Errorf("an existing key was replaced: %q", b)
		}
		ents, _ := os.ReadDir(filepath.Dir(p))
		if len(ents) != 1 {
			t.Errorf("directory holds %d entries after a lost race, want 1: %v", len(ents), ents)
		}
	})
}

func TestCreateSecretFile_ExactlyOneRacerWins(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() { errs[i] = CreateSecretFile(p, []byte(strings.Repeat("k", i+1))) })
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, fs.ErrExist):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d creators won, want exactly 1", won)
	}
}

func TestEnsureSecretDir(t *testing.T) {
	withUmask(t, 0, func() {
		root := t.TempDir()
		fresh := filepath.Join(root, "a", "b")
		if err := EnsureSecretDir(fresh); err != nil {
			t.Fatal(err)
		}
		if got := perm(t, fresh); got != 0o700 {
			t.Errorf("new dir mode %#o, want 0700", got)
		}
		// An existing install's directory, created 0755 by an older api.
		old := filepath.Join(root, "old")
		if err := os.Mkdir(old, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := EnsureSecretDir(old); err != nil {
			t.Fatal(err)
		}
		if got := perm(t, old); got != 0o700 {
			t.Errorf("existing dir mode %#o, want 0700", got)
		}
		// A regular file where the directory should be is an error.
		f := filepath.Join(root, "file")
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := EnsureSecretDir(f); err == nil {
			t.Error("EnsureSecretDir on a regular file succeeded")
		}
	})
}

func TestEnsureSecretFile(t *testing.T) {
	withUmask(t, 0, func() {
		dir := t.TempDir()
		fresh := filepath.Join(dir, "fresh.db")
		if err := EnsureSecretFile(fresh); err != nil {
			t.Fatal(err)
		}
		if got := perm(t, fresh); got != 0o600 {
			t.Errorf("created mode %#o, want 0600", got)
		}
		if info, _ := os.Stat(fresh); info.Size() != 0 {
			t.Errorf("created file is %d bytes, want empty", info.Size())
		}

		existing := filepath.Join(dir, "existing.db")
		if err := os.WriteFile(existing, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := EnsureSecretFile(existing); err != nil {
			t.Fatal(err)
		}
		if got := perm(t, existing); got != 0o600 {
			t.Errorf("existing mode %#o, want 0600", got)
		}
		if b, _ := os.ReadFile(existing); string(b) != "data" {
			t.Errorf("content changed: %q", b)
		}

		victim := filepath.Join(dir, "victim")
		if err := os.WriteFile(victim, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.db")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		if err := EnsureSecretFile(link); err == nil {
			t.Error("EnsureSecretFile followed a symlink")
		}
		if got := perm(t, victim); got != 0o644 {
			t.Errorf("symlink target's mode changed to %#o", got)
		}
	})
}

func TestTightenIfExists(t *testing.T) {
	dir := t.TempDir()
	if err := TightenIfExists(filepath.Join(dir, "missing")); err != nil {
		t.Errorf("missing file: %v", err)
	}
	p := filepath.Join(dir, "x-wal")
	if err := os.WriteFile(p, []byte("w"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := TightenIfExists(p); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, p); got != 0o600 {
		t.Errorf("mode %#o, want 0600", got)
	}
}
