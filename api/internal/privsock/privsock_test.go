package privsock

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ps")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// PrepareDir makes the directory 0700, reports a loosened one, and refuses
// a relative path, a symlink and a file.
func TestPrepareDir(t *testing.T) {
	dir := filepath.Join(shortDir(t), "sock")
	if loosened, err := PrepareDir(dir, os.Geteuid()); err != nil || loosened {
		t.Fatalf("fresh: loosened %v, %v", loosened, err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if loosened, err := PrepareDir(dir, os.Geteuid()); err != nil || !loosened {
		t.Fatalf("loosened: %v, %v", loosened, err)
	}
	if fi, _ := os.Lstat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if _, err := PrepareDir("rel", os.Geteuid()); err == nil {
		t.Error("a relative dir passed")
	}
	link := filepath.Join(shortDir(t), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareDir(link, os.Geteuid()); err == nil {
		t.Error("a symlink passed")
	}
	file := filepath.Join(shortDir(t), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareDir(file, os.Geteuid()); err == nil {
		t.Error("a file passed")
	}
}

// ClearStale removes a leftover socket, accepts nothing, and refuses and
// keeps anything else.
func TestClearStale(t *testing.T) {
	dir := shortDir(t)
	if err := ClearStale(filepath.Join(dir, "none")); err != nil {
		t.Fatalf("nothing there: %v", err)
	}
	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	if err := ClearStale(sock); err != nil {
		t.Fatalf("leftover socket: %v", err)
	}
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket is still there: %v", err)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ClearStale(file); !errors.Is(err, ErrNotSocket) {
		t.Errorf("a file: %v", err)
	}
	if _, err := os.Lstat(file); err != nil {
		t.Errorf("the file was removed: %v", err)
	}
}
