// Package privsock prepares the directory a root-only (or one-uid-only) Unix
// socket is bound in, and clears a socket a crashed listener left at its
// path. It was extracted from the Grafana socket's directory checks
// (obs/grafana_socket.go, geekdojo-brain#453) when the repair-code socket
// (geekdojo/geekdojo-brain#321) came to need the same checks (ARCH-DRY).
//
// It returns facts and errors and logs nothing: each caller logs what it
// found on its own logger.
package privsock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotSocket is ClearStale's refusal: something other than a socket sits
// at the path, so it is never removed.
var ErrNotSocket = errors.New("privsock: the path holds something other than a socket")

// PrepareDir creates and re-checks dir, the directory a socket is bound in.
// It is called before every bind, so a directory that was loosened, replaced
// or re-owned since the last one is caught rather than inherited.
//
// The checks, in order:
//
//   - dir is absolute;
//   - it exists (created 0700 when absent) and is a real directory, never a
//     symlink: a symlink would let anything that could create it redirect
//     the socket;
//   - it is owned by ownerUID, chowned to it when it is not;
//   - its mode is 0700, re-tightened unconditionally, since MkdirAll applies
//     the process umask. loosened reports that it was not 0700 before.
func PrepareDir(dir string, ownerUID int) (loosened bool, err error) {
	if !filepath.IsAbs(dir) {
		return false, fmt.Errorf("privsock: socket dir %q must be absolute", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("privsock: mkdir socket dir %s: %w", dir, err)
	}
	// Lstat, not Stat: Stat follows a symlink and would report the target's
	// mode and owner while the socket was bound somewhere else.
	fi, err := os.Lstat(dir)
	if err != nil {
		return false, fmt.Errorf("privsock: stat socket dir %s: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("privsock: socket dir %s is a symlink", dir)
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("privsock: socket dir %s is not a directory", dir)
	}
	uid, err := FileUID(fi)
	if err != nil {
		return false, fmt.Errorf("privsock: socket dir %s: %w", dir, err)
	}
	if uid != ownerUID {
		if err := os.Chown(dir, ownerUID, -1); err != nil {
			return false, fmt.Errorf("privsock: chown socket dir %s to uid %d: %w", dir, ownerUID, err)
		}
	}
	loosened = fi.Mode().Perm() != 0o700
	if err := os.Chmod(dir, 0o700); err != nil {
		return loosened, fmt.Errorf("privsock: chmod socket dir %s: %w", dir, err)
	}
	return loosened, nil
}

// ClearStale makes path free for a listener: nothing there is fine, a
// socket a crashed or killed listener left behind is removed, and anything
// else (a regular file, a symlink, a directory) is refused with
// ErrNotSocket and left alone. Call it only inside a directory PrepareDir
// verified, so no other uid could have put the socket there.
func ClearStale(path string) error {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("privsock: stat %s: %w", path, err)
	case fi.Mode()&os.ModeSocket == 0:
		return fmt.Errorf("%w: %s is %v", ErrNotSocket, path, fi.Mode().Type())
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("privsock: remove the leftover socket %s: %w", path, err)
	}
	return nil
}
