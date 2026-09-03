//go:build unix

package backupxfer

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// The no-symlink filesystem primitives the ingest server writes through —
// the same discipline as the agent's quiesce walk, from the other side.
//
// The generation directory is on a disk the operator owns and every member
// beneath it was written by a node that presented a credential. Nothing in
// that directory is trusted to be what it was a moment ago: a member name is
// validated by shape, and every component from the generation directory down
// is opened with openat(2) and O_NOFOLLOW relative to the already-opened
// parent, then fstat'd and required to be a directory. A symlink anywhere in
// the path is ELOOP, not a redirect. There is no path-based open below the
// generations directory in this package.

func openDirNoFollow(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("%s/%s is a symlink or not a directory; refusing to write through it", parent.Name(), name)
		}
		return nil, fmt.Errorf("open %s/%s: %w", parent.Name(), name, err)
	}
	f := os.NewFile(uintptr(fd), parent.Name()+"/"+name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = f.Close()
		return nil, fmt.Errorf("%s/%s is not a directory", parent.Name(), name)
	}
	return f, nil
}

// mkdirOpen creates name under parent if it does not exist, then opens it
// no-follow. EEXIST is fine only if what exists is a real directory.
func mkdirOpen(parent *os.File, name string) (*os.File, error) {
	if err := unix.Mkdirat(int(parent.Fd()), name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("mkdir %s/%s: %w", parent.Name(), name, err)
	}
	return openDirNoFollow(parent, name)
}

// existsAt reports whether anything (file, dir, symlink) sits at parent/name.
func existsAt(parent *os.File, name string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return false, err
}

// createExclusive creates a new regular file under parent. O_EXCL so a name
// that already exists — a member, a stale temp, a planted symlink — is an
// error and never opened.
func createExclusive(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create %s/%s: %w", parent.Name(), name, err)
	}
	return os.NewFile(uintptr(fd), parent.Name()+"/"+name), nil
}

func unlinkAt(parent *os.File, name string) error {
	err := unix.Unlinkat(int(parent.Fd()), name, 0)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func renameAt(parent *os.File, from, to string) error {
	return unix.Renameat(int(parent.Fd()), from, int(parent.Fd()), to)
}

// openRootDir opens an absolute directory path as the root of a walk. The
// root is the generations directory under the mount the co-located agent
// reported; everything beneath it goes through the no-follow primitives.
func openRootDir(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

const ingestSupported = true

// errUnsupportedOS is never returned on unix; it exists so server.go can name
// it on every platform.
var errUnsupportedOS = errors.New("backupxfer: ingest is only supported on unix")
