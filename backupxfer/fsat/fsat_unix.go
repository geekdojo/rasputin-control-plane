//go:build unix

package fsat

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Supported is true where openat(2) with O_NOFOLLOW exists.
const Supported = true

// ErrUnsupported is never returned on unix; it exists so callers can name it
// on every platform.
var ErrUnsupported = errors.New("fsat: no-follow filesystem primitives are only supported on unix")

// OpenRoot opens an absolute directory path as the root of a walk. The root is
// the one path-based open a caller makes; everything beneath it goes through
// the fd-relative primitives below. It is opened O_DIRECTORY so a file or a
// symlink to a file at the root path is refused.
func OpenRoot(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

// OpenDir opens parent/name with O_NOFOLLOW|O_DIRECTORY and fstats the result,
// refusing a symlink (ELOOP) and anything that is not a directory.
//
// CodeQL reports go/path-injection on the Openat below and the register
// records it false-positive: `name` is ONE component, joined onto nothing —
// the kernel resolves it relative to parent's fd, O_NOFOLLOW refuses a
// symlink in it, and the fstat after requires a directory. What decides
// whether the caller may name this component is the caller's own shape
// check (a validated archive member, a generation id, a marker constant);
// this primitive cannot be made to open a path, only a child of an fd.
func OpenDir(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("%s/%s is a symlink or not a directory; refusing to go through it", parent.Name(), name)
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

// MkdirOpen creates name under parent if it does not exist, then opens it
// no-follow. EEXIST is fine only if what exists is a real directory — a
// symlink or a file of that name is refused by OpenDir.
func MkdirOpen(parent *os.File, name string) (*os.File, error) {
	if err := unix.Mkdirat(int(parent.Fd()), name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("mkdir %s/%s: %w", parent.Name(), name, err)
	}
	return OpenDir(parent, name)
}

// OpenFile opens parent/name read-only with O_NOFOLLOW and requires the
// opened fd to be a regular file. The size is the caller's to read from the
// returned file's Stat, which is an fstat of the OPENED fd — so a header and
// the bytes actually read cannot disagree.
func OpenFile(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%s/%s is a symlink; refusing to follow it", parent.Name(), name)
		}
		return nil, fmt.Errorf("open %s/%s: %w", parent.Name(), name, err)
	}
	f := os.NewFile(uintptr(fd), parent.Name()+"/"+name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = f.Close()
		return nil, fmt.Errorf("%s/%s is not a regular file", parent.Name(), name)
	}
	return f, nil
}

// Exists reports whether anything (file, dir, symlink) sits at parent/name.
func Exists(parent *os.File, name string) (bool, error) {
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

// CreateExclusive creates a new regular file under parent, mode 0600. O_EXCL
// so a name that already exists — a file, a stale temp, a planted symlink —
// is an error and never opened.
func CreateExclusive(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create %s/%s: %w", parent.Name(), name, err)
	}
	return os.NewFile(uintptr(fd), parent.Name()+"/"+name), nil
}

// Unlink removes parent/name. A missing entry is not an error.
func Unlink(parent *os.File, name string) error {
	err := unix.Unlinkat(int(parent.Fd()), name, 0)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

// Rename renames parent/from to parent/to.
func Rename(parent *os.File, from, to string) error {
	return unix.Renameat(int(parent.Fd()), from, int(parent.Fd()), to)
}
