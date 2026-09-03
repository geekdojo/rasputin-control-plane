//go:build unix

package quiesce

import (
	"archive/tar"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

// The no-symlink filesystem primitives the walk is built on. See the file
// comment in tarwalk.go for what they defend against; what they are is
// openat(2) with O_NOFOLLOW, one component at a time, relative to a
// directory fd that was itself opened the same way — and fstat(2) on every
// fd before it is trusted to be what the walk said it was.

// errSkipDir is what a visit function returns to not descend a directory.
var errSkipDir = errors.New("skip this directory")

// entryStat is one lstat/fstat, with the questions the walk asks of it.
type entryStat struct{ st unix.Stat_t }

func (e *entryStat) kind() uint32     { return uint32(e.st.Mode) & unix.S_IFMT }
func (e *entryStat) isDir() bool      { return e.kind() == unix.S_IFDIR }
func (e *entryStat) isRegular() bool  { return e.kind() == unix.S_IFREG }
func (e *entryStat) isSymlink() bool  { return e.kind() == unix.S_IFLNK }
func (e *entryStat) size() uint64     { return byteCount(e.st.Size) }
func (e *entryStat) sizeInt64() int64 { return e.st.Size }

// header builds the tar header for this entry. Mode bits, owner and mtime
// from the stat; Size is set by the caller from the OPENED fd for regular
// files, and is zero for everything else.
func (e *entryStat) header(name string, typeflag byte, link string) *tar.Header {
	return &tar.Header{
		Name:     name,
		Typeflag: typeflag,
		Linkname: link,
		Mode:     int64(uint32(e.st.Mode) & 0o7777),
		Uid:      int(e.st.Uid),
		Gid:      int(e.st.Gid),
		ModTime:  time.Unix(statMtime(&e.st)).UTC(),
		Format:   tar.FormatPAX,
	}
}

// openRoot opens the volume root as a directory. The root is the runtime's
// answer (docker volume inspect, or the mock's own directory) and is trusted
// as a starting point; everything beneath it is not.
func openRoot(root string) (*os.File, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open volume root %s: %w", root, err)
	}
	return os.NewFile(uintptr(fd), root), nil
}

// lstatAt stats dir/name without following a final symlink.
func lstatAt(dir *os.File, name string) (*entryStat, error) {
	var e entryStat
	if err := unix.Fstatat(int(dir.Fd()), name, &e.st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, fmt.Errorf("stat %s/%s: %w", dir.Name(), name, err)
	}
	return &e, nil
}

// openAt opens dir/name with O_NOFOLLOW and fstats the result. A symlink in
// the final component is ELOOP; the parents were opened the same way, so
// there is no symlink anywhere in the resolved path.
func openAt(dir *os.File, name string, flags int) (*os.File, *entryStat, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, nil, fmt.Errorf("%w: %s/%s is a symlink or is no longer what the walk saw (%v)", ErrFileChanged, dir.Name(), name, err)
		}
		return nil, nil, fmt.Errorf("open %s/%s: %w", dir.Name(), name, err)
	}
	f := os.NewFile(uintptr(fd), dir.Name()+"/"+name)
	var e entryStat
	if err := unix.Fstat(fd, &e.st); err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("fstat %s/%s: %w", dir.Name(), name, err)
	}
	return f, &e, nil
}

// openFileAt opens a regular file beneath dir, refusing anything else.
func openFileAt(dir *os.File, name string) (*os.File, *entryStat, error) {
	f, e, err := openAt(dir, name, 0)
	if err != nil {
		return nil, nil, err
	}
	if !e.isRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%w: %s/%s is not a regular file", ErrFileChanged, dir.Name(), name)
	}
	return f, e, nil
}

// openDirAt opens a directory beneath dir, refusing anything else.
func openDirAt(dir *os.File, name string) (*os.File, error) {
	f, e, err := openAt(dir, name, unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	if !e.isDir() {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s/%s is not a directory", ErrFileChanged, dir.Name(), name)
	}
	return f, nil
}

// openBeneath opens the regular file at a slash-separated relative path
// beneath root, descending one no-follow component at a time.
func openBeneath(root *os.File, rel string) (*os.File, *entryStat, error) {
	parts, err := splitRel(rel)
	if err != nil {
		return nil, nil, err
	}
	dir := root
	for _, p := range parts[:len(parts)-1] {
		next, err := openDirAt(dir, p)
		if dir != root {
			_ = dir.Close()
		}
		if err != nil {
			return nil, nil, err
		}
		dir = next
	}
	f, e, err := openFileAt(dir, parts[len(parts)-1])
	if dir != root {
		_ = dir.Close()
	}
	return f, e, err
}

// readlinkAt reads the target of the symlink dir/name.
func readlinkAt(dir *os.File, name string) (string, error) {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(int(dir.Fd()), name, buf)
	if err != nil {
		return "", fmt.Errorf("readlink %s/%s: %w", dir.Name(), name, err)
	}
	return string(buf[:n]), nil
}

// walk visits every entry beneath dir, depth first, names sorted, calling
// visit(parentDir, name, rel, lstat) for each. A directory is entered through
// its own no-follow open; returning errSkipDir from visit does not descend.
func walk(dir *os.File, rel string, visit func(dir *os.File, name, rel string, st *entryStat) error) error {
	ents, err := dir.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("read dir %s: %w", dir.Name(), err)
	}
	// File.ReadDir returns directory order, unlike os.ReadDir; sorted so the
	// archive is deterministic and the walk order is something a test can
	// reason about.
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	for _, ent := range ents {
		name := ent.Name()
		childRel := relJoin(rel, name)
		st, err := lstatAt(dir, name)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue // vanished under a live copy; not in the archive, not an error
			}
			return err
		}
		err = visit(dir, name, childRel, st)
		if errors.Is(err, errSkipDir) {
			continue
		}
		if err != nil {
			return err
		}
		if st.isDir() {
			sub, err := openDirAt(dir, name)
			if err != nil {
				return err
			}
			err = walk(sub, childRel, visit)
			_ = sub.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}
