package quiesce

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// The copy itself: a volume directory walked into one uncompressed tar under
// the staging root, with a few substitutions and exclusions the sqlite driver
// needs. Uncompressed for the same reason the api's identity archive is —
// the seal is the CPU pass that matters, and it happens on the controlplane.
//
// # Nothing here ever follows a symlink, and that is the security property
//
// This process is root on the host, and the directory it reads is the
// host-side mountpoint of a volume whose CONTAINER MAY STILL BE RUNNING —
// for `sqlite` and `none` the app is up for the whole copy, and even under
// `stop` the volume holds whatever the app left there. A compromised app
// can plant a symlink in its own volume at any moment: replace a file the
// walk has classified but not yet opened with a link to /etc/shadow, another
// app's volume or the mesh CA key, or swap a directory for a link to /, or
// plant one in the scratch directory the sqlite snapshot is written to,
// which the container controls outright. A path-based os.Open follows every
// one of those, and the host file lands in the archive under an innocent
// name.
//
// So the walk is DIRECTORY-FD RELATIVE, one component at a time: every
// directory is opened with openat(dirfd, name, O_NOFOLLOW|O_DIRECTORY) and
// every file with openat(dirfd, name, O_NOFOLLOW), each relative to the
// already-opened parent, and every opened fd is fstat'd and required to be
// the kind of thing the walk said it was before a byte is read. A symlink
// anywhere in a path is ELOOP, not a redirect; a file swapped for something
// else between stat and open is ErrFileChanged. Sizes come from the fstat of
// the OPENED fd, so the header and the bytes copied cannot disagree. The
// snapshot substitute is opened the same way, beneath the same root. There
// is no path-based open of volume content in this file — see walk_unix.go
// for the primitives.

// scratchDirName is the directory the sqlite driver asks the container to
// write snapshots into, INSIDE the volume, because that is the one place a
// process in the container and this process on the host can both reach. It
// is never captured, always removed afterwards, and removed at the start of
// the next run in case the last one died.
const scratchDirName = ".rasputin-quiesce"

// sqliteMagic is the first sixteen bytes of every SQLite 3 database file.
const sqliteMagic = "SQLite format 3\x00"

// sqliteSidecars are the files SQLite keeps beside a database that a
// self-contained snapshot makes redundant — and that would be incoherent with
// it if they were captured alongside.
var sqliteSidecars = []string{"-wal", "-shm", "-journal"}

// ErrFileChanged is a file that changed under the copy: a different size
// than the header was written with, or a different kind of object than the
// walk classified. On a live copy the first is the window itself showing up;
// the second is what a planted symlink or a swapped directory looks like
// from here. Either way the run fails rather than writing a tar whose member
// does not match its header — or one holding bytes from outside the volume.
var ErrFileChanged = errors.New("quiesce: a file changed while it was being copied")

// plan is what a first pass over the volume learned.
type plan struct {
	bytes   uint64
	files   int
	dbs     []string // relative, slash-separated, in walk order
	dbBytes uint64
}

// measure walks the volume once for its size, and — when asked — for the
// SQLite databases in it, identified by header and never by name. Reading
// sixteen bytes of every regular file is cheap next to copying all of them.
func measure(root string, findDBs bool) (plan, error) {
	var p plan
	rootDir, err := openRoot(root)
	if err != nil {
		return p, err
	}
	defer func() { _ = rootDir.Close() }()
	err = walk(rootDir, "", func(dir *os.File, name, rel string, st *entryStat) error {
		if st.isDir() {
			if rel == scratchDirName {
				return errSkipDir
			}
			return nil
		}
		if !st.isRegular() {
			return nil
		}
		p.files++
		p.bytes += st.size()
		if findDBs {
			isDB, err := sniffSQLite(dir, name)
			if err != nil {
				return err
			}
			if isDB {
				p.dbs = append(p.dbs, rel)
				p.dbBytes += st.size()
			}
		}
		return nil
	})
	return p, err
}

// sniffSQLite reads the header of dir/name through a no-follow open.
func sniffSQLite(dir *os.File, name string) (bool, error) {
	f, _, err := openFileAt(dir, name)
	if err != nil {
		if errors.Is(err, ErrFileChanged) {
			// Not a regular file any more; not a database either way.
			return false, nil
		}
		return false, err
	}
	defer func() { _ = f.Close() }()
	var head [len(sqliteMagic)]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return false, nil //nolint:nilerr // shorter than a header is not a database
	}
	return bytes.Equal(head[:], []byte(sqliteMagic)), nil
}

// sidecarsOf lists the relative paths of a database's -wal/-shm/-journal.
func sidecarsOf(dbRel string) []string {
	out := make([]string, 0, len(sqliteSidecars))
	for _, s := range sqliteSidecars {
		out = append(out, dbRel+s)
	}
	return out
}

// tarResult is what one written archive amounts to.
type tarResult struct {
	size   uint64
	digest string
	files  int
	plain  uint64
}

// countingWriter counts the bytes that reach the file.
type countingWriter struct {
	w io.Writer
	n uint64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += byteCount(int64(n))
	return n, err
}

// writeTar walks root into a tar at dst, written through a dot-prefixed
// partial name and renamed into place. subst maps a relative path to the
// relative path (beneath the same root) to read INSTEAD of it — a snapshot
// for a database; skip is a set of relative paths to leave out. afterFile,
// when set, is called after each regular file — the test seam that lets a
// copy be killed mid-way.
func writeTar(ctx context.Context, root, dst string, subst map[string]string, skip map[string]bool, afterFile func(rel string) error) (tarResult, error) {
	partial := filepath.Join(filepath.Dir(dst), ".partial-"+filepath.Base(dst))
	f, err := os.OpenFile(partial, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return tarResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = os.Remove(partial)
		}
	}()
	rootDir, err := openRoot(root)
	if err != nil {
		return tarResult{}, err
	}
	defer func() { _ = rootDir.Close() }()

	h := sha256.New()
	cw := &countingWriter{w: io.MultiWriter(f, h)}
	tw := tar.NewWriter(cw)
	var res tarResult

	err = walk(rootDir, "", func(dir *os.File, name, rel string, st *entryStat) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if st.isDir() && rel == scratchDirName {
			return errSkipDir
		}
		if skip[rel] {
			return nil
		}
		switch {
		case st.isDir():
			return tw.WriteHeader(st.header(rel+"/", tar.TypeDir, ""))
		case st.isSymlink():
			target, err := readlinkAt(dir, name)
			if err != nil {
				return err
			}
			return tw.WriteHeader(st.header(rel, tar.TypeSymlink, target))
		case !st.isRegular():
			// A socket, a device, a pipe: not state a restore can put back.
			// Skipped, and the count in the ack says how many regular files
			// were taken, so what is absent is at least sized.
			return nil
		}
		var src *os.File
		var opened *entryStat
		if sub, ok := subst[rel]; ok {
			// The snapshot lives beneath the same root, in a directory the
			// container wrote. Opened component by component with no
			// symlink following, like everything else.
			src, opened, err = openBeneath(rootDir, sub)
			if err != nil {
				return fmt.Errorf("snapshot for %s: %w", rel, err)
			}
		} else {
			src, opened, err = openFileAt(dir, name)
			if err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
		}
		werr := writeFile(tw, opened, st, rel, src)
		_ = src.Close()
		if werr != nil {
			return werr
		}
		res.files++
		res.plain += opened.size()
		if afterFile != nil {
			return afterFile(rel)
		}
		return nil
	})
	if err != nil {
		return tarResult{}, err
	}
	if err := tw.Close(); err != nil {
		return tarResult{}, err
	}
	if err := f.Sync(); err != nil {
		return tarResult{}, err
	}
	if err := f.Close(); err != nil {
		return tarResult{}, err
	}
	if err := os.Rename(partial, dst); err != nil {
		return tarResult{}, err
	}
	committed = true
	if err := syncDir(filepath.Dir(dst)); err != nil {
		return tarResult{}, err
	}
	res.size = cw.n
	res.digest = hex.EncodeToString(h.Sum(nil))
	return res, nil
}

// writeFile copies exactly the OPENED file's size in under name, with the
// walked entry's mode and times. The size is from the fstat of the fd the
// bytes come from, so header and content cannot disagree by construction; a
// file that comes up short changed underneath the copy, and a file that grew
// is captured to its header size, which is the live-copy window doing what
// the ack says it does.
func writeFile(tw *tar.Writer, opened, walked *entryStat, name string, src io.Reader) error {
	hdr := walked.header(name, tar.TypeReg, "")
	hdr.Size = opened.sizeInt64()
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	n, err := io.CopyN(tw, src, hdr.Size)
	if errors.Is(err, io.EOF) || (err == nil && n != hdr.Size) {
		return fmt.Errorf("%w: %s shrank (%d of %d bytes)", ErrFileChanged, name, n, hdr.Size)
	}
	return err
}

// relJoin is the walk's relative path for a child, slash-separated, as the
// tar names it.
func relJoin(rel, name string) string {
	if rel == "" {
		return name
	}
	return rel + "/" + name
}

func syncDir(p string) error {
	d, err := os.Open(p)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// byteCount narrows a signed byte count to uint64, clamping a negative to
// zero — the direction the free-space guard fails safely in.
func byteCount(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// scratchRel is where a database's snapshot goes, relative to the volume
// root, mirroring the database's own path under the scratch dir.
func scratchRel(dbRel string) string { return path.Join(scratchDirName, dbRel) }

// splitRel breaks a slash-separated relative path into components, refusing
// anything that is not a plain descent — `.`, `..`, an absolute path or an
// empty component would let a caller name something outside the root.
func splitRel(rel string) ([]string, error) {
	if rel == "" || strings.HasPrefix(rel, "/") {
		return nil, fmt.Errorf("%w: %q is not a relative path", ErrFileChanged, rel)
	}
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, fmt.Errorf("%w: %q is not a plain descent", ErrFileChanged, rel)
		}
	}
	return parts, nil
}
