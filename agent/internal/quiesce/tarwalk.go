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
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// The copy itself: a volume directory walked into one uncompressed tar under
// the staging root, with a few substitutions and exclusions the sqlite driver
// needs. Uncompressed for the same reason the api's identity archive is —
// the seal is the CPU pass that matters, and it happens on the controlplane.

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

// ErrFileChanged is a file that changed size between being sized and being
// copied. On a live copy that is the window itself showing up; the run fails
// rather than writing a tar whose member does not match its header.
var ErrFileChanged = errors.New("quiesce: a file changed size while it was being copied")

// plan is what a first pass over the volume learned.
type plan struct {
	bytes   uint64
	files   int
	dbs     []string // relative, slash-separated, sorted by the walk
	dbBytes uint64
}

// measure walks the volume once for its size, and — when asked — for the
// SQLite databases in it, identified by header and never by name. Reading
// sixteen bytes of every regular file is cheap next to copying all of them.
func measure(root string, findDBs bool) (plan, error) {
	var p plan
	err := filepath.WalkDir(root, func(abs string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := relSlash(root, abs)
		if rerr != nil {
			return rerr
		}
		if d.IsDir() {
			if rel == scratchDirName {
				return fs.SkipDir
			}
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || !info.Mode().IsRegular() {
			return nil //nolint:nilerr // sockets, devices and pipes are skipped, not counted
		}
		p.files++
		p.bytes += byteCount(info.Size())
		if findDBs && isSQLite(abs) {
			p.dbs = append(p.dbs, rel)
			p.dbBytes += byteCount(info.Size())
		}
		return nil
	})
	return p, err
}

func isSQLite(abs string) bool {
	f, err := os.Open(abs)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var head [len(sqliteMagic)]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return false
	}
	return bytes.Equal(head[:], []byte(sqliteMagic))
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
// absolute file to read INSTEAD of it (a snapshot for a database); skip is a
// set of relative paths to leave out. afterFile, when set, is called after
// each regular file — the test seam that lets a copy be killed mid-way.
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

	h := sha256.New()
	cw := &countingWriter{w: io.MultiWriter(f, h)}
	tw := tar.NewWriter(cw)
	var res tarResult

	err = filepath.WalkDir(root, func(abs string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, rerr := relSlash(root, abs)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() && rel == scratchDirName {
			return fs.SkipDir
		}
		if skip[rel] {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		switch {
		case info.IsDir():
			return writeHeader(tw, info, rel+"/", "")
		case info.Mode()&fs.ModeSymlink != 0:
			target, lerr := os.Readlink(abs)
			if lerr != nil {
				return lerr
			}
			return writeHeader(tw, info, rel, target)
		case !info.Mode().IsRegular():
			// A socket, a device, a pipe: not state a restore can put back.
			// Skipped, and the count in the ack says how many regular files
			// were taken, so what is absent is at least sized.
			return nil
		}
		src := abs
		if sub, ok := subst[rel]; ok {
			src = sub
			sinfo, serr := os.Stat(sub)
			if serr != nil {
				return fmt.Errorf("snapshot for %s: %w", rel, serr)
			}
			info = sizedAs{FileInfo: info, size: sinfo.Size()}
		}
		if err := writeFile(tw, info, rel, src); err != nil {
			return err
		}
		res.files++
		res.plain += byteCount(info.Size())
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

// sizedAs reports a substitute's size under the original's name, mode and
// times — the snapshot is written into the tar where the live database was.
type sizedAs struct {
	fs.FileInfo
	size int64
}

func (s sizedAs) Size() int64 { return s.size }

func writeHeader(tw *tar.Writer, info fs.FileInfo, name, link string) error {
	hdr, err := tar.FileInfoHeader(info, link)
	if err != nil {
		return err
	}
	hdr.Name = name
	hdr.Format = tar.FormatPAX
	return tw.WriteHeader(hdr)
}

// writeFile copies exactly info.Size() bytes of src in under name. A file
// that comes up short changed underneath the copy; a file that grew is
// captured to the size in its header, which is the live-copy window doing
// what the ack says it does.
func writeFile(tw *tar.Writer, info fs.FileInfo, name, src string) error {
	if err := writeHeader(tw, info, name, ""); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	n, err := io.CopyN(tw, f, info.Size())
	if errors.Is(err, io.EOF) || (err == nil && n != info.Size()) {
		return fmt.Errorf("%w: %s (%d of %d bytes)", ErrFileChanged, name, n, info.Size())
	}
	return err
}

// relSlash is the walk's path relative to the root, slash-separated, as the
// tar names it.
func relSlash(root, abs string) (string, error) {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
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
