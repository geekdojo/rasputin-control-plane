package backupxfer

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/backupxfer/fsat"
)

// Unpacking a volume tar into a staging directory — the extraction
// discipline of design/storage.md §4.5's restore, applied to app data
// (geekdojo-brain#291 phase 2), in one place both binaries can reach.
//
// # The threat, stated the same way as everywhere else on this path
//
// This is root writing beneath a directory it created, from bytes that came
// off a disk somebody plugged in and through a process that decrypted them.
// The tar's entry names are the one string in this function that is about to
// become a path. So: every name is validated by SHAPE — relative, no empty
// component, no `.`, no `..`, no NUL — and never repaired; every directory
// and file beneath the staging root is created through fsat's fd-relative,
// O_NOFOLLOW, O_EXCL primitives, so even a name that somehow slipped past
// the shape check could only ever name a child of the fd it was handed; a
// symlink member is REFUSED, never recreated (the tar the stager writes
// archives a volume's own symlinks as symlinks, and a volume that holds one
// therefore cannot be restored by this build — the refusal names the member);
// hard links, devices, pipes and sockets are refused likewise; each entry's
// declared size is charged against the bound the manifest set for the whole
// tar; and the caller verifies the digest over the WHOLE stream against the
// manifest before it renames anything, because an unpack this function
// returned from is authentic only once that digest has agreed.
//
// # What is put back besides bytes
//
// Mode bits, ownership (uid/gid, when this process can — a root agent can, a
// dev box cannot and says so in the result) and file modification times. An
// app's data is only its data if the app can read it: a container running
// as uid 1000 cannot open a database restored as root's 0600.

// UnpackBounds is what the manifest lets the tar be.
type UnpackBounds struct {
	// MaxBytes bounds the sum of regular files' declared sizes. The tar's
	// own length from the manifest is a sufficient bound: a tar is never
	// smaller than its payload.
	MaxBytes uint64
	// MaxEntries bounds the number of members. Zero means DefaultMaxEntries.
	MaxEntries int
	// ApplyOwnership applies each entry's uid/gid. The caller sets it when
	// it runs as root; a non-root unpack skips chown and reports so.
	ApplyOwnership bool
}

// DefaultMaxEntries is the member-count bound when a caller sets none. An
// immich upload set or a Minecraft world runs to hundreds of thousands of
// files; a million is past any shipped tile's data and well short of a
// pathological archive.
const DefaultMaxEntries = 1_000_000

// UnpackResult is what one unpack amounted to.
type UnpackResult struct {
	Files int
	Dirs  int
	// Bytes is the sum of regular files' sizes as written.
	Bytes uint64
	// Digest is the SHA-256 over the whole tar stream as read, lower-case
	// hex, and StreamBytes its length — what the caller compares against the
	// manifest.
	Digest      string
	StreamBytes uint64
	// OwnershipApplied is UnpackBounds.ApplyOwnership, echoed.
	OwnershipApplied bool
}

// ErrUnpackRefused wraps every refusal of a member: the tar is not something
// this function will put into a volume. The staging directory may hold a
// partial tree; the caller removes it.
var ErrUnpackRefused = errors.New("backupxfer: the volume tar was refused")

// Unpack reads a tar from r and writes its members beneath the directory
// dst, which the caller opened (fsat.OpenRoot or fsat.MkdirOpen) and owns.
// It reads r to EOF — the digest it reports is over every byte, including
// the tar's trailing zero blocks — and returns the first refusal it meets.
func Unpack(dst *os.File, r io.Reader, b UnpackBounds) (*UnpackResult, error) {
	if dst == nil || r == nil {
		return nil, errors.New("backupxfer: Unpack needs a destination and a source")
	}
	if !fsat.Supported {
		return nil, fsat.ErrUnsupported
	}
	if b.MaxEntries <= 0 {
		b.MaxEntries = DefaultMaxEntries
	}
	digest := sha256.New()
	counter := &countingReader{r: io.TeeReader(r, digest)}
	tr := tar.NewReader(counter)
	res := &UnpackResult{OwnershipApplied: b.ApplyOwnership}
	seen := map[string]bool{}
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: reading the tar: %v", ErrUnpackRefused, err)
		}
		entries++
		if entries > b.MaxEntries {
			return nil, fmt.Errorf("%w: more than %d members; refusing to unpack more", ErrUnpackRefused, b.MaxEntries)
		}
		name := hdr.Name
		// The explicit `..`/`/` check first, in the shape the CodeQL zip-slip
		// query recognises as a sanitiser; then the full shape rule. Below
		// this point every open is fd-relative through fsat.
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
			return nil, fmt.Errorf("%w: member %q is not beneath the volume root", ErrUnpackRefused, name)
		}
		parts, err := splitVolumePath(name)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnpackRefused, err)
		}
		clean := strings.Join(parts, "/")
		if seen[clean] {
			return nil, fmt.Errorf("%w: the tar holds %q twice", ErrUnpackRefused, clean)
		}
		seen[clean] = true
		switch hdr.Typeflag {
		case tar.TypeDir:
			dir, err := openBeneathMkdir(dst, parts)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrUnpackRefused, clean, err)
			}
			derr := applyMeta(dir, hdr, b.ApplyOwnership, false)
			_ = dir.Close()
			if derr != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrUnpackRefused, clean, derr)
			}
			res.Dirs++
		case tar.TypeReg:
			if hdr.Size < 0 {
				return nil, fmt.Errorf("%w: member %q declares a negative size", ErrUnpackRefused, clean)
			}
			size := uint64(hdr.Size)
			if res.Bytes+size < res.Bytes || res.Bytes+size > b.MaxBytes {
				return nil, fmt.Errorf("%w: member %q would take the unpacked total past the %d bytes the manifest bounds", ErrUnpackRefused, clean, b.MaxBytes)
			}
			parent, err := openBeneathMkdir(dst, parts[:len(parts)-1])
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrUnpackRefused, clean, err)
			}
			werr := writeEntry(parent, parts[len(parts)-1], tr, hdr, b.ApplyOwnership)
			if parent != dst {
				_ = parent.Close()
			}
			if werr != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrUnpackRefused, clean, werr)
			}
			res.Files++
			res.Bytes += size
		case tar.TypeSymlink:
			return nil, fmt.Errorf("%w: member %q is a symlink (→ %q); a symlink is never recreated inside a restored volume, so this volume cannot be restored by this build", ErrUnpackRefused, clean, hdr.Linkname)
		default:
			return nil, fmt.Errorf("%w: member %q is not a regular file or a directory (type %q); nothing else is put back", ErrUnpackRefused, clean, string(hdr.Typeflag))
		}
	}
	// The tar reader stops at the end-of-archive marker; whatever trails it
	// (padding to a block boundary, which the writer emits) is part of the
	// stream the manifest hashed, so it is read too.
	if _, err := io.Copy(io.Discard, counter); err != nil {
		return nil, fmt.Errorf("%w: reading past the archive's end: %v", ErrUnpackRefused, err)
	}
	res.Digest = hex.EncodeToString(digest.Sum(nil))
	res.StreamBytes = counter.n
	return res, nil
}

// splitVolumePath breaks a tar member name into components, refusing
// anything that is not a plain descent: empty, absolute, a `.` or `..` or
// empty component, or a NUL. A trailing slash (a directory entry) is
// dropped. Any other byte is a legal file-name byte inside a volume — app
// data is not restricted to an identifier alphabet the way the identity set
// is — and fsat's fd-relative primitives contain any single component.
func splitVolumePath(name string) ([]string, error) {
	if name == "" {
		return nil, errors.New("empty member name")
	}
	if strings.HasPrefix(name, "/") {
		return nil, fmt.Errorf("member %q is absolute", name)
	}
	if strings.ContainsRune(name, 0) {
		return nil, fmt.Errorf("member %q contains a NUL", name)
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" {
		return nil, fmt.Errorf("member %q names no path", name)
	}
	parts := strings.Split(trimmed, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, fmt.Errorf("member %q is not a plain descent", name)
		}
	}
	return parts, nil
}

// openBeneathMkdir descends parts from root, creating each directory that
// does not exist, one no-follow component at a time, and returns the last
// one opened (root itself for an empty parts). Every directory but root is
// the caller's to close.
func openBeneathMkdir(root *os.File, parts []string) (*os.File, error) {
	dir := root
	for _, p := range parts {
		next, err := fsat.MkdirOpen(dir, p)
		if dir != root {
			_ = dir.Close()
		}
		if err != nil {
			return nil, err
		}
		dir = next
	}
	return dir, nil
}

// writeEntry creates parent/name exclusively, copies exactly the declared
// size in, refuses a short or a long member, fsyncs, and applies the
// header's mode, ownership and time.
func writeEntry(parent *os.File, name string, src io.Reader, hdr *tar.Header, chown bool) error {
	f, err := fsat.CreateExclusive(parent, name)
	if err != nil {
		return err
	}
	// One byte past the declared size, so an over-long member is detected
	// rather than silently truncated.
	n, err := io.Copy(f, io.LimitReader(src, hdr.Size+1))
	if err != nil {
		_ = f.Close()
		return err
	}
	if n != hdr.Size {
		_ = f.Close()
		return fmt.Errorf("wrote %d bytes, the header declared %d", n, hdr.Size)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := applyMeta(f, hdr, chown, true); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// countingReader counts what the tar reader consumed.
type countingReader struct {
	r io.Reader
	n uint64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n += uint64(n)
	}
	return n, err
}
