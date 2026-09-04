package backupxfer

import (
	"os"

	"github.com/geekdojo/rasputin-control-plane/backupxfer/fsat"
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
//
// The primitives themselves live in backupxfer/fsat, shared with the api's
// restore path (#291) — the third consumer of this discipline, and the one
// with the most to lose. These are the names this file has always used, kept
// so the ingest server reads as it did; each is the shared primitive.

func openDirNoFollow(parent *os.File, name string) (*os.File, error) {
	return fsat.OpenDir(parent, name)
}
func mkdirOpen(parent *os.File, name string) (*os.File, error) { return fsat.MkdirOpen(parent, name) }
func existsAt(parent *os.File, name string) (bool, error)      { return fsat.Exists(parent, name) }
func createExclusive(parent *os.File, name string) (*os.File, error) {
	return fsat.CreateExclusive(parent, name)
}
func unlinkAt(parent *os.File, name string) error     { return fsat.Unlink(parent, name) }
func renameAt(parent *os.File, from, to string) error { return fsat.Rename(parent, from, to) }
func openRootDir(path string) (*os.File, error)       { return fsat.OpenRoot(path) }

const ingestSupported = fsat.Supported

// errUnsupportedOS is never returned on unix; it exists so server.go can name
// it on every platform.
var errUnsupportedOS = fsat.ErrUnsupported
