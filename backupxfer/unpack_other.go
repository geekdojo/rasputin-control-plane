//go:build !unix

package backupxfer

import (
	"archive/tar"
	"os"

	"github.com/geekdojo/rasputin-control-plane/backupxfer/fsat"
)

// Unpack refuses before this is reached (fsat.Supported is false); it exists
// so the package builds everywhere.
func applyMeta(*os.File, *tar.Header, bool, bool) error { return fsat.ErrUnsupported }
