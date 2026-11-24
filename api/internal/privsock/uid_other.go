//go:build !unix

package privsock

import (
	"errors"
	"io/fs"
)

// FileUID has no owner to read on a non-unix platform. A socket directory is
// refused there rather than assumed private.
func FileUID(fs.FileInfo) (int, error) {
	return 0, errors.New("directory ownership cannot be verified on this platform")
}
