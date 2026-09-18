//go:build !unix

package obs

import (
	"errors"
	"io/fs"
)

// fileUID has no owner to read on a non-unix platform. The socket is
// refused there rather than assumed private — UseGrafanaSocket already
// defaults to false off Linux, so this only fires if someone forces it on.
func fileUID(fs.FileInfo) (int, error) {
	return 0, errors.New("directory ownership cannot be verified on this platform")
}
