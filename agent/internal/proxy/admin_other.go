//go:build !unix

package proxy

import (
	"errors"
	"io/fs"
)

// ownedByEUID has no owner to compare on a non-unix platform, so the admin
// socket is refused there rather than assumed private.
func ownedByEUID(fs.FileInfo) error {
	return errors.New("socket ownership cannot be verified on this platform")
}
