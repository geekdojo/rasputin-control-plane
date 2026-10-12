//go:build unix

package storeaudit

import (
	"io/fs"
	"syscall"
)

// inodeOf is the inode number behind fi, and false when fi carries none.
func inodeOf(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Ino), true //nolint:unconvert // the field type differs across unixes
}
