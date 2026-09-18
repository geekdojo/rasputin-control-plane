//go:build unix

package obs

import (
	"errors"
	"io/fs"
	"syscall"
)

// fileUID returns the uid that owns fi.
func fileUID(fi fs.FileInfo) (int, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cannot read owner")
	}
	return int(st.Uid), nil
}
