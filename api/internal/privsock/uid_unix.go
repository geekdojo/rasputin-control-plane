//go:build unix

package privsock

import (
	"errors"
	"io/fs"
	"syscall"
)

// FileUID returns the uid that owns fi.
func FileUID(fi fs.FileInfo) (int, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cannot read owner")
	}
	return int(st.Uid), nil
}
