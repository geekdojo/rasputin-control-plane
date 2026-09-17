//go:build unix

package proxy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// ownedByEUID reports an error unless fi is owned by this process's effective
// uid.
func ownedByEUID(fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read owner")
	}
	if euid := os.Geteuid(); int64(st.Uid) != int64(euid) {
		return fmt.Errorf("owned by uid %d, not this process (uid %d)", st.Uid, euid)
	}
	return nil
}
