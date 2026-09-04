//go:build linux

package quiesce

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// exchangeDirs swaps the two directories atomically: renameat2(2) with
// RENAME_EXCHANGE, one syscall, both names always present. This is what
// "the volume contents are replaced in one move" means on the appliance —
// there is no instant at which the volume path names nothing, and a failure
// leaves both trees where they were.
func exchangeDirs(live, staging string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, live, unix.AT_FDCWD, staging, unix.RENAME_EXCHANGE); err != nil {
		return fmt.Errorf("renameat2(RENAME_EXCHANGE) %s <-> %s: %w", live, staging, err)
	}
	return nil
}

// ownerOf reads the uid and gid off a stat.
func ownerOf(st os.FileInfo) (uid, gid int, ok bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(sys.Uid), int(sys.Gid), true
}
