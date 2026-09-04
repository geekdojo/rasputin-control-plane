//go:build darwin

package quiesce

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// exchangeDirs on the dev platform: renamex_np(2) with RENAME_SWAP, the
// same atomic exchange Linux's RENAME_EXCHANGE provides. Dev boxes only —
// the appliance is Linux — but the mock backend runs here, so the swap the
// tests exercise is a real atomic one and not a two-rename stand-in.
func exchangeDirs(live, staging string) error {
	if err := unix.RenamexNp(live, staging, unix.RENAME_SWAP); err != nil {
		return fmt.Errorf("renamex_np(RENAME_SWAP) %s <-> %s: %w", live, staging, err)
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
