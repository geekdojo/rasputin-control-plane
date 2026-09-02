//go:build unix

package storage

import (
	"fmt"
	"syscall"
)

// FreeBytes reports the space available to an unprivileged writer on the
// filesystem holding dir.
//
// Bavail, not Bfree, and the difference is the point on ext4: Bfree includes
// the 5% root-reserved blocks, which the api — running as a service user —
// cannot write into. Sizing a staging guard from Bfree would let a run start
// with several hundred megabytes of headroom that do not exist for it.
//
// The uint64 conversions on both operands are not decoration either: Statfs_t
// field types differ across the unixes this builds on (Bsize is int64 on Linux
// and uint32 on Darwin), so a multiplication without them does not compile on
// both.
func FreeBytes(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", dir, err)
	}
	// The guard is not ceremony. Bsize is signed on Linux, so a bare
	// `uint64(st.Bsize)` on a negative value would report a filesystem with
	// roughly eighteen exabytes free — and the one caller is a guard whose job
	// is to REFUSE when space is short. Reporting zero free on a nonsense block
	// size fails in the direction that refuses.
	if st.Bsize <= 0 {
		return 0, nil
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
