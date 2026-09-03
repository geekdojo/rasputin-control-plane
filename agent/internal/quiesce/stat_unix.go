//go:build unix

package quiesce

import "golang.org/x/sys/unix"

// statMtime reads the modification time out of a Stat_t. The field's
// integer widths differ across GOOS/GOARCH; the casts normalise them.
func statMtime(st *unix.Stat_t) (sec, nsec int64) {
	return int64(st.Mtim.Sec), int64(st.Mtim.Nsec) //nolint:unconvert // widths differ per platform
}
