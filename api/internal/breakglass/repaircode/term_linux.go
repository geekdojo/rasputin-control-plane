//go:build linux

package repaircode

import "golang.org/x/sys/unix"

// IsTerminal reports whether fd is a terminal (TCGETS answers).
func IsTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}
