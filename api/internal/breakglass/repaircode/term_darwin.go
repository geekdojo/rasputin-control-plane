//go:build darwin

package repaircode

import "golang.org/x/sys/unix"

// IsTerminal reports whether fd is a terminal (TIOCGETA answers).
func IsTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TIOCGETA)
	return err == nil
}
