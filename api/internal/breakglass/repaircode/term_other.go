//go:build !linux && !darwin

package repaircode

// IsTerminal is false where no terminal check exists, so the command
// refuses: it never prints a code it cannot tell is going to a terminal.
func IsTerminal(uintptr) bool { return false }
