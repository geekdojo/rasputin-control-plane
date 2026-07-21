//go:build !linux

package bmc

import (
	"fmt"
	"runtime"
)

// The bitscope driver needs Linux termios; the BMC host is always a
// Linux node (the rack manager Pi). Selecting it elsewhere fails loudly
// at startup, same as any misconfigured backend.
func openBitScopePort(string) (busPort, error) {
	return nil, fmt.Errorf("bitscope backend requires linux (GOOS=%s)", runtime.GOOS)
}
