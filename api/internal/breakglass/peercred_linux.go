//go:build linux

package breakglass

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID is the uid of the process at the other end of a Unix socket
// connection, as the kernel recorded it at connect (SO_PEERCRED). It cannot
// be forged by the peer.
func PeerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, errors.New("breakglass: the connection is not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("breakglass: the socket's descriptor: %w", err)
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, fmt.Errorf("breakglass: the socket's descriptor: %w", err)
	}
	if credErr != nil {
		return -1, fmt.Errorf("breakglass: SO_PEERCRED: %w", credErr)
	}
	return int(cred.Uid), nil
}
