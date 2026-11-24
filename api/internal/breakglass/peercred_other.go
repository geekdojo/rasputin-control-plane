//go:build !linux

package breakglass

import (
	"errors"
	"net"
)

// PeerUID cannot read a peer's uid off Linux, so every connection is
// refused; the socket is not served there at all (Socket.Start).
func PeerUID(net.Conn) (int, error) {
	return -1, errors.New("breakglass: a socket peer's uid can be read only on Linux")
}
