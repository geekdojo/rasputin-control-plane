//go:build !linux

package signinname

import "errors"

// GroupOpener returns the socket opener. The mDNS socket is opened by hand
// with Linux socket options, so on any other OS (a developer's Mac) every
// open fails, and the responder reports it as an open failure.
func GroupOpener(Clock) func(ifindex int) (Conn, error) {
	return func(int) (Conn, error) {
		return nil, errors.New("signinname: the mDNS socket is built only on Linux")
	}
}
