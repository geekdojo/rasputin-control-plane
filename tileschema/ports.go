package tileschema

import (
	"net/netip"
	"strconv"
	"strings"
)

// ParsePortEntry reads one compose `ports:` entry into the host side of its
// publish: the host address it binds (empty for every interface) and the host
// port. It is the grammar ValidateWebPortBind's facts are read with, shared by
// the catalog publisher and the control plane (geekdojo/geekdojo-brain#1091),
// so both judge a web port by the same reading.
//
// It accepts exactly two short-syntax forms, "HOST:CONTAINER" and
// "IP:HOST:CONTAINER" with an IPv4 address, and reports false for everything
// else: a bare container port (Docker picks the host port), a /protocol
// suffix, a bracketed IPv6 host, a range, the long mapping syntax, a
// non-string scalar and a ${VAR}. What a caller does with an entry it cannot
// read is the caller's policy.
func ParsePortEntry(e any) (PortBinding, bool) {
	s, ok := e.(string)
	if !ok {
		return PortBinding{}, false
	}
	parts := strings.Split(s, ":")
	var hostIP string
	switch len(parts) {
	case 2:
	case 3:
		addr, err := netip.ParseAddr(parts[0])
		if err != nil || !addr.Is4() {
			return PortBinding{}, false
		}
		hostIP = parts[0]
		parts = parts[1:]
	default:
		return PortBinding{}, false
	}
	published, ok := portNumber(parts[0])
	if !ok {
		return PortBinding{}, false
	}
	if _, ok := portNumber(parts[1]); !ok {
		return PortBinding{}, false
	}
	return PortBinding{HostIP: hostIP, Published: published}, true
}

// portNumber parses a decimal port in 1-65535, and nothing else: no sign, no
// range, no suffix.
func portNumber(s string) (int, bool) {
	if s == "" || strings.TrimLeft(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}
