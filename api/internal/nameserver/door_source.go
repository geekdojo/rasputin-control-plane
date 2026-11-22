package nameserver

import "net"

// DoorSource answers one sign-in door's host, signin.<cid>.internal, with the
// control plane's primary LAN IP (geekdojo/geekdojo-brain#983). The address is
// read on every query, like SelfSource's, and so is withheld: while an app
// holds a reserved name, or the apps list cannot be read, the door has no
// record and the in-zone name answers NXDOMAIN.
type DoorSource struct {
	host     string
	ipFn     func() net.IP
	withheld func() bool
}

// NewDoorSource builds the door's Source. host is canonicalized. withheld is
// main's one withheld predicate; a nil predicate withholds (fail closed).
func NewDoorSource(host string, ipFn func() net.IP, withheld func() bool) *DoorSource {
	return &DoorSource{host: canonical(host), ipFn: ipFn, withheld: withheld}
}

// Records implements [Source].
func (d *DoorSource) Records() map[string]net.IP {
	if d.host == "" || d.withheld == nil || d.withheld() {
		return nil
	}
	ip := usableIPv4(d.ipFn())
	if ip == nil {
		return nil
	}
	return map[string]net.IP{d.host: ip}
}
