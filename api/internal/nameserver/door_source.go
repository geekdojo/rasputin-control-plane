package nameserver

import "net"

// DoorSource answers one sign-in door's host with the control plane's primary
// LAN IP. It serves both doors: the app door's signin.<cid>.internal
// (geekdojo/geekdojo-brain#983), and the home door's sso-<cid>.local, an
// off-zone extra unicast name like <cid>.local (Identity 4.15). The address
// is read on every query, like SelfSource's, and so is withheld: while the
// predicate says so (for the app door, while an app holds a reserved name or
// the apps list cannot be read) the door has no record, and an in-zone name
// answers NXDOMAIN. Any other type for a served host is NODATA, never REFUSED.
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
