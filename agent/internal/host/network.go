package host

import (
	"net"
)

// PrimaryLanCIDR returns the CIDR of the interface the kernel would use
// to reach the public internet — the "primary LAN subnet" in everyday
// homelab terms. Returns "" if no route exists (e.g. air-gapped node).
//
// The "dial 8.8.8.8 and inspect LocalAddr" trick is the standard portable
// way to learn which interface holds the default route. We don't actually
// send any packets — net.Dial("udp", ...) only triggers a route lookup
// and binds a socket; nothing leaves the host. This makes the call cheap
// (microseconds) and safe to run at agent startup before nat/firewall
// is configured.
//
// Once the kernel tells us which IP it would source from, we walk the
// interface address list to find the IPNet that contains that IP and
// return its CIDR. The first matching IPv4 prefix wins; IPv6-only nodes
// fall back to whatever the kernel picked.
//
// This value is published once on agent registration via the node
// metadata so the controlplane UI can pre-fill the "advertise routes"
// field on the mesh enroll form. Re-detection on every restart keeps
// the value fresh as operators move nodes between subnets.
func PrimaryLanCIDR() string {
	// 8.8.8.8 is a public IP that always exists in the routing table
	// after a default route is set up — even if we can't reach it,
	// the kernel still picks a source interface.
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil {
		return ""
	}
	return findCIDR(local.IP, interfaceAddrs)
}

// findCIDR walks the result of an iface-addrs lookup and returns the
// IPNet that contains ip, formatted as a CIDR. Split out from
// PrimaryLanCIDR for testability — tests inject a stub addrLister.
func findCIDR(ip net.IP, list addrLister) string {
	addrs, err := list()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.Contains(ip) {
			return ipNet.String()
		}
	}
	return ""
}

// addrLister is a thin seam over net.InterfaceAddrs so the unit test can
// drive findCIDR with a hand-rolled subnet list. Pure net.InterfaceAddrs
// returns whatever the host has, which makes deterministic tests hard.
type addrLister func() ([]net.Addr, error)

func interfaceAddrs() ([]net.Addr, error) { return net.InterfaceAddrs() }
