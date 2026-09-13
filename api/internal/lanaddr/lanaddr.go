// Package lanaddr tracks the control plane's own LAN IPv4 address as the kernel
// reports it, and tells the parts of the api that derive from it when it changes.
//
// It exists because the api used to learn its address with a default-route
// lookup (dial 8.8.8.8, read the socket's source address). That answers "which
// address would reach the internet", which is the wrong question twice over
// (geekdojo/geekdojo-brain#431):
//
//   - On a LAN with no DHCP the control plane holds only rasputin-os's fallback
//     192.168.1.2/24, which is written with deliberately NO Gateway= (the .1
//     firewall it would point at does not exist yet). No default route means the
//     lookup fails, so the api concluded it had no LAN address at all while it
//     plainly held one. That is the no-DHCP bootstrap case the fallback exists
//     for, and the nameserver never started in it.
//   - The answer was asked for once, at start, by the things that mattered. A
//     lease arriving later, or a new lease on a new address, changed nothing
//     until the api restarted.
//
// So the rule here is a fact about the node, not about the routing table: the
// set of IPv4 addresses the kernel says the node holds, filtered by [Usable] and
// ordered by [Select]. Changes arrive as kernel address events (RTM_NEWADDR /
// RTM_DELADDR on Linux), never by re-checking on a timer — a state change is
// triggered by a checkable fact, and the kernel announcing an address is one.
package lanaddr

import (
	"bytes"
	"net"
	"slices"
	"strings"
)

// Addr is one IPv4 address the kernel reports on an interface.
type Addr struct {
	// IP is the address itself (4-byte form).
	IP net.IP
	// Link is the interface name, e.g. "end0" or "tailscale0".
	Link string
	// Index is the kernel interface index. It is the tie-break between links,
	// and what groups an interface's addresses in [Snapshot.LinkIPs].
	Index int
	// Loopback is the interface's IFF_LOOPBACK flag.
	Loopback bool
	// Dynamic is true when the address has a finite lifetime — the kernel's
	// "dynamic" as `ip addr` prints it (IFA_F_PERMANENT clear). systemd-networkd
	// installs a DHCPv4 lease's address with the lease lifetime, so a DHCP
	// address is dynamic; a static Address= (rasputin-os's 192.168.1.2 fallback
	// drop-in) is permanent.
	Dynamic bool
}

// excludedLinkPrefixes are interfaces whose addresses are never the control
// plane's LAN address, whatever the address is:
//
//   - tailscale*: the tailnet (100.64/10). Its names are MagicDNS's job, and a
//     LAN client cannot route to it (ADR-0004 §3).
//   - docker*, br-*: Docker's default and compose bridges — the mesh, obs and
//     app containers. Addresses on them exist only inside this host.
//   - veth*: the host side of a container's link.
//
// It mirrors what rasputin-os's 20-wired.network matches from the other side
// (Name=en* eth*, with docker0 / br-* / veth* called out as never matching), so
// the api and networkd agree on which links are the LAN.
var excludedLinkPrefixes = []string{"tailscale", "docker", "br-", "veth"}

// Usable reports whether a may be the control plane's LAN address. The rules:
//
//   - IPv4 only (Rasputin is IPv4-only, LOCKED decision #9).
//   - Not loopback — neither a 127/8 address nor any address on a loopback
//     interface.
//   - Not link-local 169.254/16. networkd's IPv4LL gives the node one while it
//     has no lease (LinkLocalAddressing=ipv4), and on the #427 bench run it sat
//     beside the 192.168.1.2 fallback. It is not a LAN address anyone should be
//     pinned to: it is not stable across reboots and it vanishes the moment a
//     lease arrives.
//   - Not unspecified, multicast or broadcast.
//   - Not on a tailnet, Docker bridge or veth interface ([excludedLinkPrefixes]).
//
// The 192.168.1.2 fallback passes: it is a static address on the wired link,
// which is exactly what it is for.
func Usable(a Addr) bool {
	ip4 := a.IP.To4()
	if ip4 == nil {
		return false
	}
	if a.Loopback || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() ||
		ip4.IsUnspecified() || ip4.IsMulticast() || ip4.Equal(net.IPv4bcast) {
		return false
	}
	if a.Link == "lo" {
		return false
	}
	for _, p := range excludedLinkPrefixes {
		if strings.HasPrefix(a.Link, p) {
			return false
		}
	}
	return true
}

// Snapshot is the node's usable LAN addresses at one moment, in primary order.
// The zero Snapshot means "no usable LAN IPv4".
type Snapshot struct {
	// Usable holds every [Usable] address, ordered so Usable[0] is the primary.
	Usable []Addr
}

// Select filters addrs down to the usable ones and orders them. The first is
// the primary — the one address the control plane reports as itself. The order
// is total, so the same address set always yields the same primary:
//
//  1. A dynamic (DHCP) address before a permanent (static) one. When both the
//     fallback 192.168.1.2 and a lease are present — the few milliseconds before
//     rasputin-os#59's release unit removes the fallback — the lease is the
//     address the LAN's DHCP server and DNS know, and the one that stays.
//  2. The lower interface index, so a multi-NIC box settles on one link.
//  3. The numerically lower address.
func Select(addrs []Addr) Snapshot {
	var out []Addr
	for _, a := range addrs {
		if !Usable(a) {
			continue
		}
		a.IP = a.IP.To4()
		out = append(out, a)
	}
	slices.SortFunc(out, func(x, y Addr) int {
		if x.Dynamic != y.Dynamic {
			if x.Dynamic {
				return -1
			}
			return 1
		}
		if x.Index != y.Index {
			if x.Index < y.Index {
				return -1
			}
			return 1
		}
		return bytes.Compare(x.IP, y.IP)
	})
	// Two identical entries would make LinkIPs bind one address twice; the
	// kernel does not report duplicates, but a Source is not required to know.
	out = slices.CompactFunc(out, func(x, y Addr) bool {
		return x.Index == y.Index && x.IP.Equal(y.IP)
	})
	return Snapshot{Usable: out}
}

// Primary returns the primary address and true, or a zero Addr and false when
// there is no usable LAN IPv4.
func (s Snapshot) Primary() (Addr, bool) {
	if len(s.Usable) == 0 {
		return Addr{}, false
	}
	return s.Usable[0], true
}

// PrimaryIP returns the primary address, or nil when there is none.
func (s Snapshot) PrimaryIP() net.IP {
	if a, ok := s.Primary(); ok {
		return a.IP
	}
	return nil
}

// LinkIPs returns every usable address on the primary's interface, primary
// first. These are the addresses the nameserver listens on: a LAN client may
// have been pointed at any of them, but only the primary's link is the LAN — a
// second NIC is not given a DNS listener just because it has an address.
func (s Snapshot) LinkIPs() []net.IP {
	p, ok := s.Primary()
	if !ok {
		return nil
	}
	var out []net.IP
	for _, a := range s.Usable {
		if a.Index == p.Index {
			out = append(out, a.IP)
		}
	}
	return out
}

// Equal reports whether two snapshots hold the same addresses in the same
// order, with the same attributes.
func (s Snapshot) Equal(o Snapshot) bool {
	return slices.EqualFunc(s.Usable, o.Usable, func(x, y Addr) bool {
		return x.IP.Equal(y.IP) && x.Link == y.Link && x.Index == y.Index &&
			x.Loopback == y.Loopback && x.Dynamic == y.Dynamic
	})
}

// String renders the snapshot for logs: "none", or the primary with its link and
// kind, followed by any other usable addresses.
func (s Snapshot) String() string {
	if len(s.Usable) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(s.Usable))
	for _, a := range s.Usable {
		kind := "static"
		if a.Dynamic {
			kind = "dhcp"
		}
		parts = append(parts, a.IP.String()+" ("+a.Link+", "+kind+")")
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return parts[0] + " + " + strings.Join(parts[1:], ", ")
}
