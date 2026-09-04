package openwrt

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/host"
)

// LANAddress answers "which address do other cluster members reach this node
// on" by ASKING THE BOX, rather than inferring it from the default route.
//
// WHY THIS EXISTS
//
//	host.PrimaryLANIP() defines the LAN address as the source address the
//	kernel would use to reach the public internet. That is correct on every
//	node except the one whose job IS reaching the public internet: on the
//	firewall the default route leaves via WAN, so the generic heuristic
//	reported the WAN address as the node's lanIP.
//
//	It was not cosmetic. The control plane projects every node's name onto
//	its lanIP for cluster DNS, so the firewall's name resolved to its WAN
//	interface — an address the firewall's own WAN input policy rejects for
//	everything but DHCP-renew, ping and IGMP. The same value also feeds the
//	mesh enroll form's advertise-routes suggestion, where it proposed the WAN
//	subnet instead of the LAN. geekdojo/geekdojo-brain#193, found on the
//	bench 2026-08-19 after it sent a debugging session to the wrong address
//	for an hour.
//
// On a router "which interface is the LAN" has a real, queryable answer, and
// guessing it is what produced the bug — so this asks UCI for the LAN
// interface and then reads that interface's LIVE address. Live rather than
// configured: a LAN on DHCP still reports what it actually holds.
func (c *UCIRealClient) LANAddress(ctx context.Context) (ip, cidr string, err error) {
	return lanAddress(ctx, c.runner, realIfaceAddrs)
}

// lanAddress is the testable core. Split from the method so tests drive it
// without a br-lan on the test host — same seam pattern as the rest of this
// package (CmdRunner) and as host.findCIDR's addrLister.
func lanAddress(ctx context.Context, runner CmdRunner, addrs ifaceAddrsByName) (string, string, error) {
	dev, err := lanDevice(ctx, runner)
	if err != nil {
		return "", "", err
	}

	list, err := addrs(dev)
	if err != nil {
		return "", "", fmt.Errorf("read addresses of LAN interface %s: %w", dev, err)
	}
	for _, a := range list {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		// IPv4 only, deliberately: Rasputin is IPv4-only (LOCKED decision #9)
		// and an interface that also holds a v6 link-local must not return it.
		v4 := ipNet.IP.To4()
		if v4 == nil {
			continue
		}
		// The ip is the LAN address (192.168.1.1); the cidr is the NETWORK it
		// sits in (192.168.1.0/24), the same shape host.PrimaryLanCIDR
		// publishes, so consumers see one — and so it is a route: the value
		// feeds --advertise-routes, which rejects a prefix with host bits set.
		return v4.String(), host.NetworkCIDR(ipNet), nil
	}
	return "", "", fmt.Errorf("LAN interface %s has no IPv4 address", dev)
}

// lanDevice asks UCI which interface is the LAN, trying both spellings.
// `device` is the modern key (and what our own image sets — br-lan, with eth0
// as its port); `ifname` is the pre-DSA name kept as a fallback so an older or
// hand-edited config still resolves rather than silently falling back to the
// heuristic this exists to replace.
func lanDevice(ctx context.Context, runner CmdRunner) (string, error) {
	var firstErr error
	for _, key := range []string{"network.lan.device", "network.lan.ifname"} {
		out, err := runner.Run(ctx, "uci", "-q", "get", key)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if dev := strings.TrimSpace(out); dev != "" {
			return dev, nil
		}
	}
	// One message for both shapes of "UCI could not tell us". `uci -q get` on a
	// missing key exits NON-ZERO rather than printing nothing, so an unset LAN
	// arrives as an error, not as empty output — reporting those two
	// differently makes the common case (no LAN configured) read like a
	// tooling fault. The underlying cause is wrapped when there was one.
	if firstErr != nil {
		return "", fmt.Errorf("uci reports no LAN interface (network.lan.device and .ifname unset or unreadable): %w", firstErr)
	}
	return "", fmt.Errorf("uci reports no LAN interface (network.lan.device and .ifname are both empty)")
}

// ifaceAddrsByName is a seam over net.InterfaceByName(...).Addrs().
type ifaceAddrsByName func(name string) ([]net.Addr, error)

func realIfaceAddrs(name string) ([]net.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return iface.Addrs()
}
