package openwrt

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// stubRunner answers `uci -q get <key>` from a map. Anything unmapped errors,
// which is what a real `uci -q get` on a missing key does.
type stubRunner struct {
	values map[string]string
	err    error
	calls  []string
}

func (s *stubRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	s.calls = append(s.calls, name+" "+strings.Join(args, " "))
	if s.err != nil {
		return "", s.err
	}
	key := args[len(args)-1]
	v, ok := s.values[key]
	if !ok {
		return "", errors.New("uci: entry not found")
	}
	return v + "\n", nil // uci prints a trailing newline
}

func addrs(specs ...string) func(string) ([]net.Addr, error) {
	return func(string) ([]net.Addr, error) {
		out := make([]net.Addr, 0, len(specs))
		for _, s := range specs {
			ip, ipNet, err := net.ParseCIDR(s)
			if err != nil {
				panic(err)
			}
			// net.Interface.Addrs() returns the INTERFACE address with the
			// network's mask, not the network address — mirror that.
			out = append(out, &net.IPNet{IP: ip, Mask: ipNet.Mask})
		}
		return out, nil
	}
}

// The case the bug was about: on the firewall the LAN is br-lan holding
// 192.168.1.1, while the default route (and therefore the old heuristic) goes
// out eth1 on 192.168.197.226. This must return the LAN, never the WAN.
func TestLANAddress_ReturnsTheLANNotTheDefaultRoute(t *testing.T) {
	r := &stubRunner{values: map[string]string{"network.lan.device": "br-lan"}}
	ip, cidr, err := lanAddress(context.Background(), r, addrs("192.168.1.1/24"))
	if err != nil {
		t.Fatalf("lanAddress: %v", err)
	}
	if ip != "192.168.1.1" {
		t.Errorf("ip = %q, want the LAN address 192.168.1.1", ip)
	}
	if cidr != "192.168.1.0/24" {
		t.Errorf("cidr = %q, want the NETWORK 192.168.1.0/24 (a route, matching PrimaryLanCIDR), not the interface address", cidr)
	}
	if len(r.calls) == 0 || !strings.Contains(r.calls[0], "network.lan.device") {
		t.Errorf("expected the modern `device` key to be asked first, calls: %v", r.calls)
	}
}

// Pre-DSA configs spell it `ifname`. Falling back matters: without it an older
// box silently drops to the heuristic this code exists to replace, which is a
// wrong answer wearing a right answer's type.
func TestLANAddress_FallsBackToIfname(t *testing.T) {
	r := &stubRunner{values: map[string]string{"network.lan.ifname": "eth0"}}
	ip, _, err := lanAddress(context.Background(), r, addrs("10.0.0.1/8"))
	if err != nil {
		t.Fatalf("lanAddress: %v", err)
	}
	if ip != "10.0.0.1" {
		t.Errorf("ip = %q", ip)
	}
	if len(r.calls) != 2 {
		t.Errorf("expected device then ifname, got %v", r.calls)
	}
}

// Rasputin is IPv4-only (LOCKED decision #9). An interface holding a v6
// link-local alongside its v4 must still report the v4.
func TestLANAddress_PrefersIPv4(t *testing.T) {
	r := &stubRunner{values: map[string]string{"network.lan.device": "br-lan"}}
	ip, cidr, err := lanAddress(context.Background(), r, addrs("fe80::1/64", "192.168.1.1/24"))
	if err != nil {
		t.Fatalf("lanAddress: %v", err)
	}
	if ip != "192.168.1.1" || cidr != "192.168.1.0/24" {
		t.Errorf("got %q / %q, want the IPv4", ip, cidr)
	}
}

// The cidr must be the network even when the LAN address is nowhere near the
// bottom of the range and the prefix does not fall on an octet boundary —
// the ip keeps the host address, the cidr loses it.
func TestLANAddress_CIDRIsTheNetworkNotTheAddress(t *testing.T) {
	r := &stubRunner{values: map[string]string{"network.lan.device": "br-lan"}}
	ip, cidr, err := lanAddress(context.Background(), r, addrs("10.20.37.9/20"))
	if err != nil {
		t.Fatalf("lanAddress: %v", err)
	}
	if ip != "10.20.37.9" {
		t.Errorf("ip = %q, want the host address 10.20.37.9", ip)
	}
	if cidr != "10.20.32.0/20" {
		t.Errorf("cidr = %q, want the network 10.20.32.0/20", cidr)
	}
}

// Every failure must be an ERROR, never a plausible-looking empty string: the
// caller falls back to the old heuristic on error, and silently returning ""
// would publish an empty lanIP instead.
func TestLANAddress_FailuresAreErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		runner *stubRunner
		addrs  func(string) ([]net.Addr, error)
		wantIn string
	}{
		{
			name:   "uci has no LAN interface at all",
			runner: &stubRunner{values: map[string]string{}},
			addrs:  addrs("192.168.1.1/24"),
			wantIn: "no LAN interface",
		},
		{
			name:   "uci itself fails — the cause is still wrapped",
			runner: &stubRunner{err: errors.New("uci: command not found")},
			addrs:  addrs("192.168.1.1/24"),
			wantIn: "no LAN interface",
		},
		{
			name:   "named interface does not exist",
			runner: &stubRunner{values: map[string]string{"network.lan.device": "br-lan"}},
			addrs:  func(string) ([]net.Addr, error) { return nil, errors.New("no such network interface") },
			wantIn: "read addresses of LAN interface br-lan",
		},
		{
			name:   "LAN interface is IPv6-only",
			runner: &stubRunner{values: map[string]string{"network.lan.device": "br-lan"}},
			addrs:  addrs("fe80::1/64"),
			wantIn: "has no IPv4 address",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip, cidr, err := lanAddress(context.Background(), tc.runner, tc.addrs)
			if err == nil {
				t.Fatalf("expected an error, got ip=%q cidr=%q", ip, cidr)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantIn)
			}
			if ip != "" || cidr != "" {
				t.Errorf("a failure must return empty strings, got %q / %q", ip, cidr)
			}
		})
	}
}
