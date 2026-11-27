package lanaddr

import (
	"net"
	"net/netip"
	"slices"
	"testing"
)

// TC-990-16: source_other's prefix length comes off the IPNet mask, in its
// 4-byte and 16-byte forms; a mask that is not a prefix gives 0.
func TestMaskBits_TC990_16(t *testing.T) {
	cases := []struct {
		m    net.IPMask
		want int
	}{
		{net.CIDRMask(24, 32), 24},
		{net.CIDRMask(16, 32), 16},
		{net.CIDRMask(32, 32), 32},
		{net.CIDRMask(96+24, 128), 24},
		{net.IPMask{255, 0, 255, 0}, 0},
		{net.CIDRMask(64, 128), 0},
	}
	for _, c := range cases {
		if got := maskBits(c.m); got != c.want {
			t.Errorf("maskBits(%v) = %d, want %d", c.m, got, c.want)
		}
	}
}

// TC-990-16: Subnets is the masked prefix of each Usable address, once
// each; never a docker*, br-*, veth*, tailscale* or lo address, a
// 169.254/16 one, or one whose prefix length is unknown.
func TestSnapshotSubnets_TC990_16(t *testing.T) {
	addr := func(ip, link string, bits int) Addr {
		return Addr{IP: net.ParseIP(ip).To4(), Link: link, Index: 2, Bits: bits}
	}
	s := Select([]Addr{
		addr("192.0.2.10", "end0", 24),
		addr("192.0.2.11", "end0", 24),
		addr("198.51.100.7", "end1", 16),
		addr("203.0.113.9", "end2", 32),
		addr("10.9.0.1", "end3", 0),
		addr("172.17.0.1", "docker0", 16),
		addr("172.18.0.1", "br-1234", 16),
		addr("172.19.0.1", "veth0", 16),
		addr("100.64.0.5", "tailscale0", 10),
		addr("127.0.0.1", "lo", 8),
		addr("169.254.3.4", "end0", 16),
	})
	got := s.Subnets()
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.0.0/16"),
		netip.MustParsePrefix("203.0.113.9/32"),
	}
	slices.SortFunc(got, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	slices.SortFunc(want, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	if !slices.Equal(got, want) {
		t.Errorf("Subnets() = %v, want %v", got, want)
	}
	if got := (Snapshot{}).Subnets(); len(got) != 0 {
		t.Errorf("the zero snapshot's subnets = %v, want none", got)
	}
	// A snapshot built by hand, bypassing Select, still names no excluded
	// link's subnet.
	if got := (Snapshot{Usable: []Addr{addr("172.17.0.1", "docker0", 16)}}).Subnets(); len(got) != 0 {
		t.Errorf("a docker address named %v", got)
	}
}
