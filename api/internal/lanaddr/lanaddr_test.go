package lanaddr

import (
	"net"
	"testing"
)

// The addresses from the #427 / #431 bench runs on e12bench, so the cases read
// as the situations that actually happened.
var (
	fallback  = Addr{IP: net.ParseIP("192.168.1.2"), Link: "end0", Index: 2}
	lease     = Addr{IP: net.ParseIP("192.168.1.226"), Link: "end0", Index: 2, Dynamic: true}
	linkLocal = Addr{IP: net.ParseIP("169.254.17.78"), Link: "end0", Index: 2}
	loopback  = Addr{IP: net.ParseIP("127.0.0.1"), Link: "lo", Index: 1, Loopback: true}
	tailnet   = Addr{IP: net.ParseIP("100.64.0.1"), Link: "tailscale0", Index: 9}
	docker0   = Addr{IP: net.ParseIP("172.17.0.1"), Link: "docker0", Index: 4}
	compose   = Addr{IP: net.ParseIP("172.18.0.1"), Link: "br-3f2a9c", Index: 5}
	veth      = Addr{IP: net.ParseIP("172.18.0.9"), Link: "veth1a2b", Index: 7}
)

func TestUsable(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr Addr
		want bool
	}{
		{"static fallback on the wired link", fallback, true},
		{"DHCP lease on the wired link", lease, true},
		{"link-local 169.254/16", linkLocal, false},
		{"loopback interface", loopback, false},
		{"127/8 address on a non-loopback link", Addr{IP: net.ParseIP("127.0.1.1"), Link: "end0", Index: 2}, false},
		{"lo by name without the flag", Addr{IP: net.ParseIP("10.1.1.1"), Link: "lo", Index: 1}, false},
		{"tailnet", tailnet, false},
		{"docker0", docker0, false},
		{"compose bridge", compose, false},
		{"veth", veth, false},
		{"IPv6", Addr{IP: net.ParseIP("fd00::2"), Link: "end0", Index: 2}, false},
		{"unspecified", Addr{IP: net.IPv4zero, Link: "end0", Index: 2}, false},
		{"multicast", Addr{IP: net.ParseIP("224.0.0.251"), Link: "end0", Index: 2}, false},
		{"broadcast", Addr{IP: net.IPv4bcast, Link: "end0", Index: 2}, false},
		{"nil IP", Addr{Link: "end0", Index: 2}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Usable(tc.addr); got != tc.want {
				t.Fatalf("Usable(%+v) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestSelect(t *testing.T) {
	for _, tc := range []struct {
		name        string
		addrs       []Addr
		wantPrimary string // "" = none
		wantLink    []string
	}{
		{
			name:        "no DHCP: the fallback beside link-local (#431 step 2)",
			addrs:       []Addr{loopback, fallback, linkLocal},
			wantPrimary: "192.168.1.2",
			wantLink:    []string{"192.168.1.2"},
		},
		{
			name:        "DHCP only",
			addrs:       []Addr{loopback, lease},
			wantPrimary: "192.168.1.226",
			wantLink:    []string{"192.168.1.226"},
		},
		{
			name: "both: the lease is primary whatever the kernel listed first (#427's race)",
			// .2 listed first and numerically lower, as `ip addr` showed it
			// primary on the bench; the dynamic rule must still win.
			addrs:       []Addr{fallback, lease},
			wantPrimary: "192.168.1.226",
			wantLink:    []string{"192.168.1.226", "192.168.1.2"},
		},
		{
			name:        "tailnet and docker present beside the lease",
			addrs:       []Addr{tailnet, docker0, compose, veth, lease, loopback},
			wantPrimary: "192.168.1.226",
			wantLink:    []string{"192.168.1.226"},
		},
		{
			name:        "only excluded addresses: none",
			addrs:       []Addr{loopback, linkLocal, tailnet, docker0},
			wantPrimary: "",
		},
		{
			name:        "empty",
			wantPrimary: "",
		},
		{
			name: "two NICs, both static: lower index wins, and only its link is listened on",
			addrs: []Addr{
				{IP: net.ParseIP("10.0.0.5"), Link: "enp2s0", Index: 3},
				{IP: net.ParseIP("192.168.50.9"), Link: "enp1s0", Index: 2},
			},
			wantPrimary: "192.168.50.9",
			wantLink:    []string{"192.168.50.9"},
		},
		{
			name: "two NICs: a lease on the higher index beats a static on the lower",
			addrs: []Addr{
				{IP: net.ParseIP("192.168.50.9"), Link: "enp1s0", Index: 2},
				{IP: net.ParseIP("10.0.0.5"), Link: "enp2s0", Index: 3, Dynamic: true},
			},
			wantPrimary: "10.0.0.5",
			wantLink:    []string{"10.0.0.5"},
		},
		{
			name: "same link, same kind: numerically lower first",
			addrs: []Addr{
				{IP: net.ParseIP("192.168.1.20"), Link: "end0", Index: 2},
				{IP: net.ParseIP("192.168.1.3"), Link: "end0", Index: 2},
			},
			wantPrimary: "192.168.1.3",
			wantLink:    []string{"192.168.1.3", "192.168.1.20"},
		},
		{
			name:        "a duplicate report binds once",
			addrs:       []Addr{fallback, fallback},
			wantPrimary: "192.168.1.2",
			wantLink:    []string{"192.168.1.2"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Select(tc.addrs)
			got := ""
			if ip := s.PrimaryIP(); ip != nil {
				got = ip.String()
			}
			if got != tc.wantPrimary {
				t.Fatalf("primary = %q, want %q (snapshot %s)", got, tc.wantPrimary, s)
			}
			var link []string
			for _, ip := range s.LinkIPs() {
				link = append(link, ip.String())
			}
			if len(link) != len(tc.wantLink) {
				t.Fatalf("LinkIPs = %v, want %v", link, tc.wantLink)
			}
			for i := range link {
				if link[i] != tc.wantLink[i] {
					t.Fatalf("LinkIPs = %v, want %v", link, tc.wantLink)
				}
			}
		})
	}
}

// The order must not depend on the order the kernel happened to list addresses
// in, or the primary would flap between two dumps of the same set.
func TestSelect_OrderIndependent(t *testing.T) {
	a := Select([]Addr{fallback, lease, tailnet})
	b := Select([]Addr{tailnet, lease, fallback})
	if !a.Equal(b) {
		t.Fatalf("same set, different order: %s vs %s", a, b)
	}
}

func TestSnapshotEqual(t *testing.T) {
	if !(Snapshot{}).Equal(Select(nil)) {
		t.Fatal("zero snapshot should equal an empty selection")
	}
	if Select([]Addr{fallback}).Equal(Select([]Addr{lease})) {
		t.Fatal("different addresses compared equal")
	}
	flipped := lease
	flipped.Dynamic = false
	if Select([]Addr{lease}).Equal(Select([]Addr{flipped})) {
		t.Fatal("a dynamic/static change compared equal")
	}
}

func TestSnapshotString(t *testing.T) {
	if got := (Snapshot{}).String(); got != "none" {
		t.Fatalf("empty = %q", got)
	}
	if got, want := Select([]Addr{fallback, lease}).String(), "192.168.1.226 (end0, dhcp) + 192.168.1.2 (end0, static)"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}
