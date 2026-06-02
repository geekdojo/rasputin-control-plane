package host

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestFindCIDR_PicksMatchingSubnet(t *testing.T) {
	target := net.ParseIP("192.168.1.42")
	list := func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("172.16.0.1"), Mask: net.CIDRMask(16, 32)},
		}, nil
	}
	got := findCIDR(target, list)
	if got != "192.168.1.1/24" {
		t.Errorf("findCIDR: got %q want 192.168.1.1/24", got)
	}
}

func TestFindCIDR_NoMatchReturnsEmpty(t *testing.T) {
	list := func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(8, 32)},
		}, nil
	}
	if got := findCIDR(net.ParseIP("192.168.1.42"), list); got != "" {
		t.Errorf("expected empty CIDR on no match, got %q", got)
	}
}

func TestFindCIDR_ListErrorReturnsEmpty(t *testing.T) {
	list := func() ([]net.Addr, error) { return nil, errors.New("boom") }
	if got := findCIDR(net.ParseIP("1.2.3.4"), list); got != "" {
		t.Errorf("expected empty CIDR on lister error, got %q", got)
	}
}

func TestFindCIDR_SkipsNonIPNet(t *testing.T) {
	// net.IPAddr (interface with no mask) should be skipped without panic.
	list := func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPAddr{IP: net.ParseIP("192.168.1.1")},
			&net.IPNet{IP: net.ParseIP("192.168.1.0"), Mask: net.CIDRMask(24, 32)},
		}, nil
	}
	got := findCIDR(net.ParseIP("192.168.1.42"), list)
	if got != "192.168.1.0/24" {
		t.Errorf("got %q want 192.168.1.0/24", got)
	}
}

// PrimaryLanCIDR is an integration smoke that depends on the host's real
// network stack — useful as a sanity check but not as a strict assertion.
// On a host with any default route it returns something CIDR-shaped;
// on an air-gapped CI runner it may return "" which is also valid.
func TestPrimaryLanCIDR_ShapeOrEmpty(t *testing.T) {
	got := PrimaryLanCIDR()
	if got == "" {
		t.Skip("no default route on host — PrimaryLanCIDR returned empty (expected for air-gapped CI)")
	}
	if !strings.Contains(got, "/") {
		t.Errorf("PrimaryLanCIDR returned a non-CIDR string: %q", got)
	}
	if _, _, err := net.ParseCIDR(got); err != nil {
		t.Errorf("PrimaryLanCIDR returned invalid CIDR %q: %v", got, err)
	}
}
