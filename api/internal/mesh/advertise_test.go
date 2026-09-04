package mesh

import (
	"errors"
	"strings"
	"testing"
)

// The bench case: a host-form route is refused, and the refusal names both
// the value that was sent and the network that would have been accepted —
// the operator fixes their input; nothing is rewritten for them.
func TestValidateAdvertiseRoutes_RefusesHostBitsNamingTheNetwork(t *testing.T) {
	err := ValidateAdvertiseRoutes([]string{"192.168.1.149/24"})
	if err == nil {
		t.Fatal("expected 192.168.1.149/24 to be refused")
	}
	if !errors.Is(err, ErrNotCanonicalRoute) {
		t.Errorf("error should wrap ErrNotCanonicalRoute, got %v", err)
	}
	for _, want := range []string{"192.168.1.149/24", "192.168.1.0/24", "host address"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestValidateAdvertiseRoutes_AcceptsCanonicalAndEmpty(t *testing.T) {
	for _, routes := range [][]string{
		nil,
		{},
		{"192.168.1.0/24"},
		{"10.1.32.0/20", "172.16.0.0/12"},
		{"192.168.1.149/32"}, // a /32 is its own network
		{"0.0.0.0/0"},        // an exit node is a valid route
	} {
		if err := ValidateAdvertiseRoutes(routes); err != nil {
			t.Errorf("ValidateAdvertiseRoutes(%v) = %v, want nil", routes, err)
		}
	}
}

// One bad entry anywhere in the list fails the list, and the message points
// at that entry rather than the list.
func TestValidateAdvertiseRoutes_RefusesBadEntryAmongGood(t *testing.T) {
	err := ValidateAdvertiseRoutes([]string{"10.0.0.0/8", "10.1.37.9/20"})
	if err == nil || !strings.Contains(err.Error(), `"10.1.37.9/20"`) || !strings.Contains(err.Error(), "10.1.32.0/20") {
		t.Errorf("got %v, want a refusal naming 10.1.37.9/20 and 10.1.32.0/20", err)
	}
}

func TestValidateAdvertiseRoutes_RefusesNonCIDRAndIPv6(t *testing.T) {
	for _, tc := range []struct{ route, wantIn string }{
		{"", "not an IPv4 CIDR"},
		{"192.168.1.0", "not an IPv4 CIDR"},    // bare address, no prefix
		{"192.168.1.0/33", "not an IPv4 CIDR"}, // impossible prefix
		{"lan", "not an IPv4 CIDR"},
		{"fd7a:115c:a1e0::/48", "IPv4-only"},    // LOCKED decision #9
		{" 192.168.1.0/24", "not an IPv4 CIDR"}, // untrimmed — the caller trims, the validator does not guess
	} {
		err := ValidateAdvertiseRoutes([]string{tc.route})
		if err == nil {
			t.Errorf("%q: expected a refusal", tc.route)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantIn) || !strings.Contains(err.Error(), tc.route) {
			t.Errorf("%q: error %q should mention %q and the value", tc.route, err, tc.wantIn)
		}
	}
}

// CanonicalRoute is the REWRITING entry point, for defaults only.
func TestCanonicalRoute_RewritesHostFormKeepsCanonical(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"192.168.1.149/24", "192.168.1.0/24"},
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"10.1.37.9/20", "10.1.32.0/20"},
	} {
		got, err := CanonicalRoute(tc.in)
		if err != nil {
			t.Errorf("CanonicalRoute(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("CanonicalRoute(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if _, err := CanonicalRoute("not-a-cidr"); err == nil {
		t.Error("CanonicalRoute should refuse a value that cannot be a route")
	}
}
