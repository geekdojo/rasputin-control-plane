package mesh

import (
	"errors"
	"fmt"
	"net"
)

// Advertised routes are what `tailscale up --advertise-routes` receives,
// and tailscale accepts only a NETWORK prefix: "192.168.1.149/24 has
// non-address bits set; expected 192.168.1.0/24" (e3bench-compute1,
// 2026-09-04). Until then the agent's primaryLanCidr was the interface
// address with its mask — net.IPNet.String() of what net.InterfaceAddrs()
// returns — so every operator-driven enroll that took the enroll-defaults
// suggestion failed at `tailscale up`, after the mesh CA had already been
// installed. The agent now reports the network; this is the api's side of
// the contract, applied to both operator input and the defaults.
//
// Two different rules for two different provenances:
//
//   - ValidateAdvertiseRoutes REFUSES a non-canonical route. Its input is
//     what the operator typed (POST /api/mesh/enroll, the enroll saga), and
//     a value someone typed is not rewritten behind their back — the error
//     names the offending value and the form that would be accepted.
//   - CanonicalRoute REWRITES. Its input is a default the api is about to
//     suggest (enroll-defaults from an older agent's host-form metadata),
//     which nobody typed, so canonicalizing it is just suggesting correctly.

// ErrNotCanonicalRoute is wrapped by every ValidateAdvertiseRoutes failure
// so callers can tell a bad route from a transport error.
var ErrNotCanonicalRoute = errors.New("advertise route is not a canonical network prefix")

// ValidateAdvertiseRoutes refuses any route that is not an IPv4 network
// prefix in canonical form. A route with host bits set is refused with a
// message naming both the offending value and the network it sits in; the
// value is NOT rewritten. nil for no routes.
func ValidateAdvertiseRoutes(routes []string) error {
	for _, r := range routes {
		if _, err := canonicalRoute(r); err != nil {
			return fmt.Errorf("%w: %s", ErrNotCanonicalRoute, err)
		}
	}
	return nil
}

// CanonicalRoute returns the route in canonical network form, rewriting a
// host-form prefix (192.168.1.149/24 → 192.168.1.0/24). Only for values the
// api generates itself — a default, never operator input (see
// ValidateAdvertiseRoutes for those). The error is the same one the
// validator produces for a value that cannot be a route at all.
func CanonicalRoute(route string) (string, error) {
	_, ipNet, err := parseIPv4Route(route)
	if err != nil {
		return "", err
	}
	return ipNet.String(), nil
}

// canonicalRoute is the check both entry points share: parse, then require
// the address to equal its own network. Returns the canonical form so the
// refusal can say what would have been accepted.
func canonicalRoute(route string) (string, error) {
	ip, ipNet, err := parseIPv4Route(route)
	if err != nil {
		return "", err
	}
	if !ip.Equal(ipNet.IP) {
		return "", fmt.Errorf("advertise route %q is a host address, not a network — advertise %s", route, ipNet)
	}
	return ipNet.String(), nil
}

// parseIPv4Route parses a route and refuses anything but IPv4: Rasputin is
// IPv4-only (LOCKED decision #9), and the firewall intent fields already
// refuse v6 addresses at the api, so the mesh does the same.
func parseIPv4Route(route string) (net.IP, *net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(route)
	if err != nil {
		return nil, nil, fmt.Errorf("advertise route %q is not an IPv4 CIDR (expected e.g. 192.168.1.0/24)", route)
	}
	if ip.To4() == nil {
		return nil, nil, fmt.Errorf("advertise route %q is IPv6; Rasputin is IPv4-only", route)
	}
	return ip, ipNet, nil
}
