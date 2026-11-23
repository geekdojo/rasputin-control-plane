package tlsca

import (
	"net"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// NameConstraints are the names a CA may sign for (RFC 5280 §4.2.1.10,
// permitted subtrees only). The zero value is unconstrained.
//
// The matching rules are Go's verifier's (crypto/x509), so a name this type
// permits is a name a leaf under the CA verifies for:
//   - a DNS domain permits itself and every name under it, by whole labels,
//     ignoring case ("bench.local" permits "x.bench.local", never
//     "sso-bench.local"). ClusterConstraints never lists a domain with a
//     leading dot, so that form is not handled;
//   - an IP range permits the addresses inside it, IPv4 and IPv6 apart;
//   - an empty list leaves that kind of name unconstrained.
type NameConstraints struct {
	DNSDomains []string
	IPRanges   []*net.IPNet
}

// IsZero reports whether n constrains nothing.
func (n NameConstraints) IsZero() bool {
	return len(n.DNSDomains) == 0 && len(n.IPRanges) == 0
}

// PermitsDNS reports whether a leaf under a CA carrying n may hold the DNS
// name name.
func (n NameConstraints) PermitsDNS(name string) bool {
	if len(n.DNSDomains) == 0 {
		return true
	}
	name = strings.ToLower(name)
	for _, d := range n.DNSDomains {
		d = strings.ToLower(d)
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// PermitsIP reports whether a leaf under a CA carrying n may hold the IP
// address ip. A nil ip is refused by a CA that constrains addresses.
func (n NameConstraints) PermitsIP(ip net.IP) bool {
	if len(n.IPRanges) == 0 {
		return true
	}
	for _, r := range n.IPRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// privateRanges are the addresses a controlplane leaf is reached at: loopback
// (the api's own back-channel and Headscale enrolment) and the RFC 1918 LAN
// ranges (break-glass by LAN address). Built fresh per call, so no caller can
// change another's list.
func privateRanges() []*net.IPNet {
	r := func(a, b, c, d byte, ones int) *net.IPNet {
		return &net.IPNet{IP: net.IPv4(a, b, c, d).To4(), Mask: net.CIDRMask(ones, 32)}
	}
	return []*net.IPNet{r(127, 0, 0, 0, 8), r(10, 0, 0, 0, 8), r(172, 16, 0, 0, 12), r(192, 168, 0, 0, 16)}
}

// ClusterConstraints are the names cluster cid's controlplane CA may sign for
// (geekdojo/geekdojo-brain#258): the cluster's own names and nothing else's.
//
//	DNS: <cid>.local (the console and Headscale), sso-<cid>.local (the home
//	     door, listed on its own: "<cid>.local" does not cover it),
//	     <cid>.internal (the app door, app leaves, the BMC) and
//	     proto.AppRelayServerName (the app relay, a fixed name).
//	IP:  loopback and the three private IPv4 ranges.
//
// An empty cid is the dev fallback "rasputin", the id proto.BaseDomain and
// firstboot already default to. Another cluster's rasputin.local is never on
// the list of a cluster with another id.
func ClusterConstraints(cid string) NameConstraints {
	id := strings.TrimSpace(cid)
	if id == "" {
		id = "rasputin"
	}
	return NameConstraints{
		DNSDomains: []string{
			id + ".local",
			proto.SignInHomeFQDN(id),
			proto.BaseDomain(id),
			proto.AppRelayServerName,
		},
		IPRanges: privateRanges(),
	}
}

// Constraints are the name constraints the CA's own certificate carries,
// read from it: a CA loaded from disk reports what it was minted with, not
// what this release would mint. A nil CA is unconstrained.
func (ca *CA) Constraints() NameConstraints {
	if ca == nil || ca.Cert == nil {
		return NameConstraints{}
	}
	return NameConstraints{DNSDomains: ca.Cert.PermittedDNSDomains, IPRanges: ca.Cert.PermittedIPRanges}
}

// Fit returns spec keeping only the DNS names and IP addresses this CA may
// sign for, so a leaf whose builder lists names for every deployment verifies
// under a CA limited to this cluster's. A CommonName the CA does not permit
// is replaced by the first kept DNS name, so no client that reads the
// CommonName finds a name outside the constraint. Under a nil or
// unconstrained CA spec is returned as it is: an existing cluster's leaves do
// not change.
func (ca *CA) Fit(spec LeafSpec) LeafSpec {
	c := ca.Constraints()
	if c.IsZero() {
		return spec
	}
	var dns []string
	for _, n := range spec.DNSNames {
		if c.PermitsDNS(n) {
			dns = append(dns, n)
		}
	}
	var ips []net.IP
	for _, ip := range spec.IPAddresses {
		if c.PermitsIP(ip) {
			ips = append(ips, ip)
		}
	}
	spec.DNSNames, spec.IPAddresses = dns, ips
	if len(dns) > 0 && !c.PermitsDNS(spec.CommonName) {
		spec.CommonName = dns[0]
	}
	return spec
}
