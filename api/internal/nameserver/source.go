package nameserver

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Source supplies the current set of authoritative A records the responder
// serves, keyed by canonical name (lowercase, fully-qualified, trailing dot).
// It is read on every query — cheap, and the point of embedding: a lease or app
// change is reflected on the next lookup with no zone-file regenerate/reload
// (reconcile-on-change, ADR-0004 §8). Implementations must be safe for
// concurrent Records calls.
//
// Slice 1 wires [SelfSource]. Slice 2 adds an inventory+apps projection; the
// responder can read more than one Source, so the projection is additive.
type Source interface {
	// Records returns fqdn -> LAN IPv4. Rasputin is IPv4-only (LOCKED decision
	// #9), so every value is a 4-byte IP; a nil/!To4 value is skipped by the
	// responder. Returning nil (e.g. the CP has no LAN route yet) is valid and
	// means "serve nothing," not an error.
	Records() map[string]net.IP
}

// SelfSource is the Slice-1 Source: the control plane answering for itself. It
// resolves the zone apex <cluster-id>.internal and the unicast <cluster>.local
// name to the CP's own LAN IP. The IP is read from ipFn on every call rather
// than snapshotted, so it tracks the box moving subnets (the same reason main's
// ServerIP recomputes per call).
type SelfSource struct {
	// zone is the canonical zone apex, e.g. "home1.internal." — always present.
	zone string
	// localName is the canonical <cluster>.local name, e.g. "home1.local." — ""
	// on a dev box with no cluster id, in which case it is not served.
	localName string
	// ipFn returns the CP's current LAN IPv4, or nil when there is no LAN route.
	ipFn func() net.IP
}

// NewSelfSource builds the CP-self Source. zone and localName are canonicalized
// (lowercased, trailing dot) so callers may pass either form. localName may be
// "" to serve only the .internal apex.
func NewSelfSource(zone, localName string, ipFn func() net.IP) *SelfSource {
	return &SelfSource{
		zone:      canonical(zone),
		localName: canonical(localName),
		ipFn:      ipFn,
	}
}

// Records implements [Source].
func (s *SelfSource) Records() map[string]net.IP {
	ip := s.ipFn()
	if ip == nil || ip.To4() == nil {
		return nil
	}
	out := map[string]net.IP{s.zone: ip}
	if s.localName != "" {
		out[s.localName] = ip
	}
	return out
}

// canonical lowercases a name and ensures a single trailing dot, the form used
// as the map key and compared against the (already-canonical) query name.
// "" stays "" (an absent name), never ".".
func canonical(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return dns.CanonicalName(name)
}
