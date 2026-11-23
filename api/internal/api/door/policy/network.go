package policy

import "net/netip"

// NetworkFacts are the addresses the registration source rule reads. The
// tailnet's prefixes come from the mesh's own configuration, through the
// provider, never from a constant here (F-985-17).
type NetworkFacts struct {
	// HomeSubnets are the control plane's home-network subnets.
	HomeSubnets []netip.Prefix
	// Tailnet are the private network's address ranges.
	Tailnet []netip.Prefix
	// Nodes are the cluster's own node addresses, which app containers leave
	// through.
	Nodes []netip.Addr
}

// AdmitsRegistration reports whether account creation may come from addr: an
// address on a home-network subnet that is neither a tailnet address nor one
// of the cluster's node addresses. An address that did not parse never is.
func (f NetworkFacts) AdmitsRegistration(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range f.Tailnet {
		if p.Contains(addr) {
			return false
		}
	}
	for _, n := range f.Nodes {
		if n.Unmap() == addr {
			return false
		}
	}
	for _, p := range f.HomeSubnets {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
