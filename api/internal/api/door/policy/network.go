package policy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

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

// NetworkSourceDeps are NetworkSource's collaborators. NewNetworkSource
// refuses a missing one.
type NetworkSourceDeps struct {
	// LAN is the control plane's home-network subnets now
	// (lanaddr.Snapshot.Subnets of the watcher's snapshot). None is a fact:
	// with no subnet, no address is admitted.
	LAN func() []netip.Prefix
	// Tailnet is the private network's address ranges (mesh.TailnetPrefixes).
	Tailnet func() []netip.Prefix
	// Nodes is every node's LAN address as the inventory holds it; "" for a
	// node that has not reported one.
	Nodes func(ctx context.Context) ([]string, error)
}

// NetworkSource is the real Network: the facts read afresh on every
// registration request (geekdojo/geekdojo-brain#990).
type NetworkSource struct{ d NetworkSourceDeps }

// NewNetworkSource checks d and returns the source. It does no I/O.
func NewNetworkSource(d NetworkSourceDeps) (*NetworkSource, error) {
	if d.LAN == nil || d.Tailnet == nil || d.Nodes == nil {
		return nil, errors.New("policy: NetworkSourceDeps has a nil collaborator")
	}
	return &NetworkSource{d: d}, nil
}

// Facts reads the facts. An empty or invalid tailnet set, an inventory that
// can't be read, or a node address that does not parse is an error, so the
// registration is refused (ERR-CLOSED). A node with no address yet is
// skipped: it has no app containers to leave through it.
func (n *NetworkSource) Facts(ctx context.Context) (NetworkFacts, error) {
	tailnet := n.d.Tailnet()
	if len(tailnet) == 0 {
		return NetworkFacts{}, errors.New("policy: no tailnet prefixes")
	}
	for _, p := range tailnet {
		if !p.IsValid() {
			return NetworkFacts{}, errors.New("policy: an invalid tailnet prefix")
		}
	}
	ips, err := n.d.Nodes(ctx)
	if err != nil {
		return NetworkFacts{}, fmt.Errorf("policy: node addresses: %w", err)
	}
	var nodes []netip.Addr
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return NetworkFacts{}, fmt.Errorf("policy: a node address does not parse: %w", err)
		}
		nodes = append(nodes, a.Unmap())
	}
	var home []netip.Prefix
	for _, p := range n.d.LAN() {
		if p.IsValid() {
			home = append(home, p.Masked())
		}
	}
	return NetworkFacts{HomeSubnets: home, Tailnet: tailnet, Nodes: nodes}, nil
}
