package mesh

import (
	"context"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// membershipStaleAfterIntervals is how many reconcile intervals may pass after
// the last completed reconcile before a device's "online" observation stops
// counting as current. Three: one interval is the normal gap between
// observations, a second absorbs a reconcile that ran long or was skipped
// behind a gated scheduler entry, and a third is the margin before the api
// stops vouching for a state it has not re-checked.
const membershipStaleAfterIntervals = 3

// MembershipMaxAge is the staleness bound on MeshMembership.Online: an
// observation older than this reads as not-online. It follows the configured
// reconcile cadence (RASPUTIN_MESH_RECONCILE_INTERVAL, default 5 min → 15 min)
// rather than a fixed constant, because the bound only means something
// relative to how often the observation is refreshed.
func (s *Service) MembershipMaxAge() time.Duration {
	return membershipStaleAfterIntervals * s.cfg.ReconcileInterval
}

// Membership builds a nodeID → membership map from the mesh device cache,
// which the mesh.reconcile workflow's fetch_observed step syncs from Headscale
// on the scheduler's cadence. Reading the local cache rather than calling
// Headscale keeps a node listing off the network path of a service that can
// be down — and a mesh lookup that hangs must never be able to stall the page
// that would tell you the mesh is unhealthy.
//
// Returns nil when membership cannot be established AT ALL, which callers must
// propagate as "undetermined" rather than "absent". The distinction is the
// whole point of the field: an empty device table means "no reconcile has run"
// just as readily as "nothing is enrolled", and reporting a node as off the
// mesh because we never looked would be the same class of unchecked assertion
// as the green 24/24 this exists to replace (geekdojo/geekdojo-brain#202).
//
// This is the one place the node↔mesh-device join is made. Inventory's status
// derivation (inventory.DeriveStatus), the /api/nodes handlers, the inventory
// transition ticker, the alerts aggregator and ExplainNoResponder all read it
// through inventory's MeshLookup hook, so "on the mesh" means the same thing
// everywhere (geekdojo/geekdojo-brain#401).
func (s *Service) Membership(ctx context.Context) map[string]*proto.MeshMembership {
	return s.membershipAt(ctx, time.Now().UTC())
}

// membershipAt is Membership with the clock injected; see the tests.
func (s *Service) membershipAt(ctx context.Context, now time.Time) map[string]*proto.MeshMembership {
	if s == nil || s.store == nil {
		return nil
	}
	// LastReconciled is the discriminator between "looked, found nothing" and
	// "never looked". Without it an unconfigured or freshly-started mesh would
	// paint the entire fleet as off-mesh.
	st, err := s.store.GetState(ctx)
	if err != nil || st == nil || st.LastReconciled == nil {
		return nil
	}
	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		return nil
	}
	observed := *st.LastReconciled
	// The observation is current while it is younger than the staleness bound.
	// A reconcile that stopped — Headscale down, the scheduler wedged — must
	// not leave every device's last "online" standing indefinitely, or a
	// machine that died an hour after the cache froze would still read as
	// reachable over the mesh.
	current := now.Sub(observed) <= s.MembershipMaxAge()

	out := make(map[string]*proto.MeshMembership, len(devices))
	for _, d := range devices {
		if d == nil || d.RasputinNodeID == "" {
			continue // user devices (laptops) are not cluster nodes
		}
		m := &proto.MeshMembership{
			State:     proto.MeshAbsent,
			Enrolled:  true,
			TailnetIP: d.TailnetIP,
		}
		if d.Online {
			m.State = proto.MeshJoined
			m.Online = current
		}
		ls := d.LastSeen
		// Headscale saying "online" at reconcile time is evidence of a session
		// at that moment, so an online device was seen no earlier than the
		// reconcile that observed it — whatever Headscale's own (unrefreshed
		// while connected, see HSNode.Online) timestamp says.
		if d.Online && observed.After(ls) {
			ls = observed
		}
		if !ls.IsZero() {
			m.LastSeen = &ls
		}
		out[d.RasputinNodeID] = m
	}
	return out
}
