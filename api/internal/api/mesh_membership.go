package api

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// meshMembership builds a nodeID -> membership map from the mesh device cache,
// which mesh.reconcile refreshes from Headscale every 30s. Reading the local
// cache rather than calling Headscale keeps a node listing off the network path
// of a service that can be down — and a mesh lookup that hangs must never be
// able to stall the page that would tell you the mesh is unhealthy.
//
// Returns nil when membership cannot be established AT ALL, which callers must
// propagate as "undetermined" rather than "absent". The distinction is the
// whole point of the field: an empty device table means "no reconcile has run"
// just as readily as "nothing is enrolled", and reporting a node as off the
// mesh because we never looked would be the same class of unchecked assertion
// as the green 24/24 this exists to replace (geekdojo/geekdojo-brain#202).
func (s *Server) meshMembership(ctx context.Context) map[string]*proto.MeshMembership {
	if s.mesh == nil || s.mesh.Store() == nil {
		return nil
	}
	// LastReconciled is the discriminator between "looked, found nothing" and
	// "never looked". Without it an unconfigured or freshly-started mesh would
	// paint the entire fleet as off-mesh.
	st, err := s.mesh.Store().GetState(ctx)
	if err != nil || st == nil || st.LastReconciled == nil {
		return nil
	}
	devices, err := s.mesh.Store().ListDevices(ctx)
	if err != nil {
		return nil
	}
	out := make(map[string]*proto.MeshMembership, len(devices))
	for _, d := range devices {
		if d == nil || d.RasputinNodeID == "" {
			continue // user devices (laptops) are not cluster nodes
		}
		m := &proto.MeshMembership{
			State:     proto.MeshAbsent,
			TailnetIP: d.TailnetIP,
		}
		if d.Online {
			m.State = proto.MeshJoined
		}
		if !d.LastSeen.IsZero() {
			ls := d.LastSeen
			m.LastSeen = &ls
		}
		out[d.RasputinNodeID] = m
	}
	return out
}

// applyMeshMembership annotates nodes in place. A nil byNode means we could not
// determine membership, so every node keeps Mesh == nil (undetermined). A node
// absent from a non-nil map has genuinely never enrolled — we looked, and it
// was not there.
func applyMeshMembership(nodes []*proto.Node, byNode map[string]*proto.MeshMembership) {
	if byNode == nil {
		return
	}
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if m, ok := byNode[n.ID]; ok {
			n.Mesh = m
			continue
		}
		n.Mesh = &proto.MeshMembership{State: proto.MeshAbsent}
	}
}
