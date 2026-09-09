package api

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// meshMembership is the node↔mesh-device join for the handlers, read from
// the mesh device cache via mesh.Service.Membership — the one place the join
// is made, shared with inventory's presence derivation and the alerts
// aggregator through inventory's MeshLookup hook (geekdojo/geekdojo-brain#401).
//
// Returns nil when membership cannot be established AT ALL (no mesh service,
// no reconcile yet), which inventory.ApplyMesh propagates as "undetermined"
// rather than "absent" (geekdojo/geekdojo-brain#202).
func (s *Server) meshMembership(ctx context.Context) map[string]*proto.MeshMembership {
	if s.mesh == nil {
		return nil
	}
	return s.mesh.Membership(ctx)
}
