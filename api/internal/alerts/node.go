package alerts

import (
	"context"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// SetMeshMembership wires the mesh side of the presence join — the same
// lookup (mesh.Service.Membership) the inventory store and the /api/nodes
// handlers read, so the alert for a lapsed node says OFF BUS exactly when the
// nodes page does (geekdojo/geekdojo-brain#401). Wired by main after New.
func (s *Service) SetMeshMembership(fn inventory.MeshLookup) { s.mesh = fn }

// nodeAlerts: one alert per node that is not online, from the same derivation
// the /api/nodes handler uses (inventory.ApplyMesh over the inventory rows and
// the mesh membership map) so both readers agree.
//
// The off-bus alert keeps the node-offline id: it is the same concern — this
// node is not on the bus — read with more evidence, and an operator who
// acknowledged the OFFLINE alert must not get a second one for the same
// silence when the mesh cache catches up. Severity stays crit for the same
// reason: a node the api cannot drive is a node the api cannot drive,
// however reachable the machine underneath is.
func (s *Service) nodeAlerts(ctx context.Context, _ time.Time) ([]proto.Alert, error) {
	nodes, err := s.inv.List(ctx)
	if err != nil {
		return nil, err
	}
	var byNode map[string]*proto.MeshMembership
	if s.mesh != nil {
		byNode = s.mesh(ctx)
	}
	inventory.ApplyMesh(nodes, byNode)
	out := make([]proto.Alert, 0, len(nodes))
	for _, n := range nodes {
		switch n.Status {
		case proto.StatusOffBus:
			out = append(out, proto.Alert{
				ID:          "node-offline:" + n.ID,
				Severity:    proto.AlertCrit,
				Source:      proto.AlertSourceNode,
				Title:       fmt.Sprintf("Node %s is OFF BUS", n.ID),
				Detail:      offBusDetail(n),
				Since:       n.LastSeen,
				RelatedKind: "node",
				RelatedID:   n.ID,
			})
		case proto.StatusOffline:
			out = append(out, proto.Alert{
				ID:          "node-offline:" + n.ID,
				Severity:    proto.AlertCrit,
				Source:      proto.AlertSourceNode,
				Title:       fmt.Sprintf("Node %s is offline", n.ID),
				Detail:      fmt.Sprintf("Last heartbeat %s ago", humanizeDuration(time.Since(n.LastSeen))),
				Since:       n.LastSeen,
				RelatedKind: "node",
				RelatedID:   n.ID,
			})
		case proto.StatusStale:
			out = append(out, proto.Alert{
				ID:          "node-stale:" + n.ID,
				Severity:    proto.AlertWarn,
				Source:      proto.AlertSourceNode,
				Title:       fmt.Sprintf("Node %s heartbeat is stale", n.ID),
				Detail:      fmt.Sprintf("Last heartbeat %s ago", humanizeDuration(time.Since(n.LastSeen))),
				Since:       n.LastSeen,
				RelatedKind: "node",
				RelatedID:   n.ID,
			})
		}
	}
	return out, nil
}

// offBusDetail: "reachable over the mesh (seen 40s ago) but its agent has not
// heartbeated for 3h; restart the agent". Names both facts the operator would
// otherwise have to cross-reference across two pages, and the one action.
func offBusDetail(n *proto.Node) string {
	seen := ""
	if n.Mesh != nil && n.Mesh.LastSeen != nil {
		seen = fmt.Sprintf(" (seen %s ago)", humanizeDuration(time.Since(*n.Mesh.LastSeen)))
	}
	return fmt.Sprintf("Reachable over the mesh%s but its agent has not heartbeated for %s; restart the agent or check its log",
		seen, humanizeDuration(time.Since(n.LastSeen)))
}
