package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// nodeRemovalImpact summarises what a DELETE /api/nodes/{id} would touch
// besides the inventory row itself. The UI uses this to render a
// confirmation dialog listing the cascade so the operator knows what
// they're about to delete.
type nodeRemovalImpact struct {
	NodeID           string   `json:"nodeId"`
	AppIDs           []string `json:"appIds"`
	MeshDeviceHSID   string   `json:"meshDeviceHsId,omitempty"`
	HasFirewallState bool     `json:"hasFirewallState"`
}

// GET /api/nodes/{id}/removal-impact — preview the cascade for the UI's
// confirm dialog. Read-only; does not modify state. 404 if the node id
// is unknown.
func (s *Server) handleGetNodeRemovalImpact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.inv.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n == nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	impact, err := s.computeRemovalImpact(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, impact)
}

// DELETE /api/nodes/{id} — remove a node from inventory and cascade the
// dependent rows. Intended for nodes that have gone permanently offline
// (dead hardware, repurposed unit) where no agent-side de-register is
// possible. There is no blocklist in v1 — if the agent re-registers, a
// fresh inventory row is created. See backlog for blocklist + PKI
// revocation.
//
// Order matters: Headscale first (external system; if it errors we want
// to surface that before touching local DB), then the DB cascade in
// app → firewall_state → inventory order, then the in-memory cleanup
// and event emission inside Service.Remove. On a Headscale failure the
// local DB is left untouched so the operator can retry once Headscale
// is reachable again.
//
// Returns the impact summary in the 200 body so the UI can show a
// confirmation toast with what was removed.
func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	n, err := s.inv.Get(ctx, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n == nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	// The controlplane is the cluster: removing its inventory row would
	// orphan every subsystem that routes through it while the api keeps
	// running on the very node it just "removed". Server-side refusal —
	// the UI hides the control too, but the api is the authority
	// (backlog: nodes "hide REMOVE NODE for the controlplane").
	if n.Role == proto.RoleControlPlane {
		writeError(w, http.StatusConflict, "the controlplane node cannot be removed — it is the cluster itself")
		return
	}

	impact, err := s.computeRemovalImpact(ctx, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if impact.MeshDeviceHSID != "" {
		if err := s.mesh.Client().DeleteNode(ctx, impact.MeshDeviceHSID); err != nil {
			writeError(w, http.StatusBadGateway, "headscale delete: "+err.Error())
			return
		}
		if err := s.mesh.Store().DeleteDevice(ctx, impact.MeshDeviceHSID); err != nil &&
			!errors.Is(err, sql.ErrNoRows) && err.Error() != "sql: no rows in result set" {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	deletedAppIDs, err := s.apps.DeleteByTargetNode(ctx, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete apps: "+err.Error())
		return
	}
	for _, appID := range deletedAppIDs {
		s.publishAppDeleted(appID)
	}

	if _, err := s.fw.DeleteNodeState(ctx, id); err != nil {
		writeError(w, http.StatusInternalServerError, "delete firewall state: "+err.Error())
		return
	}

	// Revoke the node's enrollment token(s) so a removed node leaves no dangling
	// bound token — which would otherwise resurface as a ghost "pending" bay and
	// let the node silently rejoin — and close its live bus session, so a
	// removed node is evicted now rather than whenever it next reconnects
	// (certificates.md §4.2(1)). Best-effort: a leftover token is less harmful
	// than blocking the removal.
	if revoked, disconnected, err := s.busTokens.RevokeByNodeID(ctx, id); err != nil {
		log.Printf("rasputin-api: revoke bus tokens for removed node %q: %v", id, err)
	} else if revoked > 0 || disconnected > 0 {
		log.Printf("rasputin-api: revoked %d enrollment token(s) and closed %d live bus connection(s) for removed node %q",
			revoked, disconnected, id)
	}

	if err := s.invSvc.Remove(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// The node's collector client leaf and key go with it. The ingress already
	// refuses the leaf (the node is out of inventory and its tokens are
	// revoked); deleting it means a removed node leaves no private key of its
	// own on the controlplane. After the inventory row, so a collector
	// reconcile running now cannot mint it again for a node it still lists.
	s.removeCollectorLeaf(id)

	writeJSON(w, http.StatusOK, impact)
}

// removeCollectorLeaf deletes <collectorLeafDir>/<nodeID>. Best-effort and
// logged, like the token revoke above: the node is already gone, and a leaf
// left behind is refused at the ingress. The id is checked against the node-id
// rule first, so it can only name one directory directly under the leaf dir.
func (s *Server) removeCollectorLeaf(nodeID string) {
	if s.collectorLeafDir == "" {
		return
	}
	if !busauth.ValidNodeID(nodeID) {
		log.Printf("rasputin-api: not deleting a collector leaf for removed node %q: not a valid node id, so it names no leaf directory", nodeID)
		return
	}
	dir := filepath.Join(s.collectorLeafDir, nodeID)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		log.Printf("rasputin-api: delete collector leaf for removed node %q at %s: %v", nodeID, dir, err)
		return
	}
	log.Printf("rasputin-api: deleted the collector leaf for removed node %q", nodeID)
}

// computeRemovalImpact gathers the cascade preview without mutating
// anything. Shared between the dry-run endpoint and the delete handler
// (which uses it to pick up the hs_id it needs to pass to Headscale).
func (s *Server) computeRemovalImpact(ctx context.Context, nodeID string) (*nodeRemovalImpact, error) {
	// Apps targeting this node.
	appRows, err := s.apps.List(ctx)
	if err != nil {
		return nil, err
	}
	var appIDs []string
	for _, a := range appRows {
		if a.TargetNode == nodeID {
			appIDs = append(appIDs, a.ID)
		}
	}

	// Mesh device.
	var hsID string
	if d, err := s.mesh.Store().GetDeviceByRasputinNodeID(ctx, nodeID); err != nil {
		return nil, err
	} else if d != nil {
		hsID = d.HSID
	}

	// Firewall state.
	hasFW := false
	if ns, err := s.fw.GetNodeState(ctx, nodeID); err != nil {
		return nil, err
	} else if ns != nil && ns.NodeID != "" {
		hasFW = true
	}

	if appIDs == nil {
		appIDs = []string{}
	}
	return &nodeRemovalImpact{
		NodeID:           nodeID,
		AppIDs:           appIDs,
		MeshDeviceHSID:   hsID,
		HasFirewallState: hasFW,
	}, nil
}

// publishAppDeleted emits an apps.deleted change event on the bus so the
// /ws/apps subscribers (the apps UI) refresh after a cascade delete. Best
// effort — failure to publish does not roll the cascade back.
func (s *Server) publishAppDeleted(appID string) {
	ev := proto.AppChangeEvt{
		AppID:  appID,
		Change: proto.AppDeleted,
		Status: proto.AppStatusStopped,
		Ts:     time.Now().UTC(),
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return
	}
	_ = s.nc.Publish(proto.AppChangeSubject(appID, proto.AppDeleted), payload)
}
