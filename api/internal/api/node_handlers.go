package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// nodeRemovalImpact summarises what a DELETE /api/nodes/{id} would touch
// besides the inventory row itself. The UI uses this to render a
// confirmation dialog listing the cascade so the operator knows what
// they're about to delete.
type nodeRemovalImpact struct {
	NodeID         string   `json:"nodeId"`
	AppIDs         []string `json:"appIds"`
	MeshDeviceHSID string   `json:"meshDeviceHsId,omitempty"`
	// MeshDeviceHSIDs is every mesh device bound to the node. Normally one
	// (then also MeshDeviceHSID). More than one is a duplicate binding;
	// removal deletes them all rather than pick one, and never refuses: a
	// removal is a revocation, so a mesh ambiguity must not block it.
	MeshDeviceHSIDs  []string `json:"meshDeviceHsIds,omitempty"`
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

	if len(impact.MeshDeviceHSIDs) > 1 {
		log.Printf("rasputin-api: removing node %q, which is bound to %d mesh devices (%q); deleting all of them",
			n.ID, len(impact.MeshDeviceHSIDs), impact.MeshDeviceHSIDs)
	}
	for _, hsID := range impact.MeshDeviceHSIDs {
		if err := s.mesh.Client().DeleteNode(ctx, hsID); err != nil {
			writeError(w, http.StatusBadGateway, "headscale delete: "+err.Error())
			return
		}
		if err := s.mesh.Store().DeleteDevice(ctx, hsID); err != nil &&
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

	// And its console root password record, so a removed node stops being
	// counted as a fleet node that never took the password (#587).
	if s.console != nil {
		if err := s.console.ForgetNode(ctx, id); err != nil {
			log.Printf("rasputin-api: forget the console root password record for removed node %q: %v", id, err)
		}
	}

	writeJSON(w, http.StatusOK, impact)
}

// removeCollectorLeaf deletes <collectorLeafDir>/<nodeID>. Best-effort and
// logged, like the token revoke above: the node is already gone, and a leaf
// left behind is refused at the ingress. The id is checked against the node-id
// rule first, and the delete runs through an os.Root opened on the leaf
// directory, so it cannot reach anything outside that directory whatever the
// id is.
func (s *Server) removeCollectorLeaf(nodeID string) {
	if s.collectorLeafDir == "" {
		return
	}
	if !busauth.ValidNodeID(nodeID) {
		log.Printf("rasputin-api: not deleting a collector leaf for removed node %q: not a valid node id, so it names no leaf directory", nodeID)
		return
	}
	root, err := os.OpenRoot(s.collectorLeafDir)
	if errors.Is(err, os.ErrNotExist) {
		return // no collector ever had a leaf here
	}
	if err != nil {
		log.Printf("rasputin-api: open the collector leaf directory to delete removed node %q's leaf: %v", nodeID, err)
		return
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Lstat(nodeID); errors.Is(err, os.ErrNotExist) {
		return
	}
	if err := root.RemoveAll(nodeID); err != nil {
		log.Printf("rasputin-api: delete collector leaf for removed node %q: %v", nodeID, err)
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

	// Mesh devices bound to the node — all of them, so a duplicate binding
	// is removed whole rather than resolved by picking one.
	bound, err := s.mesh.Store().DevicesBoundTo(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	var hsIDs []string
	for _, d := range bound {
		hsIDs = append(hsIDs, d.HSID)
	}
	hsID := ""
	if len(hsIDs) == 1 {
		hsID = hsIDs[0]
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
		MeshDeviceHSIDs:  hsIDs,
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
