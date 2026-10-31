package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// nodeAppRemover removes a removed node's apps and every secret they had in
// the store (geekdojo/geekdojo-brain#783). *apps.NodeApps satisfies it.
type nodeAppRemover interface {
	// CheckSecrets refuses, changing nothing, when the store cannot take
	// the deletes; the error is an *apps.NodeSecretsError.
	CheckSecrets(ctx context.Context, nodeID string) error
	// Remove deletes the node's app rows and then their secrets, returning
	// the removed app ids; an error of kind apps.ErrSecretsLeft comes with
	// them.
	Remove(ctx context.Context, user, nodeID string) ([]string, error)
}

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
// Order matters. The secret store preflight first: the removal destroys
// every secret of the node's apps, and once their rows are gone nothing
// could reach those entries, so a store that cannot take the deletes refuses
// the removal with nothing changed (geekdojo/geekdojo-brain#783). Then
// Headscale (external system; if it errors we want to surface that before
// touching local DB), then firewall_state, the bus-token revoke and the
// inventory row, so the node's access is revoked before anything slow runs
// (F-783-22). Then the node's apps and their secrets, on a context the
// request cannot cancel. On a Headscale failure the local DB is left
// untouched so the operator can retry once Headscale is reachable again.
//
// When only secret deletes fail, the removal still completes, because it is
// a revocation, and the answer names the entries left in the store.
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

	if err := s.nodeApps.CheckSecrets(ctx, id); err != nil {
		var nse *apps.NodeSecretsError
		status, code, msg := http.StatusServiceUnavailable, codeNodeSecretsUnavailable, "The secrets of the node's apps could not be checked, so the node was not removed."
		if errors.As(err, &nse) {
			msg = nse.Sentence
		}
		if errors.Is(err, apps.ErrNodeSecretsUnreadable) {
			status, code = http.StatusInternalServerError, codeNodeSecretsUnreadable
		}
		s.writeCodedError(w, r, status, code, msg, slog.String("node_id", id), slog.String("err", err.Error()))
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

	// The node's apps and their secrets, after its access is revoked. A store
	// delete is one call per entry, each bounded by the store client's own
	// timeout; a client that disconnects must not abandon them halfway
	// (F-783-22).
	deletedAppIDs, appsErr := s.nodeApps.Remove(context.WithoutCancel(ctx), userName(r), id)
	for _, appID := range deletedAppIDs {
		s.publishAppDeleted(appID)
	}

	// And its console root password record, so a removed node stops being
	// counted as a fleet node that never took the password (#587).
	if s.console != nil {
		if err := s.console.ForgetNode(ctx, id); err != nil {
			// gosec G706 (.github/sast-register.tsv): %q, and `id` reached
			// this line only by matching a registered inventory row above.
			log.Printf("rasputin-api: forget the console root password record for removed node %q: %v", id, err)
		}
	}

	if appsErr != nil {
		var nse *apps.NodeSecretsError
		if errors.Is(appsErr, apps.ErrSecretsLeft) && errors.As(appsErr, &nse) {
			s.writeCodedError(w, r, http.StatusInternalServerError, codeNodeSecretsLeft, nse.Sentence, slog.String("node_id", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "delete apps: "+appsErr.Error())
		return
	}

	writeJSON(w, http.StatusOK, impact)
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
