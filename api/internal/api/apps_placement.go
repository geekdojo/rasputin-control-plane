package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// design/storage.md §6.4's per-app placement, on the api side: the two checks
// that must happen where the operator is standing rather than on the node.
//
// The api does NOT resolve a placement. It cannot: the mount root plus the
// partition UUID names a path, but whether the filesystem at that path is the
// disk is a question only the agent can answer, and §6.3 makes answering it
// with the on-platter marker the whole enforcement. What the api owns is the
// pair of refusals that would otherwise reach the operator as an agent-side
// surprise minutes later — a malformed UUID, and a node that cannot hold a data
// disk at all.

// dataPlacementRefusal reports why an app placed on the data disk partUUID
// cannot run on node, or "" when the placement may be recorded and deployed.
//
// An empty partUUID is always allowed and is the default: it means the boot
// medium, which is where every app's volumes have always gone and where every
// app installed before §6.4 still goes.
//
// The eligibility question is routed through storage.CanHoldTarget rather than
// answered here, so the sentence an operator reads when a placement is refused
// is the SAME sentence the disk picker gives them when the claim itself is
// refused. Two spellings of one rule is how the picker and the installer come
// to disagree about which nodes can hold a data disk.
//
// ⚠️ Today that rule refuses every compute node, and apps run on compute nodes
// only — so every placement is refused, and that is the honest state rather
// than an oversight. CanHoldTarget's header records the two moves that change
// it, in order: this field is the first of them, and widening the agent's role
// gate to arm the force-formatting storage.claim on every compute node is the
// second, which is a decision and not a refactor.
func dataPlacementRefusal(node *proto.Node, partUUID string) string {
	partUUID = strings.TrimSpace(partUUID)
	if partUUID == "" {
		return ""
	}
	// The shape check is the api's, applied at the door, because the value
	// becomes a path segment under the data mount root on the node. Both sides
	// check: the agent refuses it again in DataMountPath, because neither end
	// is entitled to assume the other did.
	if !storage.ValidPartUUID(partUUID) {
		return fmt.Sprintf("%q is not a partition UUID, and a data disk is addressed by partition UUID and by nothing else (design/storage.md §6.2)", partUUID)
	}
	if ok, reason := storage.CanHoldTarget(node, proto.StoragePurposeData); !ok {
		return "this app cannot be placed on a data disk: " + reason
	}
	return ""
}

// deployPlacementRefusal is dataPlacementRefusal for an app that already
// exists: it loads the app and its node and applies the same rule.
//
// It is deliberately SILENT about everything except placement. A missing app,
// an unregistered node or a lookup that errors all return "" and let the job be
// submitted, because those are the deploy saga's own refusals and it words them
// — duplicating them here would give an operator two different sentences for
// one condition depending on which check happened to run first.
func (s *Server) deployPlacementRefusal(r *http.Request, appID string) string {
	app, err := s.apps.Get(r.Context(), appID)
	if err != nil || app == nil || strings.TrimSpace(app.DataDiskPartUUID) == "" {
		return ""
	}
	node, err := s.inv.Get(r.Context(), app.TargetNode)
	if err != nil || node == nil {
		return ""
	}
	return dataPlacementRefusal(node, app.DataDiskPartUUID)
}
