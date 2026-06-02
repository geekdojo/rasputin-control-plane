package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/oklog/ulid/v2"
)

// GET /api/mesh/state — singleton row (intent_hash, observed_hash, last_*).
func (s *Server) handleMeshState(w http.ResponseWriter, r *http.Request) {
	state, err := s.mesh.Store().GetState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Backend     string          `json:"backend"`
		LoginServer string          `json:"loginServer"`
		DefaultUser string          `json:"defaultUser"`
		State       *mesh.MeshState `json:"state"`
	}{
		Backend:     s.mesh.Client().Backend(),
		LoginServer: s.mesh.Config().LoginServer,
		DefaultUser: s.mesh.Config().DefaultUser,
		State:       state,
	})
}

// GET /api/mesh/devices
func (s *Server) handleListMeshDevices(w http.ResponseWriter, r *http.Request) {
	out, err := s.mesh.Store().ListDevices(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []*mesh.Device{}
	}
	writeJSON(w, http.StatusOK, out)
}

// DELETE /api/mesh/devices/{hsId} — removes the device from Headscale and
// drops the local cache row. Headscale.DeleteNode is idempotent (a missing
// Headscale node resolves to nil), so a stale local row whose Headscale
// counterpart was already removed still gets cleaned up. Order matters:
// Headscale first, local row second, so a Headscale failure leaves the
// row visible in the UI (matching reality) instead of silently dropping
// it from the operator's view.
func (s *Server) handleDeleteMeshDevice(w http.ResponseWriter, r *http.Request) {
	hsID := r.PathValue("hsId")
	if err := s.mesh.Client().DeleteNode(r.Context(), hsID); err != nil {
		writeError(w, http.StatusBadGateway, "headscale delete: "+err.Error())
		return
	}
	if err := s.mesh.Store().DeleteDevice(r.Context(), hsID); err != nil {
		if errors.Is(err, errNoRowsSentinel) || err.Error() == "sql: no rows in result set" {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/mesh/keys — list preauth_key intents. Returns the plaintext
// only on the freshly-created response below; subsequent GETs hide it.
func (s *Server) handleListMeshKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.mesh.Store().ListIntentsByKind(r.Context(), string(proto.IntentPreAuthKey))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if keys == nil {
		keys = []*mesh.Intent{}
	}
	// Hide the secret value on list — only the creation response includes it.
	scrubbed := make([]*mesh.Intent, 0, len(keys))
	for _, k := range keys {
		cp := *k
		cp.HSValue = ""
		scrubbed = append(scrubbed, &cp)
	}
	writeJSON(w, http.StatusOK, scrubbed)
}

// POST /api/mesh/keys
// Body: { "name": "Bryce's MacBook", "deviceHint": "MacBook Pro", ... }
// Creates a preauth_key intent AND immediately runs mesh.apply so the key
// is minted on Headscale. Returns the intent with the plaintext key value
// — this is the only time the value is visible.
func (s *Server) handleCreateMeshKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string   `json:"name"`
		DeviceHint string   `json:"deviceHint"`
		Reusable   bool     `json:"reusable"`
		Ephemeral  bool     `json:"ephemeral"`
		ExpiresIn  string   `json:"expiresIn"`
		Tags       []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.ExpiresIn == "" {
		req.ExpiresIn = "24h"
	}
	if len(req.Tags) == 0 {
		req.Tags = []string{"tag:user-device"}
	}
	spec := proto.PreAuthKeySpec{
		User:       s.mesh.Config().DefaultUser,
		Reusable:   req.Reusable,
		Ephemeral:  req.Ephemeral,
		ExpiresIn:  req.ExpiresIn,
		Tags:       req.Tags,
		DeviceHint: req.DeviceHint,
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now().UTC()
	intent := &mesh.Intent{
		ID:        ulid.Make().String(),
		Kind:      string(proto.IntentPreAuthKey),
		Name:      req.Name,
		Enabled:   true,
		Spec:      specJSON,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.mesh.Store().CreateIntent(r.Context(), intent); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Inline mint (don't make the user wait for a job + poll for a key
	// they need to copy out of the UI right now).
	id, value, err := s.mesh.Client().CreatePreAuthKey(r.Context(), mesh.CreatePreAuthKeyInput{
		User:      spec.User,
		Reusable:  spec.Reusable,
		Ephemeral: spec.Ephemeral,
		Expiry:    now.Add(parseDurationOr(spec.ExpiresIn, 24*time.Hour)),
		Tags:      spec.Tags,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "mint key: "+err.Error())
		return
	}
	if err := s.mesh.Store().SetIntentHSRef(r.Context(), intent.ID, id, value); err != nil {
		writeError(w, http.StatusInternalServerError, "persist hs ref: "+err.Error())
		return
	}
	intent.HSID = id
	intent.HSValue = value

	// Publish a key_created change.
	publishMeshKeyCreated(s, intent.ID, id)

	// Recompute hash on the way out.
	intents, _ := s.mesh.Store().ListIntents(r.Context())
	_, hash, _ := mesh.Compile(intents)
	_ = s.mesh.Store().UpdateAfterApply(r.Context(), hash, now)

	writeJSON(w, http.StatusCreated, intent)
}

// DELETE /api/mesh/keys/{id}
func (s *Server) handleDeleteMeshKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	intent, err := s.mesh.Store().GetIntent(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if intent == nil {
		writeError(w, http.StatusNotFound, "key not found")
		return
	}
	if intent.HSID != "" {
		_ = s.mesh.Client().ExpirePreAuthKey(r.Context(), intent.HSID)
	}
	if err := s.mesh.Store().DeleteIntent(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/mesh/routes — list subnet_route intents.
func (s *Server) handleListMeshRoutes(w http.ResponseWriter, r *http.Request) {
	rows, err := s.mesh.Store().ListIntentsByKind(r.Context(), string(proto.IntentSubnetRoute))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []*mesh.Intent{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// POST /api/mesh/routes
// Body: { "name": "...", "nodeId": "node-fw", "cidr": "10.0.0.0/24" }
func (s *Server) handleCreateMeshRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		NodeID string `json:"nodeId"`
		CIDR   string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Name == "" || req.NodeID == "" || req.CIDR == "" {
		writeError(w, http.StatusBadRequest, "name, nodeId, cidr are required")
		return
	}
	specJSON, _ := json.Marshal(proto.SubnetRouteSpec{NodeID: req.NodeID, CIDR: req.CIDR})
	now := time.Now().UTC()
	intent := &mesh.Intent{
		ID:        ulid.Make().String(),
		Kind:      string(proto.IntentSubnetRoute),
		Name:      req.Name,
		Enabled:   true,
		Spec:      specJSON,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.mesh.Store().CreateIntent(r.Context(), intent); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, intent)
}

// DELETE /api/mesh/routes/{id}
func (s *Server) handleDeleteMeshRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.mesh.Store().DeleteIntent(r.Context(), id); err != nil {
		if errors.Is(err, errNoRowsSentinel) || err.Error() == "sql: no rows in result set" {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/mesh/apply
func (s *Server) handleMeshApply(w http.ResponseWriter, r *http.Request) {
	j, err := s.runner.Submit(r.Context(), "mesh.apply", json.RawMessage("{}"), creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// POST /api/mesh/reconcile
func (s *Server) handleMeshReconcile(w http.ResponseWriter, r *http.Request) {
	j, err := s.runner.Submit(r.Context(), "mesh.reconcile", json.RawMessage("{}"), creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// POST /api/mesh/enroll/{nodeId}
// Body (optional): { "advertiseRoutes": ["10.0.0.0/24"] }
func (s *Server) handleMeshEnrollNode(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("nodeId")
	var req struct {
		AdvertiseRoutes []string `json:"advertiseRoutes"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
	}
	spec, _ := json.Marshal(mesh.EnrollSpec{NodeID: nodeID, AdvertiseRoutes: req.AdvertiseRoutes})
	j, err := s.runner.Submit(r.Context(), "mesh.enroll_node", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// parseDurationOr is a small helper for handlers — kept here to avoid
// re-exporting from mesh.
func parseDurationOr(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// publishMeshKeyCreated emits a key_created change on the bus. Kept local
// because it's a one-shot used only by handleCreateMeshKey's inline-mint
// path; the workflow path emits its own changes.
func publishMeshKeyCreated(s *Server, intentID, hsID string) {
	ev := proto.MeshChangeEvt{
		Scope:     "global",
		Change:    proto.MeshKeyCreated,
		TailnetID: hsID,
		Detail:    intentID,
		Ts:        time.Now().UTC(),
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return
	}
	_ = s.nc.Publish(proto.MeshChangeSubject("global", proto.MeshKeyCreated), payload)
}
