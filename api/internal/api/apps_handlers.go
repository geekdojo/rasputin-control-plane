package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalog"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/oklog/ulid/v2"
)

// GET /api/apps
func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request) {
	out, err := s.apps.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []*apps.App{}
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/apps
// Body: { "name": "minecraft", "composeYaml": "...", "targetNode": "node-dev" }
func (s *Server) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		ComposeYAML string `json:"composeYaml"`
		TargetNode  string `json:"targetNode"`
		// ExposeLAN opts the app into LAN reachability (ADR-0004 §9). Absent →
		// false: tailnet-only by default; LAN is always an explicit opt-in.
		ExposeLAN bool `json:"exposeLan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	req.Name = normalizeAppName(req.Name)
	req.TargetNode = strings.TrimSpace(req.TargetNode)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !validAppName(req.Name) {
		writeError(w, http.StatusBadRequest, appNameRuleMsg)
		return
	}
	if strings.TrimSpace(req.ComposeYAML) == "" {
		writeError(w, http.StatusBadRequest, "composeYaml is required")
		return
	}
	if req.TargetNode == "" {
		writeError(w, http.StatusBadRequest, "targetNode is required")
		return
	}

	// Validate target node exists.
	node, err := s.inv.Get(r.Context(), req.TargetNode)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node == nil {
		writeError(w, http.StatusBadRequest, "target node not registered")
		return
	}
	if node.Role != proto.RoleCompute {
		writeError(w, http.StatusBadRequest, appTargetRoleMsg)
		return
	}

	if existing, _ := s.apps.GetByName(r.Context(), req.Name); existing != nil {
		writeError(w, http.StatusConflict, "an app with that name already exists")
		return
	}

	// A tailnet-only app on a node that is not on the tailnet cannot work: the
	// proxy binds the tailnet interface, and there is no tailnet interface. The
	// install would "succeed" and the app would be unreachable, with the node
	// showing green the whole time because its agent heartbeat rides the LAN
	// (geekdojo/geekdojo-brain#202). Refuse at install — the one moment the
	// mismatch is cheap to fix.
	//
	// Gated on KnownAbsent, not on "not joined": undetermined membership must
	// not block an operator whose cluster has no mesh service at all.
	if !req.ExposeLAN {
		applyMeshMembership([]*proto.Node{node}, s.meshMembership(r.Context()))
		if node.Mesh.KnownAbsent() {
			writeError(w, http.StatusConflict, tailnetOnlyOffMeshMsg(req.TargetNode, node.Mesh))
			return
		}
	}

	now := time.Now().UTC()
	app := &apps.App{
		ID:          ulid.Make().String(),
		Name:        req.Name,
		ComposeYAML: req.ComposeYAML,
		TargetNode:  req.TargetNode,
		ExposeLAN:   req.ExposeLAN,
		LastStatus:  proto.AppStatusStopped,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.apps.Create(r.Context(), app); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, app)
}

// GET /api/apps/{id}
func (s *Server) handleGetApp(w http.ResponseWriter, r *http.Request) {
	app, err := s.apps.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	writeJSON(w, http.StatusOK, app)
}

// PATCH /api/apps/{id}
// Body: { "exposeLan": false }
//
// The reverse edge LAN exposure never had (#197). ExposeLAN was set once from
// the create payload and never updated, so withdrawing LAN reachability meant
// DELETING the app — for any tile with volumes, choosing between leaving it on
// the LAN and destroying its data. A security control must not force that.
//
// Only exposeLan is patchable, and deliberately so. The compose was signed and
// installed; an exposure toggle has no business rewriting it, and a general
// "update the app" route is how it would grow the ability to.
//
// The flip is not just a database write. The .lan name is a route on the
// proxy's LAN listener, so revoking it has to reach the node before it means
// anything. RotateAppLeaf asserts the app's desired state unconditionally, so
// the new exposure ships simply by running it — there is no "did anything
// change?" question to get wrong. Running it NOW rather than at the next sweep
// is the whole point of this call. An offline node is not an error: the next
// sweep re-asserts, so the change lands when the node returns.
func (s *Server) handleUpdateApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	app, err := s.apps.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}

	var body struct {
		ExposeLAN *bool `json:"exposeLan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.ExposeLAN == nil {
		writeError(w, http.StatusBadRequest, "nothing to update: exposeLan is the only patchable field")
		return
	}
	if *body.ExposeLAN == app.ExposeLAN {
		writeJSON(w, http.StatusOK, app) // already there; re-minting would be churn
		return
	}

	if err := s.apps.SetExposeLAN(r.Context(), id, *body.ExposeLAN, time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	app.ExposeLAN = *body.ExposeLAN

	// Re-mint and re-ship against the NEW exposure. Reported but not fatal: the
	// record is already authoritative for DNS, and the rotation sweep is the
	// backstop for the proxy half.
	if s.rotateAppLeaf != nil {
		if res := apps.RotateAppLeaf(r.Context(), s.inv, s.nc, s.rotateAppLeaf, app); res.Err != nil {
			writeJSON(w, http.StatusOK, struct {
				*apps.App
				LeafWarning string `json:"leafWarning"`
			}{app, res.Err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, app)
}

// DELETE /api/apps/{id}
// Runs the app.delete saga: stop the running deployment on the target node
// (docker compose down) THEN remove the api's record — so delete actually tears
// the containers down instead of orphaning them. Async, like deploy/stop:
// returns the job; the row disappears on the `deleted` change event once the
// stop completes. On a reachable node the stop must succeed or the delete fails
// (the record stays); on an unreachable node it removes the record with a
// logged warning.
func (s *Server) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if existing, _ := s.apps.Get(r.Context(), id); existing == nil {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	spec, _ := json.Marshal(apps.DeleteSpec{AppID: id})
	j, err := s.runner.Submit(r.Context(), "app.delete", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// POST /api/apps/{id}/deploy
func (s *Server) handleDeployApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	spec, _ := json.Marshal(map[string]string{"appId": id})
	j, err := s.runner.Submit(r.Context(), "app.deploy", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// POST /api/apps/{id}/stop
func (s *Server) handleStopApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	spec, _ := json.Marshal(map[string]string{"appId": id})
	j, err := s.runner.Submit(r.Context(), "app.stop", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// normalizeAppName lower-cases and trims an operator-supplied app name. The
// name becomes a DNS label and a TLS SAN (ADR-0004 §4), and DNS labels are
// case-insensitive — so we canonicalize to lowercase on input. Because every
// new row is stored lowercase, the existing BINARY-collated `name UNIQUE`
// constraint then enforces case-insensitive uniqueness on the write path
// (`Jellyfin` and `jellyfin` both normalize to one key), which is the
// "lowercase-normalize before store + compare" option ADR-0004 §5 sanctions in
// lieu of rebuilding the table with COLLATE NOCASE. Pre-fix mixed-case rows are
// grandfathered: they stay until renamed and, per ADR §5, get no DNS record /
// cert until they pass validAppName (a Phase-B concern, once records exist).
func normalizeAppName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// appTargetRoleMsg is the 400 body when someone aims an app at a node that
// cannot host one. Apps run on COMPUTE nodes only.
//
// The controlplane node is excluded deliberately, and it is the reason this
// message exists. rasputin-api owns :443 there — the OS image's unit sets
// RASPUTIN_HTTPS_ADDR=:443, the wildcard — so the node-local Caddy that fronts
// apps can never bind the port it needs. Nothing about that is visible from the
// deploy: the leaf is delivered, the saga logs "delivered TLS leaf + proxy
// route", the app reports RUNNING, and its name resolves to the control plane
// and serves the control plane's own cert and 404. Measured on e3bench
// 2026-08-23 with a 12s deploy that never went near a timeout.
//
// Refusing up front is not the end state — a one-node cluster is a topology we
// want, and that needs the two to share the port properly. It is the honest
// state until then: an install that cannot work should fail where the operator
// is standing, not five minutes later as an app that looks healthy and answers
// nothing.
const appTargetRoleMsg = "apps run on compute nodes only — the controlplane node cannot host them yet, because the control plane itself owns the HTTPS port an app would need"

// appNameRuleMsg is the 400 body when a name fails validAppName. It describes
// the post-normalization rule (input is already lower-cased), so it omits the
// case requirement to avoid confusing an operator who typed mixed case.
const appNameRuleMsg = "name must be a DNS-safe label: 1-32 chars of lowercase letters, digits, and hyphens, not starting or ending with a hyphen"

// validAppName reports whether s is a strict RFC 1123 DNS label short enough to
// be an app name, the constraint ADR-0004 §5 requires now that the name is
// load-bearing for DNS and TLS. The old check accepted `[a-zA-Z0-9_-]`, which
// allowed three things that break once the name is a hostname + dNSName SAN:
// underscores, leading/trailing hyphens, and uppercase (which collided with the
// case-sensitive UNIQUE). It reuses catalog.ValidDNSLabel — the same Guard #2
// predicate that keeps every catalog id usable as `<app>.<cluster-domain>` — and
// only tightens the length cap from the 63-char DNS-label max to 32 for app
// names. It is deliberately strict on case: callers normalizeAppName first, so
// uppercase input is folded to lowercase before it reaches here.
func validAppName(s string) bool {
	return len(s) <= 32 && catalog.ValidDNSLabel(s)
}

// tailnetOnlyOffMeshMsg explains a refused tailnet-only install. It names how
// long the node has been off the mesh, because "is this a blip or has it been
// broken for a month?" is the question the old reporting made unanswerable, and
// it states both ways forward so the operator is not left guessing.
func tailnetOnlyOffMeshMsg(nodeID string, m *proto.MeshMembership) string {
	var b strings.Builder
	fmt.Fprintf(&b, "node %s is not on the tailnet, so it cannot serve a tailnet-only app", nodeID)
	if m != nil && m.LastSeen != nil {
		fmt.Fprintf(&b, " (last seen on the mesh %s, %s ago)",
			m.LastSeen.UTC().Format(time.RFC3339),
			time.Since(*m.LastSeen).Truncate(time.Minute))
	}
	b.WriteString(". The node is reachable on the LAN — that is what its status reflects — but mesh membership is a separate property. ")
	b.WriteString("Either bring the node back onto the mesh, or install with exposeLan: true to reach it over the LAN instead.")
	return b.String()
}
