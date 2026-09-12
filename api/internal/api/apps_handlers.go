package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalog"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/oklog/ulid/v2"
)

// appView is an /api/apps row: the app record plus where it stands against
// its backup cadence (design/storage.md §4.4, #298). The backup state rides on
// the row the Apps page already fetches, so the OVERDUE badge costs no second
// request and cannot lag the list it decorates. Absent when no backup ledger
// is wired.
type appView struct {
	*apps.App
	Backup *proto.AppBackupState `json:"backup,omitempty"`
	// UpgradeAvailable says the app's tile, in the catalog in effect, carries
	// a compose other than the installed one (#409). False for a custom app,
	// for a tile the catalog no longer offers, and for a catalog older than
	// the one the app's compose came from. It is apps.ResolveUpgrade's answer,
	// the same function PUT /api/apps/{id}/compose asks for
	// {"source":"catalog"}, so the badge cannot offer an upgrade the route
	// would refuse.
	UpgradeAvailable bool `json:"upgradeAvailable"`
	// UpgradeCatalogVersion is the catalog version an upgrade would take the
	// compose from. Absent unless UpgradeAvailable.
	UpgradeCatalogVersion int `json:"upgradeCatalogVersion,omitempty"`
	// RevertAvailable says the app has a previous compose that PUT
	// /api/apps/{id}/compose would re-apply (#411) — apps.CanRevert's answer.
	// Always present, like upgradeAvailable, so false is never inferred from
	// absence.
	RevertAvailable bool `json:"revertAvailable"`
	// PreviousComposeSHA256 is the hash a re-apply names: {"sha256": this}.
	// A re-apply names its target (#410), so a client needs the hash, and
	// computing it from previousComposeYaml would make every client
	// reimplement ComposeHash byte for byte. Absent unless RevertAvailable.
	PreviousComposeSHA256 string `json:"previousComposeSha256,omitempty"`
}

// newAppView decorates one app row with what the catalog in effect says about
// upgrading it. Backup state is attached by the callers, which fetch it in bulk
// or singly.
func (s *Server) newAppView(a *apps.App) appView {
	v := appView{App: a}
	if target, err := apps.ResolveUpgrade(a, s.tileLookup()); err == nil {
		v.UpgradeAvailable = true
		v.UpgradeCatalogVersion = target.CatalogVersion
	}
	if apps.CanRevert(a) == nil {
		v.RevertAvailable = true
		v.PreviousComposeSHA256 = apps.ComposeHash(a.PreviousComposeYAML)
	}
	return v
}

// tileLookup is the verified catalog store's versioned lookup, or nil when this
// api has no live catalog. Never the embedded catalog: an upgrade's compose
// comes from the store whose bundle was verified, and nothing else.
func (s *Server) tileLookup() apps.TileLookup {
	if s.catalogStore == nil {
		return nil
	}
	return s.catalogStore.GetVersioned
}

// GET /api/apps
func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request) {
	all, err := s.apps.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]appView, 0, len(all))
	for _, a := range all {
		out = append(out, s.newAppView(a))
	}
	if s.backupStates != nil && len(out) > 0 {
		states, err := s.backupStates.AppBackupStates(r.Context())
		if err != nil {
			// The rows are still the answer; a derivation that failed is
			// logged, and the field's absence is what the UI reads as
			// "unknown" — never as "fine".
			log.Printf("apps: backup state: %v", err)
		} else {
			byID := make(map[string]*proto.AppBackupState, len(states))
			for i := range states {
				byID[states[i].AppID] = &states[i].AppBackupState
			}
			for i := range out {
				out[i].Backup = byID[out[i].ID]
			}
		}
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
		inventory.ApplyMesh([]*proto.Node{node}, s.meshMembership(r.Context()))
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
	s.writeAppView(w, r, app)
}

// writeAppView answers 200 with app as GET /api/apps/{id} shows it: the row,
// what the catalog says about upgrading it, and its backup state.
func (s *Server) writeAppView(w http.ResponseWriter, r *http.Request, app *apps.App) {
	view := s.newAppView(app)
	if s.backupStates != nil {
		if st, err := s.backupStates.AppBackupState(r.Context(), app.ID); err != nil {
			// The id is request-supplied and stays out of the log line; so does
			// anything else from the request.
			log.Printf("apps: backup state (GET /api/apps/{id} or a no-op PUT .../compose): %v", err)
		} else {
			view.Backup = st
		}
	}
	writeJSON(w, http.StatusOK, view)
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
// Body (optional): { "deleteVolumes": true }
//
// Runs the app.delete saga: stop the running deployment on the target node
// (docker compose down) THEN remove the api's record — so delete actually tears
// the containers down instead of orphaning them. Async, like deploy/stop:
// returns the job; the row disappears on the `deleted` change event once the
// stop completes. On a reachable node the stop must succeed or the delete fails
// (the record stays); on an unreachable node it removes the record with a
// logged warning.
//
// deleteVolumes is the operator's answer to "Delete volumes?" on the uninstall
// confirmation (geekdojo/geekdojo-brain#399). No body, or false, keeps the
// app's named volumes on the node — the pre-#399 behaviour and the default.
// True makes the stop a `compose down -v`, and makes an unreachable node a
// refusal rather than a warning: data the operator asked to destroy is not
// left behind as an orphan they believe is gone. Decoded strictly for the same
// reason every job-spec body is: it is persisted and rendered, and the one
// field that destroys data must be spelled the way it was declared.
func (s *Server) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if existing, _ := s.apps.Get(r.Context(), id); existing == nil {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	var req struct {
		DeleteVolumes bool `json:"deleteVolumes"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	if len(bytes.TrimSpace(body)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
	}
	spec, _ := json.Marshal(apps.DeleteSpec{AppID: id, DeleteVolumes: req.DeleteVolumes})
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

// maxComposeBody caps a PUT /api/apps/{id}/compose body. A compose file is a
// few kilobytes; a megabyte is room for any real one, and the whole body is
// read into memory and held until its job ends.
const maxComposeBody = 1 << 20

// composeRequest is the body of PUT /api/apps/{id}/compose. Exactly one field
// is set; pointers, so a field that is present is told apart from one that is
// absent.
type composeRequest struct {
	Source      *string `json:"source"`
	ComposeYAML *string `json:"composeYaml"`
	SHA256      *string `json:"sha256"`
	// DeleteVolumes rides beside whichever of the three is set: the named
	// volumes the owner asks to delete because the change drops them (#412).
	// Not a fourth variant, so it is not counted among them.
	DeleteVolumes []string `json:"deleteVolumes"`
}

// PUT /api/apps/{id}/compose
//
// The app's compose, as one resource (geekdojo/geekdojo-brain#410). The body
// names the compose the app should run, in one of three ways:
//
//	{"source": "catalog"}   its tile's compose in the verified catalog (#409) — catalog apps only
//	{"composeYaml": "…"}    a compose the owner supplies — custom apps only
//	{"sha256": "<hash>"}    the installed or retained previous compose with that hash (#411) — both
//
// Every change runs in place, as a job whose first step pulls the new
// compose's images and changes nothing if that fails: app.upgrade, app.edit
// and app.revert respectively. The app keeps its ULID, so its Compose project
// and named volumes are the ones it already has. 202 with the job.
//
// PUT is idempotent, and so is this. A body naming the compose that is already
// installed — the tile's current compose, the installed compose's own hash, or
// the same composeYaml again — changes nothing, starts no job, and answers 200
// with the app as GET /api/apps/{id} shows it.
//
// Refusals come before a job exists. 404 for an unknown app. 400 for a body
// that is not JSON, names an unknown field, or sets none or more than one of
// the three (an ambiguous request is not guessed at), and for a source other
// than "catalog", an empty composeYaml, or a sha256 that is not a sha256. 409
// for a body the app's kind does not allow — composeYaml on a catalog app,
// whose compose changes only to a signed tile's or back to one that already
// ran; source catalog on a custom app — and for everything the upgrade refuses
// (a tile the catalog in effect does not offer, a catalog older than the app's
// compose), and for a sha256 that is neither the installed compose nor the
// retained previous one.
//
// A composeYaml is not validated, as it is not at custom create (ADR-0006
// D12). It is also never put in the job's spec: specs are rendered on the
// Tasks page, and a custom compose can inline secrets. It is held in the
// ComposeStash under the job's id before the job starts, read from there by
// the job's pull and persist steps, and discarded when the job ends.
//
// No privilege re-consent is asked for here: consent is the UI's, as it is at
// install (Bryce, 2026-09-12).
//
// A change must not orphan a volume (#412). A compose that no longer declares
// a named volume the app has on disk — a renamed key, a dropped service — is
// refused with 409 and the list of those volumes (volumeGateResponse), unless
// the body's optional "deleteVolumes" names exactly them; they are then
// deleted once the new compose is up. Every name must be one of this app's
// named volumes, rasp_<appid>_<volume>, and appear once, or the body is a 400.
// A name the change does not drop — one the new compose still declares, or
// one not on the node — is a 409, since a volume the compose declares is never
// deleted. This check asks the node and is advisory: when it gets no answer
// the job starts anyway, and the job's pull step applies the same gate before
// it changes anything. A body that is already installed is still the 200
// no-op, whatever deleteVolumes says.
func (s *Server) handlePutAppCompose(w http.ResponseWriter, r *http.Request) {
	app, err := s.apps.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxComposeBody+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	if len(body) > maxComposeBody {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body larger than %d bytes", maxComposeBody))
		return
	}
	var req composeRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid JSON body: more than one JSON value")
		return
	}
	set := 0
	for _, f := range []*string{req.Source, req.ComposeYAML, req.SHA256} {
		if f != nil {
			set++
		}
	}
	if set != 1 {
		writeError(w, http.StatusBadRequest, `name exactly one of "source", "composeYaml" or "sha256"`)
		return
	}

	switch {
	case req.Source != nil:
		s.putComposeFromCatalog(w, r, app, *req.Source, req.DeleteVolumes)
	case req.ComposeYAML != nil:
		s.putComposeYAML(w, r, app, *req.ComposeYAML, req.DeleteVolumes)
	default:
		s.putComposeByHash(w, r, app, *req.SHA256, req.DeleteVolumes)
	}
}

// putComposeFromCatalog is {"source":"catalog"}: upgrade to the tile's
// compose. apps.ResolveUpgrade decides, the same function the upgradeAvailable
// flag and the saga ask, so the badge cannot offer an upgrade this refuses.
// The compose itself is not taken from the request; the saga resolves it from
// the verified store when it runs.
func (s *Server) putComposeFromCatalog(w http.ResponseWriter, r *http.Request, app *apps.App, source string, deleteVolumes []string) {
	if source != "catalog" {
		writeError(w, http.StatusBadRequest, `source must be "catalog"`)
		return
	}
	target, err := apps.ResolveUpgrade(app, s.tileLookup())
	switch {
	case errors.Is(err, apps.ErrUpgradeAlreadyCurrent):
		s.writeAppView(w, r, app)
		return
	case err != nil:
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	named, ok := s.deleteVolumesFor(w, app, deleteVolumes)
	if !ok {
		return
	}
	if s.refuseDroppedVolumes(w, r, app, named, s.catalogDropped(r, app, target.Tile)) {
		return
	}
	s.submitComposeJob(w, r, "app.upgrade", apps.ComposeChangeSpec{AppID: app.ID, DeleteVolumes: named}, nil)
}

// putComposeYAML is {"composeYaml":"…"}: replace a custom app's compose.
func (s *Server) putComposeYAML(w http.ResponseWriter, r *http.Request, app *apps.App, compose string, deleteVolumes []string) {
	if strings.TrimSpace(compose) == "" {
		writeError(w, http.StatusBadRequest, "composeYaml must not be empty")
		return
	}
	if app.SourceTile != "" {
		writeError(w, http.StatusConflict, apps.ErrEditCatalogApp.Error())
		return
	}
	if apps.ComposeHash(compose) == app.ComposeSHA256 {
		s.writeAppView(w, r, app)
		return
	}
	if s.composeStash == nil {
		writeError(w, http.StatusServiceUnavailable, "compose editing is not available on this api")
		return
	}
	named, ok := s.deleteVolumesFor(w, app, deleteVolumes)
	if !ok {
		return
	}
	if s.refuseDroppedVolumes(w, r, app, named, s.nodeDropped(r, app, compose)) {
		return
	}
	s.submitComposeJob(w, r, "app.edit", apps.ComposeChangeSpec{AppID: app.ID, DeleteVolumes: named}, func(jobID string) error {
		return s.composeStash.Put(jobID, compose)
	})
}

// putComposeByHash is {"sha256":"…"}: re-apply the compose with that hash.
func (s *Server) putComposeByHash(w http.ResponseWriter, r *http.Request, app *apps.App, sha string, deleteVolumes []string) {
	sha = strings.ToLower(sha)
	if !apps.ValidComposeHash(sha) {
		writeError(w, http.StatusBadRequest, "sha256 must be the 64 hex digits of a compose's sha256")
		return
	}
	current, err := apps.ResolveReapply(app, sha)
	switch {
	case err != nil:
		writeError(w, http.StatusConflict, err.Error())
		return
	case current:
		s.writeAppView(w, r, app)
		return
	}
	named, ok := s.deleteVolumesFor(w, app, deleteVolumes)
	if !ok {
		return
	}
	// ResolveReapply said sha is the retained previous compose, so that is
	// the compose the node is asked about.
	if s.refuseDroppedVolumes(w, r, app, named, s.nodeDropped(r, app, app.PreviousComposeYAML)) {
		return
	}
	s.submitComposeJob(w, r, "app.revert", apps.RevertSpec{AppID: app.ID, ComposeSHA256: sha, DeleteVolumes: named}, nil)
}

// submitComposeJob starts a compose change and answers 202 with its job.
// stash, when set, runs with the job's id before the job starts, so a compose
// that must not be in the spec is where the job will look for it by the time
// its first step runs.
func (s *Server) submitComposeJob(w http.ResponseWriter, r *http.Request, kind string, spec any, stash func(jobID string) error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var stashedFor string
	prepare := func(jobID string) error {
		if stash == nil {
			return nil
		}
		if err := stash(jobID); err != nil {
			return err
		}
		stashedFor = jobID
		return nil
	}
	j, err := s.runner.SubmitPrepared(r.Context(), kind, raw, creator(r), prepare)
	if err != nil {
		// No job will run under that id, so no OnTerminal will discard what
		// was held for it.
		if stashedFor != "" {
			s.composeStash.Discard(stashedFor)
		}
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
