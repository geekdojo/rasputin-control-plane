package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalog"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/oklog/ulid/v2"
)

// effectiveTiles is the catalog in effect: the most recent verified fetch, or
// the embedded floor if no fetch has ever succeeded (ADR-0006 Decision 6).
//
// Never a union of the two. A merge would make "which tile is live" depend on
// two sources with no obvious precedence, which is the two-sources-of-truth
// failure this project has already been bitten by twice.
func (s *Server) effectiveTiles() []catalog.Tile {
	if s.catalogStore == nil {
		return s.catalog.All()
	}
	b := s.catalogStore.Current()
	out := make([]catalog.Tile, 0, len(b.Tiles))
	for _, bt := range b.Tiles {
		t := bt.Tile
		t.ComposeYAML = bt.Compose
		out = append(out, t)
	}
	return out
}

func (s *Server) effectiveTile(id string) (catalog.Tile, bool) {
	if s.catalogStore == nil {
		return s.catalog.Get(id)
	}
	for _, bt := range s.catalogStore.Current().Tiles {
		if bt.Tile.ID == id {
			t := bt.Tile
			t.ComposeYAML = bt.Compose
			return t, true
		}
	}
	return catalog.Tile{}, false
}

// GET /api/catalog — list every curated tile in display order.
func (s *Server) handleListCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.effectiveTiles())
}

// GET /api/catalog/{id} — one tile, including its compose YAML so advanced
// users can preview exactly what they're installing. The list view omits the
// compose (it's `json:"-"` on the Tile) to stay lean; the detail view adds it
// back explicitly.
func (s *Server) handleGetCatalogTile(w http.ResponseWriter, r *http.Request) {
	t, ok := s.effectiveTile(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "catalog tile not found")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		catalog.Tile
		ComposeYAML string `json:"composeYaml"`
	}{Tile: t, ComposeYAML: t.ComposeYAML})
}

// POST /api/catalog/{id}/install — create an app instance from a tile.
// Body: { "targetNode": "node-dev", "name": "jellyfin" (optional) }
//
// Install only declares the app (seeding compose + published port from the
// tile); it does NOT deploy — the caller POSTs /api/apps/{id}/deploy after,
// same as a hand-authored app. Keeps the create/deploy split consistent.
func (s *Server) handleInstallCatalogTile(w http.ResponseWriter, r *http.Request) {
	tile, ok := s.effectiveTile(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "catalog tile not found")
		return
	}
	if !tile.Available() {
		writeError(w, http.StatusConflict, "this app is a preview and isn't available to install yet")
		return
	}

	var req struct {
		TargetNode string `json:"targetNode"`
		Name       string `json:"name"`
		// ExposeLAN opts the app into LAN reachability (ADR-0004 §9). Absent →
		// false (tailnet-only). The tile's ExposureDefault is a UI hint for
		// pre-filling this; the stored default stays tailnet-only unless the
		// operator explicitly opts in.
		ExposeLAN bool `json:"exposeLan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	req.TargetNode = strings.TrimSpace(req.TargetNode)
	req.Name = strings.TrimSpace(req.Name)
	if req.TargetNode == "" {
		writeError(w, http.StatusBadRequest, "targetNode is required")
		return
	}
	// Default the instance name to the tile id (already a DNS-safe label).
	// Normalize operator input the same way handleCreateApp does — the name
	// becomes a DNS label + TLS SAN (ADR-0004 §4/§5).
	name := normalizeAppName(req.Name)
	if name == "" {
		name = tile.ID
	}
	if !validAppName(name) {
		writeError(w, http.StatusBadRequest, appNameRuleMsg)
		return
	}

	// Validate the target node exists and can run apps.
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
	// Arch gate: block only on a clear mismatch. An unreported arch ("") is
	// allowed through — we don't fail on missing inventory data.
	if tile.Arch != "both" && node.Architecture != "" && node.Architecture != tile.Arch {
		writeError(w, http.StatusBadRequest,
			"this app requires a "+tile.Arch+" node; the selected node is "+node.Architecture)
		return
	}

	if existing, _ := s.apps.GetByName(r.Context(), name); existing != nil {
		writeError(w, http.StatusConflict, "an app with that name already exists")
		return
	}

	now := time.Now().UTC()
	app := &apps.App{
		ID:            ulid.Make().String(),
		Name:          name,
		ComposeYAML:   tile.ComposeYAML,
		TargetNode:    req.TargetNode,
		PublishedPort: tile.PrimaryPort(),
		SourceTile:    tile.ID,
		// The tile's budget is COPIED, not looked up at deploy time: a catalog
		// update can change the tile under a running install, and the budget a
		// deploy is judged against should be the one the owner installed.
		DeployBudgetSeconds: tile.DeployBudgetSeconds,
		ExposeLAN:           req.ExposeLAN,
		LastStatus:          proto.AppStatusStopped,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.apps.Create(r.Context(), app); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, app)
}
