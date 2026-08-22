package api

import (
	"encoding/json"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The route hazard this endpoint was named around: tile ids are DNS-1123
// labels, "status" is a legal one, and GET /api/catalog/{id} already exists.
// A literal /api/catalog/status route would shadow a publishable tile. The
// underscore makes the namespaces disjoint by construction, and this test
// pins that property rather than trusting anyone to remember it.
func TestCatalogSync_StatusPathCannotCollideWithATileID(t *testing.T) {
	for _, id := range []string{"status", "refresh"} {
		if !tileschema.ValidDNSLabel(id) {
			t.Errorf("%q is not a legal tile id, so the collision this route avoids is imaginary — re-check the naming", id)
		}
	}
	for _, seg := range []string{"_status", "_refresh"} {
		if tileschema.ValidDNSLabel(seg) {
			t.Fatalf("%q became a legal tile id; the endpoint namespace is no longer disjoint", seg)
		}
	}
}

// Without the sync machinery configured, the api must report itself as serving
// the embedded catalog rather than erroring. That is the airgapped case and it
// is a normal state, not a fault.
func TestCatalogSync_StatusFallsBackToEmbedded(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	w := f.do(t, http.MethodGet, "/api/catalog/_status", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var got catalogStatus
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Source != "embedded" {
		t.Errorf("source = %q, want embedded", got.Source)
	}
	if got.Tiles == 0 {
		t.Error("an unconfigured api still serves the embedded tiles; count must not be zero")
	}
	if got.Checked != nil {
		t.Error("lastChecked must be null when nothing has ever polled — the UI needs to tell that apart from a poll that found nothing")
	}
}

// The _status route must win over {id}. Go's mux prefers the more specific
// pattern; this asserts it rather than assuming it, because getting it wrong
// returns a plausible 404 that looks like a missing tile.
func TestCatalogSync_StatusRouteIsNotSwallowedByTheTileRoute(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	w := f.do(t, http.MethodGet, "/api/catalog/_status", "", cookie)
	if w.Code == http.StatusNotFound {
		t.Fatal("_status was routed to the tile handler and 404'd")
	}
	if !strings.Contains(w.Body.String(), `"source"`) {
		t.Errorf("did not get a status document: %s", w.Body.String())
	}
}

// Refresh with no poller is a configuration state, not a server fault.
func TestCatalogSync_RefreshWithoutAPollerIsUnavailable(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	w := f.do(t, http.MethodPost, "/api/catalog/_refresh", "", cookie)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d (%s)", w.Code, w.Body.String())
	}
}

// Both endpoints sit behind auth like the rest of the catalog surface.
func TestCatalogSync_RequiresAuth(t *testing.T) {
	f := newAPIFixture(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/catalog/_status"},
		{http.MethodPost, "/api/catalog/_refresh"},
	} {
		w := f.do(t, c.method, c.path, "", nil)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: want 401 unauthenticated, got %d", c.method, c.path, w.Code)
		}
	}
}

// The payoff of #161: once a verified catalog is in effect, the tile endpoints
// serve IT, not the copy baked into the binary. Without this the floor and the
// fetch would both exist and the api would quietly keep showing the old one.
func TestCatalogSync_HandlersServeTheFetchedCatalogNotTheFloor(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	// A floor that is deliberately NOT the embedded one, so "served the floor"
	// and "served the fetch" are distinguishable in the response body.
	floorBundle := oneTileBundle(1, "floor-only-tile")
	store, err := catalogsync.New(t.TempDir(), stubVerifier{}, floorBundle)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	f.srv.SetCatalogSync(store, nil)

	w := f.do(t, http.MethodGet, "/api/catalog", "", cookie)
	if !strings.Contains(w.Body.String(), "floor-only-tile") {
		t.Fatalf("list should serve the store's floor, got %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"id":"jellyfin"`) {
		t.Error("the embedded catalog leaked through while a store was configured")
	}

	// Now a verified fetch supersedes it.
	dir := t.TempDir()
	raw, err := json.MarshalIndent(oneTileBundle(2, "fetched-tile"), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	bp := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(bp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bp+".sig", []byte("sig"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(bp, bp+".sig"); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	w = f.do(t, http.MethodGet, "/api/catalog", "", cookie)
	if !strings.Contains(w.Body.String(), "fetched-tile") {
		t.Fatalf("list should now serve the fetched catalog, got %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "floor-only-tile") {
		t.Error("the floor is still being served after a successful fetch; resolution is one source, not a union")
	}

	w = f.do(t, http.MethodGet, "/api/catalog/_status", "", cookie)
	var st catalogStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Source != "fetched" || st.Version != 2 {
		t.Errorf("status = %s v%d, want fetched v2", st.Source, st.Version)
	}
}

type stubVerifier struct{}

func (stubVerifier) VerifyForPurpose(artifactPath, sigPath string) error { return nil }

func oneTileBundle(version int, id string) tileschema.Bundle {
	return tileschema.Bundle{
		SchemaVersion: tileschema.BundleSchemaVersion,
		Version:       version,
		PublishedAt:   "2026-08-21T00:00:00Z",
		Tiles: []tileschema.BundleTile{{
			Tile: tileschema.Tile{
				ID: id, Name: "N", Tagline: "t", Description: "d",
				Collection: tileschema.CollectionEssentials, Arch: "both",
				ExposureDefault: "lan-only", RAMFloorMB: 256,
				Status: tileschema.StatusPreview,
			},
		}},
	}
}

// A refused tile must be visible to an operator, not merely absent. Without
// this the catalog just quietly has fewer apps in it and there is nothing to
// search for (#162, ADR-0006 Decision 7).
func TestCatalogSync_StatusReportsRefusedTiles(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	store, err := catalogsync.New(t.TempDir(), stubVerifier{}, oneTileBundle(1, "floor-tile"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	f.srv.SetCatalogSync(store, nil)

	// A v2 carrying one acceptable tile and one this build cannot understand.
	b := oneTileBundle(2, "keeper")
	future := b.Tiles[0]
	future.Tile.ID = "from-the-future"
	future.Tile.Requires = []string{"tile.capability-from-the-future"}
	b.Tiles = append(b.Tiles, future)

	dir := t.TempDir()
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	bp := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(bp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bp+".sig", []byte("sig"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(bp, bp+".sig"); err != nil {
		t.Fatalf("one unreadable tile must not cost the catalog: %v", err)
	}

	w := f.do(t, http.MethodGet, "/api/catalog", "", cookie)
	if !strings.Contains(w.Body.String(), "keeper") {
		t.Errorf("the acceptable tile should be served, got %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "from-the-future") {
		t.Error("a refused tile was served anyway")
	}

	w = f.do(t, http.MethodGet, "/api/catalog/_status", "", cookie)
	var st catalogStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if st.Version != 2 || st.Tiles != 1 {
		t.Errorf("want v2 with 1 served tile, got v%d with %d", st.Version, st.Tiles)
	}
	if len(st.Rejected) != 1 || st.Rejected[0].ID != "from-the-future" {
		t.Fatalf("the refusal must be reported, got %+v", st.Rejected)
	}
	if !strings.Contains(st.Rejected[0].Reason, "unknown capability") {
		t.Errorf("the reason must say why, got %q", st.Rejected[0].Reason)
	}
}
