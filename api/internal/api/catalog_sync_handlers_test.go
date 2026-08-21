package api

import (
	"encoding/json"
	"net/http"
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
