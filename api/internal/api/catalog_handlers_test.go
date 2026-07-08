package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func TestCatalog_ListAndGet(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	w := f.do(t, http.MethodGet, "/api/catalog", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	for _, id := range []string{"jellyfin", "pi-hole", "uptime-kuma"} {
		if !strings.Contains(w.Body.String(), `"id":"`+id+`"`) {
			t.Errorf("catalog list missing %q", id)
		}
	}

	w = f.do(t, http.MethodGet, "/api/catalog/jellyfin", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "jellyfin/jellyfin:") {
		t.Errorf("tile detail should include compose YAML, got %s", w.Body.String())
	}

	w = f.do(t, http.MethodGet, "/api/catalog/does-not-exist", "", cookie)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown tile: want 404, got %d", w.Code)
	}
}

// TestCatalog_InstallPersistsPort is the guard-1 end-to-end check: installing a
// tile must persist its primary published port onto the app record so the
// future reverse proxy can route without parsing compose YAML.
func TestCatalog_InstallPersistsPort(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "pi-1", Role: proto.RoleCompute, Hostname: "pi", Architecture: "arm64",
	}); err != nil {
		t.Fatalf("seed node: %v", err)
	}

	w := f.do(t, http.MethodPost, "/api/catalog/jellyfin/install", `{"targetNode":"pi-1"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("install: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"publishedPort":8096`) {
		t.Errorf("install response should carry publishedPort 8096, got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"sourceTile":"jellyfin"`) {
		t.Errorf("install should record the source tile, got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"name":"jellyfin"`) {
		t.Errorf("install should default the name to the tile id, got %s", w.Body.String())
	}

	// The port must survive a round-trip through the store.
	w = f.do(t, http.MethodGet, "/api/apps", "", cookie)
	if !strings.Contains(w.Body.String(), `"publishedPort":8096`) {
		t.Errorf("app list should show persisted publishedPort, got %s", w.Body.String())
	}

	// Re-installing the same tile collides on the unique name.
	w = f.do(t, http.MethodPost, "/api/catalog/jellyfin/install", `{"targetNode":"pi-1"}`, cookie)
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate install: want 409, got %d", w.Code)
	}
}

func TestCatalog_InstallRejectsBadTarget(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	w := f.do(t, http.MethodPost, "/api/catalog/navidrome/install", `{"targetNode":"ghost"}`, cookie)
	if w.Code != http.StatusBadRequest {
		t.Errorf("unregistered node: want 400, got %d (%s)", w.Code, w.Body.String())
	}

	w = f.do(t, http.MethodPost, "/api/catalog/does-not-exist/install", `{"targetNode":"pi-1"}`, cookie)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown tile install: want 404, got %d", w.Code)
	}
}
