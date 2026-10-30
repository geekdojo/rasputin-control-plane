package api

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// operatorSecretsBundleTile is a live, installable tile that declares an
// operator-supplied secret its compose uses (#780).
func operatorSecretsBundleTile() tileschema.BundleTile {
	bt := oneTileBundle(upgradeCatalogVersion, "feeds").Tiles[0]
	image := "e/feeds:1@sha256:" + strings.Repeat("c", 64)
	bt.Tile.Status = ""
	bt.Tile.Requires = []string{tileschema.CapabilityTileSecrets, tileschema.CapabilityOperatorSecrets}
	bt.Tile.OperatorSecrets = []tileschema.OperatorSecret{{Name: "feed-key", Label: "Feed API key"}}
	bt.Compose = "services:\n  feeds:\n    image: " + image + "\n    environment:\n      FEED_KEY: ${secret:feed-key}\n"
	bt.Tile.ComposeYAML = bt.Compose
	bt.Safety = tileschema.SafetyFacts{Images: []string{image}}
	return bt
}

// TC-780-09: install copies the tile's declarations onto the stored app, and a
// tile without any installs with none.
func TestCatalogInstall_CopiesOperatorSecrets(t *testing.T) {
	f, cookie, _, _ := upgradeFixtureWith(t, operatorSecretsBundleTile())

	w := f.do(t, http.MethodPost, "/api/catalog/feeds/install", `{"targetNode":"n1"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("install: %d %s", w.Code, w.Body.String())
	}
	created := decodeBody[apps.App](t, w.Body.String())
	got, err := f.appsStore.Get(f.ctx, created.ID)
	if err != nil || got == nil {
		t.Fatalf("Get: %v, %v", got, err)
	}
	want := []tileschema.OperatorSecret{{Name: "feed-key", Label: "Feed API key"}}
	if !reflect.DeepEqual(got.OperatorSecrets, want) {
		t.Errorf("stored declarations %+v, want %+v", got.OperatorSecrets, want)
	}

	w = f.do(t, http.MethodPost, "/api/catalog/jellyfin/install", `{"targetNode":"n1"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("install jellyfin: %d %s", w.Code, w.Body.String())
	}
	plain := decodeBody[apps.App](t, w.Body.String())
	got, err = f.appsStore.Get(f.ctx, plain.ID)
	if err != nil || got == nil {
		t.Fatalf("Get: %v, %v", got, err)
	}
	if got.OperatorSecrets != nil {
		t.Errorf("a tile with no declarations installed with %+v", got.OperatorSecrets)
	}
}
