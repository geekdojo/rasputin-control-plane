package catalog

import (
	"strings"
	"testing"
	"testing/fstest"
)

// TestShippedCatalogLoads is the CI gate behind MustLoad: every embedded tile
// must parse and pass validation, ids must be unique, and every tile with
// ports must name exactly one primary.
func TestShippedCatalogLoads(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("embedded catalog failed to load: %v", err)
	}
	all := c.All()
	if len(all) == 0 {
		t.Fatal("catalog is empty")
	}
	var available, preview int
	for _, tile := range all {
		if !ValidDNSLabel(tile.ID) {
			t.Errorf("tile %q: id is not a DNS label", tile.ID)
		}
		if tile.Available() {
			available++
			// Installable tiles must ship a runnable stack with a routable port.
			if tile.ComposeYAML == "" {
				t.Errorf("tile %q: available but empty compose", tile.ID)
			}
			if len(tile.Ports) > 0 && tile.PrimaryPort() == 0 {
				t.Errorf("tile %q: has ports but no primary", tile.ID)
			}
		} else {
			preview++
		}
		if got, ok := c.Get(tile.ID); !ok || got.ID != tile.ID {
			t.Errorf("tile %q: not retrievable by id", tile.ID)
		}
	}
	if available == 0 {
		t.Error("catalog has no installable tiles")
	}
	t.Logf("catalog: %d available, %d preview", available, preview)
}

func TestShippedCatalogDisplayOrder(t *testing.T) {
	c, _ := Load()
	prev := -1
	for _, tile := range c.All() {
		o := collectionOrder[tile.Collection]
		if o < prev {
			t.Errorf("tile %q (collection %q) out of collection order", tile.ID, tile.Collection)
		}
		prev = o
	}
}

func TestValidDNSLabel(t *testing.T) {
	cases := map[string]bool{
		"jellyfin":    true,
		"pi-hole":     true,
		"uptime-kuma": true,
		"a":           true,
		"Jellyfin":    false, // uppercase
		"pi_hole":     false, // underscore
		"-lead":       false, // leading hyphen
		"trail-":      false, // trailing hyphen
		"":            false, // empty
		"has space":   false,
		"app.name":    false, // dot
	}
	for in, want := range cases {
		if got := ValidDNSLabel(in); got != want {
			t.Errorf("ValidDNSLabel(%q) = %v, want %v", in, got, want)
		}
	}
}

// baseTile is a minimal valid tile fixture that individual guard tests mutate.
func baseTile() map[string]string {
	return map[string]string{
		"tile.json": `{
			"id": "demo",
			"name": "Demo",
			"tagline": "A demo tile.",
			"collection": "everyday",
			"arch": "both",
			"ramFloorMB": 128,
			"exposureDefault": "lan-only",
			"ports": [{"name":"web","container":80,"published":8080,"primary":true}]
		}`,
		"docker-compose.yml": "services:\n  demo:\n    image: traefik/whoami\n",
	}
}

func fsWith(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for name, body := range files {
		m["tiles/demo/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

func TestValidateTile_Guards(t *testing.T) {
	tests := []struct {
		name    string
		tileErr string // substring the load error must contain; "" means must succeed
		mutate  func(f map[string]string)
	}{
		{name: "valid baseline"},
		{
			name:    "guard2 non-dns id",
			tileErr: "id",
			mutate:  func(f map[string]string) { f["tile.json"] = replaceID(f["tile.json"], "Demo_App") },
		},
		{
			name:    "guard1 ports without primary",
			tileErr: "primary",
			mutate: func(f map[string]string) {
				f["tile.json"] = `{"id":"demo","name":"Demo","tagline":"x","collection":"everyday","arch":"both","ramFloorMB":128,"exposureDefault":"lan-only","ports":[{"name":"web","container":80,"published":8080}]}`
			},
		},
		{
			name:    "guard1 two primaries",
			tileErr: "primary",
			mutate: func(f map[string]string) {
				f["tile.json"] = `{"id":"demo","name":"Demo","tagline":"x","collection":"everyday","arch":"both","ramFloorMB":128,"exposureDefault":"lan-only","ports":[{"name":"a","container":80,"published":8080,"primary":true},{"name":"b","container":81,"published":8081,"primary":true}]}`
			},
		},
		{
			name:    "bad collection",
			tileErr: "collection",
			mutate:  func(f map[string]string) { f["tile.json"] = replaceField(f["tile.json"], "everyday", "nonsense") },
		},
		{
			name:    "bad arch",
			tileErr: "arch",
			mutate:  func(f map[string]string) { f["tile.json"] = replaceField(f["tile.json"], `"both"`, `"risc-v"`) },
		},
		{
			name:    "bad exposure",
			tileErr: "exposureDefault",
			mutate:  func(f map[string]string) { f["tile.json"] = replaceField(f["tile.json"], "lan-only", "everywhere") },
		},
		{
			name:    "port out of range",
			tileErr: "out of range",
			mutate:  func(f map[string]string) { f["tile.json"] = replaceField(f["tile.json"], "8080", "70000") },
		},
		{
			name:    "empty compose",
			tileErr: "empty",
			mutate:  func(f map[string]string) { f["docker-compose.yml"] = "" },
		},
		{
			name:    "bad category",
			tileErr: "category",
			mutate: func(f map[string]string) {
				f["tile.json"] = replaceField(f["tile.json"], `"lan-only"`, `"lan-only", "category": "nonsense"`)
			},
		},
		{
			name:    "bad status",
			tileErr: "status",
			mutate: func(f map[string]string) {
				f["tile.json"] = replaceField(f["tile.json"], `"lan-only"`, `"lan-only", "status": "live"`)
			},
		},
		{
			name:    "unknown field rejected",
			tileErr: "parse",
			mutate: func(f map[string]string) {
				f["tile.json"] = replaceField(f["tile.json"], `"name": "Demo"`, `"name": "Demo", "bogus": 1`)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files := baseTile()
			if tc.mutate != nil {
				tc.mutate(files)
			}
			_, err := loadFromFS(fsWith(files))
			if tc.tileErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.tileErr)
			}
			if !strings.Contains(err.Error(), tc.tileErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.tileErr)
			}
		})
	}
}

// A preview tile may omit its compose file entirely and still load (it can't
// be installed, so the stack + primary-port requirements are waived).
func TestPreviewTile_LoadsWithoutCompose(t *testing.T) {
	m := fstest.MapFS{
		"tiles/soon/tile.json": &fstest.MapFile{Data: []byte(`{
			"id": "soon", "name": "Soon", "tagline": "Coming soon.",
			"collection": "everyday", "category": "productivity", "arch": "both",
			"ramFloorMB": 256, "exposureDefault": "lan-only", "status": "preview"
		}`)},
	}
	c, err := loadFromFS(m)
	if err != nil {
		t.Fatalf("preview tile should load without a compose: %v", err)
	}
	got, ok := c.Get("soon")
	if !ok {
		t.Fatal("preview tile not retrievable")
	}
	if got.Available() {
		t.Error("preview tile should report Available()==false")
	}
	if got.ComposeYAML != "" {
		t.Error("preview tile should have empty compose")
	}
}

func replaceID(s, newID string) string        { return replaceField(s, `"demo"`, `"`+newID+`"`) }
func replaceField(s, old, repl string) string { return strings.Replace(s, old, repl, 1) }
