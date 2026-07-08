// Package catalog is the curated first-party app catalog: the read-only set
// of tiles a user installs *from*. It is authored by us, versioned in-repo,
// and embedded into the api binary — deliberately NOT a database table. The
// user's installed instances live in the apps package; a tile is the template
// an install is seeded from.
//
// Design: design/control-plane/app-catalog-candidates.md (the longlist +
// per-tile metadata schema) and app-access.md (why the published port is
// structured metadata, not just text inside the compose YAML).
package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// tilesFS holds one directory per tile: tiles/<id>/tile.json (metadata) +
// tiles/<id>/docker-compose.yml (the raw stack, never parsed by the api). This
// mirrors the Runtipi appstore layout and keeps compose YAML as real YAML
// instead of an escaped JSON string.
//
//go:embed all:tiles
var tilesFS embed.FS

// Collection groups tiles in the catalog UI. Order here is display order.
const (
	CollectionEssentials = "essentials"
	CollectionShowoff    = "show-off"
	CollectionEveryday   = "everyday"
	CollectionDongle     = "dongle"
)

var collectionOrder = map[string]int{
	CollectionEssentials: 0,
	CollectionShowoff:    1,
	CollectionEveryday:   2,
	CollectionDongle:     3,
}

// Exposure defaults mirror app-access.md's resolution tiers.
var validExposure = map[string]bool{"lan-only": true, "tailnet": true, "public": true}

var validArch = map[string]bool{"both": true, "arm64": true, "amd64": true}

var validPlacement = map[string]bool{"": true, "any": true, "prefer-x86": true, "prefer-arm64": true}

// Port is a structured published port. Guard #1 from the app-access design:
// the proxy must be able to route <app>.<zone> to a concrete host port without
// parsing the compose YAML, so every web-facing tile declares its ports here
// and marks exactly one Primary (the one the reverse proxy fronts).
type Port struct {
	Name      string `json:"name"`               // "web", "dns", …
	Container int    `json:"container"`          // port inside the container
	Published int    `json:"published"`          // host port
	Protocol  string `json:"protocol,omitempty"` // "tcp" (default) | "udp"
	Primary   bool   `json:"primary,omitempty"`  // the port the reverse proxy routes to
}

// Tile is one catalog entry. Fields mirror the metadata schema in
// app-catalog-candidates.md §5.
type Tile struct {
	ID              string   `json:"id"`                      // Guard #2: DNS-1123 label, unique
	Name            string   `json:"name"`                    // display name
	Tagline         string   `json:"tagline"`                 // one-line pitch
	Description     string   `json:"description"`             // a paragraph
	Collection      string   `json:"collection"`              // essentials | show-off | everyday | dongle
	Arch            string   `json:"arch"`                    // both | arm64 | amd64
	PlacementHint   string   `json:"placementHint"`           // "" | any | prefer-x86 | prefer-arm64
	RAMFloorMB      int      `json:"ramFloorMB"`              // warn before deploying on a smaller node
	NeedsHardware   string   `json:"needsHardware,omitempty"` // e.g. "rtl-sdr"
	NeedsFeedKey    []string `json:"needsFeedKey,omitempty"`  // external API keys prompted at install
	ExposureDefault string   `json:"exposureDefault"`         // lan-only | tailnet | public
	Ports           []Port   `json:"ports"`
	Website         string   `json:"website,omitempty"`
	Icon            string   `json:"icon,omitempty"`        // emoji or asset ref
	PostInstall     string   `json:"postInstall,omitempty"` // one-line first-run guidance shown after deploy

	// ComposeYAML is loaded from the sibling docker-compose.yml, not tile.json.
	ComposeYAML string `json:"-"`
}

// PrimaryPort returns the published host port the reverse proxy should front,
// or 0 if the tile declares none (a headless/no-UI tile).
func (t Tile) PrimaryPort() int {
	for _, p := range t.Ports {
		if p.Primary {
			return p.Published
		}
	}
	return 0
}

// Catalog is the loaded, validated set of tiles.
type Catalog struct {
	byID  map[string]Tile
	order []string // ids, in display order
}

// MustLoad loads the embedded catalog, panicking on any invalid tile. A bad
// tile is a build defect in our own content — fail loudly at startup, the same
// contract as template.Must. A CI unit test (catalog_test.go) catches this
// before it ever reaches a binary.
func MustLoad() *Catalog {
	c, err := Load()
	if err != nil {
		panic("catalog: " + err.Error())
	}
	return c
}

// Load parses and validates the embedded catalog.
func Load() (*Catalog, error) { return loadFromFS(tilesFS) }

func loadFromFS(fsys fs.FS) (*Catalog, error) {
	entries, err := fs.ReadDir(fsys, "tiles")
	if err != nil {
		return nil, fmt.Errorf("read tiles dir: %w", err)
	}
	c := &Catalog{byID: make(map[string]Tile)}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := e.Name()
		meta, err := fs.ReadFile(fsys, "tiles/"+dir+"/tile.json")
		if err != nil {
			return nil, fmt.Errorf("tile %q: %w", dir, err)
		}
		var t Tile
		dec := json.NewDecoder(strings.NewReader(string(meta)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&t); err != nil {
			return nil, fmt.Errorf("tile %q: parse tile.json: %w", dir, err)
		}
		compose, err := fs.ReadFile(fsys, "tiles/"+dir+"/docker-compose.yml")
		if err != nil {
			return nil, fmt.Errorf("tile %q: %w", dir, err)
		}
		t.ComposeYAML = string(compose)

		if t.ID != dir {
			return nil, fmt.Errorf("tile %q: id %q must equal its directory name", dir, t.ID)
		}
		if err := validateTile(t); err != nil {
			return nil, fmt.Errorf("tile %q: %w", dir, err)
		}
		if _, dup := c.byID[t.ID]; dup {
			return nil, fmt.Errorf("tile %q: duplicate id", t.ID)
		}
		c.byID[t.ID] = t
	}
	// Stable display order: collection, then name.
	ids := make([]string, 0, len(c.byID))
	for id := range c.byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := c.byID[ids[i]], c.byID[ids[j]]
		if collectionOrder[a.Collection] != collectionOrder[b.Collection] {
			return collectionOrder[a.Collection] < collectionOrder[b.Collection]
		}
		return a.Name < b.Name
	})
	c.order = ids
	return c, nil
}

func validateTile(t Tile) error {
	if !ValidDNSLabel(t.ID) {
		return fmt.Errorf("id must be a DNS-1123 label (1-63 chars, [a-z0-9-], no leading/trailing hyphen)")
	}
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(t.Tagline) == "" {
		return fmt.Errorf("tagline is required")
	}
	if _, ok := collectionOrder[t.Collection]; !ok {
		return fmt.Errorf("collection %q is not one of essentials|show-off|everyday|dongle", t.Collection)
	}
	if !validArch[t.Arch] {
		return fmt.Errorf("arch %q is not one of both|arm64|amd64", t.Arch)
	}
	if !validPlacement[t.PlacementHint] {
		return fmt.Errorf("placementHint %q is not one of any|prefer-x86|prefer-arm64", t.PlacementHint)
	}
	if !validExposure[t.ExposureDefault] {
		return fmt.Errorf("exposureDefault %q is not one of lan-only|tailnet|public", t.ExposureDefault)
	}
	if t.RAMFloorMB <= 0 {
		return fmt.Errorf("ramFloorMB must be > 0")
	}
	if strings.TrimSpace(t.ComposeYAML) == "" {
		return fmt.Errorf("docker-compose.yml is empty")
	}
	primaries := 0
	for i, p := range t.Ports {
		if p.Container < 1 || p.Container > 65535 {
			return fmt.Errorf("ports[%d] container %d out of range", i, p.Container)
		}
		if p.Published < 1 || p.Published > 65535 {
			return fmt.Errorf("ports[%d] published %d out of range", i, p.Published)
		}
		if p.Protocol != "" && p.Protocol != "tcp" && p.Protocol != "udp" {
			return fmt.Errorf("ports[%d] protocol %q is not tcp|udp", i, p.Protocol)
		}
		if p.Primary {
			primaries++
		}
	}
	// A web-facing tile (any ports) must mark exactly one primary so the proxy
	// knows which host:port to front. A headless tile declares no ports.
	if len(t.Ports) > 0 && primaries != 1 {
		return fmt.Errorf("exactly one port must be primary (found %d)", primaries)
	}
	return nil
}

// All returns every tile in display order.
func (c *Catalog) All() []Tile {
	out := make([]Tile, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.byID[id])
	}
	return out
}

// Get returns a tile by id.
func (c *Catalog) Get(id string) (Tile, bool) {
	t, ok := c.byID[id]
	return t, ok
}

// ValidDNSLabel reports whether s is a valid RFC-1123 DNS label: 1-63 chars,
// lowercase alphanumerics and hyphens, no leading/trailing hyphen. This is
// Guard #2 — it keeps every catalog id usable as-is in <app>.<cluster-domain>
// so an installed tile never needs renaming to get a hostname.
func ValidDNSLabel(s string) bool {
	if len(s) < 1 || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
