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

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// tilesFS holds one directory per tile: tiles/<id>/tile.json (metadata) +
// tiles/<id>/docker-compose.yml (the raw stack, never parsed by the api). This
// mirrors the Runtipi appstore layout and keeps compose YAML as real YAML
// instead of an escaped JSON string.
//
//go:embed all:tiles
var tilesFS embed.FS

// The tile contract — types, vocabularies and validation — lives in the
// tileschema MODULE, because rasputin-app-catalog validates the same tiles
// before publishing them and ADR-0006 Decision 8 permits exactly one
// implementation of those rules. These aliases keep catalog.Tile working for
// every existing caller in the api while the definitions live in one place.
type (
	Tile        = tileschema.Tile
	Port        = tileschema.Port
	SafetyFacts = tileschema.SafetyFacts
	Privilege   = tileschema.Privilege
)

const (
	CollectionEssentials = tileschema.CollectionEssentials
	CollectionShowoff    = tileschema.CollectionShowoff
	CollectionEveryday   = tileschema.CollectionEveryday
	CollectionDongle     = tileschema.CollectionDongle

	StatusAvailable = tileschema.StatusAvailable
	StatusPreview   = tileschema.StatusPreview

	// ADR-0006 Decision 12b. Aliased here so the consent surface (#200) reads
	// the same vocabulary as the validator rather than a second copy of it.
	TierRoutine      = tileschema.TierRoutine
	TierElevated     = tileschema.TierElevated
	TierHostTrusting = tileschema.TierHostTrusting
)

var collectionOrder = tileschema.CollectionOrder

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
			// A preview tile may ship without a compose file — it can't be
			// installed, so the stack is optional until it clears the bench.
			if t.Status != StatusPreview {
				return nil, fmt.Errorf("tile %q: %w", dir, err)
			}
		} else {
			t.ComposeYAML = string(compose)
		}

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

// validateTile delegates to the shared module. The api keeps the wrapper so
// the loader's error wrapping stays put and so there is one obvious place to
// add a load-time-only check if one is ever justified.
func validateTile(t Tile) error { return tileschema.ValidateTile(t) }

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

// ValidDNSLabel is re-exported from tileschema so existing api callers keep
// working; the implementation lives there with the rest of the contract.
func ValidDNSLabel(s string) bool { return tileschema.ValidDNSLabel(s) }
