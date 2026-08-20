package tileschema

import (
	"encoding/json"
	"fmt"
	"sort"
)

// BundleSchemaVersion is the catalog-bundle contract this module implements.
//
// Separate from SchemaVersion, which versions a TILE. A bundle can gain fields
// without the tile contract moving and vice versa, and conflating them would
// force a lockstep bump on two things that change for different reasons.
const BundleSchemaVersion = 1

// Bundle is one published catalog: the whole tile corpus plus the metadata a
// reader needs to decide whether to trust and adopt it.
//
// ADR-0006 Decision 2 — one atomic signed artifact per publish, never per-tile.
// The bundle is a SINGLE JSON DOCUMENT rather than an archive, decided
// 2026-08-20. An archive would mean the control plane extracting
// attacker-supplied entries, which is a path-traversal surface Decision 4
// exists to avoid; a corpus small enough to embed in a binary is small enough
// to carry as one document. The signature is detached CMS over these exact
// bytes, the same shape artifactsig already verifies for OS and firmware.
type Bundle struct {
	// SchemaVersion is the bundle contract this document was written against.
	// A reader refuses a bundle whose value exceeds what it understands
	// (Decision 7) — the whole bundle, not a tile, because a reader that
	// cannot parse the envelope cannot be selective about its contents.
	SchemaVersion int `json:"schemaVersion"`

	// Version is the monotonic catalog version. A reader REFUSES a bundle
	// whose version is not greater than the one it already has (Decision 5):
	// a validly-signed old bundle is a rollback to image digests with known
	// CVEs, and a signature check cannot tell that from a legitimate update.
	//
	// A plain integer, decided 2026-08-20. The ADR requires exactly one
	// property — a strict total order — and every additional bit of structure
	// is a comparison bug waiting to happen. Human-facing context lives in the
	// fields below instead of being encoded into the number.
	Version int `json:"version"`

	// PublishedAt is RFC 3339 and INFORMATIONAL. It is displayed, never
	// compared — trusting a timestamp for ordering would reintroduce the
	// rollback the Version gate closes.
	PublishedAt string `json:"publishedAt"`

	// Source names the repository and commit this corpus was built from, so a
	// cluster can say where its catalog came from. Informational.
	Source string `json:"source,omitempty"`

	// Tiles is the corpus, sorted by ID. Sorted because the bundle is signed
	// over its bytes: map or directory iteration order would make an identical
	// corpus produce a different artifact on every build.
	Tiles []BundleTile `json:"tiles"`
}

// BundleTile is one tile as PUBLISHED: what the author wrote, the compose it
// ships, and the safety facts the publisher derived from that compose.
//
// The three are separate fields rather than one flattened object because they
// have different authors. Tile is hand-written, Compose is hand-written, and
// Safety is DERIVED — and the derivation is what the control plane validates
// instead of re-parsing YAML. Flattening them would blur which is which.
type BundleTile struct {
	Tile    Tile        `json:"tile"`
	Compose string      `json:"compose"`
	Safety  SafetyFacts `json:"safety"`
}

// ParseBundle decodes and fully validates a catalog bundle.
//
// It is the ONLY supported way to turn bundle bytes into a Bundle: every
// refusal in this file is a property the caller would otherwise have to
// remember to check, and a reader that forgets one fails open. Callers verify
// the signature over the bytes BEFORE calling this — parsing an unverified
// bundle is exactly what Decision 4 forbids.
func ParseBundle(raw []byte) (Bundle, error) {
	var b Bundle
	// An unknown field in a bundle is tolerated within a major (Decision 7's
	// additive rule), so DisallowUnknownFields is deliberately NOT set. The
	// must-understand escape hatch is Tile.Requires, not strict decoding.
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, fmt.Errorf("parse catalog bundle: %w", err)
	}
	if err := b.Validate(); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// Validate enforces every rule that does not need a signature or a filesystem.
func (b Bundle) Validate() error {
	if b.SchemaVersion <= 0 {
		return fmt.Errorf("bundle declares no schemaVersion")
	}
	if b.SchemaVersion > BundleSchemaVersion {
		return fmt.Errorf(
			"bundle schemaVersion %d exceeds the %d this build understands — refusing the whole bundle rather than guessing at it",
			b.SchemaVersion, BundleSchemaVersion)
	}
	if b.Version <= 0 {
		return fmt.Errorf("bundle version must be a positive integer, got %d", b.Version)
	}
	if len(b.Tiles) == 0 {
		return fmt.Errorf("bundle declares no tiles — an empty catalog is a publish bug, not a valid state")
	}

	seen := make(map[string]bool, len(b.Tiles))
	for i, bt := range b.Tiles {
		if seen[bt.Tile.ID] {
			return fmt.Errorf("tiles[%d]: duplicate tile id %q", i, bt.Tile.ID)
		}
		seen[bt.Tile.ID] = true

		// Reconstruct the tile as the validators expect it. ComposeYAML is
		// carried beside the tile in the wire format, not inside it.
		t := bt.Tile
		t.ComposeYAML = bt.Compose

		if err := ValidateTile(t); err != nil {
			return fmt.Errorf("tile %q: %w", bt.Tile.ID, err)
		}
		// A preview tile may ship no compose at all, so it has no stack to
		// have facts about. Anything installable does.
		if t.Available() {
			if err := ValidateTileSafety(t, bt.Safety); err != nil {
				return fmt.Errorf("tile %q: %w", bt.Tile.ID, err)
			}
		}
	}
	return nil
}

// SupersedesVersion reports whether this bundle may replace one at have.
//
// Strictly greater, not greater-or-equal: re-adopting the same version is
// pointless work, and accepting it would let an attacker replay a bundle to
// undo a local refusal. have == 0 means the cluster has never adopted one.
func (b Bundle) SupersedesVersion(have int) bool { return b.Version > have }

// SortTiles orders the corpus canonically. The publisher calls this before
// marshalling; the signature is over the resulting bytes, so an unsorted
// corpus would sign differently on every build for no semantic reason.
func SortTiles(tiles []BundleTile) {
	sort.Slice(tiles, func(i, j int) bool { return tiles[i].Tile.ID < tiles[j].Tile.ID })
}
