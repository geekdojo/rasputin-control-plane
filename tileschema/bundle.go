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

// TileRejection is one tile a reader refused, and why.
//
// It exists so a refusal is REPORTABLE rather than merely silent. A catalog
// that quietly loses tiles is a worse failure than one that fails loudly:
// nobody goes looking for an app they were never shown, so the operator's
// symptom is "the app I wanted isn't in the catalog" with no thread to pull.
type TileRejection struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// ParseBundle decodes and STRICTLY validates a catalog bundle: one bad tile
// fails the whole thing.
//
// For bundles WE produced — the publisher's own output, and the floor embedded
// in this binary. Both are build artifacts, so a bad tile in either is a build
// defect that should stop the build rather than be routed around. The floor in
// particular is deliberately fatal at startup (see api/cmd/rasputin-api): an
// image that silently boots with tiles missing is worse than one that refuses.
//
// For a bundle that ARRIVED from somewhere, use ParseFetchedBundle.
//
// Callers verify the signature over the bytes BEFORE calling either — parsing
// an unverified bundle is exactly what Decision 4 forbids.
func ParseBundle(raw []byte) (Bundle, error) {
	b, err := decodeBundle(raw)
	if err != nil {
		return Bundle{}, err
	}
	if err := b.Validate(); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// ParseFetchedBundle decodes a bundle that arrived from outside this build,
// keeping every tile that validates and REPORTING the ones that do not.
//
// ADR-0006 Decision 7, stated exactly: a tile a reader cannot accept "is fatal
// to their tile and only their tile", while "the rest of the catalog loads
// normally". ParseBundle could not express that — it returns on the first bad
// tile, so a single malformed entry costs a cluster its entire catalog and
// pins it to whatever it held before.
//
// WHY THIS IS NOT PARANOIA ABOUT OUR OWN PUBLISHER. Today the publisher and
// this reader compile the same validator, so the publisher refuses anything
// this would. That equality is temporary and not a property to rely on: a
// cluster runs the validator it shipped with, so the moment KnownCapabilities
// gains an entry — Decision 11's `tile.secrets` is the first — a current
// publisher legitimately emits tiles that older clusters must refuse. Decision
// 7 exists precisely for that case, and without per-tile refusal its arrival
// would take out the catalog on every cluster that had not updated.
//
// The envelope is still all-or-nothing. A reader that cannot trust the
// schemaVersion, the monotonic version, or the JSON itself cannot be selective
// about the contents, and a bundle whose tiles ALL fail is not a catalog.
func ParseFetchedBundle(raw []byte) (Bundle, []TileRejection, error) {
	b, err := decodeBundle(raw)
	if err != nil {
		return Bundle{}, nil, err
	}
	if err := b.validateEnvelope(); err != nil {
		return Bundle{}, nil, err
	}

	kept, rejected := b.partitionTiles()
	if len(kept) == 0 {
		// Not "an empty catalog": every tile was individually refused, which
		// says something is wrong with the bundle or with this reader's
		// understanding of it. Adopting nothing would replace a working
		// catalog with a blank one and record it as success.
		return Bundle{}, rejected, fmt.Errorf(
			"every one of the %d tiles in bundle v%d was refused — refusing the bundle rather than adopting an empty catalog",
			len(b.Tiles), b.Version)
	}
	b.Tiles = kept
	return b, rejected, nil
}

func decodeBundle(raw []byte) (Bundle, error) {
	var b Bundle
	// An unknown field in a bundle is tolerated within a major (Decision 7's
	// additive rule), so DisallowUnknownFields is deliberately NOT set. The
	// must-understand escape hatch is Tile.Requires, not strict decoding.
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, fmt.Errorf("parse catalog bundle: %w", err)
	}
	return b, nil
}

// partitionTiles splits the corpus into the tiles this reader accepts and the
// ones it refuses. Pure and order-preserving over b.Tiles, which matters more
// than it looks: the store re-parses the SAME persisted bytes on every boot, so
// a partition that depended on map order or wall-clock would silently change a
// cluster's catalog across a restart.
func (b Bundle) partitionTiles() (kept []BundleTile, rejected []TileRejection) {
	seen := make(map[string]bool, len(b.Tiles))
	for _, bt := range b.Tiles {
		if err := checkTile(bt, seen); err != nil {
			rejected = append(rejected, TileRejection{ID: bt.Tile.ID, Reason: err.Error()})
			continue
		}
		seen[bt.Tile.ID] = true
		kept = append(kept, bt)
	}
	return kept, rejected
}

// checkTile is the per-tile judgement, shared by the strict and tolerant paths
// so the two can never disagree about what a valid tile is. Only the
// DISPOSITION differs: strict returns the error, tolerant drops the tile.
func checkTile(bt BundleTile, seen map[string]bool) error {
	if seen[bt.Tile.ID] {
		return fmt.Errorf("duplicate tile id %q", bt.Tile.ID)
	}
	// Reconstruct the tile as the validators expect it. ComposeYAML is
	// carried beside the tile in the wire format, not inside it.
	t := bt.Tile
	t.ComposeYAML = bt.Compose

	if err := ValidateTile(t); err != nil {
		return err
	}
	// A preview tile may ship no compose at all, so it has no stack to have
	// facts about. Anything installable does.
	if t.Available() {
		if err := ValidateTileSafety(t, bt.Safety); err != nil {
			return err
		}
	}
	return nil
}

// Validate enforces every rule that does not need a signature or a filesystem,
// STRICTLY: the first bad tile fails the bundle. ParseFetchedBundle applies the
// same per-tile rules with a different disposition.
//
// Both paths route through checkTile, so "what makes a tile valid" has exactly
// one definition. Only what happens next differs. Keeping that in one place is
// the same reasoning as Decision 8's one-validator-two-callers, applied a level
// down: a strict and a tolerant copy of these checks would drift, and the drift
// would show up as a tile the publisher accepted and the cluster silently
// dropped.
func (b Bundle) Validate() error {
	if err := b.validateEnvelope(); err != nil {
		return err
	}
	seen := make(map[string]bool, len(b.Tiles))
	for i, bt := range b.Tiles {
		if err := checkTile(bt, seen); err != nil {
			return fmt.Errorf("tiles[%d] (%q): %w", i, bt.Tile.ID, err)
		}
		seen[bt.Tile.ID] = true
	}
	return nil
}

// validateEnvelope checks the properties that describe the bundle rather than
// any tile in it. These are all-or-nothing by nature and stay that way in both
// paths: a reader that cannot trust the schema version, the ordering guarantee,
// or the JSON has no basis for being selective about the contents.
func (b Bundle) validateEnvelope() error {
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
