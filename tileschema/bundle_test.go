package tileschema

import (
	"encoding/json"
	"strings"
	"testing"
)

func okBundleTile() BundleTile {
	t := okTile()
	compose := t.ComposeYAML
	t.ComposeYAML = ""
	return BundleTile{Tile: t, Compose: compose, Safety: okFacts()}
}

func okBundle() Bundle {
	return Bundle{
		SchemaVersion: BundleSchemaVersion,
		Version:       1,
		PublishedAt:   "2026-08-20T00:00:00Z",
		Tiles:         []BundleTile{okBundleTile()},
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestParseBundle_HappyPath(t *testing.T) {
	got, err := ParseBundle(mustJSON(t, okBundle()))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if got.Version != 1 || len(got.Tiles) != 1 {
		t.Fatalf("round-trip lost content: %#v", got)
	}
}

// Decision 7: a reader refuses a bundle whose major exceeds what it
// understands — the WHOLE bundle, because a reader that cannot parse the
// envelope has no basis for being selective about the contents.
func TestParseBundle_RefusesFutureSchema(t *testing.T) {
	b := okBundle()
	b.SchemaVersion = BundleSchemaVersion + 1
	_, err := ParseBundle(mustJSON(t, b))
	if err == nil {
		t.Fatal("a bundle from a newer schema must be refused, not partially read")
	}
	if !strings.Contains(err.Error(), "refusing the whole bundle") {
		t.Errorf("error should say the whole bundle is refused; got %v", err)
	}
}

// The additive half of Decision 7: an unknown field within a major is IGNORED.
// Strict decoding here would make every additive change breaking, which is the
// alternative the ADR rejected by name.
func TestParseBundle_ToleratesUnknownFieldsWithinAMajor(t *testing.T) {
	raw := mustJSON(t, okBundle())
	injected := strings.Replace(string(raw), `{"schemaVersion"`, `{"somethingFromTheFuture":true,"schemaVersion"`, 1)
	if injected == string(raw) {
		t.Fatal("test did not inject the unknown field")
	}
	if _, err := ParseBundle([]byte(injected)); err != nil {
		t.Fatalf("an unknown field within a major must be ignored, not fatal: %v", err)
	}
}

func TestParseBundle_Refuses(t *testing.T) {
	cases := map[string]func(*Bundle){
		"no schemaVersion": func(b *Bundle) { b.SchemaVersion = 0 },
		"zero version":     func(b *Bundle) { b.Version = 0 },
		"negative version": func(b *Bundle) { b.Version = -1 },
		"empty corpus":     func(b *Bundle) { b.Tiles = nil },
		"duplicate ids": func(b *Bundle) {
			b.Tiles = append(b.Tiles, okBundleTile())
		},
		"tile fails ValidateTile": func(b *Bundle) {
			b.Tiles[0].Tile.ID = "Not A DNS Label"
		},
		"available tile fails ValidateTileSafety": func(b *Bundle) {
			b.Tiles[0].Safety.Privileged = true
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := okBundle()
			mutate(&b)
			if _, err := ParseBundle(mustJSON(t, b)); err == nil {
				t.Fatalf("%s must be refused", name)
			}
		})
	}
}

// A preview tile may ship no compose at all, so it has no stack to have facts
// about. Running the safety validator over it would refuse the corpus for a
// tile that cannot be installed.
func TestParseBundle_PreviewTileSkipsSafety(t *testing.T) {
	b := okBundle()
	b.Tiles[0].Tile.Status = StatusPreview
	b.Tiles[0].Compose = ""
	b.Tiles[0].Safety = SafetyFacts{}
	if _, err := ParseBundle(mustJSON(t, b)); err != nil {
		t.Fatalf("a preview tile with no stack must be allowed: %v", err)
	}
}

// Decision 5. Strictly greater, not greater-or-equal: accepting an equal
// version would let a replay undo a local refusal, and re-adopting the same
// corpus is work with no outcome.
func TestBundle_SupersedesVersion(t *testing.T) {
	b := okBundle()
	b.Version = 7
	for _, c := range []struct {
		have int
		want bool
	}{{0, true}, {6, true}, {7, false}, {8, false}, {99, false}} {
		if got := b.SupersedesVersion(c.have); got != c.want {
			t.Errorf("version 7 vs have %d: got %v, want %v", c.have, got, c.want)
		}
	}
}

// The bundle is signed over its bytes, so an identical corpus must marshal
// identically. Directory or map iteration order leaking into the artifact
// would make every rebuild a different signature for no semantic reason.
func TestSortTiles_IsCanonical(t *testing.T) {
	mk := func(id string) BundleTile {
		bt := okBundleTile()
		bt.Tile.ID = id
		return bt
	}
	a := []BundleTile{mk("zulu"), mk("alpha"), mk("mike")}
	b := []BundleTile{mk("mike"), mk("zulu"), mk("alpha")}
	SortTiles(a)
	SortTiles(b)
	if string(mustJSON(t, a)) != string(mustJSON(t, b)) {
		t.Fatalf("two orderings of one corpus did not canonicalise to the same bytes")
	}
	if a[0].Tile.ID != "alpha" || a[2].Tile.ID != "zulu" {
		t.Errorf("not sorted by id: %v %v %v", a[0].Tile.ID, a[1].Tile.ID, a[2].Tile.ID)
	}
}

// Guards the field split. Compose and Safety are carried BESIDE the tile, not
// inside it, because they have different authors — hand-written vs derived.
// A future refactor that folds Compose into Tile would silently change the
// signed wire format.
func TestBundleTile_WireShapeIsPinned(t *testing.T) {
	raw := string(mustJSON(t, okBundleTile()))
	for _, key := range []string{`"tile":`, `"compose":`, `"safety":`} {
		if !strings.Contains(raw, key) {
			t.Errorf("BundleTile JSON is missing %s — the signed wire format changed\ngot: %s", key, raw)
		}
	}
}

// --- Per-tile refusal (#162, ADR-0006 Decision 7) ---------------------------
//
// The property under test is the one the ADR states and ParseBundle could not
// express: a tile a reader cannot accept is "fatal to their tile and only their
// tile", while "the rest of the catalog loads normally".

// badBundleTile returns a tile that every reader must refuse, for a reason that
// is unambiguously the TILE's and not the bundle's. An unknown `requires`
// capability is the most faithful choice available: it is Decision 7's own
// named case, and it is what a current publisher will legitimately emit to an
// older cluster the moment KnownCapabilities gains its first entry.
func badBundleTile(id string) BundleTile {
	bt := okBundleTile()
	bt.Tile.ID = id
	bt.Tile.Requires = []string{"tile.capability-from-the-future"}
	return bt
}

func TestParseFetchedBundle_OneBadTileCostsOneTile(t *testing.T) {
	b := okBundle()
	good := okBundleTile()
	good.Tile.ID = "good-one"
	good2 := okBundleTile()
	good2.Tile.ID = "good-two"
	b.Tiles = []BundleTile{good, badBundleTile("from-the-future"), good2}

	got, rejected, err := ParseFetchedBundle(mustJSON(t, b))
	if err != nil {
		t.Fatalf("a bundle with one bad tile must still load: %v", err)
	}
	if len(got.Tiles) != 2 {
		t.Fatalf("want the 2 good tiles kept, got %d", len(got.Tiles))
	}
	for _, bt := range got.Tiles {
		if bt.Tile.ID == "from-the-future" {
			t.Fatal("the refused tile was served anyway")
		}
	}
	if len(rejected) != 1 || rejected[0].ID != "from-the-future" {
		t.Fatalf("want exactly the bad tile reported, got %+v", rejected)
	}
	if !strings.Contains(rejected[0].Reason, "unknown capability") {
		t.Errorf("the reason must say why, got %q", rejected[0].Reason)
	}
	// The same bytes must remain strictly invalid: this changes the reader's
	// disposition, not its standards.
	if _, err := ParseBundle(mustJSON(t, b)); err == nil {
		t.Error("ParseBundle must still refuse the whole bundle — the publisher and the floor rely on it")
	}
}

func TestParseFetchedBundle_AllTilesBadIsNotAnEmptyCatalog(t *testing.T) {
	b := okBundle()
	b.Tiles = []BundleTile{badBundleTile("a"), badBundleTile("b")}

	_, rejected, err := ParseFetchedBundle(mustJSON(t, b))
	if err == nil {
		t.Fatal("a bundle whose every tile is refused must not be adopted — that would replace a working catalog with a blank one and call it success")
	}
	if len(rejected) != 2 {
		t.Errorf("the refusals are still reported so an operator can see why, got %+v", rejected)
	}
}

func TestParseFetchedBundle_EnvelopeStaysAllOrNothing(t *testing.T) {
	// A reader that cannot trust the envelope has no basis for being selective
	// about the contents, so these must fail the bundle even in the tolerant
	// path — the opposite of the per-tile rule above.
	for name, mutate := range map[string]func(*Bundle){
		"schema from the future": func(b *Bundle) { b.SchemaVersion = BundleSchemaVersion + 1 },
		"no version":             func(b *Bundle) { b.Version = 0 },
		"no tiles at all":        func(b *Bundle) { b.Tiles = nil },
	} {
		t.Run(name, func(t *testing.T) {
			b := okBundle()
			mutate(&b)
			if _, _, err := ParseFetchedBundle(mustJSON(t, b)); err == nil {
				t.Error("want the whole bundle refused")
			}
		})
	}
	if _, _, err := ParseFetchedBundle([]byte("{not json")); err == nil {
		t.Error("unparseable bytes must fail the bundle")
	}
}

func TestParseFetchedBundle_DuplicateIDDropsTheDuplicateNotTheCatalog(t *testing.T) {
	b := okBundle()
	first := okBundleTile()
	first.Tile.ID = "twice"
	first.Tile.Name = "The First One"
	dup := okBundleTile()
	dup.Tile.ID = "twice"
	dup.Tile.Name = "The Impostor"
	b.Tiles = []BundleTile{first, dup}

	got, rejected, err := ParseFetchedBundle(mustJSON(t, b))
	if err != nil {
		t.Fatalf("a duplicate id costs the duplicate, not the bundle: %v", err)
	}
	if len(got.Tiles) != 1 || got.Tiles[0].Tile.Name != "The First One" {
		t.Fatalf("the FIRST occurrence wins — a later entry must not be able to shadow an earlier one: %+v", got.Tiles)
	}
	if len(rejected) != 1 || !strings.Contains(rejected[0].Reason, "duplicate") {
		t.Errorf("want the duplicate reported, got %+v", rejected)
	}
}

func TestParseFetchedBundle_IsDeterministicAcrossReparse(t *testing.T) {
	// The store re-parses the SAME persisted bytes on every boot. If the
	// surviving set could vary, a cluster's catalog would change across a
	// restart with nothing having been published.
	b := okBundle()
	var tiles []BundleTile
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		if id == "c" || id == "f" {
			tiles = append(tiles, badBundleTile(id))
			continue
		}
		bt := okBundleTile()
		bt.Tile.ID = id
		tiles = append(tiles, bt)
	}
	b.Tiles = tiles
	raw := mustJSON(t, b)

	first, firstRej, err := ParseFetchedBundle(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i := 0; i < 20; i++ {
		got, rej, err := ParseFetchedBundle(raw)
		if err != nil {
			t.Fatalf("reparse %d: %v", i, err)
		}
		if len(got.Tiles) != len(first.Tiles) || len(rej) != len(firstRej) {
			t.Fatalf("reparse %d differs: %d kept/%d rejected vs %d/%d",
				i, len(got.Tiles), len(rej), len(first.Tiles), len(firstRej))
		}
		for j := range got.Tiles {
			if got.Tiles[j].Tile.ID != first.Tiles[j].Tile.ID {
				t.Fatalf("reparse %d reordered tiles at %d", i, j)
			}
		}
	}
	if len(first.Tiles) != 6 || len(firstRej) != 2 {
		t.Fatalf("want 6 kept / 2 rejected, got %d/%d", len(first.Tiles), len(firstRej))
	}
}
