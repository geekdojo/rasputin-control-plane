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
