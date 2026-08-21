package floor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The floor ships in every image. If it does not parse, every cluster built
// from this commit starts with no catalog at all — so this is a build gate,
// not a unit test.
func TestFloor_ParsesAndValidates(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatalf("the embedded floor is not a valid bundle: %v", err)
	}
	if len(b.Tiles) == 0 {
		t.Fatal("the floor has no tiles; an airgapped cluster would show an empty catalog")
	}
	if len(Signature()) == 0 {
		t.Error("the floor's signature is missing, so nobody can re-check what was embedded")
	}
	t.Logf("floor: catalog v%d, %d tiles", b.Version, len(b.Tiles))
}

// The pin file is the human-readable label; the bundle is the content. A
// hand-edit to either must fail here rather than ship a floor whose contents
// disagree with what the repo says it embedded.
func TestFloor_VersionMatchesThePinFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "catalog-version.txt"))
	if err != nil {
		t.Fatalf("read catalog-version.txt: %v", err)
	}
	var pinned string
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		pinned = s
	}
	want, err := strconv.Atoi(pinned)
	if err != nil {
		t.Fatalf("catalog-version.txt must end in a bare integer, got %q", pinned)
	}

	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != want {
		t.Fatalf("catalog-version.txt says v%d but the embedded bundle is v%d — run scripts/embed-catalog.sh", want, b.Version)
	}
}

// A floor with no installable tile is technically valid and practically
// useless: the whole point is that a cluster with no egress can still install
// something.
func TestFloor_HasAtLeastOneInstallableTile(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, bt := range b.Tiles {
		tile := bt.Tile
		tile.ComposeYAML = bt.Compose
		if tile.Available() {
			return
		}
	}
	t.Fatal("every tile in the floor is preview-only; an airgapped cluster could browse but never install")
}
