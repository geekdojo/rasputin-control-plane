package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The fan-out against the REAL catalog object — catalogsync.Store, the thing
// /api/catalog serves from — rather than against a fake tile map.
//
// Every other fan-out test hands the plan a fakeTiles it wrote three lines
// earlier, which is right for testing the join and useless for testing the
// wiring: the 2026-09-03 e3bench run had the join working perfectly against
// the wrong catalog. main.go wired RunConfig.Tiles to catalog.MustLoad(), the
// tile set embedded in the binary, while /api/catalog served a verified v17
// whose vaultwarden tile declared its `critical` volume. The embedded tiles
// carried no `volumes` at all, so the plan saw an installed app with nothing to
// classify, recorded nothing, and the manifest said `complete: true` over an
// archive that omitted the password vault.
//
// These cases build the store the way main.go does — a floor, then a verified
// fetch that supersedes it — and run the saga against it.

// catalogBundle is one published catalog holding one tile, in the shape the
// publisher emits. Preview status, because a preview tile may ship without a
// compose and the fan-out's join never looks at availability.
func catalogBundle(version int, tile tileschema.Tile) tileschema.Bundle {
	tile.Name, tile.Tagline, tile.Description = "N", "t", "d"
	tile.Collection, tile.Arch, tile.ExposureDefault = tileschema.CollectionEssentials, "both", "lan-only"
	tile.RAMFloorMB, tile.Status = 256, tileschema.StatusPreview
	return tileschema.Bundle{
		SchemaVersion: tileschema.BundleSchemaVersion,
		Version:       version,
		PublishedAt:   "2026-09-03T00:00:00Z",
		Tiles:         []tileschema.BundleTile{{Tile: tile}},
	}
}

// acceptAll stands in for the CMS verifier. What is under test is which
// catalog the fan-out READS, not whether the store checks signatures — that
// has its own tests in catalogsync.
type acceptAll struct{}

func (acceptAll) VerifyForPurpose(string, string) error { return nil }

// newCatalogStore builds a store on `floor` and, when `fetched` is non-nil,
// applies it as a verified fetch — exactly the two states a cluster's catalog
// can be in (ADR-0006 Decision 6).
func newCatalogStore(t *testing.T, floor tileschema.Bundle, fetched *tileschema.Bundle) *catalogsync.Store {
	t.Helper()
	s, err := catalogsync.New(t.TempDir(), acceptAll{}, floor)
	if err != nil {
		t.Fatalf("catalogsync.New: %v", err)
	}
	if fetched == nil {
		return s
	}
	tileschema.SortTiles(fetched.Tiles)
	raw, err := json.MarshalIndent(fetched, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bp := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(bp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bp+".sig", []byte("sig"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(bp, bp+".sig"); err != nil {
		t.Fatalf("Apply v%d: %v", fetched.Version, err)
	}
	return s
}

// benchFloor is the catalog a cluster boots on: the tile exists, and declares
// no volumes — every tile published before storage.md §4.2 is this shape.
func benchFloor() tileschema.Bundle {
	return catalogBundle(14, tileschema.Tile{ID: "vaultwarden"})
}

// benchFetched is catalog v17 as /api/catalog served it on e3bench: the same
// tile, now classifying its one volume `critical`.
func benchFetched() tileschema.Bundle {
	return catalogBundle(17, testTile("vaultwarden",
		vol("vaultwarden-data", tileschema.BackupCritical, tileschema.QuiesceStop)))
}

// TestFanOutReadsTheCatalogInEffect is the e3bench run of 2026-09-03, job
// 01M1M8K44120MAVB9CPKJN3C2V, as a test: Vaultwarden deployed on a compute
// node, the catalog in effect a verified v17 whose tile classifies
// vaultwarden-data `critical`, and a backup run. The only honest manifest has
// one record — not captured, off-node — and `complete: false`.
//
// Against the wiring this replaces (RunConfig.Tiles = catalog.MustLoad()),
// this test FAILS with the bench's exact symptom: zero records, complete true.
func TestFanOutReadsTheCatalogInEffect(t *testing.T) {
	fetched := benchFetched()
	r := runWithApps(t, runHarnessOpts{
		apps:  []*apps.App{testApp("app-vw", "vaultwarden", computeNodeID, "vaultwarden")},
		tiles: newCatalogStore(t, benchFloor(), &fetched),
	})
	if r.job.Status != "succeeded" {
		t.Fatalf("job failed: %s", r.job.Error)
	}
	if n := len(r.manifest.AppVolumes.Volumes); n != 1 {
		t.Fatalf("the manifest has %d app-volume record(s), want exactly one for vaultwarden-data: %+v\n"+
			"summary: %s", n, r.manifest.AppVolumes.Volumes, r.manifest.AppVolumes.Summary)
	}
	rec := r.record(t, "vaultwarden", "vaultwarden-data")
	if rec.Captured {
		t.Error("an off-node volume is marked captured, and nothing could have carried it here")
	}
	if rec.Reason != ReasonOffNode {
		t.Errorf("reason = %q, want ReasonOffNode", rec.Reason)
	}
	if rec.Class != tileschema.BackupCritical || rec.TileID != "vaultwarden" || rec.Node != computeNodeID {
		t.Errorf("record = %+v; class, tile and node come from the join and must all be there", rec)
	}
	if r.manifest.Complete || r.row.Complete {
		t.Errorf("complete is manifest=%v row=%v over an archive that omits a `critical` volume — the bench's exact lie",
			r.manifest.Complete, r.row.Complete)
	}
	if r.manifest.AppVolumes.SkippedCount != 1 || r.manifest.AppVolumes.CapturedCount != 0 {
		t.Errorf("counts = %d captured / %d skipped, want 0/1", r.manifest.AppVolumes.CapturedCount, r.manifest.AppVolumes.SkippedCount)
	}
	if !strings.Contains(r.ledger, "vaultwarden-data") {
		t.Error("the job feed never named the volume it could not capture")
	}
	// The manifest says what was looked at, and which catalog answered.
	e := r.manifest.AppVolumes
	if !e.Enumerated || e.AppsInstalled != 1 || e.AppsResolved != 1 || e.Catalog != "v17 (verified fetch)" {
		t.Errorf("enumeration = enumerated=%v installed=%d resolved=%d catalog=%q", e.Enumerated, e.AppsInstalled, e.AppsResolved, e.Catalog)
	}
	if !strings.Contains(r.ledger, "against catalog v17 (verified fetch)") {
		t.Error("the job feed never said which catalog the fan-out read")
	}
}

// TestFanOutRecordsATileThatDeclaresNoVolumes is the same cluster before any
// catalog fetch has succeeded — first boot, an airgapped install — running on
// the embedded floor, whose vaultwarden tile predates §4.2 and declares
// nothing. Vaultwarden is on the controlplane this time, so the ONLY thing
// between it and the archive is the missing classification.
//
// The run is not refused. It captures the identity set — the database, the
// mesh CA, Headscale — which is what a cluster in this state most needs on a
// disk, and it records Vaultwarden as not captured with a reason that names
// the tile and the catalog, so the manifest says `complete: false` and the
// job feed says why. A refusal would have left this cluster with no backup of
// anything, and said less.
func TestFanOutRecordsATileThatDeclaresNoVolumes(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{
		apps:  []*apps.App{testApp("app-vw", "vaultwarden", runNodeID, "vaultwarden")},
		tiles: newCatalogStore(t, benchFloor(), nil),
	})
	if r.job.Status != "succeeded" {
		t.Fatalf("job failed: %s — the identity set is still worth writing when an app cannot be classified", r.job.Error)
	}
	if n := len(r.manifest.AppVolumes.Volumes); n != 1 {
		t.Fatalf("the manifest has %d app-volume record(s), want one for vaultwarden: %+v", n, r.manifest.AppVolumes.Volumes)
	}
	rec := r.manifest.AppVolumes.Volumes[0]
	if rec.App != "vaultwarden" || rec.TileID != "vaultwarden" || rec.Captured || rec.Class != "unclassified" {
		t.Errorf("record = %+v", rec)
	}
	for _, want := range []string{"declares no volumes", "`vaultwarden`", "v14 (embedded floor"} {
		if !strings.Contains(rec.Reason, want) {
			t.Errorf("reason does not say %q: %q", want, rec.Reason)
		}
	}
	if r.manifest.Complete || r.row.Complete {
		t.Errorf("complete is manifest=%v row=%v with an installed app nobody classified", r.manifest.Complete, r.row.Complete)
	}
	e := r.manifest.AppVolumes
	if e.AppsInstalled != 1 || e.AppsResolved != 0 || !strings.Contains(e.Catalog, "embedded floor") {
		t.Errorf("enumeration = installed=%d resolved=%d catalog=%q", e.AppsInstalled, e.AppsResolved, e.Catalog)
	}
	// The identity set went in regardless.
	members := r.archiveMembers(t)
	for _, want := range []string{"manifest.json", "trust/mesh-ca.pem"} {
		if _, ok := members[want]; !ok {
			t.Errorf("the archive has no member %s; members are %v", want, keysOf(members))
		}
	}
	if _, ok := members["app-volumes/vaultwarden/vaultwarden-data.tar"]; ok {
		t.Error("an unclassified volume is in the archive; nothing could have known to stage it")
	}
	// And the job feed said so while it was happening — with the catalog
	// named, which is the one line that would have explained the bench.
	for _, want := range []string{"NOT captured: vaultwarden/", "against catalog v14 (embedded floor"} {
		if !strings.Contains(r.ledger, want) {
			t.Errorf("the job feed lacks %q", want)
		}
	}
	if !strings.Contains(r.row.Warning, "1 app volume(s) were not captured") {
		t.Errorf("ledger row warning = %q", r.row.Warning)
	}
}
