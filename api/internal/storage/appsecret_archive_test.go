package storage

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// BOTH HALVES OR NEITHER (geekdojo/geekdojo-brain#520).
//
// The app-secret seed is the one file in the identity set with no second copy
// and no way to recompute it: every generated app credential on the cluster is a
// function of it, and each app's data volume keeps the value it was handed. A
// seed that ships out and cannot come back means a restored cluster whose apps
// hold credentials nothing can re-derive.
//
// The two halves fail differently, which is why both are tested here. Leaving it
// out of trustFiles is at least visible — the manifest does not list it. Leaving
// out the case in restore_apply.go's hand-written path switch is SILENT: the
// entry is staged, verified, written into the report as restored, and then
// dropped on the floor, so the report says the seed came back and the live file
// is the fresh install's.

func appSecretFixtureSeed(t *testing.T, dir string) []byte {
	t.Helper()
	if _, err := appsecret.EnsureSeed(dir); err != nil {
		t.Fatalf("EnsureSeed: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, appsecret.SeedFileName))
	if err != nil {
		t.Fatalf("read the seed back: %v", err)
	}
	return raw
}

func TestAssembleCapturesTheAppSecretSeed(t *testing.T) {
	dir := t.TempDir()
	trustDir := filepath.Join(dir, "trust")
	seedBytes := appSecretFixtureSeed(t, trustDir)
	writeTestFile(t, filepath.Join(trustDir, "mesh-ca.key"), "MESH-CA-KEY")
	writeTestFile(t, filepath.Join(trustDir, "mesh-ca.pem"), "MESH-CA-PEM")
	snap := filepath.Join(dir, "snapshot.db")
	writeTestFile(t, snap, "SQLITE-SNAPSHOT-BYTES")

	var buf bytes.Buffer
	m, err := Assemble(&buf, AssembleOptions{
		Sources:      IdentitySources{TrustDir: trustDir},
		SnapshotPath: snap,
		GenerationID: "20260923T000000Z-test-full",
		ClusterID:    "home1",
		KeyID:        "key-1",
		Scope:        proto.BackupScopeFull,
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	var entry *ManifestEntry
	for i := range m.Entries {
		if m.Entries[i].Path == appSecretSeedArchivePath {
			entry = &m.Entries[i]
		}
	}
	if entry == nil {
		t.Fatalf("the manifest does not list %s — a restore of this generation loses every app secret on the cluster permanently, with no way to re-derive them", appSecretSeedArchivePath)
	}
	if entry.SHA256 != mustSHA(seedBytes) || entry.SizeBytes != int64(len(seedBytes)) {
		t.Errorf("manifest entry for the seed: digest %s size %d, want %s / %d", entry.SHA256, entry.SizeBytes, mustSHA(seedBytes), len(seedBytes))
	}
	// The note is what an operator reading the manifest has to work from.
	if entry.Note == "" {
		t.Error("the seed's manifest entry says nothing about what the file is")
	}

	// And the bytes are actually in the tar, not just in the index.
	found := false
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read archive: %v", err)
		}
		if h.Name != appSecretSeedArchivePath {
			continue
		}
		found = true
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read the seed member: %v", err)
		}
		if !bytes.Equal(body, seedBytes) {
			t.Errorf("the archived seed differs from the one on disk:\n got %q\nwant %q", body, seedBytes)
		}
	}
	if !found {
		t.Fatalf("%s is in the manifest but not in the archive", appSecretSeedArchivePath)
	}
}

// MeasureIdentitySet sizes the staging guard and the target preflight estimate.
// A file in the archive that the measurement does not count makes both estimates
// smaller than the archive they are sizing.
func TestMeasureIdentitySetCountsTheAppSecretSeed(t *testing.T) {
	trustDir := filepath.Join(t.TempDir(), "trust")
	seedBytes := appSecretFixtureSeed(t, trustDir)
	got := MeasureIdentitySet(IdentitySources{TrustDir: trustDir}, 0)
	if got < uint64(len(seedBytes)) {
		t.Errorf("MeasureIdentitySet reports %d bytes for a trust dir holding only the %d-byte seed", got, len(seedBytes))
	}
}

// The restore half: the case in restore_apply.go's path switch. Without it this
// test's live seed stays the fresh install's while the report claims the
// archive's was restored.
func TestApplyPendingRestorePutsTheAppSecretSeedBack(t *testing.T) {
	dataDir := t.TempDir()
	trustDir := filepath.Join(dataDir, "trust")

	// The fresh install: a seed this box minted at its own first start, which a
	// restore must displace.
	freshSeed := appSecretFixtureSeed(t, trustDir)

	// The archive's seed, staged by PrepareRestore. A different seed, so the
	// swap is observable: two valid seed files that derive different secrets.
	archivedSeed := []byte("rasputin-app-secret-seed/1 " +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + "\n")
	if bytes.Equal(freshSeed, archivedSeed) {
		t.Fatal("the fixture's two seeds are identical, so this test cannot see the swap")
	}
	pending := filepath.Join(dataDir, restorePendingDirName)
	if err := os.MkdirAll(filepath.Join(pending, "trust"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(pending, filepath.FromSlash(appSecretSeedArchivePath)), string(archivedSeed))
	report := RestoreReport{
		ID: "r-appsecret", Phase: RestorePhase, GenerationID: "g1", PreparedAt: time.Now().UTC(),
		Restored: []RestoredEntry{{
			Path: appSecretSeedArchivePath, SizeBytes: int64(len(archivedSeed)), SHA256: mustSHA(archivedSeed),
		}},
	}
	writeReportFile(t, filepath.Join(pending, restoreReportFile), report)

	applied, ok, err := ApplyPendingRestore(RestoreLayout{DataDir: dataDir, TrustDir: trustDir})
	if err != nil || !ok || applied == nil {
		t.Fatalf("ApplyPendingRestore: %v applied=%v report=%+v", err, ok, applied)
	}

	live, err := os.ReadFile(filepath.Join(trustDir, appsecret.SeedFileName))
	if err != nil {
		t.Fatalf("read the live seed: %v", err)
	}
	if !bytes.Equal(live, archivedSeed) {
		t.Fatalf("the restored seed is not in place — an entry with no case in restore_apply.go's switch is staged, reported as restored, and silently dropped.\n live %q\nwant %q", live, archivedSeed)
	}

	// The fresh install's own seed was moved ASIDE, not deleted: a failed or
	// mistaken restore must leave the interim identity recoverable by hand.
	var replaced string
	for _, e := range dataDirEntries(t, dataDir) {
		if len(e) > len(restoreReplacedPrefix) && e[:len(restoreReplacedPrefix)] == restoreReplacedPrefix {
			replaced = filepath.Join(dataDir, e)
		}
	}
	if replaced == "" {
		t.Fatal("no restore-replaced directory was created")
	}
	aside, err := os.ReadFile(filepath.Join(replaced, filepath.FromSlash(appSecretSeedArchivePath)))
	if err != nil || !bytes.Equal(aside, freshSeed) {
		t.Fatalf("the fresh install's seed was not set aside: %v / %q", err, aside)
	}

	// And the seed that landed is one the api can actually derive from on its
	// next start — the whole point of putting it back.
	seed, err := appsecret.EnsureSeed(trustDir)
	if err != nil {
		t.Fatalf("the next start cannot load the restored seed: %v", err)
	}
	if _, err := seed.Derive("01K5R6P8Q9ZJ7V2XW4YB3D5EFG", "db-password", appsecret.InitialVersion); err != nil {
		t.Fatalf("the restored seed cannot derive: %v", err)
	}
}

// writeReportFile writes a pending restore's report, as PrepareRestore leaves it.
func writeReportFile(t *testing.T, path string, report RestoreReport) {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, string(raw))
}
