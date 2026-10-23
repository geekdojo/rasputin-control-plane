package storage

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
// out its row in restore_apply.go's identityApplyRules table used to be SILENT:
// the entry was staged, verified, written into the report as restored, and then
// dropped on the floor. The apply now refuses an entry no row names, and
// TestEveryIdentityMemberHasARestorePath fails on a member no row names.
// The restore half is two lists, not one: until geekdojo/geekdojo-brain#751
// identityRestorePath did not map the seed, so PrepareRestore listed it under
// NotRestored and reported green. TestRestorePutsTheArchivedAppSecretSeedBack
// now starts from a real sealed archive, so neither list can drop it unseen.

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

// seedHarness is a restore harness whose generation carries an app-secret seed
// minted by the real EnsureSeed, over a fresh data dir whose own first start
// minted a different one. It returns the harness and the archived seed's dir,
// so a test can load the original seed to compare derivations.
func seedHarness(t *testing.T, tamper func(t *testing.T, in []byte, m *Manifest) []byte) (*restoreHarness, string) {
	t.Helper()
	origDir := t.TempDir()
	archived := appSecretFixtureSeed(t, origDir)
	h := newRestoreHarness(t, generationOpts{complete: true, tamper: tamper, identity: func(fx *identityFixture) {
		fx.appSecretSeed = archived
	}})
	return h, origDir
}

// TC-751-01: a seed captured by the real Assemble and Seal is staged against
// the sealed manifest, put back over the fresh install's seed, and derives the
// same app secrets the backed-up cluster derived.
func TestRestorePutsTheArchivedAppSecretSeedBack(t *testing.T) {
	h, origDir := seedHarness(t, nil)
	archived := h.fx.appSecretSeed
	seedFreshInstall(t, h.dataDir)
	trustDir := filepath.Join(h.dataDir, "trust")
	freshSeed := appSecretFixtureSeed(t, trustDir)
	if bytes.Equal(freshSeed, archived) {
		t.Fatal("the fresh and archived seeds are identical, so this test cannot see the swap")
	}

	// (a) Prepare: staged, verified, reported restored with its note.
	report, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	if err != nil {
		t.Fatalf("PrepareRestore: %v", err)
	}
	var entry *RestoredEntry
	for i := range report.Restored {
		if report.Restored[i].Path == appSecretSeedArchivePath {
			entry = &report.Restored[i]
		}
	}
	if entry == nil {
		t.Fatalf("%s is not in report.Restored: %+v", appSecretSeedArchivePath, report.Restored)
	}
	if entry.SHA256 != mustSHA(archived) || entry.SizeBytes != int64(len(archived)) || entry.Note != appSecretSeedNote {
		t.Errorf("restored entry = %+v, want sha %s size %d and the seed's note", *entry, mustSHA(archived), len(archived))
	}
	for _, n := range report.NotRestored {
		if n.Path == appSecretSeedArchivePath {
			t.Errorf("%s is listed under NotRestored: %+v", appSecretSeedArchivePath, n)
		}
	}
	staged, err := os.ReadFile(filepath.Join(h.dataDir, restorePendingDirName, filepath.FromSlash(appSecretSeedArchivePath)))
	if err != nil || !bytes.Equal(staged, archived) {
		t.Fatalf("staged seed: %v, equal to the archived bytes: %v", err, bytes.Equal(staged, archived))
	}

	// (b) Apply: the archived seed is live, and the fresh one is set aside.
	layout := RestoreLayout{DataDir: h.dataDir, TrustDir: trustDir, MeshStateDir: filepath.Join(h.dataDir, "mesh")}
	if _, applied, err := ApplyPendingRestore(layout); err != nil || !applied {
		t.Fatalf("ApplyPendingRestore: %v applied=%v", err, applied)
	}
	live, err := os.ReadFile(filepath.Join(trustDir, appsecret.SeedFileName))
	if err != nil || !bytes.Equal(live, archived) {
		t.Fatalf("live seed after apply: %v, equal to the archived bytes: %v", err, bytes.Equal(live, archived))
	}
	aside, err := os.ReadFile(filepath.Join(replacedDir(t, h.dataDir), filepath.FromSlash(appSecretSeedArchivePath)))
	if err != nil || !bytes.Equal(aside, freshSeed) {
		t.Fatalf("the fresh install's seed was not set aside: %v", err)
	}

	// (c) The next start loads it, and it derives what the original derived:
	// every ${secret:} value an app's volume holds comes back the same.
	restored, err := appsecret.EnsureSeed(trustDir)
	if err != nil {
		t.Fatalf("the next start cannot load the restored seed: %v", err)
	}
	original, err := appsecret.EnsureSeed(origDir)
	if err != nil {
		t.Fatal(err)
	}
	const appID, name = "01K5R6P8Q9ZJ7V2XW4YB3D5EFG", "db-password"
	got, err := restored.Derive(appID, name, appsecret.InitialVersion)
	if err != nil {
		t.Fatalf("the restored seed cannot derive: %v", err)
	}
	want, err := original.Derive(appID, name, appsecret.InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Reveal(), want.Reveal()) {
		t.Fatal("the restored seed derives a different db-password than the backed-up cluster's seed")
	}
}

// TC-751-02: an archived seed whose bytes no longer match the sealed
// manifest's sha256 is refused at prepare, by name, with nothing staged.
func TestPrepareRestoreRefusesASeedThatFailsItsDigest(t *testing.T) {
	h, _ := seedHarness(t, func(t *testing.T, in []byte, m *Manifest) []byte {
		return rewriteTar(t, in, func(hd *tar.Header, body []byte) (*tar.Header, []byte, bool) {
			if hd.Name == appSecretSeedArchivePath {
				body = append([]byte{}, body...)
				body[0] ^= 0xff // same size, different bytes
			}
			return hd, body, true
		}, nil)
	})
	assertSeedRefused(t, h, "sha256")
}

// TC-751-03: a manifest that names the seed over an archive that lacks it is
// refused at prepare, by name, with nothing staged.
func TestPrepareRestoreRefusesAManifestSeedTheArchiveLacks(t *testing.T) {
	h, _ := seedHarness(t, func(t *testing.T, in []byte, m *Manifest) []byte {
		return rewriteTar(t, in, func(hd *tar.Header, body []byte) (*tar.Header, []byte, bool) {
			return hd, body, hd.Name != appSecretSeedArchivePath
		}, nil)
	})
	assertSeedRefused(t, h, "the manifest names "+appSecretSeedArchivePath+" but the archive has no such member")
}

func assertSeedRefused(t *testing.T, h *restoreHarness, want string) {
	t.Helper()
	_, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	if !errors.Is(err, ErrRestoreArchive) {
		t.Fatalf("err = %v, want ErrRestoreArchive", err)
	}
	if !strings.Contains(err.Error(), appSecretSeedArchivePath) || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %q, want it to name %s and say %q", err, appSecretSeedArchivePath, want)
	}
	if got := dataDirEntries(t, h.dataDir); len(got) != 0 {
		t.Fatalf("data dir was left with %v after a refused restore", got)
	}
}

// TC-751-04: the warning names the seed among what was restored, and names
// every member the restore saw and did not put back.
func TestIdentityRestoreWarning(t *testing.T) {
	const clause = "NOT put back"
	empty := identityRestoreWarning([]NotRestoredItem{})
	t.Run("empty list", func(t *testing.T) {
		if !strings.Contains(empty, "the app-secret seed") || !strings.Contains(empty, "APP DATA WAS NOT RESTORED") {
			t.Errorf("standing text = %q, want it to name the app-secret seed and say APP DATA WAS NOT RESTORED", empty)
		}
		if strings.Contains(empty, clause) {
			t.Errorf("an empty list produced a %q clause: %q", clause, empty)
		}
	})
	t.Run("two items", func(t *testing.T) {
		got := identityRestoreWarning([]NotRestoredItem{{Path: "a/x", Reason: "r"}, {Path: "b/y", Reason: "r"}})
		if !strings.HasPrefix(got, empty) {
			t.Errorf("the standing text is not kept: %q", got)
		}
		sentence := strings.TrimPrefix(got, empty)
		if !strings.Contains(sentence, clause) || !strings.Contains(sentence, "a/x") || !strings.Contains(sentence, "b/y") || !strings.HasSuffix(sentence, ".") || strings.Count(sentence, ".") != 1 {
			t.Errorf("added sentence = %q, want one sentence naming a/x and b/y, ending with a full stop", sentence)
		}
	})
	t.Run("nil", func(t *testing.T) {
		if got := identityRestoreWarning(nil); got != empty {
			t.Errorf("nil gives %q, want the empty-list text %q", got, empty)
		}
	})
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
