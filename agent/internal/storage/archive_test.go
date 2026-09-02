package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The agent half of design/storage.md §4.1 — preflight, write, prune — against
// the mock backend's REAL directories.
//
// The mock's mount root is an actual directory on disk (mountLocked mkdirs it),
// so everything here is exercising the filesystem code that runs on hardware.
// What the mock stands in for is the block layer, not the archive layer.

// claimedTarget formats the mock's USB disk and returns its partition UUID plus
// the mount path, so the backup verbs have a real target to work on.
func claimedTarget(t *testing.T, m *MockBackend) (partUUID, mountPath string) {
	t.Helper()
	ctx := context.Background()
	ack, err := m.Enumerate(ctx)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	var cand *proto.StorageCandidate
	for i := range ack.Candidates {
		if !ack.Candidates[i].Protected {
			cand = &ack.Candidates[i]
			break
		}
	}
	if cand == nil {
		t.Fatal("the mock machine offers no unprotected disk")
	}
	claim, err := m.Claim(ctx, proto.StorageClaimCmd{
		DevicePath: cand.DevicePath, Fingerprint: cand.Fingerprint, Label: "the archive disk",
	})
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if !claim.OK || claim.PartUUID == "" {
		t.Fatalf("claim ack = %+v", claim)
	}
	mp, err := m.Mount(ctx, claim.PartUUID)
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	return claim.PartUUID, mp
}

// stageArchive writes a fake sealed archive into a staging root and returns its
// name and digest — what the api would have produced.
func stageArchive(t *testing.T, root, name, body string) (string, string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
		t.Fatalf("stage %s: %v", name, err)
	}
	sum := sha256.Sum256([]byte(body))
	return name, hex.EncodeToString(sum[:])
}

func testManifest(scope string) string {
	b, _ := json.Marshal(map[string]any{
		"manifestVersion": 1,
		"scope":           scope,
		"complete":        scope == proto.BackupScopeFull,
		"appVolumes":      map[string]any{"captured": []string{}, "capturedCount": 0},
	})
	return string(b)
}

func writeGeneration(t *testing.T, m *MockBackend, partUUID, staging, genID string) {
	t.Helper()
	name, digest := stageArchive(t, staging, genID+".sealed", "sealed bytes for "+genID)
	ack, err := BackupWrite(context.Background(), m, staging, proto.BackupWriteCmd{
		PartUUID: partUUID, GenerationID: genID, StagingName: name,
		Digest: digest, SizeBytes: uint64(len("sealed bytes for " + genID)),
		ManifestJSON: testManifest(proto.BackupScopeIdentityOnly),
	})
	if err != nil {
		t.Fatalf("BackupWrite %s: %v", genID, err)
	}
	if !ack.OK {
		t.Fatalf("BackupWrite %s: %+v", genID, ack)
	}
	// Distinct mtimes so the newest-first ordering is deterministic rather than
	// dependent on filesystem timestamp granularity.
	time.Sleep(5 * time.Millisecond)
}

// TestBackupWriteLandsAGenerationAndItsManifest covers the happy path and the
// two files a generation is.
func TestBackupWriteLandsAGenerationAndItsManifest(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	partUUID, mountPath := claimedTarget(t, m)
	staging := t.TempDir()

	body := "SEALED-ARCHIVE-BYTES"
	name, digest := stageArchive(t, staging, "gen-a.sealed", body)
	genID := "20260902T030000Z-aaaaaaaa-identity-only"

	ack, err := BackupWrite(context.Background(), m, staging, proto.BackupWriteCmd{
		PartUUID: partUUID, GenerationID: genID, StagingName: name,
		Digest: digest, SizeBytes: uint64(len(body)),
		ManifestJSON: testManifest(proto.BackupScopeIdentityOnly),
	})
	if err != nil {
		t.Fatalf("BackupWrite: %v", err)
	}
	if !ack.OK {
		t.Fatalf("ack = %+v", ack)
	}
	if ack.Generation.Scope != proto.BackupScopeIdentityOnly {
		t.Errorf("the ack reports scope %q; it is read from the manifest so the api never has to be trusted about it", ack.Generation.Scope)
	}

	dir := filepath.Join(mountPath, proto.BackupGenerationsDir, genID)
	got, err := os.ReadFile(filepath.Join(dir, proto.BackupArchiveFile))
	if err != nil {
		t.Fatalf("read the written archive: %v", err)
	}
	if string(got) != body {
		t.Errorf("the archive on the target is %q, want %q", got, body)
	}
	if _, err := os.ReadFile(filepath.Join(dir, proto.BackupManifestFile)); err != nil {
		t.Fatalf("the manifest was not written beside the archive: %v", err)
	}
	// The manifest is CLEAR TEXT on purpose: an operator holding this disk and
	// no custody secret must be able to read what a generation contains.
	raw, _ := os.ReadFile(filepath.Join(dir, proto.BackupManifestFile))
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Errorf("the manifest on the platter is not readable JSON: %v", err)
	}

	// No `.partial-*` litter left behind.
	ents, _ := os.ReadDir(filepath.Join(mountPath, proto.BackupGenerationsDir))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".partial-") {
			t.Errorf("a partial directory survived a successful write: %s", e.Name())
		}
	}
}

// TestBackupWriteRefusals covers every way the write verb declines, and the
// property they share: NOTHING is written.
func TestBackupWriteRefusals(t *testing.T) {
	goodBody := "SEALED"
	goodDigest := func() string {
		sum := sha256.Sum256([]byte(goodBody))
		return hex.EncodeToString(sum[:])
	}()

	cases := []struct {
		name    string
		mutate  func(cmd *proto.BackupWriteCmd)
		wantErr error
		wantMsg string
	}{
		{
			name:    "a staging name that is a path is refused by shape",
			mutate:  func(c *proto.BackupWriteCmd) { c.StagingName = "../../etc/shadow" },
			wantErr: ErrStagingMissing,
			wantMsg: "not a plain file name",
		},
		{
			name:    "an absolute staging path is refused",
			mutate:  func(c *proto.BackupWriteCmd) { c.StagingName = "/etc/shadow" },
			wantErr: ErrStagingMissing,
			wantMsg: "not a plain file name",
		},
		{
			name:    "a dotfile staging name is refused",
			mutate:  func(c *proto.BackupWriteCmd) { c.StagingName = ".ssh" },
			wantErr: ErrStagingMissing,
			wantMsg: "not a plain file name",
		},
		{
			name:    "a staged file that is not there is refused",
			mutate:  func(c *proto.BackupWriteCmd) { c.StagingName = "never-written.sealed" },
			wantErr: ErrStagingMissing,
		},
		{
			name:    "a generation id that is not a plain name is refused",
			mutate:  func(c *proto.BackupWriteCmd) { c.GenerationID = "../escape" },
			wantErr: ErrStagingMissing,
			wantMsg: "not a usable generation id",
		},
		{
			name:    "a wrong digest is refused",
			mutate:  func(c *proto.BackupWriteCmd) { c.Digest = strings.Repeat("0", 64) },
			wantErr: ErrDigestMismatch,
		},
		{
			name:    "an absent digest is refused rather than skipping the check",
			mutate:  func(c *proto.BackupWriteCmd) { c.Digest = "" },
			wantErr: ErrDigestMismatch,
			wantMsg: "carried no digest",
		},
		{
			name:    "a size that disagrees with the staged file is refused",
			mutate:  func(c *proto.BackupWriteCmd) { c.SizeBytes = 999999 },
			wantErr: ErrDigestMismatch,
		},
		{
			name:    "a generation with no manifest is refused",
			mutate:  func(c *proto.BackupWriteCmd) { c.ManifestJSON = "" },
			wantMsg: "no manifest",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestMock(t, defaultMockMachine())
			partUUID, mountPath := claimedTarget(t, m)
			staging := t.TempDir()
			name, digest := stageArchive(t, staging, "gen-a.sealed", goodBody)

			cmd := proto.BackupWriteCmd{
				PartUUID: partUUID, GenerationID: "20260902T030000Z-aaaaaaaa-identity-only",
				StagingName: name, Digest: digest, SizeBytes: uint64(len(goodBody)),
				ManifestJSON: testManifest(proto.BackupScopeIdentityOnly),
			}
			if digest != goodDigest {
				t.Fatalf("fixture digest drifted: %s", digest)
			}
			tc.mutate(&cmd)

			_, err := BackupWrite(context.Background(), m, staging, cmd)
			if err == nil {
				t.Fatal("the write was accepted")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want it to wrap %v", err, tc.wantErr)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantMsg)
			}
			// Nothing on the target, and no partial left behind.
			gens := filepath.Join(mountPath, proto.BackupGenerationsDir)
			if ents, rerr := os.ReadDir(gens); rerr == nil {
				for _, e := range ents {
					t.Errorf("a refused write left %s on the target", e.Name())
				}
			}
		})
	}
}

// TestBackupWriteRefusesToOverwriteAGeneration: the api's step is Irreversible,
// and so is the verb's own answer to a replay. The generation on the platter is
// a record of something that happened.
func TestBackupWriteRefusesToOverwriteAGeneration(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	partUUID, _ := claimedTarget(t, m)
	staging := t.TempDir()
	genID := "20260902T030000Z-aaaaaaaa-identity-only"
	writeGeneration(t, m, partUUID, staging, genID)

	name, digest := stageArchive(t, staging, "again.sealed", "different bytes")
	_, err := BackupWrite(context.Background(), m, staging, proto.BackupWriteCmd{
		PartUUID: partUUID, GenerationID: genID, StagingName: name, Digest: digest,
		SizeBytes: uint64(len("different bytes")), ManifestJSON: testManifest(proto.BackupScopeIdentityOnly),
	})
	if err == nil {
		t.Fatal("a replayed write overwrote an existing generation")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q", err)
	}
}

// TestBackupPruneKeepsExactlyFour is §4.4's retention, against real
// directories.
func TestBackupPruneKeepsExactlyFour(t *testing.T) {
	ctx := context.Background()
	m := newTestMock(t, defaultMockMachine())
	partUUID, mountPath := claimedTarget(t, m)
	staging := t.TempDir()

	ids := []string{
		"20260801T030000Z-g1-identity-only",
		"20260808T030000Z-g2-identity-only",
		"20260815T030000Z-g3-identity-only",
		"20260822T030000Z-g4-identity-only",
		"20260829T030000Z-g5-identity-only",
		"20260902T030000Z-g6-identity-only",
	}
	for _, id := range ids {
		writeGeneration(t, m, partUUID, staging, id)
	}
	newest := ids[len(ids)-1]

	ack, err := BackupPrune(ctx, m, proto.BackupPruneCmd{
		PartUUID: partUUID, Keep: proto.BackupRetainGenerations, ProtectGenerationID: newest,
	})
	if err != nil {
		t.Fatalf("BackupPrune: %v", err)
	}
	if !ack.OK {
		t.Fatalf("ack = %+v", ack)
	}
	if len(ack.Kept) != 4 {
		t.Errorf("kept %d generation(s) (%v), want exactly 4", len(ack.Kept), ack.Kept)
	}
	if len(ack.Pruned) != 2 {
		t.Errorf("pruned %d, want 2 (%v)", len(ack.Pruned), ack.Pruned)
	}
	// Oldest first, as §4.4 says.
	for _, want := range []string{ids[0], ids[1]} {
		found := false
		for _, p := range ack.Pruned {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s survived; prune removes the OLDEST first", want)
		}
	}

	// And the disk agrees with the ack.
	ents, err := os.ReadDir(filepath.Join(mountPath, proto.BackupGenerationsDir))
	if err != nil {
		t.Fatalf("read generations: %v", err)
	}
	if len(ents) != 4 {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("the target holds %d generation(s) (%v), want 4", len(ents), names)
	}

	// CONVERGENT: a second prune on a settled target removes nothing. This is
	// the property that makes the api's prune step safe to retry, and it is why
	// that step is deliberately NOT declared Irreversible.
	again, err := BackupPrune(ctx, m, proto.BackupPruneCmd{
		PartUUID: partUUID, Keep: proto.BackupRetainGenerations, ProtectGenerationID: newest,
	})
	if err != nil {
		t.Fatalf("second BackupPrune: %v", err)
	}
	if len(again.Pruned) != 0 {
		t.Errorf("a repeated prune removed %v; the verb is meant to converge, not to take a bite each time", again.Pruned)
	}
	if len(again.Kept) != 4 {
		t.Errorf("a repeated prune kept %d, want 4", len(again.Kept))
	}
}

// TestBackupPruneNeverDeletesTheRunsOwnGeneration: no clock skew or coarse
// filesystem timestamp may cost a run its own output.
func TestBackupPruneProtectsTheNewestGeneration(t *testing.T) {
	ctx := context.Background()
	m := newTestMock(t, defaultMockMachine())
	partUUID, _ := claimedTarget(t, m)
	staging := t.TempDir()
	for i := 1; i <= 3; i++ {
		writeGeneration(t, m, partUUID, staging, fmt.Sprintf("gen-%d-identity-only", i))
	}
	protected := "gen-1-identity-only" // the OLDEST, so ordering alone would delete it

	ack, err := BackupPrune(ctx, m, proto.BackupPruneCmd{
		PartUUID: partUUID, Keep: 1, ProtectGenerationID: protected,
	})
	if err != nil {
		t.Fatalf("BackupPrune: %v", err)
	}
	for _, p := range ack.Pruned {
		if p == protected {
			t.Fatal("prune deleted the generation it was told to protect")
		}
	}
}

// TestBackupPruneRefusesKeepZero: a prune that empties the disk is not a
// retention policy, and a zero-valued struct must not be able to express one.
func TestBackupPruneRefusesKeepZero(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	partUUID, _ := claimedTarget(t, m)
	for _, keep := range []int{0, -1} {
		_, err := BackupPrune(context.Background(), m, proto.BackupPruneCmd{PartUUID: partUUID, Keep: keep})
		if err == nil {
			t.Fatalf("keep=%d was accepted", keep)
		}
		if !strings.Contains(err.Error(), "not a retention policy") {
			t.Errorf("keep=%d: error = %q", keep, err)
		}
	}
}

// TestBackupPruneIgnoresPartialDirectories: a write that crashed mid-copy is
// the write path's own litter. Counting one as a generation would let a crashed
// run push a real generation over the retention line.
func TestBackupPruneIgnoresPartialDirectories(t *testing.T) {
	ctx := context.Background()
	m := newTestMock(t, defaultMockMachine())
	partUUID, mountPath := claimedTarget(t, m)
	staging := t.TempDir()
	for i := 1; i <= 4; i++ {
		writeGeneration(t, m, partUUID, staging, fmt.Sprintf("gen-%d-identity-only", i))
	}
	partial := filepath.Join(mountPath, proto.BackupGenerationsDir, ".partial-crashed")
	if err := os.MkdirAll(partial, 0o700); err != nil {
		t.Fatal(err)
	}

	ack, err := BackupPrune(ctx, m, proto.BackupPruneCmd{PartUUID: partUUID, Keep: 4})
	if err != nil {
		t.Fatalf("BackupPrune: %v", err)
	}
	if len(ack.Pruned) != 0 {
		t.Errorf("a partial directory pushed a real generation over the line: pruned %v", ack.Pruned)
	}
	if len(ack.Kept) != 4 {
		t.Errorf("kept %d, want 4", len(ack.Kept))
	}
	// The same reasoning applies to the count the adopt-or-wipe prompt shows.
	n, err := countGenerations(mountPath)
	if err != nil {
		t.Fatalf("countGenerations: %v", err)
	}
	if n != 4 {
		t.Errorf("countGenerations = %d, want 4 — a partial must not inflate what a wipe is said to destroy", n)
	}
}

// TestBackupPreflightReportsSpaceAndRetention covers §4.4's pre-flight check on
// a target that has room.
func TestBackupPreflightReportsSpaceAndRetention(t *testing.T) {
	ctx := context.Background()
	m := newTestMock(t, defaultMockMachine())
	partUUID, _ := claimedTarget(t, m)
	staging := t.TempDir()
	writeGeneration(t, m, partUUID, staging, "gen-1-identity-only")
	writeGeneration(t, m, partUUID, staging, "gen-2-identity-only")

	ack, err := BackupPreflight(ctx, m, staging, proto.BackupPreflightCmd{PartUUID: partUUID, EstimateBytes: 1024})
	if err != nil {
		t.Fatalf("BackupPreflight: %v", err)
	}
	if !ack.OK || !ack.Present || !ack.Sufficient {
		t.Fatalf("ack = %+v", ack)
	}
	if len(ack.Generations) != 2 {
		t.Errorf("reported %d generation(s), want 2", len(ack.Generations))
	}
	if ack.RequiredBytes != 1024+proto.BackupTargetReserveBytes {
		t.Errorf("requiredBytes = %d, want the estimate plus the reserve", ack.RequiredBytes)
	}
	// Newest first, so an operator reading the list sees the current backup at
	// the top and prune's victim at the bottom.
	if ack.Generations[0].ID != "gen-2-identity-only" {
		t.Errorf("generations are not newest-first: %s", ack.Generations[0].ID)
	}
	if ack.Generations[0].Scope != proto.BackupScopeIdentityOnly {
		t.Errorf("generation scope = %q, read from the manifest", ack.Generations[0].Scope)
	}
}

// TestBackupPreflightRefusesOnLowSpace is §4.4's "refuses rather than starting".
//
// Driven through requiredBytes rather than by filling a disk: an estimate
// larger than any filesystem is the only portable way to make a real statfs
// report insufficient space.
func TestBackupPreflightRefusesOnLowSpace(t *testing.T) {
	ctx := context.Background()
	m := newTestMock(t, defaultMockMachine())
	partUUID, _ := claimedTarget(t, m)

	ack, err := BackupPreflight(ctx, m, t.TempDir(), proto.BackupPreflightCmd{
		PartUUID: partUUID, EstimateBytes: 1 << 60, // an exabyte
	})
	if err != nil {
		t.Fatalf("BackupPreflight: %v", err)
	}
	if ack.Sufficient {
		t.Fatal("an exabyte fits")
	}
	if ack.OK {
		t.Error("an insufficient-space preflight answered OK: §4.4 wants a refusal, not a caveat")
	}
	if ack.Refusal != proto.BackupRefusalInsufficientSpace {
		t.Errorf("refusal = %q, want %q", ack.Refusal, proto.BackupRefusalInsufficientSpace)
	}
	// The numbers must survive into the refusal — "there is not room" is not
	// actionable and "900 MiB free, needs 1.4 GiB" is.
	for _, want := range []string{"free", "reserve", "Nothing was written"} {
		if !strings.Contains(ack.Detail, want) {
			t.Errorf("the refusal does not mention %q: %s", want, ack.Detail)
		}
	}
	if ack.FreeBytes == 0 || ack.RequiredBytes == 0 {
		t.Error("the refusal carries no numbers")
	}
}

// TestRequiredBytesSaturates: an estimate that overflowed would produce a
// requirement SMALLER than the archive — a preflight that passes on a disk with
// no room, arrived at by arithmetic.
func TestRequiredBytesSaturates(t *testing.T) {
	if got := requiredBytes(^uint64(0)); got != ^uint64(0) {
		t.Errorf("requiredBytes(max) = %d, want saturation at max", got)
	}
	if got := requiredBytes(1024); got != 1024+proto.BackupTargetReserveBytes {
		t.Errorf("requiredBytes(1024) = %d", got)
	}
}

// TestBackupVerbsRefuseAnUnattachedTarget: "the operator unplugged it" is an
// answer, not a backend failure, and each verb has to say so in its own shape.
func TestBackupVerbsRefuseAnUnattachedTarget(t *testing.T) {
	ctx := context.Background()
	m := newTestMock(t, defaultMockMachine())
	staging := t.TempDir()
	const absent = "00000000-0000-0000-0000-00000000dead"

	pre, err := BackupPreflight(ctx, m, staging, proto.BackupPreflightCmd{PartUUID: absent})
	if err != nil {
		t.Fatalf("BackupPreflight: %v", err)
	}
	if pre.Present {
		t.Error("preflight reported an absent target as present")
	}
	if pre.Refusal != proto.StorageRefusalNotFound {
		t.Errorf("preflight refusal = %q", pre.Refusal)
	}

	name, digest := stageArchive(t, staging, "gen.sealed", "bytes")
	w, err := BackupWrite(ctx, m, staging, proto.BackupWriteCmd{
		PartUUID: absent, GenerationID: "gen-identity-only", StagingName: name,
		Digest: digest, SizeBytes: 5, ManifestJSON: testManifest(proto.BackupScopeIdentityOnly),
	})
	if err != nil {
		t.Fatalf("BackupWrite: %v", err)
	}
	if w.OK || w.Refusal != proto.StorageRefusalNotFound {
		t.Errorf("write ack = %+v", w)
	}

	p, err := BackupPrune(ctx, m, proto.BackupPruneCmd{PartUUID: absent, Keep: 4})
	if err != nil {
		t.Fatalf("BackupPrune: %v", err)
	}
	if p.OK || p.Refusal != proto.StorageRefusalNotFound {
		t.Errorf("prune ack = %+v", p)
	}
}

// TestCleanStagingSweepsOrphans is §4.7's "cleanup on failure and on boot", on
// the agent's half of the handoff.
func TestCleanStagingSweepsOrphans(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gen-1.sealed"), []byte("orphaned archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "not-ours"), 0o700); err != nil {
		t.Fatal(err)
	}
	n, freed := CleanStaging(dir)
	if n != 1 || freed == 0 {
		t.Errorf("CleanStaging removed %d file(s), %d bytes", n, freed)
	}
	if _, err := os.Stat(filepath.Join(dir, "not-ours")); err != nil {
		t.Error("CleanStaging removed a directory it did not create")
	}
}

// TestStagingRootIsTheDeployedDefaultWithNoEnvironmentSet pins the DEFAULT —
// the one configuration that ships, and the one nothing tested.
//
// The test this replaces asked both halves of the handoff to resolve the same
// argument ("/var/lib/rasputin") and found them equal. Production does not ask
// that question. It gives the api its DATA dir (/var/lib/rasputin) and the
// agent its STATE dir (/var/lib/rasputin/agent-state, set by the shipping unit
// file), and the shared RASPUTIN_BACKUP_STAGING_DIR that both files claimed
// kept them aligned is set nowhere on the image. So the api sealed a 105 MB
// archive into one directory and the agent refused it as missing from another,
// on every run, with a green test suite (e3bench 2026-09-02).
//
// The fix is not a better-agreed default: it is that only ONE side derives a
// path at all. This pins that side's answer, with no environment set.
func TestStagingRootIsTheDeployedDefaultWithNoEnvironmentSet(t *testing.T) {
	// Explicitly empty rather than merely unset in the runner's environment:
	// the assertion is about the no-override path, and it must hold whatever
	// the machine running the test happens to export.
	t.Setenv("RASPUTIN_BACKUP_STAGING_DIR", "")

	// What RASPUTIN_AGENT_STATE_DIR is on the shipping image.
	const deployedStateDir = "/var/lib/rasputin/agent-state"
	const want = deployedStateDir + "/" + backupStagingDirName
	if got := StagingRoot(deployedStateDir); got != want {
		t.Errorf("StagingRoot(%q) = %q, want %q", deployedStateDir, got, want)
	}
}

// TestPreflightReportsExactlyWhatTheWriteVerbWillRead is the assertion that
// makes the e3bench failure unreachable, and it is deliberately end-to-end with
// NO environment variable set.
//
// The api does not derive a staging path any more; it stages into
// BackupPreflightAck.StagingRoot. So the property that has to hold is: the
// directory preflight NAMES is the directory write READS. Both come from one
// expression here, which is what "by construction" means — there is no second
// derivation left to drift.
func TestPreflightReportsExactlyWhatTheWriteVerbWillRead(t *testing.T) {
	t.Setenv("RASPUTIN_BACKUP_STAGING_DIR", "")
	ctx := context.Background()
	m := newTestMock(t, defaultMockMachine())
	partUUID, _ := claimedTarget(t, m)

	// The agent resolves its root the way main.go does, from its state dir,
	// with nothing in the environment.
	stateDir := t.TempDir()
	root := StagingRoot(stateDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("staging root: %v", err)
	}

	ack, err := BackupPreflight(ctx, m, root, proto.BackupPreflightCmd{PartUUID: partUUID, EstimateBytes: 1024})
	if err != nil {
		t.Fatalf("BackupPreflight: %v", err)
	}
	if ack.StagingRoot != root {
		t.Fatalf("preflight reported staging root %q, but the write verb reads %q — that gap IS the bug", ack.StagingRoot, root)
	}

	// Now do what the api does: stage into the directory it was told about, and
	// hand the write verb a NAME. It must find it.
	name, digest := stageArchive(t, ack.StagingRoot, "20260902T195950Z-job-identity-only.sealed", "sealed-bytes")
	w, err := BackupWrite(ctx, m, root, proto.BackupWriteCmd{
		PartUUID: partUUID, GenerationID: "20260902T195950Z-job-identity-only",
		StagingName: name, Digest: digest, SizeBytes: uint64(len("sealed-bytes")),
		ManifestJSON: testManifest(proto.BackupScopeIdentityOnly),
	})
	if err != nil {
		t.Fatalf("an archive staged where preflight said to stage it was refused: %v", err)
	}
	if !w.OK {
		t.Fatalf("write ack = %+v", w)
	}
}

// TestStagingRootOverrideMovesBothHalvesTogether: the override still works, and
// because the api is TOLD the root rather than resolving one, setting it on the
// agent moves the api with it. A half-applied override is the original bug in a
// different hat, and there is no longer a half to apply it to.
func TestStagingRootOverrideMovesBothHalvesTogether(t *testing.T) {
	ctx := context.Background()
	m := newTestMock(t, defaultMockMachine())
	partUUID, _ := claimedTarget(t, m)

	elsewhere := t.TempDir()
	t.Setenv("RASPUTIN_BACKUP_STAGING_DIR", elsewhere)

	stateDir := t.TempDir() // deliberately NOT where the archive will go
	root := StagingRoot(stateDir)
	if root != elsewhere {
		t.Fatalf("the override was ignored: %q", root)
	}
	ack, err := BackupPreflight(ctx, m, root, proto.BackupPreflightCmd{PartUUID: partUUID})
	if err != nil {
		t.Fatalf("BackupPreflight: %v", err)
	}
	if ack.StagingRoot != elsewhere {
		t.Errorf("preflight reported %q, so the api would stage somewhere the override did not move", ack.StagingRoot)
	}
}

// TestPreflightReportsTheStagingRootEvenWhenTheTargetIsUnplugged: the root is a
// property of the node, not of the disk, and an operator reading a
// target-unplugged refusal should still see where this node stages.
func TestPreflightReportsTheStagingRootEvenWhenTheTargetIsUnplugged(t *testing.T) {
	ctx := context.Background()
	m := newTestMock(t, defaultMockMachine())
	root := t.TempDir()

	ack, err := BackupPreflight(ctx, m, root, proto.BackupPreflightCmd{
		PartUUID: "00000000-0000-0000-0000-00000000dead",
	})
	if err != nil {
		t.Fatalf("BackupPreflight: %v", err)
	}
	if ack.Present {
		t.Fatal("an absent target reported present")
	}
	if ack.StagingRoot != root {
		t.Errorf("staging root = %q on the unplugged path, want %q", ack.StagingRoot, root)
	}
}

// TestListGenerationsTieBreaksOnTheID covers the ordering fallback for two
// generations whose archive files share a modification time.
//
// Not a hypothetical: some filesystems have one-second timestamp granularity,
// and two generations written inside the same second would then sort
// arbitrarily — which decides which one prune deletes. The tiebreak makes that
// deterministic and, because generation ids start with a sortable UTC
// timestamp, correct.
func TestListGenerationsTieBreaksOnTheID(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	partUUID, mountPath := claimedTarget(t, m)
	staging := t.TempDir()
	ids := []string{
		"20260801T030000Z-g1-identity-only",
		"20260808T030000Z-g2-identity-only",
		"20260815T030000Z-g3-identity-only",
	}
	for _, id := range ids {
		writeGeneration(t, m, partUUID, staging, id)
	}
	// Force identical mtimes, as a coarse-granularity filesystem would.
	same := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	for _, id := range ids {
		p := filepath.Join(mountPath, proto.BackupGenerationsDir, id, proto.BackupArchiveFile)
		if err := os.Chtimes(p, same, same); err != nil {
			t.Fatalf("chtimes %s: %v", id, err)
		}
	}

	gens, err := listGenerations(mountPath)
	if err != nil {
		t.Fatalf("listGenerations: %v", err)
	}
	if len(gens) != 3 {
		t.Fatalf("got %d generations, want 3", len(gens))
	}
	// Newest first, decided by the id when the timestamps cannot decide.
	want := []string{ids[2], ids[1], ids[0]}
	for i, id := range want {
		if gens[i].ID != id {
			t.Errorf("position %d is %s, want %s — with equal mtimes the id has to break the tie, or prune deletes an arbitrary generation",
				i, gens[i].ID, id)
		}
	}
	// And prune then removes the genuinely oldest.
	ack, err := BackupPrune(context.Background(), m, proto.BackupPruneCmd{PartUUID: partUUID, Keep: 2})
	if err != nil {
		t.Fatalf("BackupPrune: %v", err)
	}
	if len(ack.Pruned) != 1 || ack.Pruned[0] != ids[0] {
		t.Errorf("pruned %v, want just the oldest (%s)", ack.Pruned, ids[0])
	}
}
