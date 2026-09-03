package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
)

// §4.7's staging path and the source-side guard, tested against a real SQLite
// file — because `VACUUM INTO` is the one thing in this slice a mock cannot
// stand in for. A file copy of a live WAL-mode database also "produces a file";
// what distinguishes the two is whether that file OPENS, and that is what this
// asserts.

// TestSnapshotDBProducesAReadableDatabase is the reason step 3 exists.
//
// It writes to the source WHILE the snapshot is being taken — an open
// transaction with uncommitted rows — because that is the state the api is
// actually in at 3 a.m., and it is the state a `cp` of a WAL-mode database
// silently mangles.
func TestSnapshotDBProducesAReadableDatabase(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rasputin.db")

	st, err := OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Real rows, through the store's own writes.
	for i, id := range []string{"job-a", "job-b", "job-c"} {
		if err := st.CreatePending(ctx, id, "n1", "/dev/sdb", "disk", time.Now().UTC()); err != nil {
			t.Fatalf("CreatePending %d: %v", i, err)
		}
	}

	snap := filepath.Join(dir, "snapshot.db")
	size, err := SnapshotDB(ctx, st.DB(), snap)
	if err != nil {
		t.Fatalf("SnapshotDB: %v", err)
	}
	if size == 0 {
		t.Fatal("the snapshot is empty")
	}

	// It opens ON ITS OWN, with no -wal and no -shm beside it. That is the
	// property `VACUUM INTO` has and a file copy does not.
	for _, sidecar := range []string{snap + "-wal", snap + "-shm"} {
		if _, err := os.Stat(sidecar); err == nil {
			t.Errorf("%s exists: the snapshot is not self-contained", sidecar)
		}
	}
	copied, err := dbutil.Open(ctx, snap, "", "snapshot")
	if err != nil {
		t.Fatalf("the snapshot does not open as a database: %v", err)
	}
	defer func() { _ = copied.Close() }()

	var n int
	if err := copied.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_targets`).Scan(&n); err != nil {
		t.Fatalf("read the snapshot: %v", err)
	}
	if n != 3 {
		t.Errorf("the snapshot holds %d backup_targets rows, want 3", n)
	}
	var integrity string
	if err := copied.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("integrity_check: %v", err)
	}
	if integrity != "ok" {
		t.Errorf("integrity_check = %q, want ok", integrity)
	}
}

// TestSnapshotDBRefusesToOverwrite: a leftover from a crashed run must not be
// silently adopted as this run's database. Sealing yesterday's snapshot as
// today's backup is a failure nobody would notice until a restore.
func TestSnapshotDBRefusesToOverwrite(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := OpenStore(ctx, filepath.Join(dir, "rasputin.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	snap := filepath.Join(dir, "snapshot.db")
	if err := os.WriteFile(snap, []byte("yesterday's leftover"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SnapshotDB(ctx, st.DB(), snap); err == nil {
		t.Fatal("SnapshotDB overwrote an existing file")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q", err)
	}
	// And the leftover is untouched, so a human can see what was there.
	if b, _ := os.ReadFile(snap); string(b) != "yesterday's leftover" {
		t.Error("the refusal modified the existing file")
	}
}

// TestStagingBudgetArithmetic pins the guard's sizing and its refusal message.
//
// The peak is deliberately pessimistic — snapshot plus tar plus sealed, without
// modelling the deletes that happen between them — because an estimate that is
// optimistic about a disk-full failure is not a guard.
func TestStagingBudgetArithmetic(t *testing.T) {
	const gib = uint64(1) << 30
	cases := []struct {
		name          string
		db, identity  uint64
		free          uint64
		wantSufficent bool
	}{
		{"comfortable", gib, 2 * gib, 20 * gib, true},
		{"exactly at the line", gib, 2 * gib, 5*gib + StagingReserveBytes, true},
		{"one byte short", gib, 2 * gib, 5*gib + StagingReserveBytes - 1, false},
		{"free space below the reserve alone", 0, 0, StagingReserveBytes - 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := StagingBudget{
				DBBytes: tc.db, IdentityBytes: tc.identity,
				PeakBytes: tc.db + 2*tc.identity,
				FreeBytes: tc.free, ReserveBytes: StagingReserveBytes,
			}
			if got := b.Sufficient(); got != tc.wantSufficent {
				t.Errorf("Sufficient() = %v, want %v (peak %d + reserve %d vs free %d)",
					got, tc.wantSufficent, b.PeakBytes, b.ReserveBytes, b.FreeBytes)
			}
			msg := b.Explain("/var/lib/rasputin/backup-staging")
			// §4.4 wants a refusal an operator can act on: both numbers, always.
			for _, want := range []string{"/var/lib/rasputin/backup-staging", "free", "reserve", "Nothing was written"} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal message does not mention %q: %s", want, msg)
				}
			}
		})
	}

	// The reserve is §5's VictoriaMetrics free-space reservation, and that is
	// not a coincidence to be broken casually: below it VM stops accepting
	// samples. A backup must never be the thing that blinds the metrics store.
	if StagingReserveBytes != 2<<30 {
		t.Errorf("StagingReserveBytes = %d; §5 pins it to VictoriaMetrics' 2 GB -storage.minFreeDiskSpaceBytes reservation", StagingReserveBytes)
	}
}

// TestSufficientSaturates: an overflowing peak must read as insufficient rather
// than wrapping to a small number and passing.
func TestSufficientSaturates(t *testing.T) {
	b := StagingBudget{
		PeakBytes: ^uint64(0) - 10, ReserveBytes: StagingReserveBytes, FreeBytes: ^uint64(0),
	}
	if b.Sufficient() {
		t.Error("an overflowing requirement was reported as satisfiable")
	}
}

// TestPlanStagingRefusesOnARealDirectory drives the whole guard against a real
// filesystem: a requirement no disk could satisfy must produce ErrStagingFull
// with the numbers in it.
func TestPlanStagingRefusesOnARealDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := PlanStaging(dir, 1<<20, 1<<20, 0, 0); err != nil {
		t.Fatalf("a megabyte should fit in a temp dir: %v", err)
	}
	// An exabyte will not.
	_, err := PlanStaging(dir, 1<<60, 1<<60, 0, 0)
	if err == nil {
		t.Fatal("PlanStaging accepted an exabyte")
	}
	if !strings.Contains(err.Error(), "not enough free space") {
		t.Errorf("error = %q", err)
	}
}

// TestPlanStagingSizesForTheLargestSingleVolume is §4.7's peak, with app
// volumes in it: the payload is resident twice (assembled, then sealed) and the
// largest single staged volume is resident alongside both.
//
// The assertion that matters is the LAST one — a run whose volumes are small
// enough to fit but whose largest single volume is not must be refused. Sizing
// only for the total would let a backup fill the disk it is protecting on the
// one volume that mattered.
func TestPlanStagingSizesForTheLargestSingleVolume(t *testing.T) {
	dir := t.TempDir()
	b, err := PlanStaging(dir, 1<<20, 4<<20, 8<<20, 5<<20)
	if err != nil {
		t.Fatalf("a few megabytes should fit in a temp dir: %v", err)
	}
	want := uint64(1<<20) + 2*(4<<20+8<<20) + 5<<20
	if b.PeakBytes != want {
		t.Errorf("peak = %d, want %d (db + 2×(identity+volumes) + largest single volume)", b.PeakBytes, want)
	}
	if b.VolumeBytes != 8<<20 || b.LargestVolumeBytes != 5<<20 {
		t.Errorf("the budget did not carry the volume terms it was sized from: %+v", b)
	}
	// The largest single volume alone is what tips it over. Everything else is
	// tiny; if the guard ignored LargestVolumeBytes this would be accepted.
	if _, err := PlanStaging(dir, 0, 0, 0, 1<<60); err == nil {
		t.Fatal("PlanStaging accepted an exabyte-sized single volume — the peak is not being sized for it")
	}
}

// TestCleanStagingRemovesOrphansAndNothingElse is §4.7's third discipline. An
// orphaned staged archive after a crash is a permanent disk leak with no owner
// and no alert — and it is the largest single thing this product stages.
func TestCleanStagingRemovesOrphansAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gen-1.sealed"), []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gen-1.tar"), []byte("orphan too"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory is not something this package put there.
	if err := os.MkdirAll(filepath.Join(dir, "someone-elses"), 0o700); err != nil {
		t.Fatal(err)
	}

	removed, freed := CleanStaging(dir)
	if removed != 2 {
		t.Errorf("removed %d orphan(s), want 2", removed)
	}
	if freed == 0 {
		t.Error("freed 0 bytes")
	}
	if _, err := os.Stat(filepath.Join(dir, "someone-elses")); err != nil {
		t.Error("CleanStaging removed a directory it did not create")
	}
	// Idempotent: a second sweep on a clean directory does nothing.
	if n, _ := CleanStaging(dir); n != 0 {
		t.Errorf("a second sweep removed %d more", n)
	}
}

// TestMeasureIdentitySetCountsTheWholeSet keeps the preflight estimate and the
// staging guard sized from measurement rather than from a constant.
func TestMeasureIdentitySetCountsTheWholeSet(t *testing.T) {
	dir := t.TempDir()
	trust := filepath.Join(dir, "trust")
	mesh := filepath.Join(dir, "mesh", "headscale", "db")
	if err := os.MkdirAll(trust, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mesh, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(trust, "mesh-ca.key"), strings.Repeat("k", 100))
	writeTestFile(t, filepath.Join(trust, "mesh-ca.pem"), strings.Repeat("p", 200))
	writeTestFile(t, filepath.Join(mesh, "headscale.sqlite"), strings.Repeat("h", 400))

	src := IdentitySources{TrustDir: trust, MeshStateDir: filepath.Join(dir, "mesh")}
	got := MeasureIdentitySet(src, 1000)
	if want := uint64(1000 + 100 + 200 + 400); got != want {
		t.Errorf("MeasureIdentitySet = %d, want %d", got, want)
	}

	// A dev install with no mesh and no trust dir contributes only the
	// database, and does not error: the estimate is not the place to refuse.
	if got := MeasureIdentitySet(IdentitySources{}, 1000); got != 1000 {
		t.Errorf("with no sources MeasureIdentitySet = %d, want the database's 1000", got)
	}
}

// The test that used to live here asserted StagingDir(dataDir) and the agent's
// StagingRoot(stateDir) agreed — by handing BOTH of them "/var/lib/rasputin".
// Production hands the api its data dir and the agent its state dir, which are
// not the same directory on the shipping image, so the two halves disagreed in
// the only configuration that ships while this test stayed green. It is gone
// with the function it tested: the api derives no staging path at all now.
//
// What replaces it: the agent pins its one derivation with no environment set
// (agent/internal/storage, TestStagingRootIsTheDeployedDefaultWithNoEnvironment
// Set and TestPreflightReportsExactlyWhatTheWriteVerbWillRead), and
// TestBackupRunStagesWhereTheAgentSaysAndNowhereElse below pins the api to the
// root it is told about.
