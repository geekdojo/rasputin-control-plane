package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// These are the tests the feature exists for.
//
// "Pick the wrong disk and force-format it" is not something that can be
// rehearsed on hardware — the rehearsal destroys the cluster — so the mock is
// where the safety rules are actually exercised. Each test below is one of the
// ways §4.8 says this goes wrong.

// newTestMock builds a mock over a supplied machine, with a deterministic UUID
// minter and clock so assertions can name exact values.
func newTestMock(t *testing.T, machine *mockState) *MockBackend {
	t.Helper()
	m, err := NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	n := 0
	m.newUUID = func() string {
		n++
		return fmt.Sprintf("claimed-%04d", n)
	}
	m.now = func() time.Time { return time.Date(2026, 8, 31, 3, 0, 0, 0, time.UTC) }
	if machine != nil {
		if err := m.saveState(machine); err != nil {
			t.Fatalf("seed state: %v", err)
		}
	}
	return m
}

func enumerate(t *testing.T, m *MockBackend) *proto.StorageEnumerateAck {
	t.Helper()
	ack, err := m.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	return ack
}

func candidateBySerial(t *testing.T, ack *proto.StorageEnumerateAck, serial string) proto.StorageCandidate {
	t.Helper()
	for _, c := range ack.Candidates {
		if c.Serial == serial {
			return c
		}
	}
	t.Fatalf("no candidate with serial %q in %+v", serial, ack.Candidates)
	return proto.StorageCandidate{}
}

// ---------------------------------------------------------------------------
// 1. Two NVMes, unstable enumeration order
// ---------------------------------------------------------------------------

// The seeded machine is a two-NVMe controlplane: same transport, neither
// removable, and the only thing separating them is which one the mounts sit on.
// Flipping NameOrder renames both disks without moving anything — exactly what a
// reboot does — and protection must follow the disk, not the name.
func TestMock_ProtectionSurvivesAnEnumerationReorder(t *testing.T) {
	machine := defaultMockMachine()
	m := newTestMock(t, machine)

	first := enumerate(t, m)
	boot := candidateBySerial(t, first, "SN-BOOT-0001")
	spare := candidateBySerial(t, first, "SN-SPARE-0002")
	if boot.DevicePath != "/dev/nvme0n1" || spare.DevicePath != "/dev/nvme1n1" {
		t.Fatalf("unexpected initial naming: boot=%s spare=%s", boot.DevicePath, spare.DevicePath)
	}
	if !boot.Protected {
		t.Fatal("the boot disk was not protected on the first enumeration")
	}

	// Reboot: the kernel probes the spare first.
	machine.NameOrder = []int{1, 0, 2}
	if err := m.saveState(machine); err != nil {
		t.Fatalf("save reordered state: %v", err)
	}

	second := enumerate(t, m)
	bootAfter := candidateBySerial(t, second, "SN-BOOT-0001")
	spareAfter := candidateBySerial(t, second, "SN-SPARE-0002")

	if bootAfter.DevicePath != "/dev/nvme1n1" || spareAfter.DevicePath != "/dev/nvme0n1" {
		t.Fatalf("the reorder did not rename the disks: boot=%s spare=%s", bootAfter.DevicePath, spareAfter.DevicePath)
	}
	if !bootAfter.Protected {
		t.Errorf("the boot disk lost its protection when it was renamed to %s — this is the bug that destroys a cluster", bootAfter.DevicePath)
	}
	if spareAfter.Protected {
		t.Errorf("the spare picked up protection by inheriting the name %s", spareAfter.DevicePath)
	}
	// Identity, and therefore the fingerprint, is unchanged by a rename.
	if bootAfter.Fingerprint != boot.Fingerprint {
		t.Errorf("the boot disk's fingerprint changed across a pure rename: %s -> %s",
			short(boot.Fingerprint), short(bootAfter.Fingerprint))
	}
	if spareAfter.Fingerprint != spare.Fingerprint {
		t.Errorf("the spare's fingerprint changed across a pure rename")
	}
}

// The device path that names the boot disk now names the spare after a reorder.
// A claim issued against that path with the SPARE's fingerprint (i.e. the
// operator picked the spare, then the machine rebooted) must not format the
// boot disk — and the fingerprint is what catches it.
func TestMock_ClaimRefusesWhenAReorderMovedThePathToTheBootDisk(t *testing.T) {
	machine := defaultMockMachine()
	m := newTestMock(t, machine)

	before := enumerate(t, m)
	spare := candidateBySerial(t, before, "SN-SPARE-0002")
	if spare.DevicePath != "/dev/nvme1n1" {
		t.Fatalf("precondition: spare is %s", spare.DevicePath)
	}

	// Reboot renumbers: /dev/nvme1n1 is now the BOOT disk.
	machine.NameOrder = []int{1, 0, 2}
	if err := m.saveState(machine); err != nil {
		t.Fatalf("save: %v", err)
	}

	_, err := m.Claim(context.Background(), claimCmd("/dev/nvme1n1", spare.Fingerprint, "backup"))
	if err == nil {
		t.Fatal("claim succeeded against the boot disk after a renumber — the cluster is gone")
	}
	if !errors.Is(err, ErrProtected) {
		t.Errorf("want ErrProtected, got %v", err)
	}
	assertUnformatted(t, m, "SN-BOOT-0001", 3)
}

// ---------------------------------------------------------------------------
// 2. The boot device offered as a candidate
// ---------------------------------------------------------------------------

// The boot disk is ENUMERATED, not hidden — an operator who sees one disk in a
// list of two needs to know why — and it comes back Protected with a reason
// that names the mount.
func TestMock_BootDeviceIsOfferedButProtected(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	ack := enumerate(t, m)

	boot := candidateBySerial(t, ack, "SN-BOOT-0001")
	if !boot.Protected {
		t.Fatal("boot disk not protected")
	}
	if boot.ProtectedReason == "" {
		t.Error("protected with no reason — the operator is told a disk is unavailable and not why")
	}
	for _, c := range ack.Candidates {
		if c.Serial != "SN-BOOT-0001" && c.Protected {
			t.Errorf("%s (%s) was protected and should not be: %s", c.DevicePath, c.Serial, c.ProtectedReason)
		}
	}
	if len(ack.Candidates) != 3 {
		t.Errorf("candidates = %d, want 3 — protected disks are reported, not filtered out", len(ack.Candidates))
	}
}

// And the claim refuses it, with the right refusal code, having touched nothing.
func TestMock_ClaimRefusesTheBootDisk(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	boot := candidateBySerial(t, enumerate(t, m), "SN-BOOT-0001")

	_, err := m.Claim(context.Background(), claimCmd(boot.DevicePath, boot.Fingerprint, "backup"))
	if err == nil {
		t.Fatal("the boot disk was claimed")
	}
	if !errors.Is(err, ErrProtected) {
		t.Fatalf("want ErrProtected, got %v", err)
	}
	if got := refusalFor(err); got != proto.StorageRefusalProtected {
		t.Errorf("refusal code = %q, want %q", got, proto.StorageRefusalProtected)
	}
	assertUnformatted(t, m, "SN-BOOT-0001", 3)
}

// ---------------------------------------------------------------------------
// 3. A fingerprint that drifted between enumerate and claim
// ---------------------------------------------------------------------------

// The TOCTOU window: the operator confirms, and before the format runs the disk
// changes underneath — someone partitioned it on another machine and plugged it
// back, or the path now names a different disk entirely.
func TestMock_ClaimRefusesADriftedFingerprint(t *testing.T) {
	machine := defaultMockMachine()
	m := newTestMock(t, machine)
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")

	// The disk gains a partition between the confirmation and the claim.
	machine.Disks[1].Partitions = []mockPartition{
		{PartUUID: "someone-elses-0001", FSType: "ntfs", Label: "BACKUPS", SizeBytes: 2000 << 30},
	}
	if err := m.saveState(machine); err != nil {
		t.Fatalf("save: %v", err)
	}

	_, err := m.Claim(context.Background(), claimCmd(spare.DevicePath, spare.Fingerprint, "backup"))
	if err == nil {
		t.Fatal("claim succeeded on a disk that changed after confirmation")
	}
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("want ErrFingerprintMismatch, got %v", err)
	}
	if got := refusalFor(err); got != proto.StorageRefusalFingerprintMismatch {
		t.Errorf("refusal code = %q, want %q", got, proto.StorageRefusalFingerprintMismatch)
	}
	// And the partition somebody else wrote is still there.
	after := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
	if len(after.Partitions) != 1 || after.Partitions[0].Label != "BACKUPS" {
		t.Errorf("the refused claim modified the disk: %+v", after.Partitions)
	}
}

// An empty fingerprint is a refusal, not a wildcard. A caller that cannot name
// the disk it confirmed has not confirmed a disk.
func TestMock_ClaimRefusesAnEmptyFingerprint(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")

	if _, err := m.Claim(context.Background(), claimCmd(spare.DevicePath, "", "backup")); !errors.Is(err, ErrNoFingerprint) {
		t.Fatalf("want ErrNoFingerprint, got %v", err)
	}
	assertUnformatted(t, m, "SN-SPARE-0002", 0)
}

// ---------------------------------------------------------------------------
// 4. A disk already carrying a Rasputin backup set
// ---------------------------------------------------------------------------

// Restore-before-first-boot (#291) has the operator plug their archive disk into
// a REPLACEMENT controlplane. The enumeration must say, loudly, that this disk
// already holds a backup set — that report is the only thing standing between a
// first-run flow and the only copy of what is being restored.
func TestMock_ReportsAnExistingBackupSet(t *testing.T) {
	machine := defaultMockMachine()
	machine.Disks[2].Partitions = []mockPartition{{
		PartUUID: "restore-disk-0001", FSType: "ext4",
		Label: proto.StorageBackupLabel, SizeBytes: 64 << 30,
		BackupSet: &proto.StorageBackupSet{
			MarkerVersion: proto.StorageMarkerVersion,
			ClusterID:     "old-cluster",
			PartUUID:      "restore-disk-0001",
			KeyID:         "key-7",
			Generations:   4,
		},
	}}
	m := newTestMock(t, machine)

	c := candidateBySerial(t, enumerate(t, m), "USB-0003")
	if !c.HasBackupSet {
		t.Fatal("a disk carrying a Rasputin backup set was reported as blank")
	}
	if c.BackupSet == nil {
		t.Fatal("HasBackupSet with no details — the adopt-or-wipe prompt has nothing to show")
	}
	if c.BackupSet.ClusterID != "old-cluster" || c.BackupSet.Generations != 4 {
		t.Errorf("backup set details lost: %+v", c.BackupSet)
	}
	if c.BackupSet.KeyID != "key-7" {
		t.Errorf("key id lost: %+v", c.BackupSet)
	}
	if c.Protected {
		t.Error("carrying a backup set is not protection — adopt-or-wipe is the api's decision, not the agent's")
	}
}

// The agent does not decide adopt-or-wipe. A claim against a disk holding a
// backup set, with a matching fingerprint, goes through — because by then the
// api's check_existing step has already put the choice to the operator. What
// this test pins is that the agent reports and obeys rather than inventing a
// second, silent policy that the UI cannot explain.
func TestMock_ClaimOverABackupSetIsTheAPIsDecision(t *testing.T) {
	machine := defaultMockMachine()
	machine.Disks[2].Partitions = []mockPartition{{
		PartUUID: "restore-disk-0001", FSType: "ext4",
		Label: proto.StorageBackupLabel, SizeBytes: 64 << 30,
		BackupSet: &proto.StorageBackupSet{MarkerVersion: 1, ClusterID: "old-cluster"},
	}}
	m := newTestMock(t, machine)
	c := candidateBySerial(t, enumerate(t, m), "USB-0003")

	ack, err := m.Claim(context.Background(), claimCmd(c.DevicePath, c.Fingerprint, "new target"))
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if ack.PartUUID == "restore-disk-0001" {
		t.Error("the old partition UUID survived a format")
	}
}

// ---------------------------------------------------------------------------
// 5. A claim replayed with a stale fingerprint after a successful format
// ---------------------------------------------------------------------------

// The repeat guard, and it needs no dedup state: the format rewrites the
// partition table the fingerprint hashes, so the same command sent twice — a
// lost ack over core NATS, an operator double-click, a saga retry — refuses the
// second time on its own.
func TestMock_ReplayedClaimFailsClosedAfterASuccessfulFormat(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")

	first, err := m.Claim(context.Background(), claimCmd(spare.DevicePath, spare.Fingerprint, "backup"))
	if err != nil {
		t.Fatalf("first Claim: %v", err)
	}
	if first.PartUUID == "" || first.MountPath == "" {
		t.Fatalf("claim ack is missing the target: %+v", first)
	}
	if first.Fingerprint == spare.Fingerprint {
		t.Error("the post-format fingerprint equals the pre-format one — the repeat guard does not exist")
	}

	// Exactly the same command again.
	_, err = m.Claim(context.Background(), claimCmd(spare.DevicePath, spare.Fingerprint, "backup"))
	if err == nil {
		t.Fatal("a replayed claim reformatted the target — every retained generation is gone")
	}
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("want ErrFingerprintMismatch, got %v", err)
	}

	// The first claim's target is untouched: same partition UUID, same marker.
	ack, err := m.Inspect(context.Background(), first.PartUUID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !ack.Present || ack.PartUUID != first.PartUUID {
		t.Errorf("the target did not survive the replayed claim: %+v", ack)
	}
}

// ---------------------------------------------------------------------------
// The happy path, and what a claim actually produces
// ---------------------------------------------------------------------------

func TestMock_ClaimFormatsLabelsAndMints(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")

	ack, err := m.Claim(context.Background(), claimCmd(spare.DevicePath, spare.Fingerprint, "weekly archive"))
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if ack.PartUUID != "claimed-0001" {
		t.Errorf("partUUID = %q, want the freshly minted one", ack.PartUUID)
	}
	if ack.FSLabel != proto.StorageBackupLabel {
		t.Errorf("fs label = %q, want %q", ack.FSLabel, proto.StorageBackupLabel)
	}
	if ack.Label != "weekly archive" {
		t.Errorf("operator label = %q", ack.Label)
	}
	if ack.BackupSet == nil || ack.BackupSet.MarkerVersion != proto.StorageMarkerVersion {
		t.Errorf("no marker written: %+v", ack.BackupSet)
	}
	if st, err := os.Stat(ack.MountPath); err != nil || !st.IsDir() {
		t.Errorf("mount path %q is not a usable directory: %v", ack.MountPath, err)
	}

	// The claimed disk now enumerates as one ext4 partition carrying the set.
	after := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
	if len(after.Partitions) != 1 {
		t.Fatalf("want one partition after the format, got %+v", after.Partitions)
	}
	if after.Partitions[0].Label != proto.StorageBackupLabel || !after.HasBackupSet {
		t.Errorf("the formatted disk does not describe itself: %+v", after)
	}
}

// A claim against a path no disk answers to is a refusal, not a guess.
func TestMock_ClaimRefusesAnAbsentDevice(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	_, err := m.Claim(context.Background(), claimCmd("/dev/nvme9n1", "anything", "backup"))
	if !errors.Is(err, ErrDeviceAbsent) {
		t.Fatalf("want ErrDeviceAbsent, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Mount / Inspect
// ---------------------------------------------------------------------------

func TestMock_MountIsIdempotentAndKeyedByPartUUID(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
	ack, err := m.Claim(context.Background(), claimCmd(spare.DevicePath, spare.Fingerprint, "backup"))
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	first, err := m.Mount(context.Background(), ack.PartUUID)
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	second, err := m.Mount(context.Background(), ack.PartUUID)
	if err != nil {
		t.Fatalf("Mount again: %v", err)
	}
	if first != second {
		t.Errorf("mount is not idempotent: %q then %q", first, second)
	}
	if filepath.Base(first) != ack.PartUUID {
		t.Errorf("mount path %q is not keyed by the partition UUID", first)
	}
}

func TestMock_MountRefusesAPartitionOnAProtectedDisk(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	// boot-data-0001 is the persistent partition on the boot disk.
	if _, err := m.Mount(context.Background(), "boot-data-0001"); !errors.Is(err, ErrProtected) {
		t.Fatalf("want ErrProtected mounting a partition of the boot disk, got %v", err)
	}
}

func TestMock_InspectAnUnpluggedTargetIsAnAnswerNotAFailure(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	ack, err := m.Inspect(context.Background(), "never-claimed")
	if err != nil {
		t.Fatalf("Inspect returned an error for an absent target: %v", err)
	}
	if !ack.OK {
		t.Error("OK=false — the agent answered fine, the disk is simply not there")
	}
	if ack.Present {
		t.Error("Present=true for a target that does not exist")
	}
	if ack.Refusal != proto.StorageRefusalNotFound {
		t.Errorf("refusal = %q, want %q", ack.Refusal, proto.StorageRefusalNotFound)
	}
}

func TestMock_InspectCountsRetainedGenerations(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
	claim, err := m.Claim(context.Background(), claimCmd(spare.DevicePath, spare.Fingerprint, "backup"))
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	for i := range 4 {
		dir := filepath.Join(claim.MountPath, GenerationsDir, fmt.Sprintf("2026-08-%02d", 10+i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir generation: %v", err)
		}
	}
	ack, err := m.Inspect(context.Background(), claim.PartUUID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if ack.BackupSet == nil || ack.BackupSet.Generations != 4 {
		t.Errorf("generations = %+v, want 4 — the wipe prompt needs to say what it destroys", ack.BackupSet)
	}
}

// ---------------------------------------------------------------------------
// State handling
// ---------------------------------------------------------------------------

// A claimed target must survive an agent restart, the same way a real one does:
// the mount is re-established from the partition UUID, not remembered as a path.
func TestMock_ClaimedTargetSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	m1, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	spare := candidateBySerial(t, enumerate(t, m1), "SN-SPARE-0002")
	claim, err := m1.Claim(context.Background(), claimCmd(spare.DevicePath, spare.Fingerprint, "backup"))
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	m2, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	ack, err := m2.Inspect(context.Background(), claim.PartUUID)
	if err != nil {
		t.Fatalf("Inspect after restart: %v", err)
	}
	if !ack.Present || ack.MountPath != claim.MountPath {
		t.Errorf("target did not survive a restart: %+v", ack)
	}
}

// The injected failure mode is the orphaned-claim case: formatted, unrecorded.
// §4.8 needs no compensation for it because the disk is self-describing — this
// pins that re-enumerating finds the set, which is the whole recovery story.
func TestMock_OrphanedClaimIsRecoverableByReEnumerating(t *testing.T) {
	t.Setenv("RASPUTIN_STORAGE_FAIL_MODE", "claim")
	m := newTestMock(t, defaultMockMachine())
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")

	if _, err := m.Claim(context.Background(), claimCmd(spare.DevicePath, spare.Fingerprint, "backup")); err == nil {
		t.Fatal("the injected failure did not fire")
	}
	after := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
	if !after.HasBackupSet || after.BackupSet == nil {
		t.Fatalf("the formatted-but-unrecorded disk does not describe itself: %+v", after)
	}
	if after.BackupSet.PartUUID == "" {
		t.Error("the marker carries no partition UUID, so the operator cannot adopt the disk by its own account")
	}
}

func TestMock_NameIsMock(t *testing.T) {
	m := newTestMock(t, nil)
	if m.Name() != "mock" {
		t.Errorf("Name() = %q", m.Name())
	}
	if enumerate(t, m).Backend != "mock" {
		t.Error("the enumerate ack does not say which backend answered")
	}
}

// assertUnformatted checks a disk still has the partition count it started
// with — i.e. the refusal happened BEFORE anything was written.
func assertUnformatted(t *testing.T, m *MockBackend, serial string, wantParts int) {
	t.Helper()
	c := candidateBySerial(t, enumerate(t, m), serial)
	if len(c.Partitions) != wantParts {
		t.Errorf("%s has %d partitions, want %d — the refusal did not happen before the write",
			serial, len(c.Partitions), wantParts)
	}
}
