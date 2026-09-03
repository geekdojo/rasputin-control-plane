package proto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The staging verbs' subjects sit under the node command filter like every
// other agent verb, and match the `storage.backup_*` family they extend.
func TestStageVolumeSubjectsMatchTheBackupFamily(t *testing.T) {
	const node = "n-1"
	cases := map[string]string{
		"stage":   BackupStageVolumeSubject(node),
		"unstage": BackupUnstageSubject(node),
	}
	for name, subj := range cases {
		if !strings.HasPrefix(subj, "rasputin.node.n-1.cmd.storage.backup_") {
			t.Errorf("%s subject %q is outside the storage.backup_ family the agent subscribes for", name, subj)
		}
	}
	if got := BackupStageVolumeSubject(node); got != "rasputin.node.n-1.cmd.storage.backup_stage_volume" {
		t.Errorf("BackupStageVolumeSubject = %q", got)
	}
	if got := BackupUnstageSubject(node); got != "rasputin.node.n-1.cmd.storage.backup_unstage" {
		t.Errorf("BackupUnstageSubject = %q", got)
	}
}

// The wire shape, pinned: the fan-out is built against these keys next, in a
// different package, and the agent decodes them on a node that may be running
// a different build than the api.
func TestStageVolumeCmdWireShape(t *testing.T) {
	cmd := BackupStageVolumeCmd{
		AppID: "01J8", AppName: "Vaultwarden", Volume: "vaultwarden-data",
		Class: "critical", Quiesce: "stop", StagingName: "01J8-vaultwarden-data.tar",
	}
	b, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"appId"`, `"appName"`, `"volume"`, `"class"`, `"quiesce"`, `"stagingName"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("BackupStageVolumeCmd JSON lacks %s: %s", key, b)
		}
	}
	var back BackupStageVolumeCmd
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != cmd {
		t.Errorf("round trip changed the command: %+v -> %+v", cmd, back)
	}
}

// AppRestored, WasRunning, Stopped and ServiceInterrupting are NEVER omitted
// from the ack. A false that vanished from the JSON would read, to a fan-out
// checking for the key, exactly like a true that was never sent — and
// AppRestored=false is the one field in this contract that is an alert.
func TestStageVolumeAckAlwaysCarriesTheRestartFacts(t *testing.T) {
	b, err := json.Marshal(BackupStageVolumeAck{OK: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"appRestored":false`, `"wasRunning":false`, `"stopped":false`, `"serviceInterrupting":false`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("a zero-valued ack omits %s; the restart facts must be present on every reply: %s", key, b)
		}
	}
	// Unstage's Existed likewise: "removed nothing" must be sayable.
	ub, _ := json.Marshal(BackupUnstageAck{OK: true})
	if !strings.Contains(string(ub), `"existed":false`) {
		t.Errorf("BackupUnstageAck omits existed=false: %s", ub)
	}
}

func TestStageVolumeAckRoundTrip(t *testing.T) {
	at := time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)
	ack := BackupStageVolumeAck{
		OK: true, AppID: "a", Volume: "v", StagingName: "n", StagedPath: "/p/n",
		SizeBytes: 10, Digest: "ab", PlaintextBytes: 9, FileCount: 2,
		Consistency: BackupConsistencyCleanShutdown, Window: "none",
		ServiceInterrupting: true, WasRunning: true, Stopped: true,
		StoppedAt: at, RestartedAt: at.Add(time.Second), DowntimeMillis: 1000,
		AppRestored: true, RestoredBy: "driver",
		Databases: []string{"home-assistant_v2.db"}, SnapshotTool: "python3",
	}
	b, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	var back BackupStageVolumeAck
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Consistency != ack.Consistency || back.DowntimeMillis != ack.DowntimeMillis ||
		back.RestoredBy != ack.RestoredBy || len(back.Databases) != 1 || !back.StoppedAt.Equal(at) {
		t.Errorf("round trip lost fields: %+v", back)
	}
}

// The staging reserve is the SAME number the api keeps on the controlplane
// (§5's VictoriaMetrics reservation). Pinned so a change to one side is a
// change to this test, not a silent divergence.
func TestStagingReserveIsTwoGiB(t *testing.T) {
	if BackupStagingReserveBytes != 2<<30 {
		t.Errorf("BackupStagingReserveBytes = %d, want 2 GiB — the api's StagingReserveBytes is derived from it", BackupStagingReserveBytes)
	}
}

// Every consistency value is a distinct, non-empty string: the ack's
// Consistency field is a closed set a restore branches on.
func TestConsistencyValuesAreDistinct(t *testing.T) {
	seen := map[BackupConsistency]bool{}
	for _, c := range []BackupConsistency{BackupConsistencyCleanShutdown, BackupConsistencySnapshotPlusLive, BackupConsistencyLiveCopy} {
		if c == "" || seen[c] {
			t.Errorf("consistency value %q is empty or duplicated", c)
		}
		seen[c] = true
	}
}

// The refusal codes added here do not collide with the existing storage or
// backup refusals — they travel in the same field and the UI branches on the
// union.
func TestStageRefusalsAreDistinctFromTheExistingOnes(t *testing.T) {
	all := []StorageRefusal{
		StorageRefusalProtected, StorageRefusalFingerprintMismatch, StorageRefusalDeviceAbsent,
		StorageRefusalNotWholeDisk, StorageRefusalBackupSetPresent, StorageRefusalNotFound,
		StorageRefusalBackendError, BackupRefusalInsufficientSpace, BackupRefusalStagingMissing,
		BackupRefusalDigestMismatch,
		BackupRefusalQuiesceUnsupported, BackupRefusalClassNotStaged, BackupRefusalVolumeNotFound,
		BackupRefusalQuiesceFailed, BackupRefusalStagingExists,
	}
	seen := map[StorageRefusal]bool{}
	for _, r := range all {
		if r == "" || seen[r] {
			t.Errorf("refusal %q is empty or duplicated", r)
		}
		seen[r] = true
	}
}
