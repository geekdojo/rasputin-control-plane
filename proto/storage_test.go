package proto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStorageSubjects(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"enumerate", StorageEnumerateSubject("n1"), "rasputin.node.n1.cmd.storage.enumerate"},
		{"claim", StorageClaimSubject("n1"), "rasputin.node.n1.cmd.storage.claim"},
		{"mount", StorageMountSubject("n1"), "rasputin.node.n1.cmd.storage.mount"},
		{"inspect", StorageInspectSubject("n1"), "rasputin.node.n1.cmd.storage.inspect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
}

// The claim subject must stay under the node's own cmd prefix. A node's minted
// bus credential subscribes on rasputin.node.<id>.cmd.> and nothing else, so a
// storage verb parked anywhere else would silently never be delivered — and the
// destructive one failing OPEN (never arriving) is fine, while the enumerate
// failing that way looks like "no disks attached".
func TestStorageSubjectsAreUnderTheNodeCmdPrefix(t *testing.T) {
	prefix := NodeCmdSubject("n1", "")
	for _, s := range []string{
		StorageEnumerateSubject("n1"),
		StorageClaimSubject("n1"),
		StorageMountSubject("n1"),
		StorageInspectSubject("n1"),
	} {
		if !strings.HasPrefix(s, prefix) {
			t.Errorf("%q is not under %q — a node's bus grant only covers its own cmd subtree", s, prefix)
		}
	}
}

func TestStorageEnumerateAckRoundTrip(t *testing.T) {
	in := StorageEnumerateAck{
		OK:      true,
		Backend: "mock",
		Ts:      time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC),
		Candidates: []StorageCandidate{
			{
				DevicePath: "/dev/nvme0n1",
				Model:      "CT500P3SSD8",
				Serial:     "SN-BOOT-0001",
				SizeBytes:  500 << 30,
				Transport:  StorageTransportNVMe,
				Partitions: []StoragePartition{
					{DevicePath: "/dev/nvme0n1p3", PartUUID: "u3", FSType: "ext4", Label: "persistent",
						SizeBytes: 400 << 30, Mountpoint: "/var/lib/rasputin"},
				},
				Protected:       true,
				ProtectedReason: "holds the mounted persistent partition (/var/lib/rasputin)",
				Fingerprint:     "abc123",
			},
		},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out StorageEnumerateAck
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(out.Candidates))
	}
	c := out.Candidates[0]
	if !c.Protected || c.ProtectedReason == "" {
		t.Errorf("protection did not survive the round trip: %+v", c)
	}
	if c.Fingerprint != "abc123" {
		t.Errorf("fingerprint = %q, want abc123", c.Fingerprint)
	}
	if !out.Ts.Equal(in.Ts) {
		t.Errorf("ts = %v, want %v", out.Ts, in.Ts)
	}
}

// The wire names of the two safety fields are pinned. The api and the UI both
// read them, and a rename that compiles on the Go side and silently drops the
// flag on the JSON side would show a boot disk in a picker as unprotected.
func TestStorageCandidateSafetyFieldWireNames(t *testing.T) {
	b, err := json.Marshal(StorageCandidate{Protected: true, ProtectedReason: "r", Fingerprint: "f"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"protected", "protectedReason", "fingerprint"} {
		if _, ok := m[key]; !ok {
			t.Errorf("candidate JSON has no %q key: %s", key, b)
		}
	}
	// Protected must be present even when false — omitempty here would make
	// "not protected" and "an older agent that never evaluated it" identical on
	// the wire, and the safe reading of the second is not "false".
	b, err = json.Marshal(StorageCandidate{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"protected"`) {
		t.Errorf("protected is omitted when false — absent must not be indistinguishable from evaluated-false: %s", b)
	}
}

func TestStorageClaimAckRoundTrip(t *testing.T) {
	in := StorageClaimAck{
		OK: true, DevicePath: "/dev/nvme1n1", PartUUID: "9d0f-4a",
		FSLabel: StorageBackupLabel, FSType: "ext4",
		MountPath: "/run/rasputin/storage/9d0f-4a", Fingerprint: "after",
		BackupSet: &StorageBackupSet{MarkerVersion: StorageMarkerVersion, PartUUID: "9d0f-4a", KeyID: "k1"},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out StorageClaimAck
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.PartUUID != in.PartUUID || out.MountPath != in.MountPath {
		t.Errorf("round trip lost the target: %+v", out)
	}
	if out.BackupSet == nil || out.BackupSet.KeyID != "k1" {
		t.Errorf("backup set did not survive: %+v", out.BackupSet)
	}
}

// The marker carries a key IDENTIFIER and must have no field capable of holding
// key material. §4.6's plaintext data key never enters a marker file, a job
// ledger, or a log line, and the cheapest way to keep that true is for the type
// to have nowhere to put it.
func TestStorageBackupSetHasNoKeyMaterialField(t *testing.T) {
	b, err := json.Marshal(StorageBackupSet{MarkerVersion: 1, KeyID: "k1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k := range m {
		switch strings.ToLower(k) {
		case "key", "datakey", "secret", "passphrase", "wrappedkey", "recoverycode":
			t.Errorf("StorageBackupSet carries a %q field — the marker is written to a removable disk", k)
		}
	}
}

func TestStorageRefusalsAreDistinct(t *testing.T) {
	seen := map[StorageRefusal]bool{}
	for _, r := range []StorageRefusal{
		StorageRefusalProtected,
		StorageRefusalFingerprintMismatch,
		StorageRefusalDeviceAbsent,
		StorageRefusalNotWholeDisk,
		StorageRefusalBackupSetPresent,
		StorageRefusalNotFound,
		StorageRefusalBackendError,
	} {
		if r == "" {
			t.Error("a refusal code is empty — empty means 'no refusal' on the wire")
		}
		if seen[r] {
			t.Errorf("duplicate refusal code %q", r)
		}
		seen[r] = true
	}
}
