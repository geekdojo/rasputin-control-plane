package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

// The purpose table is the whole of §6's generalisation on the wire: two
// backends and an api pick their GPT name, filesystem label and marker file
// from it, and a disagreement between any two of them is a disk formatted as
// something nobody asked for. So the table is asserted by value rather than by
// "it returned something".

func TestStoragePurposeSpecFor(t *testing.T) {
	tests := []struct {
		name       string
		purpose    StoragePurpose
		wantErr    bool
		partName   string
		fsLabel    string
		markerFile string
	}{
		{
			name:       "backup",
			purpose:    StoragePurposeBackup,
			partName:   "rasputin-backup",
			fsLabel:    "RASPUTIN-BACKUP",
			markerFile: ".rasputin-backup-set.json",
		},
		{
			name:       "data",
			purpose:    StoragePurposeData,
			partName:   "rasputin-data",
			fsLabel:    "RASPUTIN-DATA",
			markerFile: ".rasputin-data-set.json",
		},
		// The refusals. Every one of these is a value that reached a
		// destructive verb meaning something this build cannot do, and the only
		// safe answer is to stop — a fall back to backup would format a disk as
		// the wrong thing, which is the outcome §4.8 exists to prevent.
		{name: "empty is not a purpose here", purpose: "", wantErr: true},
		{name: "unknown", purpose: "scratch", wantErr: true},
		{name: "wrong case", purpose: "Backup", wantErr: true},
		{name: "whitespace", purpose: " data", wantErr: true},
		{name: "the filesystem label is not the purpose", purpose: "RASPUTIN-DATA", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := StoragePurposeSpecFor(tc.purpose)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("StoragePurposeSpecFor(%q) = %+v, want an error — an unrecognised purpose must never yield a spec", tc.purpose, spec)
				}
				// And it must yield NOTHING usable, so a caller that ignores
				// the error cannot format a disk off a half-filled spec.
				if spec != (StoragePurposeSpec{}) {
					t.Errorf("StoragePurposeSpecFor(%q) returned %+v alongside its error", tc.purpose, spec)
				}
				if !strings.Contains(err.Error(), string(tc.purpose)) {
					t.Errorf("the error does not name the rejected value: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("StoragePurposeSpecFor(%q): %v", tc.purpose, err)
			}
			if spec.Purpose != tc.purpose {
				t.Errorf("Purpose = %q, want %q", spec.Purpose, tc.purpose)
			}
			if spec.PartName != tc.partName {
				t.Errorf("PartName = %q, want %q", spec.PartName, tc.partName)
			}
			if spec.FSLabel != tc.fsLabel {
				t.Errorf("FSLabel = %q, want %q", spec.FSLabel, tc.fsLabel)
			}
			if spec.MarkerFile != tc.markerFile {
				t.Errorf("MarkerFile = %q, want %q", spec.MarkerFile, tc.markerFile)
			}
		})
	}
}

// The two purposes must not collide on any of the three constants. A shared GPT
// name or filesystem label would resolve ACROSS drives the moment two Rasputin
// disks share a machine (#307), and a shared marker filename would make a data
// disk parse as a backup set and land in §4.8's adopt-or-wipe prompt.
func TestStoragePurposeSpecsDoNotCollide(t *testing.T) {
	backup, err := StoragePurposeSpecFor(StoragePurposeBackup)
	if err != nil {
		t.Fatalf("backup spec: %v", err)
	}
	data, err := StoragePurposeSpecFor(StoragePurposeData)
	if err != nil {
		t.Fatalf("data spec: %v", err)
	}
	for _, c := range []struct {
		what     string
		a, b     string
		alsoNot  string
		alsoWhat string
	}{
		{what: "GPT partition name", a: backup.PartName, b: data.PartName, alsoNot: "persistent", alsoWhat: "the OS partition the amd64 fstab finds by PARTLABEL"},
		{what: "filesystem label", a: backup.FSLabel, b: data.FSLabel, alsoNot: "persistent", alsoWhat: "the OS partition"},
		{what: "marker file", a: backup.MarkerFile, b: data.MarkerFile},
	} {
		if c.a == c.b {
			t.Errorf("both purposes use the same %s (%q)", c.what, c.a)
		}
		if c.alsoNot != "" && (c.a == c.alsoNot || c.b == c.alsoNot) {
			t.Errorf("a purpose's %s collides with %q — %s", c.what, c.alsoNot, c.alsoWhat)
		}
	}
}

// The reverse lookup enumeration uses to decide which partitions are worth
// peeking at, and which of the two markers to read once it does.
func TestStoragePurposeForFSLabel(t *testing.T) {
	tests := []struct {
		label string
		want  StoragePurpose
		ok    bool
	}{
		{label: StorageBackupLabel, want: StoragePurposeBackup, ok: true},
		{label: StorageDataLabel, want: StoragePurposeData, ok: true},
		{label: "", ok: false},
		{label: "persistent", ok: false},
		{label: "MYSTUFF", ok: false},
		// Labels are compared exactly. ext4 preserves case, mkfs applies what
		// we hand it, and a near-miss is somebody else's disk.
		{label: "rasputin-backup", ok: false},
		{label: "RASPUTIN-BACKUP ", ok: false},
	}
	for _, tc := range tests {
		got, ok := StoragePurposeForFSLabel(tc.label)
		if ok != tc.ok || got != tc.want {
			t.Errorf("StoragePurposeForFSLabel(%q) = (%q, %v), want (%q, %v)", tc.label, got, ok, tc.want, tc.ok)
		}
	}
}

// EffectivePurpose is the ONE place the empty-means-backup rule lives, and the
// rule is wire compatibility and nothing else: an api that predates §6 sends no
// purpose and means the backup target. The precedent is backupxfer.Grant.Use,
// where an empty use is the upload credential that was the only kind when it
// was minted.
func TestStorageClaimCmdEffectivePurpose(t *testing.T) {
	tests := []struct {
		name string
		cmd  StorageClaimCmd
		want StoragePurpose
	}{
		{
			name: "absent means backup — the pre-§6 api's claim",
			cmd:  StorageClaimCmd{DevicePath: "/dev/sdb", Fingerprint: "fp"},
			want: StoragePurposeBackup,
		},
		{
			name: "explicit backup",
			cmd:  StorageClaimCmd{DevicePath: "/dev/sdb", Fingerprint: "fp", Purpose: StoragePurposeBackup},
			want: StoragePurposeBackup,
		},
		{
			name: "explicit data",
			cmd:  StorageClaimCmd{DevicePath: "/dev/sdb", Fingerprint: "fp", Purpose: StoragePurposeData},
			want: StoragePurposeData,
		},
		{
			// NOT defaulted. It is returned unchanged so the spec lookup
			// refuses it by name and the operator is told which value was
			// rejected — the default covers "absent", never "unrecognised".
			name: "an unknown purpose is passed through to be refused",
			cmd:  StorageClaimCmd{DevicePath: "/dev/sdb", Fingerprint: "fp", Purpose: "scratch"},
			want: "scratch",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cmd.EffectivePurpose(); got != tc.want {
				t.Errorf("EffectivePurpose() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A claim that carries no purpose must still MARSHAL without one, or the
// compatibility runs the other way and a §6 agent starts telling a pre-§6 api
// about a field it will not understand. omitempty is doing that work.
func TestStorageClaimCmdOmitsAnAbsentPurpose(t *testing.T) {
	b, err := json.Marshal(StorageClaimCmd{DevicePath: "/dev/sdb", Fingerprint: "fp"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "purpose") {
		t.Errorf("a purposeless claim serialised a purpose: %s", b)
	}
	b, err = json.Marshal(StorageClaimCmd{DevicePath: "/dev/sdb", Fingerprint: "fp", Purpose: StoragePurposeData})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"purpose":"data"`) {
		t.Errorf("a data claim did not serialise its purpose: %s", b)
	}
}

// The data marker is the disk's own record of itself, and the ONE thing it must
// never grow is key custody. §4.6's material belongs to a backup target; a data
// disk holds no archive, so a key-shaped field here would be key material
// written onto a disk no unlock path ever reads.
func TestStorageDataSetHasNoKeyMaterialField(t *testing.T) {
	b, err := json.Marshal(StorageDataSet{MarkerVersion: StorageDataMarkerVersion, ClusterID: "bitscope", PartUUID: "p-1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// An exact whitelist rather than a forbidden list: the question a future
	// field has to answer is "was this decided", not "does its name look bad".
	allowed := map[string]bool{
		"markerVersion": true, "clusterId": true, "partUuid": true,
		"label": true, "createdAt": true,
	}
	for k := range m {
		if !allowed[k] {
			t.Errorf("StorageDataSet grew field %q — a data disk's marker carries identity and nothing else", k)
		}
	}
}

// ClaimedPurpose is derived from the two set pairs rather than carried, so a
// candidate can never say one thing and hold the other.
func TestStorageCandidateClaimedPurpose(t *testing.T) {
	tests := []struct {
		name string
		cand StorageCandidate
		want StoragePurpose
		ok   bool
	}{
		{name: "blank disk", cand: StorageCandidate{}},
		{
			name: "backup",
			cand: StorageCandidate{HasBackupSet: true, BackupSet: &StorageBackupSet{MarkerVersion: 1}},
			want: StoragePurposeBackup, ok: true,
		},
		{
			name: "data",
			cand: StorageCandidate{HasDataSet: true, DataSet: &StorageDataSet{MarkerVersion: 1}},
			want: StoragePurposeData, ok: true,
		},
		{
			// Nothing this code path can produce — a claim formats one
			// filesystem and drops one marker — so "it is one of the two, pick
			// one" is not an answer to hand a destructive dialog.
			name: "both is no answer",
			cand: StorageCandidate{HasBackupSet: true, HasDataSet: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.cand.ClaimedPurpose()
			if got != tc.want || ok != tc.ok {
				t.Errorf("ClaimedPurpose() = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}
