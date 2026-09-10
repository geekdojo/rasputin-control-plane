package main

import (
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

var realBackend = backendChoice{Name: "blockdev"}
var mockBackend = backendChoice{Name: "mock", Fixture: true}

// ---------------------------------------------------------------------------
// enumerate
// ---------------------------------------------------------------------------

func TestNewEnumerateReport(t *testing.T) {
	boot := proto.StorageCandidate{
		DevicePath: "/dev/nvme0n1", Model: "CT500P3SSD8", SizeBytes: 500 << 30,
		Protected: true, ProtectedReason: "holds the mounted persistent partition (/var/lib/rasputin)",
		Fingerprint: "fp-boot",
	}
	spare := proto.StorageCandidate{
		DevicePath: "/dev/nvme1n1", Model: "CT500P3SSD8", SizeBytes: 500 << 30,
		Fingerprint: "fp-spare",
	}

	tests := []struct {
		name          string
		ack           *proto.StorageEnumerateAck
		sel           backendChoice
		wantProtected []string
		wantClaimable []string
		// wantWarning is a substring every one of these must appear in some
		// warning; wantNoWarning must appear in none.
		wantWarning   []string
		wantNoWarning []string
	}{
		{
			name: "the protected disk is separated from the identical spare",
			ack: &proto.StorageEnumerateAck{
				OK: true, Backend: "blockdev", Candidates: []proto.StorageCandidate{boot, spare},
			},
			sel:           realBackend,
			wantProtected: []string{"/dev/nvme0n1"},
			wantClaimable: []string{"/dev/nvme1n1"},
			wantNoWarning: []string{"NO DISK IN THIS LIST IS PROTECTED", fixtureBanner},
		},
		{
			// protect.go cannot resolve an empty set on a real machine, so
			// reaching here means the boot medium is not a candidate at all.
			name: "candidates with nothing protected is the loud case",
			ack: &proto.StorageEnumerateAck{
				OK: true, Backend: "blockdev", Candidates: []proto.StorageCandidate{spare},
			},
			sel:           realBackend,
			wantClaimable: []string{"/dev/nvme1n1"},
			wantWarning:   []string{"NO DISK IN THIS LIST IS PROTECTED"},
		},
		{
			name: "no candidates at all is not the nothing-protected warning",
			ack:  &proto.StorageEnumerateAck{OK: true, Backend: "blockdev"},
			sel:  realBackend,
			// An empty machine has nothing to protect and nothing to claim.
			// Warning on it would train an operator to ignore the warning that
			// matters.
			wantNoWarning: []string{"NO DISK IN THIS LIST IS PROTECTED"},
		},
		{
			name: "a protected disk with no reason is a bug, not a clean bill of health",
			ack: &proto.StorageEnumerateAck{
				OK: true, Backend: "blockdev",
				Candidates: []proto.StorageCandidate{{DevicePath: "/dev/sda", Protected: true, ProtectedReason: "   "}},
			},
			sel:           realBackend,
			wantProtected: []string{"/dev/sda"},
			wantWarning:   []string{"/dev/sda is protected but names no reason"},
		},
		{
			name: "weak identity is surfaced per disk",
			ack: &proto.StorageEnumerateAck{
				OK: true, Backend: "blockdev",
				Candidates: []proto.StorageCandidate{boot, {DevicePath: "/dev/sdb", IdentityWeak: true}},
			},
			sel:           realBackend,
			wantProtected: []string{"/dev/nvme0n1"},
			wantClaimable: []string{"/dev/sdb"},
			wantWarning:   []string{"/dev/sdb reports neither WWN nor serial"},
		},
		{
			name:        "a mock run is stamped as fixture output",
			ack:         &proto.StorageEnumerateAck{OK: true, Backend: "mock", Candidates: []proto.StorageCandidate{boot, spare}},
			sel:         mockBackend,
			wantWarning: []string{fixtureBanner},
			// Order matters: the fixture banner is the first thing printed,
			// before any disk.
			wantProtected: []string{"/dev/nvme0n1"},
			wantClaimable: []string{"/dev/nvme1n1"},
		},
		{
			name:          "ok=false is reported even when candidates came back",
			ack:           &proto.StorageEnumerateAck{OK: false, Backend: "blockdev", Refusal: proto.StorageRefusalBackendError, Detail: "lsblk exploded", Candidates: []proto.StorageCandidate{boot}},
			sel:           realBackend,
			wantProtected: []string{"/dev/nvme0n1"},
			wantWarning:   []string{"ok=false", "lsblk exploded"},
		},
		{
			name:        "a nil ack does not panic and says so",
			ack:         nil,
			sel:         realBackend,
			wantWarning: []string{"returned no enumerate ack"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := newEnumerateReport(tc.ack, tc.sel)
			assertDevicePaths(t, "protected", rep.Protected, tc.wantProtected)
			assertDevicePaths(t, "claimable", rep.Claimable, tc.wantClaimable)
			joined := strings.Join(rep.Warnings, "\n")
			for _, want := range tc.wantWarning {
				if !strings.Contains(joined, want) {
					t.Errorf("warnings do not mention %q; got:\n%s", want, joined)
				}
			}
			for _, unwanted := range tc.wantNoWarning {
				if strings.Contains(joined, unwanted) {
					t.Errorf("warnings unexpectedly mention %q; got:\n%s", unwanted, joined)
				}
			}
		})
	}
}

// The fixture banner must be the FIRST warning, because the renderer prints
// warnings in order at the top and an operator who reads one line reads that
// one.
func TestNewEnumerateReport_FixtureBannerComesFirst(t *testing.T) {
	rep := newEnumerateReport(&proto.StorageEnumerateAck{
		OK: true, Backend: "mock",
		Candidates: []proto.StorageCandidate{{DevicePath: "/dev/sda", IdentityWeak: true}},
	}, mockBackend)
	if len(rep.Warnings) == 0 || rep.Warnings[0] != fixtureBanner {
		t.Fatalf("first warning = %q, want the fixture banner", firstWarning(rep.Warnings))
	}
}

func assertDevicePaths(t *testing.T, what string, got []proto.StorageCandidate, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %d disks, want %d (%v)", what, len(got), len(want), want)
	}
	for i := range want {
		if got[i].DevicePath != want[i] {
			t.Errorf("%s[%d] = %q, want %q", what, i, got[i].DevicePath, want[i])
		}
	}
}

func firstWarning(w []string) string {
	if len(w) == 0 {
		return "(none)"
	}
	return w[0]
}

// ---------------------------------------------------------------------------
// claim
// ---------------------------------------------------------------------------

// goodDataAck is a claim ack with every ground-truth field present. Cases
// below take a copy and remove one thing, so each case names exactly the
// field it is about.
func goodDataAck() *proto.StorageClaimAck {
	return &proto.StorageClaimAck{
		OK:          true,
		DevicePath:  "/dev/nvme1n1",
		PartUUID:    "1111-2222",
		Purpose:     proto.StoragePurposeData,
		Label:       "media",
		FSLabel:     proto.StorageDataLabel,
		FSType:      "ext4",
		MountPath:   "/var/lib/rasputin/data/1111-2222",
		SizeBytes:   2000 << 30,
		Fingerprint: "fp-after",
		DataSet:     &proto.StorageDataSet{MarkerVersion: 1, PartUUID: "1111-2222"},
	}
}

// The rule this whole type exists for: a claim is never reported as a success
// without the fields an operator has to go and check on the platter.
func TestNewClaimReport_RefusesWithoutGroundTruth(t *testing.T) {
	tests := []struct {
		name string
		// mutate removes or corrupts one thing.
		mutate func(*proto.StorageClaimAck)
		// wantErr is a substring the refusal must name, so the operator is told
		// WHICH field is missing rather than that something is.
		wantErr string
	}{
		{
			name:    "no partUuid",
			mutate:  func(a *proto.StorageClaimAck) { a.PartUUID = "" },
			wantErr: "partUuid",
		},
		{
			name:    "a whitespace partUuid is no partUuid",
			mutate:  func(a *proto.StorageClaimAck) { a.PartUUID = "   " },
			wantErr: "partUuid",
		},
		{
			name:    "no mount path",
			mutate:  func(a *proto.StorageClaimAck) { a.MountPath = "" },
			wantErr: "mountPath",
		},
		{
			name:    "no filesystem label",
			mutate:  func(a *proto.StorageClaimAck) { a.FSLabel = "" },
			wantErr: "fsLabel",
		},
		{
			// The ack's Purpose is documented as RESOLVED — a claim that sent
			// none comes back saying "backup". Empty therefore means the agent
			// did not answer, and applying the wire default here would be this
			// command inventing the answer it was sent to report. Without it
			// the GPT name, mount options and marker file cannot be named at
			// all.
			name:    "no purpose, so no spec, so no gpt name or marker path",
			mutate:  func(a *proto.StorageClaimAck) { a.Purpose = "" },
			wantErr: "purpose",
		},
		{
			name:    "a purpose this build does not know",
			mutate:  func(a *proto.StorageClaimAck) { a.Purpose = "scratch" },
			wantErr: "resolvable purpose",
		},
		{
			// A refusal that arrived without an error is still a refusal.
			name:    "ok=false is never a claim",
			mutate:  func(a *proto.StorageClaimAck) { a.OK = false; a.Refusal = proto.StorageRefusalProtected },
			wantErr: "ok=false",
		},
		{
			// Every missing field at once, reported together rather than one
			// per re-run.
			name: "several missing fields are all named",
			mutate: func(a *proto.StorageClaimAck) {
				a.PartUUID, a.MountPath, a.FSLabel = "", "", ""
			},
			wantErr: "partUuid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ack := goodDataAck()
			tc.mutate(ack)
			rep, err := newClaimReport(ack, realBackend)
			if err == nil {
				t.Fatalf("newClaimReport reported a success: %+v", rep)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("refusal does not name %q: %v", tc.wantErr, err)
			}
		})
	}
}

func TestNewClaimReport_MissingFieldsAreAllNamedAtOnce(t *testing.T) {
	ack := goodDataAck()
	ack.PartUUID, ack.MountPath, ack.FSLabel = "", "", ""
	_, err := newClaimReport(ack, realBackend)
	if err == nil {
		t.Fatal("newClaimReport reported a success")
	}
	for _, want := range []string{"partUuid", "mountPath", "fsLabel"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
}

func TestNewClaimReport_NilAck(t *testing.T) {
	if _, err := newClaimReport(nil, realBackend); err == nil {
		t.Fatal("a nil ack was reported as a claim")
	}
}

// The three fields StorageClaimAck does not carry come from proto's per-purpose
// spec table, keyed on the purpose the agent echoed back. Both purposes are
// checked, because the whole of #302 is that these two answers differ.
func TestNewClaimReport_DerivesTheSpecFieldsPerPurpose(t *testing.T) {
	tests := []struct {
		name             string
		purpose          proto.StoragePurpose
		fsLabel          string
		mountPath        string
		wantGPTName      string
		wantMountOptions string
		wantMarkerPath   string
	}{
		{
			name: "data", purpose: proto.StoragePurposeData,
			fsLabel: proto.StorageDataLabel, mountPath: "/var/lib/rasputin/data/u1",
			wantGPTName: proto.StorageDataPartName,
			// A data disk deliberately does NOT get noexec: it hosts app
			// volumes, which can legitimately hold executables.
			wantMountOptions: proto.StorageDataMountOptions,
			wantMarkerPath:   "/var/lib/rasputin/data/u1/" + proto.StorageDataMarkerFile,
		},
		{
			name: "backup", purpose: proto.StoragePurposeBackup,
			fsLabel: proto.StorageBackupLabel, mountPath: "/run/rasputin/storage/u1",
			wantGPTName: proto.StorageBackupPartName,
			// A backup target does, because its contents are an archive.
			wantMountOptions: proto.StorageBackupMountOptions,
			wantMarkerPath:   "/run/rasputin/storage/u1/" + proto.StorageMarkerFile,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ack := goodDataAck()
			ack.Purpose, ack.FSLabel, ack.MountPath = tc.purpose, tc.fsLabel, tc.mountPath
			ack.DataSet, ack.BackupSet = nil, nil
			ack.BackupSet = &proto.StorageBackupSet{MarkerVersion: 1}
			rep, err := newClaimReport(ack, realBackend)
			if err != nil {
				t.Fatalf("newClaimReport: %v", err)
			}
			if rep.GPTName != tc.wantGPTName {
				t.Errorf("gptName = %q, want %q", rep.GPTName, tc.wantGPTName)
			}
			if rep.MountOptions != tc.wantMountOptions {
				t.Errorf("mountOptions = %q, want %q", rep.MountOptions, tc.wantMountOptions)
			}
			if rep.MarkerPath != tc.wantMarkerPath {
				t.Errorf("markerPath = %q, want %q", rep.MarkerPath, tc.wantMarkerPath)
			}
		})
	}
}

// A filesystem label that is not the one the spec table names for this purpose
// means the backend and proto disagree — the exact drift the table exists to
// stop. Both values are printed rather than one being silently preferred.
func TestNewClaimReport_LabelDisagreementIsWarnedWithBothValues(t *testing.T) {
	ack := goodDataAck()
	ack.FSLabel = "RASPUTIN-BACKUP" // a data claim wearing the backup label
	rep, err := newClaimReport(ack, realBackend)
	if err != nil {
		t.Fatalf("newClaimReport: %v", err)
	}
	joined := strings.Join(rep.Warnings, "\n")
	for _, want := range []string{"RASPUTIN-BACKUP", proto.StorageDataLabel, "disagree"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings do not mention %q; got:\n%s", want, joined)
		}
	}
	if rep.FSLabel != "RASPUTIN-BACKUP" {
		t.Errorf("fsLabel = %q, want the value the backend actually reported", rep.FSLabel)
	}
}

func TestNewClaimReport_SoftWarnings(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*proto.StorageClaimAck)
		wantWarning string
	}{
		{
			name:        "no post-format fingerprint",
			mutate:      func(a *proto.StorageClaimAck) { a.Fingerprint = "" },
			wantWarning: "no post-format fingerprint",
		},
		{
			name:        "no fsType",
			mutate:      func(a *proto.StorageClaimAck) { a.FSType = "" },
			wantWarning: "no fsType",
		},
		{
			name:        "neither marker reported back",
			mutate:      func(a *proto.StorageClaimAck) { a.DataSet = nil },
			wantWarning: "neither a backup set nor a data set",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ack := goodDataAck()
			tc.mutate(ack)
			rep, err := newClaimReport(ack, realBackend)
			if err != nil {
				// These are warnings, not refusals: none of them stops an
				// operator using the disk.
				t.Fatalf("newClaimReport refused over a soft condition: %v", err)
			}
			if !strings.Contains(strings.Join(rep.Warnings, "\n"), tc.wantWarning) {
				t.Errorf("warnings do not mention %q; got:\n%s", tc.wantWarning, strings.Join(rep.Warnings, "\n"))
			}
		})
	}
}

// verifyClaimedMarker runs §6.3's check against a real directory, so a claim
// whose mount reported success but landed nowhere is caught.
func TestVerifyClaimedMarker(t *testing.T) {
	t.Run("a data claim with no marker on the mount fails the check", func(t *testing.T) {
		rep := claimReport{
			Purpose:    proto.StoragePurposeData,
			PartUUID:   "1111-2222",
			MountPath:  t.TempDir(), // empty: the mount point without the disk
			MarkerPath: "irrelevant",
		}
		verifyClaimedMarker(&rep)
		if rep.MarkerVerified != "NO" {
			t.Errorf("markerVerified = %q, want NO", rep.MarkerVerified)
		}
		if !strings.Contains(strings.Join(rep.Warnings, "\n"), "marker check FAILS") {
			t.Errorf("no warning about the failed marker check: %v", rep.Warnings)
		}
	})

	t.Run("a backup claim is left alone", func(t *testing.T) {
		// Not an oversight: there is no exported reader for
		// .rasputin-backup-set.json, and writing a second one here would be a
		// second answer to a question the backend already answers.
		rep := claimReport{Purpose: proto.StoragePurposeBackup, MountPath: t.TempDir()}
		verifyClaimedMarker(&rep)
		if rep.MarkerVerified != "" || len(rep.Warnings) != 0 {
			t.Errorf("a backup claim was verified: %+v", rep)
		}
	})
}

// ---------------------------------------------------------------------------
// mount-data
// ---------------------------------------------------------------------------

func TestNewDataMountReport(t *testing.T) {
	mounts := []storage.DataMount{
		{PartUUID: "u1", DevicePath: "/dev/sdb", MountPath: "/var/lib/rasputin/data/u1"},
		{PartUUID: "u2", DevicePath: "/dev/sdc", MountPath: "/var/lib/rasputin/data/u2", AlreadyMounted: true},
		{PartUUID: "u3", DevicePath: "/dev/sdd", Err: storage.ErrDataMarkerMissing},
	}
	rep := newDataMountReport(mounts, realBackend)

	if len(rep.Mounted) != 2 || len(rep.Skipped) != 1 {
		t.Fatalf("mounted=%d skipped=%d, want 2 and 1", len(rep.Mounted), len(rep.Skipped))
	}
	if rep.Skipped[0].PartUUID != "u3" || rep.Skipped[0].Error == "" {
		t.Errorf("the skipped disk lost its identity or its reason: %+v", rep.Skipped[0])
	}
	if !rep.Mounted[1].AlreadyMounted {
		t.Errorf("an already-mounted disk was reported as freshly mounted: %+v", rep.Mounted[1])
	}
	// The marker path is derived from the data purpose's spec, so an operator
	// has something to cat without assembling the path themselves.
	want := "/var/lib/rasputin/data/u1/" + proto.StorageDataMarkerFile
	if rep.Mounted[0].MarkerPath != want {
		t.Errorf("markerPath = %q, want %q", rep.Mounted[0].MarkerPath, want)
	}
	// A skipped disk has no mount, so it must not be given a marker path that
	// would read as somewhere to look.
	if rep.Skipped[0].MarkerPath != "" {
		t.Errorf("a skipped disk was given a marker path: %q", rep.Skipped[0].MarkerPath)
	}
}

// An empty sweep is not a failure — nothing on this node is claimed — but it
// is also not silence, because "no data disk" and "the sweep could not look"
// are indistinguishable to an operator who sees neither.
func TestNewDataMountReport_EmptySweepSaysSo(t *testing.T) {
	rep := newDataMountReport(nil, realBackend)
	if len(rep.Mounted) != 0 || len(rep.Skipped) != 0 {
		t.Fatalf("an empty sweep produced disks: %+v", rep)
	}
	if !strings.Contains(strings.Join(rep.Warnings, "\n"), "found no claimed data disk") {
		t.Errorf("an empty sweep said nothing: %v", rep.Warnings)
	}
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

func TestNewInspectReport(t *testing.T) {
	created := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		ack            *proto.StorageInspectAck
		wantPurpose    proto.StoragePurpose
		wantMarkerPath string
		wantWarning    string
	}{
		{
			name: "a mounted data disk resolves its purpose from the label hint",
			ack: &proto.StorageInspectAck{
				OK: true, Present: true, PartUUID: "u1", MountPath: "/var/lib/rasputin/data/u1",
				FSLabel: proto.StorageDataLabel,
				DataSet: &proto.StorageDataSet{MarkerVersion: 1, PartUUID: "u1", CreatedAt: created},
			},
			wantPurpose:    proto.StoragePurposeData,
			wantMarkerPath: "/var/lib/rasputin/data/u1/" + proto.StorageDataMarkerFile,
		},
		{
			name: "a mounted backup target resolves the other way",
			ack: &proto.StorageInspectAck{
				OK: true, Present: true, PartUUID: "u2", MountPath: "/run/rasputin/storage/u2",
				FSLabel:   proto.StorageBackupLabel,
				BackupSet: &proto.StorageBackupSet{MarkerVersion: 1, PartUUID: "u2", CreatedAt: created},
			},
			wantPurpose:    proto.StoragePurposeBackup,
			wantMarkerPath: "/run/rasputin/storage/u2/" + proto.StorageMarkerFile,
		},
		{
			// Present=false is an answer, not a failure — the operator
			// unplugged it — and the report says which.
			name:        "not present is an answer",
			ack:         &proto.StorageInspectAck{OK: true, Present: false, PartUUID: "u3"},
			wantWarning: "NOT PRESENT",
		},
		{
			// The third state: attached and unmountable, which the health poll
			// renders as UNMOUNTED rather than MISSING.
			name:        "attached and unanswerable is not the same as missing",
			ack:         &proto.StorageInspectAck{OK: false, Present: true, PartUUID: "u4"},
			wantWarning: "the disk IS attached and the agent could not answer",
		},
		{
			// §6.3: the marker is the whole enforcement. Mounted with none is
			// either an unmounted mount point on the boot medium or not the
			// disk it claims to be.
			name:           "mounted with no marker is the §6.3 hazard",
			ack:            &proto.StorageInspectAck{OK: true, Present: true, PartUUID: "u5", MountPath: "/var/lib/rasputin/data/u5", FSLabel: proto.StorageDataLabel},
			wantPurpose:    proto.StoragePurposeData,
			wantMarkerPath: "/var/lib/rasputin/data/u5/" + proto.StorageDataMarkerFile,
			wantWarning:    "carries NO marker",
		},
		{
			name: "a foreign label resolves no purpose and invents no marker path",
			ack:  &proto.StorageInspectAck{OK: true, Present: true, PartUUID: "u6", MountPath: "/mnt/x", FSLabel: "MYSTUFF", DataSet: &proto.StorageDataSet{MarkerVersion: 1}},
		},
		{
			name:        "a nil ack does not panic",
			ack:         nil,
			wantWarning: "returned no inspect ack",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := newInspectReport(tc.ack, realBackend)
			if rep.Purpose != tc.wantPurpose {
				t.Errorf("purpose = %q, want %q", rep.Purpose, tc.wantPurpose)
			}
			if rep.MarkerPath != tc.wantMarkerPath {
				t.Errorf("markerPath = %q, want %q", rep.MarkerPath, tc.wantMarkerPath)
			}
			if tc.wantWarning != "" && !strings.Contains(strings.Join(rep.Warnings, "\n"), tc.wantWarning) {
				t.Errorf("warnings do not mention %q; got:\n%s", tc.wantWarning, strings.Join(rep.Warnings, "\n"))
			}
		})
	}
}

// ---------------------------------------------------------------------------

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		n    uint64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{512 << 20, "512.0 MiB"},
		{500 << 30, "500.0 GiB"},
		{2000 << 30, "2.0 TiB"},
		// The top of the ladder: nothing may render as a bare huge number, and
		// nothing may index past "KMGTPE".
		{1 << 62, "4.0 EiB"},
	}
	for _, tc := range tests {
		if got := humanBytes(tc.n); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
