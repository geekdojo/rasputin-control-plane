package storage

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// §6 gave the claim a PURPOSE. These are the tests for the two ways that can go
// wrong on a verb that formats disks: performing a purpose we do not understand,
// and performing the right purpose with the wrong contents.
//
// Both backends are asserted for every rule. The mock is the dev/CI backend and
// the only place the destructive path can be exercised at all, so a rule the
// mock does not enforce is a rule CI does not test.

// The same machine after nvme1n1 has been claimed as a §6 DATA disk. The only
// difference from claimedLsblk is the filesystem label, which is what tells
// enumeration which marker to look for.
const claimedDataLsblk = `{
   "blockdevices": [
      {"name":"nvme1n1","kname":"nvme1n1","path":"/dev/nvme1n1","type":"disk","size":2000398934016,"model":"CT2000P3SSD8","serial":"SN-SPARE-0002","wwn":"eui.0002","tran":"nvme","rm":false,
        "children":[
          {"name":"nvme1n1p1","kname":"nvme1n1p1","path":"/dev/nvme1n1p1","type":"part","size":2000397885440,"fstype":"ext4","label":"RASPUTIN-DATA","partuuid":"9d0f4a2b-01","mountpoint":null}
        ]}
   ]
}`

// ---------------------------------------------------------------------------
// The purpose decides the three constants — and an absent purpose means backup
// ---------------------------------------------------------------------------

// The wire-compatibility default, proven where it matters: on the platter. An
// api that predates §6 sends no purpose, and the disk it gets back has to be
// byte-for-byte the backup target it would have got before the field existed —
// same GPT name, same filesystem label, same marker file.
func TestBlockDev_ClaimAppliesThePurposesConstants(t *testing.T) {
	tests := []struct {
		name     string
		purpose  proto.StoragePurpose
		after    string
		partName string
		fsLabel  string
		marker   string
	}{
		{
			name:     "an absent purpose is the backup target",
			purpose:  "",
			after:    claimedLsblk,
			partName: proto.StorageBackupPartName,
			fsLabel:  proto.StorageBackupLabel,
			marker:   proto.StorageMarkerFile,
		},
		{
			name:     "backup, stated",
			purpose:  proto.StoragePurposeBackup,
			after:    claimedLsblk,
			partName: proto.StorageBackupPartName,
			fsLabel:  proto.StorageBackupLabel,
			marker:   proto.StorageMarkerFile,
		},
		{
			name:     "data",
			purpose:  proto.StoragePurposeData,
			after:    claimedDataLsblk,
			partName: proto.StorageDataPartName,
			fsLabel:  proto.StorageDataLabel,
			marker:   proto.StorageDataMarkerFile,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sh := &fakeShell{lsblkJSON: twoNVMeLsblk, afterJSON: tc.after, partUUID: "9d0f4a2b-01"}
			b := newTestBlockDev(t, sh)
			spare := bdCandidate(t, mustEnumerate(t, b), "/dev/nvme1n1")
			sh.calls = nil

			cmd := claimCmd("/dev/nvme1n1", spare.Fingerprint, "the disk")
			cmd.Purpose = tc.purpose
			ack, err := b.Claim(context.Background(), cmd)
			if err != nil {
				t.Fatalf("Claim: %v", err)
			}

			// (1) The GPT name in the sfdisk script. Not the identifier, but
			// it is what a human reads in lsblk and what #307 says must not
			// collide across two Rasputin disks in one machine.
			var sfdisk fakeCall
			for _, c := range sh.calls {
				if c.name == "sfdisk" {
					sfdisk = c
				}
			}
			if !strings.Contains(sfdisk.stdin, `name="`+tc.partName+`"`) {
				t.Errorf("sfdisk script does not name the partition %q: %q", tc.partName, sfdisk.stdin)
			}
			// The type GUID and --wipe always are purpose-independent and must
			// have survived the parameterisation untouched.
			if !strings.Contains(sfdisk.stdin, "type=0FC63DAF-8483-4772-8E79-3D69D8477DE4") {
				t.Errorf("sfdisk script lost the Linux filesystem type GUID: %q", sfdisk.stdin)
			}
			if !containsArg(sfdisk.args, "--wipe") || !containsArg(sfdisk.args, "always") {
				t.Errorf("sfdisk lost --wipe always: %v", sfdisk.args)
			}

			// (2) The filesystem label mkfs applied, with -F and -m 0 intact.
			var mkfs fakeCall
			for _, c := range sh.calls {
				if c.name == "mkfs.ext4" {
					mkfs = c
				}
			}
			if !containsArg(mkfs.args, tc.fsLabel) {
				t.Errorf("mkfs did not apply the %s label: %v", tc.fsLabel, mkfs.args)
			}
			if !containsArg(mkfs.args, "-F") || !containsArg(mkfs.args, "-m") || !containsArg(mkfs.args, "0") {
				t.Errorf("mkfs lost -F or -m 0: %v", mkfs.args)
			}

			// (3) The marker file that landed, read back off the "disk". The
			// ack is not the thing being tested — a marker that reaches the
			// reply and not the platter is the bug this package already has a
			// regression test for.
			assertMarkerFileLanded(t, ack.MountPath, tc.marker)
			assertOnlyMarker(t, ack.MountPath, tc.marker)

			if ack.Purpose != cmd.EffectivePurpose() {
				t.Errorf("ack purpose = %q, want the resolved %q", ack.Purpose, cmd.EffectivePurpose())
			}
			if ack.FSLabel != tc.fsLabel {
				t.Errorf("ack fsLabel = %q, want %q", ack.FSLabel, tc.fsLabel)
			}
		})
	}
}

// The mock has to reach the same three answers, because it is the backend CI
// runs and a mock that formats differently from production proves nothing.
func TestMock_ClaimAppliesThePurposesConstants(t *testing.T) {
	tests := []struct {
		name    string
		purpose proto.StoragePurpose
		fsLabel string
		backup  bool
	}{
		{name: "an absent purpose is the backup target", purpose: "", fsLabel: proto.StorageBackupLabel, backup: true},
		{name: "backup, stated", purpose: proto.StoragePurposeBackup, fsLabel: proto.StorageBackupLabel, backup: true},
		{name: "data", purpose: proto.StoragePurposeData, fsLabel: proto.StorageDataLabel},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestMock(t, defaultMockMachine())
			spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")

			cmd := claimCmd(spare.DevicePath, spare.Fingerprint, "the disk")
			cmd.Purpose = tc.purpose
			ack, err := m.Claim(context.Background(), cmd)
			if err != nil {
				t.Fatalf("Claim: %v", err)
			}
			if ack.FSLabel != tc.fsLabel {
				t.Errorf("ack fsLabel = %q, want %q", ack.FSLabel, tc.fsLabel)
			}
			if ack.Purpose != cmd.EffectivePurpose() {
				t.Errorf("ack purpose = %q, want the resolved %q", ack.Purpose, cmd.EffectivePurpose())
			}
			// Exactly one marker, and it is the right one.
			if tc.backup {
				if ack.BackupSet == nil || ack.DataSet != nil {
					t.Fatalf("a backup claim produced backupSet=%v dataSet=%v", ack.BackupSet, ack.DataSet)
				}
				if ack.BackupSet.PartUUID != ack.PartUUID {
					t.Errorf("marker partUuid = %q, want %q", ack.BackupSet.PartUUID, ack.PartUUID)
				}
			} else {
				if ack.DataSet == nil || ack.BackupSet != nil {
					t.Fatalf("a data claim produced backupSet=%v dataSet=%v", ack.BackupSet, ack.DataSet)
				}
				if ack.DataSet.PartUUID != ack.PartUUID {
					t.Errorf("marker partUuid = %q, want %q", ack.DataSet.PartUUID, ack.PartUUID)
				}
				if ack.DataSet.MarkerVersion != proto.StorageDataMarkerVersion {
					t.Errorf("data marker version = %d", ack.DataSet.MarkerVersion)
				}
			}

			// And it survives the round trip through enumeration and inspect,
			// which is how everything downstream meets it.
			again := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
			gotPurpose, ok := again.ClaimedPurpose()
			if !ok || gotPurpose != cmd.EffectivePurpose() {
				t.Fatalf("re-enumeration reports purpose (%q, %v), want %q", gotPurpose, ok, cmd.EffectivePurpose())
			}
			// A data disk must NOT trip §4.8's adopt-or-wipe gate: that prompt
			// offers the operator a choice about an archive it does not hold,
			// and §6.1 declines to generalise adopt-not-wipe to data disks.
			if again.HasBackupSet != tc.backup {
				t.Errorf("hasBackupSet = %v for a %q claim", again.HasBackupSet, cmd.EffectivePurpose())
			}
			if again.HasDataSet == tc.backup {
				t.Errorf("hasDataSet = %v for a %q claim", again.HasDataSet, cmd.EffectivePurpose())
			}

			insp, err := m.Inspect(context.Background(), ack.PartUUID)
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			if insp.FSLabel != tc.fsLabel {
				t.Errorf("inspect fsLabel = %q, want %q", insp.FSLabel, tc.fsLabel)
			}
			if (insp.BackupSet != nil) != tc.backup || (insp.DataSet != nil) == tc.backup {
				t.Errorf("inspect reported backupSet=%v dataSet=%v for a %q target", insp.BackupSet, insp.DataSet, cmd.EffectivePurpose())
			}
		})
	}
}

// Enumeration has to recognise a data disk it did not just claim — the marker
// on the platter is the record, and a replacement controlplane reads it cold.
func TestBlockDev_EnumerateRecognisesEitherPurpose(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk, afterJSON: claimedDataLsblk, partUUID: "9d0f4a2b-01"}
	b := newTestBlockDev(t, sh)
	spare := bdCandidate(t, mustEnumerate(t, b), "/dev/nvme1n1")

	cmd := claimCmd("/dev/nvme1n1", spare.Fingerprint, "media library")
	cmd.Purpose = proto.StoragePurposeData
	ack, err := b.Claim(context.Background(), cmd)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	// Read it back the way enumeration would, off the mount rather than out of
	// the ack.
	set, err := readDataMarker(ack.MountPath)
	if err != nil {
		t.Fatalf("readDataMarker: %v", err)
	}
	if set.PartUUID != ack.PartUUID || set.Label != "media library" {
		t.Errorf("data marker = %+v", set)
	}
	if set.MarkerVersion != proto.StorageDataMarkerVersion {
		t.Errorf("data marker version = %d, want %d", set.MarkerVersion, proto.StorageDataMarkerVersion)
	}
	// The backup reader must not see it. Two markers with two shapes is the
	// whole reason StorageBackupSet could stay frozen.
	if _, err := readMarker(ack.MountPath); err == nil {
		t.Error("readMarker found a backup set on a data disk — the markers are not distinct")
	}
}

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

// An unrecognised purpose is a refusal, never a fall back to backup. This is
// the one that would be silent: a value this build does not know, defaulted,
// formats a disk as something nobody asked for.
func TestClaimRefusesAnUnknownPurpose(t *testing.T) {
	for _, purpose := range []proto.StoragePurpose{"scratch", "Backup", "DATA", "backup ", "swap"} {
		t.Run(string(purpose), func(t *testing.T) {
			// The real backend, where the assertion that matters is that
			// nothing was written.
			sh := &fakeShell{lsblkJSON: twoNVMeLsblk, afterJSON: claimedLsblk, partUUID: "9d0f4a2b-01"}
			b := newTestBlockDev(t, sh)
			spare := bdCandidate(t, mustEnumerate(t, b), "/dev/nvme1n1")
			sh.calls = nil

			cmd := claimCmd("/dev/nvme1n1", spare.Fingerprint, "the disk")
			cmd.Purpose = purpose
			if _, err := b.Claim(context.Background(), cmd); !errors.Is(err, ErrBadPurpose) {
				t.Fatalf("blockdev Claim(%q) = %v, want ErrBadPurpose", purpose, err)
			}
			sh.assertNothingWasWritten(t)

			// And the mock refuses identically.
			m := newTestMock(t, defaultMockMachine())
			mspare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
			mcmd := claimCmd(mspare.DevicePath, mspare.Fingerprint, "the disk")
			mcmd.Purpose = purpose
			if _, err := m.Claim(context.Background(), mcmd); !errors.Is(err, ErrBadPurpose) {
				t.Fatalf("mock Claim(%q) = %v, want ErrBadPurpose", purpose, err)
			}
			// Nothing was formatted: the disk is still the blank one.
			if got := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002"); len(got.Partitions) != 0 {
				t.Fatalf("a REFUSED claim partitioned the disk: %+v", got.Partitions)
			}
		})
	}
}

// §4.6 backup-key custody riding on a §6 data claim is a refusal, per field.
// A data disk holds no archive to encrypt, so writing key blobs onto it would
// mean nothing there and would scatter §4.6 material onto a disk no unlock path
// ever reads.
func TestClaimRefusesKeyMaterialOnADataClaim(t *testing.T) {
	tests := []struct {
		name  string
		field string
		set   func(*proto.StorageClaimCmd)
	}{
		{"keyId", "keyId", func(c *proto.StorageClaimCmd) { c.KeyID = "ak-DEADBEEF" }},
		{"keyAlg", "keyAlg", func(c *proto.StorageClaimCmd) { c.KeyAlg = testKeyAlg }},
		{"publicKey", "publicKey", func(c *proto.StorageClaimCmd) { c.PublicKey = testPublicKey }},
		{"wrappedByPassphrase", "wrappedByPassphrase", func(c *proto.StorageClaimCmd) { c.WrappedByPassphrase = testWrappedPP }},
		{"wrappedByRecoveryCode", "wrappedByRecoveryCode", func(c *proto.StorageClaimCmd) { c.WrappedByRecoveryCode = testWrappedRC }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sh := &fakeShell{lsblkJSON: twoNVMeLsblk, afterJSON: claimedDataLsblk, partUUID: "9d0f4a2b-01"}
			b := newTestBlockDev(t, sh)
			spare := bdCandidate(t, mustEnumerate(t, b), "/dev/nvme1n1")
			sh.calls = nil

			cmd := claimCmd("/dev/nvme1n1", spare.Fingerprint, "media library")
			cmd.Purpose = proto.StoragePurposeData
			tc.set(&cmd)

			_, err := b.Claim(context.Background(), cmd)
			if !errors.Is(err, ErrBadPurpose) {
				t.Fatalf("blockdev Claim = %v, want ErrBadPurpose", err)
			}
			// The refusal has to name the offending field, or the api author
			// reading it in a job feed learns nothing.
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("the refusal does not name %q: %v", tc.field, err)
			}
			sh.assertNothingWasWritten(t)

			m := newTestMock(t, defaultMockMachine())
			mspare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
			mcmd := claimCmd(mspare.DevicePath, mspare.Fingerprint, "media library")
			mcmd.Purpose = proto.StoragePurposeData
			tc.set(&mcmd)
			if _, err := m.Claim(context.Background(), mcmd); !errors.Is(err, ErrBadPurpose) {
				t.Fatalf("mock Claim = %v, want ErrBadPurpose", err)
			}
			if got := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002"); len(got.Partitions) != 0 {
				t.Fatalf("a REFUSED claim partitioned the disk: %+v", got.Partitions)
			}
		})
	}
}

// The same material on a BACKUP claim is not merely allowed, it is the point —
// §4.6's custody is what makes the disk adoptable by a controlplane that has
// never seen it. Asserted here so the refusal above cannot be over-applied.
func TestClaimAcceptsKeyMaterialOnABackupClaim(t *testing.T) {
	for _, purpose := range []proto.StoragePurpose{"", proto.StoragePurposeBackup} {
		m := newTestMock(t, defaultMockMachine())
		spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
		cmd := keyedClaimCmd(spare.DevicePath, spare.Fingerprint, "weekly archive")
		cmd.Purpose = purpose
		ack, err := m.Claim(context.Background(), cmd)
		if err != nil {
			t.Fatalf("Claim(purpose=%q): %v", purpose, err)
		}
		assertMarkerCarriesCustody(t, ack.BackupSet, ack.PartUUID)
	}
}

// The refusal has to reach the api as its own code. "bad-purpose" says the
// agent understood the command and will not perform it; "backend-error" says
// something broke, which is a different sentence to show an operator.
func TestBadPurposeHasItsOwnRefusalCode(t *testing.T) {
	if got := refusalFor(ErrBadPurpose); got != proto.StorageRefusalBadPurpose {
		t.Errorf("refusalFor(ErrBadPurpose) = %q, want %q", got, proto.StorageRefusalBadPurpose)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func assertMarkerFileLanded(t *testing.T, mountPath, name string) {
	t.Helper()
	switch name {
	case proto.StorageMarkerFile:
		set, err := readMarker(mountPath)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if set.MarkerVersion != proto.StorageMarkerVersion {
			t.Errorf("marker version = %d", set.MarkerVersion)
		}
	case proto.StorageDataMarkerFile:
		set, err := readDataMarker(mountPath)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if set.MarkerVersion != proto.StorageDataMarkerVersion {
			t.Errorf("marker version = %d", set.MarkerVersion)
		}
	default:
		t.Fatalf("no assertion for marker %q", name)
	}
}

// assertOnlyMarker proves the OTHER marker is absent. A claim writes one
// filesystem for one purpose; two markers on one disk would make
// StorageCandidate.ClaimedPurpose report neither, which is a claimed disk that
// cannot say what it is.
func assertOnlyMarker(t *testing.T, mountPath, name string) {
	t.Helper()
	if name != proto.StorageMarkerFile {
		if _, err := readMarker(mountPath); err == nil {
			t.Errorf("a %s claim also left a backup marker behind", name)
		}
	}
	if name != proto.StorageDataMarkerFile {
		if _, err := readDataMarker(mountPath); err == nil {
			t.Errorf("a %s claim also left a data marker behind", name)
		}
	}
}
