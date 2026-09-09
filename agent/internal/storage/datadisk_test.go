package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// §6's three new properties, tested where each of them can actually fail:
// the mount lands under the right root with the right options, the startup
// sweep skips a bad disk instead of wedging, and the marker check refuses a
// mount point that is populated but unmarked.

// ---------------------------------------------------------------------------
// A shell whose `mount` actually makes a filesystem appear
// ---------------------------------------------------------------------------

// dataShell is fakeShell's opposite number for the mount path. fakeShell
// answers commands; this one has SIDE EFFECTS, because the thing under test is
// what appears at the mount point.
//
// `mount` writes the marker into the directory it was pointed at — that is
// what mounting a claimed filesystem does — and `umount` takes it away again.
// Both matter: enumeration peeks by mounting read-only and unmounting, and the
// sweep's own verification reads what the durable mount left behind.
type dataShell struct {
	calls     []fakeCall
	lsblkJSON string
	// marker is written on each successful mount. Nil means a mount that
	// SUCCEEDS AND MOUNTS NOTHING, which is §6.3's failure.
	marker *proto.StorageDataSet
	// markerMounts, when > 0, writes the marker for that many mounts and then
	// stops — the disk enumeration could read but whose durable mount then
	// produced an empty directory.
	markerMounts int
	mounts       int
	failMount    bool
	// backupDevice / backupMarker make one partition a §4 BACKUP target: a
	// mount of that device yields the backup marker instead of the data one,
	// which is what the machine looks like when a controlplane has both.
	backupDevice string
	backupMarker *proto.StorageBackupSet
}

// mountedDevice is the device operand of a `mount -o <opts> <device> <dir>`.
func mountedDevice(args []string) string {
	if len(args) < 2 {
		return ""
	}
	return args[len(args)-2]
}

func (d *dataShell) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	base := filepath.Base(name)
	d.calls = append(d.calls, fakeCall{name: base, args: args, stdin: string(stdin)})
	switch base {
	case "lsblk":
		return []byte(d.lsblkJSON), nil
	case "mount":
		if d.failMount {
			return nil, errors.New("mount: wrong fs type, bad option, bad superblock")
		}
		d.mounts++
		dir := args[len(args)-1]
		if d.backupMarker != nil && mountedDevice(args) == d.backupDevice {
			return nil, writeMarker(dir, proto.StorageMarkerFile, d.backupMarker)
		}
		if d.marker != nil && (d.markerMounts == 0 || d.mounts <= d.markerMounts) {
			if err := writeMarker(dir, proto.StorageDataMarkerFile, d.marker); err != nil {
				return nil, err
			}
		}
		return nil, nil
	case "umount":
		for _, f := range []string{proto.StorageDataMarkerFile, proto.StorageMarkerFile} {
			_ = os.Remove(filepath.Join(args[len(args)-1], f))
		}
		return nil, nil
	default:
		return nil, nil
	}
}

func (d *dataShell) mountCalls() []fakeCall {
	var out []fakeCall
	for _, c := range d.calls {
		if c.name == "mount" {
			out = append(out, c)
		}
	}
	return out
}

// mountedDevices lists every device this shell was asked to mount, read-only
// peeks included. The assertion these sweep tests are for is about which
// FILESYSTEMS were made live, so it counts mounts rather than results.
func (d *dataShell) mountedDevices() []string {
	var out []string
	for _, c := range d.mountCalls() {
		out = append(out, mountedDevice(c.args))
	}
	return out
}

// newDataBlockDev is newTestBlockDev's twin for a shell that writes files.
// Same fabricated machine — the two-NVMe controlplane whose nvme0n1 holds
// /boot, / and the persistent partition — so protection resolves identically.
func newDataBlockDev(t *testing.T, sh *dataShell) *BlockDevBackend {
	t.Helper()
	sys := newFakeSys(t)
	sys.addDisk("nvme0n1", "259:0")
	sys.addPartition("nvme0n1", "nvme0n1p1", "259:1")
	sys.addPartition("nvme0n1", "nvme0n1p2", "259:2")
	sys.addPartition("nvme0n1", "nvme0n1p3", "259:3")
	sys.addDisk("nvme1n1", "259:8")
	sys.addPartition("nvme1n1", "nvme1n1p1", "259:9")
	// The USB stick a controlplane's backup target actually lives on. Not
	// mounted, so it changes no protection answer; present so a fixture can
	// put a claimed backup disk on the same machine as a data disk.
	sys.addDisk("sda", "8:0")
	sys.addPartition("sda", "sda1", "8:1")

	mi := mountinfoFile(t, [][3]string{
		{"259:1", "/boot", "/dev/nvme0n1p1"},
		{"259:2", "/", "/dev/nvme0n1p2"},
		{"259:3", DefaultPersistentDir, "/dev/nvme0n1p3"},
	})

	b := newBlockDevBackend(t.TempDir(), map[string]string{}, sh.run)
	b.prot.sysfsRoot = sys.root
	b.prot.mountinfoPath = mi
	roots := t.TempDir()
	b.mountRoots = map[proto.StoragePurpose]string{
		proto.StoragePurposeBackup: filepath.Join(roots, "mounts"),
		proto.StoragePurposeData:   filepath.Join(roots, "data"),
	}
	b.scratchRoot = b.mountRoots[proto.StoragePurposeBackup]
	for _, root := range b.mountRoots {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatalf("mkdir mount root: %v", err)
		}
	}
	return b
}

// A controlplane with BOTH: the claimed data disk on nvme1n1 and §4's backup
// target on the USB stick. This is the ordinary shape of the machine §6.5's
// sweep runs on, and the one that shows what the sweep is allowed to touch.
const dataAndBackupLsblk = `{
   "blockdevices": [
      {"name":"nvme1n1","kname":"nvme1n1","path":"/dev/nvme1n1","type":"disk","size":2000398934016,"model":"CT2000P3SSD8","serial":"SN-SPARE-0002","wwn":"eui.0002","tran":"nvme","rm":false,
        "children":[
          {"name":"nvme1n1p1","kname":"nvme1n1p1","path":"/dev/nvme1n1p1","type":"part","size":2000397885440,"fstype":"ext4","label":"RASPUTIN-DATA","partuuid":"9d0f4a2b-01","mountpoint":null}
        ]},
      {"name":"sda","kname":"sda","path":"/dev/sda","type":"disk","size":64023257088,"model":"SanDisk Ultra","serial":"USB-0003","wwn":null,"tran":"usb","rm":true,
        "children":[
          {"name":"sda1","kname":"sda1","path":"/dev/sda1","type":"part","size":64023257088,"fstype":"ext4","label":"RASPUTIN-BACKUP","partuuid":"bbbb-01","mountpoint":null}
        ]}
   ]
}`

func testBackupSet(partUUID string) *proto.StorageBackupSet {
	return &proto.StorageBackupSet{
		MarkerVersion: proto.StorageMarkerVersion,
		ClusterID:     "cluster-1",
		PartUUID:      partUUID,
	}
}

func testDataSet(partUUID string) *proto.StorageDataSet {
	return &proto.StorageDataSet{
		MarkerVersion: proto.StorageDataMarkerVersion,
		ClusterID:     "cluster-1",
		PartUUID:      partUUID,
		Label:         "media library",
		CreatedAt:     time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC),
	}
}

// ---------------------------------------------------------------------------
// §6.5: the root and the options come from the purpose
// ---------------------------------------------------------------------------

// A claim mounts what it just formatted, and where it puts it — and with which
// options — is now the purpose's business. The backup row is the regression
// test: /run and noexec,nosuid,nodev are what shipped, and this change is not
// allowed to move them.
func TestBlockDev_ClaimMountsUnderThePurposesRootWithItsOptions(t *testing.T) {
	tests := []struct {
		name        string
		purpose     proto.StoragePurpose
		after       string
		wantPurpose proto.StoragePurpose
		wantOptions string
	}{
		{
			name:    "an absent purpose mounts as the backup target always did",
			purpose: "", after: claimedLsblk,
			wantPurpose: proto.StoragePurposeBackup, wantOptions: "noexec,nosuid,nodev",
		},
		{
			name: "backup, stated", purpose: proto.StoragePurposeBackup, after: claimedLsblk,
			wantPurpose: proto.StoragePurposeBackup, wantOptions: "noexec,nosuid,nodev",
		},
		{
			name:    "data mounts under its own root, without noexec",
			purpose: proto.StoragePurposeData, after: claimedDataLsblk,
			wantPurpose: proto.StoragePurposeData, wantOptions: "nosuid,nodev",
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

			wantPath := filepath.Join(bdMountRoot(t, b, tc.wantPurpose), "9d0f4a2b-01")
			if ack.MountPath != wantPath {
				t.Errorf("mounted at %q, want %q", ack.MountPath, wantPath)
			}
			// The DURABLE mount — the one pointed at the mount point the ack
			// reports. Enumeration's read-only peeks mount the same partition
			// elsewhere, before and after, and are not what this asserts.
			var mount fakeCall
			for _, c := range sh.calls {
				if c.name == "mount" && len(c.args) > 0 && c.args[len(c.args)-1] == wantPath {
					mount = c
				}
			}
			if len(mount.args) < 2 || mount.args[0] != "-o" {
				t.Fatalf("nothing was mounted at %s; mount calls were %v", wantPath, sh.calls)
			}
			if mount.args[1] != tc.wantOptions {
				t.Errorf("mount options = %q, want %q", mount.args[1], tc.wantOptions)
			}
		})
	}
}

// A data disk must not be mounted noexec. App volumes can legitimately hold
// executables, and /var/lib/rasputin — where those same volumes live today —
// is mounted `defaults`, so noexec would break apps to buy a property the
// partition they came from never had.
func TestBlockDev_DataMountIsNotNoexec(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk, afterJSON: claimedDataLsblk, partUUID: "9d0f4a2b-01"}
	b := newTestBlockDev(t, sh)
	spare := bdCandidate(t, mustEnumerate(t, b), "/dev/nvme1n1")
	sh.calls = nil

	cmd := claimCmd("/dev/nvme1n1", spare.Fingerprint, "media library")
	cmd.Purpose = proto.StoragePurposeData
	if _, err := b.Claim(context.Background(), cmd); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	for _, c := range sh.calls {
		if c.name != "mount" {
			continue
		}
		// peek's read-only mounts are exempt: they mount a disk nobody has
		// claimed anything about, for one read, and noexec is right there.
		if containsArg(c.args, "ro,noexec,nosuid,nodev") {
			continue
		}
		if strings.Contains(strings.Join(c.args, " "), "noexec") {
			t.Errorf("the data disk was mounted noexec: %v", c.args)
		}
	}
}

// Mount is addressed by partition UUID alone, so the purpose is read off the
// filesystem label — the same hint enumeration uses to decide which marker to
// read. The fallback matters most: a label that is none of ours means backup,
// which is where every target claimed before §6 has to keep landing.
func TestBlockDev_MountResolvesTheRootFromTheLabel(t *testing.T) {
	const unlabelled = `{"blockdevices":[
      {"name":"nvme1n1","kname":"nvme1n1","path":"/dev/nvme1n1","type":"disk","size":2000398934016,"tran":"nvme","rm":false,
        "children":[{"name":"nvme1n1p1","kname":"nvme1n1p1","path":"/dev/nvme1n1p1","type":"part","size":2000397885440,"fstype":"ext4","label":"SOMEBODY-ELSES","partuuid":"9d0f4a2b-01","mountpoint":null}]}]}`
	tests := []struct {
		name    string
		lsblk   string
		want    proto.StoragePurpose
		options string
	}{
		{name: "the backup label", lsblk: claimedLsblk, want: proto.StoragePurposeBackup, options: "noexec,nosuid,nodev"},
		{name: "the data label", lsblk: claimedDataLsblk, want: proto.StoragePurposeData, options: "nosuid,nodev"},
		{name: "a label that is none of ours falls back to backup", lsblk: unlabelled, want: proto.StoragePurposeBackup, options: "noexec,nosuid,nodev"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sh := &dataShell{lsblkJSON: tc.lsblk}
			b := newDataBlockDev(t, sh)
			path, err := b.Mount(context.Background(), "9d0f4a2b-01")
			if err != nil {
				t.Fatalf("Mount: %v", err)
			}
			want := filepath.Join(bdMountRoot(t, b, tc.want), "9d0f4a2b-01")
			if path != want {
				t.Errorf("mounted at %q, want %q", path, want)
			}
			calls := sh.mountCalls()
			if len(calls) != 1 {
				t.Fatalf("mount ran %d times, want once", len(calls))
			}
			if calls[0].args[1] != tc.options {
				t.Errorf("mount options = %q, want %q", calls[0].args[1], tc.options)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// §6.3 / §6.5: the startup sweep
// ---------------------------------------------------------------------------

func TestBlockDev_MountClaimedDataMountsTheClaimedDisk(t *testing.T) {
	sh := &dataShell{lsblkJSON: claimedDataLsblk, marker: testDataSet("9d0f4a2b-01")}
	b := newDataBlockDev(t, sh)

	mounts, err := b.MountClaimedData(context.Background())
	if err != nil {
		t.Fatalf("MountClaimedData: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("swept %d disks, want 1: %+v", len(mounts), mounts)
	}
	got := mounts[0]
	if got.Err != nil {
		t.Fatalf("the claimed data disk was skipped: %v", got.Err)
	}
	want := filepath.Join(bdMountRoot(t, b, proto.StoragePurposeData), "9d0f4a2b-01")
	if got.MountPath != want {
		t.Errorf("mounted at %q, want %q", got.MountPath, want)
	}
	if got.PartUUID != "9d0f4a2b-01" || got.DevicePath != "/dev/nvme1n1" {
		t.Errorf("reported %+v", got)
	}
	// The marker is there to be verified afterwards, which is the property
	// that makes the mount worth trusting.
	if _, err := VerifyDataMarker(got.MountPath, got.PartUUID); err != nil {
		t.Errorf("VerifyDataMarker on the freshly mounted disk: %v", err)
	}
}

// ⚠️ THE SWEEP MUST NOT TOUCH THE BACKUP DISK.
//
// Reading a marker means mounting the partition read-only and unmounting it,
// so an unnarrowed enumeration makes every Rasputin-labelled filesystem on the
// machine live for a moment. Run at agent startup, that would mount a
// controlplane's backup target on every boot — a §4 path that shipped without
// it, and a disk that is usually removable and usually holds the only copy of
// the archives. The sweep enumerates for the data purpose alone so the backup
// partition is never mounted AT ALL, rather than mounted and then ignored.
func TestBlockDev_MountClaimedDataNeverMountsTheBackupTarget(t *testing.T) {
	sh := &dataShell{
		lsblkJSON:    dataAndBackupLsblk,
		marker:       testDataSet("9d0f4a2b-01"),
		backupDevice: "/dev/sda1",
		backupMarker: testBackupSet("bbbb-01"),
	}
	b := newDataBlockDev(t, sh)

	mounts, err := b.MountClaimedData(context.Background())
	if err != nil {
		t.Fatalf("MountClaimedData: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("swept %d disks, want only the data one: %+v", len(mounts), mounts)
	}
	if mounts[0].Err != nil {
		t.Fatalf("the claimed data disk was skipped: %v", mounts[0].Err)
	}
	if mounts[0].PartUUID != "9d0f4a2b-01" {
		t.Errorf("swept %+v, want the data disk", mounts[0])
	}
	// The assertion this test exists for. Not "the backup disk was not
	// RETURNED" — not mounted, at all, read-only peek included.
	for _, dev := range sh.mountedDevices() {
		if dev == "/dev/sda1" || dev == "/dev/sda" {
			t.Errorf("the startup sweep mounted the backup target: mounts were %v", sh.mountedDevices())
		}
	}
}

// ...and the operator-facing enumeration is UNCHANGED by that narrowing. The
// disk picker's whole job is to say what is on a disk before an operator
// confirms a destructive format, so it still reads both markers — and still
// mounts the backup partition read-only to do it. Narrowing THIS would hide a
// claimed backup target from the one screen that has to show it.
func TestBlockDev_EnumerateStillReadsTheBackupTarget(t *testing.T) {
	sh := &dataShell{
		lsblkJSON:    dataAndBackupLsblk,
		marker:       testDataSet("9d0f4a2b-01"),
		backupDevice: "/dev/sda1",
		backupMarker: testBackupSet("bbbb-01"),
	}
	b := newDataBlockDev(t, sh)

	ack, err := b.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	backup := bdCandidate(t, ack, "/dev/sda")
	if !backup.HasBackupSet || backup.BackupSet == nil {
		t.Fatalf("the picker cannot see the claimed backup target: %+v", backup)
	}
	if backup.BackupSet.PartUUID != "bbbb-01" {
		t.Errorf("backup set = %+v", backup.BackupSet)
	}
	data := bdCandidate(t, ack, "/dev/nvme1n1")
	if !data.HasDataSet || data.DataSet == nil || data.DataSet.PartUUID != "9d0f4a2b-01" {
		t.Fatalf("the picker cannot see the claimed data disk: %+v", data)
	}
	// And it got there the only way it can: by peeking, read-only.
	var peeked bool
	for _, c := range sh.mountCalls() {
		if mountedDevice(c.args) == "/dev/sda1" {
			peeked = true
			if !containsArg(c.args, "ro,noexec,nosuid,nodev") {
				t.Errorf("enumeration mounted the backup target writable: %v", c.args)
			}
		}
	}
	if !peeked {
		t.Error("enumeration never read the backup target's marker, so the picker is guessing")
	}
}

// The whole point of the sweep's error handling: a disk that will not mount is
// logged and skipped, and the agent keeps starting. §6.3 — a missing data disk
// must never make a node unbootable — and under §6.5 the agent is what mounts
// it, so an agent that failed here would BE the hazard.
func TestBlockDev_MountClaimedDataSkipsABadDiskWithoutFailing(t *testing.T) {
	tests := []struct {
		name   string
		shell  *dataShell
		wantIn string
	}{
		{
			// Nothing mounts, so enumeration never reads the marker either
			// and the disk is known only by its label. It is still REPORTED,
			// because a labelled disk that yields no marker is exactly the
			// disk an operator has to hear about, and it is invisible
			// otherwise.
			name:   "the filesystem will not mount",
			shell:  &dataShell{lsblkJSON: claimedDataLsblk, marker: testDataSet("9d0f4a2b-01"), failMount: true},
			wantIn: "carries the " + proto.StorageDataLabel + " label but no readable",
		},
		{
			// mount(8) returned 0 and mounted nothing — the case a bare error
			// check cannot see, and the one §6.3 says the marker exists for.
			name:   "the mount succeeds and the marker is not there",
			shell:  &dataShell{lsblkJSON: claimedDataLsblk, marker: testDataSet("9d0f4a2b-01"), markerMounts: 1},
			wantIn: "carries no " + proto.StorageDataMarkerFile,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newDataBlockDev(t, tc.shell)
			mounts, err := b.MountClaimedData(context.Background())
			if err != nil {
				t.Fatalf("the sweep failed outright, which would take agent startup with it: %v", err)
			}
			if len(mounts) != 1 {
				t.Fatalf("swept %d disks, want 1: %+v", len(mounts), mounts)
			}
			if mounts[0].Err == nil {
				t.Fatalf("a disk that could not be used was reported as mounted: %+v", mounts[0])
			}
			if !strings.Contains(mounts[0].Err.Error(), tc.wantIn) {
				t.Errorf("skip reason %q should say %q", mounts[0].Err, tc.wantIn)
			}
			// And it is loggable rather than silent.
			LogDataMounts(mounts)
		})
	}
}

// A node with no data disk sweeps nothing and says nothing is wrong. This is
// every node in the fleet today, so it is the case that must not log a scare.
func TestBlockDev_MountClaimedDataOnANodeWithNoDataDisk(t *testing.T) {
	sh := &dataShell{lsblkJSON: twoNVMeLsblk}
	b := newDataBlockDev(t, sh)
	mounts, err := b.MountClaimedData(context.Background())
	if err != nil {
		t.Fatalf("MountClaimedData: %v", err)
	}
	if len(mounts) != 0 {
		t.Errorf("swept %+v on a node with no claimed data disk", mounts)
	}
	for _, c := range sh.mountCalls() {
		// Read-only peeks are enumeration's; nothing may be mounted for real.
		if !containsArg(c.args, "ro,noexec,nosuid,nodev") {
			t.Errorf("something was mounted on a node with no data disk: %v", c.args)
		}
	}
}

// The discovery half, as a pure function, because these are the cases a shell
// harness cannot reach: a data marker on the BOOT disk, and a marker naming a
// partition that is not there.
func TestDataDiskCandidates(t *testing.T) {
	part := func(uuid, label string) proto.StoragePartition {
		return proto.StoragePartition{DevicePath: "/dev/sdb1", PartUUID: uuid, FSType: "ext4", Label: label}
	}
	good := proto.StorageCandidate{
		DevicePath: "/dev/sdb", HasDataSet: true, DataSet: testDataSet("uuid-1"),
		Partitions: []proto.StoragePartition{part("uuid-1", proto.StorageDataLabel)},
	}
	tests := []struct {
		name        string
		cand        proto.StorageCandidate
		wantClaimed bool
		wantSkipped string
	}{
		{name: "a claimed data disk", cand: good, wantClaimed: true},
		{
			name: "a disk with no data set is not a data disk and not a skip",
			cand: proto.StorageCandidate{DevicePath: "/dev/sdc", Partitions: []proto.StoragePartition{part("uuid-2", proto.StorageBackupLabel)}},
		},
		{
			name: "a data marker on a protected disk is refused",
			cand: proto.StorageCandidate{
				DevicePath: "/dev/nvme0n1", Protected: true, ProtectedReason: "holds /boot, / and the persistent partition",
				HasDataSet: true, DataSet: testDataSet("uuid-1"),
				Partitions: []proto.StoragePartition{part("uuid-1", proto.StorageDataLabel)},
			},
			wantSkipped: "refusing to touch the device holding the mounted boot",
		},
		{
			name: "a marker naming a partition that is not on the disk",
			cand: proto.StorageCandidate{
				DevicePath: "/dev/sdb", HasDataSet: true, DataSet: testDataSet("uuid-somewhere-else"),
				Partitions: []proto.StoragePartition{part("uuid-1", proto.StorageDataLabel)},
			},
			wantSkipped: "which is not one of its partitions",
		},
		{
			name: "a marker naming no partition at all",
			cand: proto.StorageCandidate{
				DevicePath: "/dev/sdb", HasDataSet: true, DataSet: testDataSet(""),
				Partitions: []proto.StoragePartition{part("uuid-1", proto.StorageDataLabel)},
			},
			wantSkipped: "names no partition UUID",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claimed, skipped := dataDiskCandidates(&proto.StorageEnumerateAck{Candidates: []proto.StorageCandidate{tc.cand}})
			if tc.wantClaimed {
				if len(claimed) != 1 || len(skipped) != 0 {
					t.Fatalf("claimed=%d skipped=%+v, want one claimed", len(claimed), skipped)
				}
				return
			}
			if len(claimed) != 0 {
				t.Fatalf("%s was offered for mounting", tc.cand.DevicePath)
			}
			if tc.wantSkipped == "" {
				if len(skipped) != 0 {
					t.Fatalf("skipped %+v, want silence", skipped)
				}
				return
			}
			if len(skipped) != 1 {
				t.Fatalf("skipped %d, want 1", len(skipped))
			}
			if !strings.Contains(skipped[0].Err.Error(), tc.wantSkipped) {
				t.Errorf("skip reason %q should say %q", skipped[0].Err, tc.wantSkipped)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// §6.3: the marker check
// ---------------------------------------------------------------------------

func TestVerifyDataMarker(t *testing.T) {
	tests := []struct {
		name string
		// setup prepares the directory and returns the partUUID to verify.
		setup   func(t *testing.T, dir string) string
		wantErr error
		wantIn  string
	}{
		{
			name: "a mounted data disk verifies",
			setup: func(t *testing.T, dir string) string {
				mustWriteDataMarker(t, dir, testDataSet("uuid-1"))
				return "uuid-1"
			},
		},
		{
			name:    "an empty mount point is refused",
			setup:   func(t *testing.T, dir string) string { return "uuid-1" },
			wantErr: ErrDataMarkerMissing,
		},
		{
			// THE case. An unmounted mount point that a previous deploy
			// already filled is exactly the failure being caught, and it is
			// not empty — so a "is the directory empty?" check would pass it
			// through and let the app keep refilling the boot medium.
			name: "a NON-EMPTY mount point with no marker is refused",
			setup: func(t *testing.T, dir string) string {
				if err := os.MkdirAll(filepath.Join(dir, "postgres", "base"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "postgres", "base", "1"), []byte("app data"), 0o600); err != nil {
					t.Fatal(err)
				}
				return "uuid-1"
			},
			wantErr: ErrDataMarkerMissing,
		},
		{
			name: "a marker naming another partition is refused",
			setup: func(t *testing.T, dir string) string {
				mustWriteDataMarker(t, dir, testDataSet("uuid-somebody-else"))
				return "uuid-1"
			},
			wantErr: ErrDataMarkerMismatch,
			wantIn:  "cloned disk",
		},
		{
			name: "a marker with no version is refused",
			setup: func(t *testing.T, dir string) string {
				mustWriteDataMarker(t, dir, &proto.StorageDataSet{PartUUID: "uuid-1"})
				return "uuid-1"
			},
			wantErr: ErrDataMarkerMismatch,
			wantIn:  "no version",
		},
		{
			name: "a corrupt marker is refused, and not as an absent one",
			setup: func(t *testing.T, dir string) string {
				if err := os.WriteFile(filepath.Join(dir, proto.StorageDataMarkerFile), []byte("{not json"), 0o600); err != nil {
					t.Fatal(err)
				}
				return "uuid-1"
			},
			wantIn: "could not be read",
		},
		{
			name: "a marker from a NEWER agent still verifies",
			setup: func(t *testing.T, dir string) string {
				set := testDataSet("uuid-1")
				set.MarkerVersion = proto.StorageDataMarkerVersion + 1
				mustWriteDataMarker(t, dir, set)
				return "uuid-1"
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			partUUID := tc.setup(t, dir)
			set, err := VerifyDataMarker(dir, partUUID)
			if tc.wantErr == nil && tc.wantIn == "" {
				if err != nil {
					t.Fatalf("VerifyDataMarker: %v", err)
				}
				if set == nil || set.PartUUID != partUUID {
					t.Fatalf("returned %+v", set)
				}
				return
			}
			if err == nil {
				t.Fatalf("VerifyDataMarker accepted %s", dir)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantIn != "" && !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q should say %q", err, tc.wantIn)
			}
			// MARKER ABSENT MEANS REFUSE, NEVER CREATE. A check that wrote
			// the marker it could not find would turn the dangerous case —
			// an unmounted mount point on the boot medium — into a permanent
			// lie every later check would believe.
			if _, statErr := os.Stat(filepath.Join(dir, proto.StorageDataMarkerFile)); errors.Is(statErr, os.ErrNotExist) == false && tc.wantErr == ErrDataMarkerMissing {
				t.Errorf("a refused verification created %s", proto.StorageDataMarkerFile)
			}
		})
	}
}

// The path a claimed data disk belongs at is derived from the purpose spec,
// never assembled by a caller — one spelling of <root>/<partUUID>.
func TestDataMountPath(t *testing.T) {
	got, err := DataMountPath("9d0f4a2b-01")
	if err != nil {
		t.Fatalf("DataMountPath: %v", err)
	}
	if got != "/var/lib/rasputin/data/9d0f4a2b-01" {
		t.Errorf("DataMountPath = %q", got)
	}
	// The same argument guard every other UUID-addressed verb has: a value
	// that is not a partition UUID names no path.
	if _, err := DataMountPath("../../etc"); err == nil {
		t.Error("DataMountPath accepted a traversal")
	}
}

func mustWriteDataMarker(t *testing.T, dir string, set *proto.StorageDataSet) {
	t.Helper()
	if err := writeMarker(dir, proto.StorageDataMarkerFile, set); err != nil {
		t.Fatalf("write marker: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The mock has to reach the same answers
// ---------------------------------------------------------------------------

// Two purposes, two roots, in the backend CI actually runs. The paths are the
// mock's own — nothing can mount under /run or /var/lib in a test — but a
// backup target and a data disk landing in the same directory is the mistake
// this catches.
func TestMock_ClaimMountsEachPurposeUnderItsOwnRoot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		purpose proto.StoragePurpose
		root    func(m *MockBackend) string
	}{
		{name: "backup", purpose: proto.StoragePurposeBackup, root: func(m *MockBackend) string { return m.MountRoot() }},
		{name: "an absent purpose is backup", purpose: "", root: func(m *MockBackend) string { return m.MountRoot() }},
		{name: "data", purpose: proto.StoragePurposeData, root: func(m *MockBackend) string { return m.DataMountRoot() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestMock(t, defaultMockMachine())
			if m.MountRoot() == m.DataMountRoot() {
				t.Fatal("both purposes share a mount root")
			}
			spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
			cmd := claimCmd(spare.DevicePath, spare.Fingerprint, "the disk")
			cmd.Purpose = tc.purpose
			ack, err := m.Claim(context.Background(), cmd)
			if err != nil {
				t.Fatalf("Claim: %v", err)
			}
			want := filepath.Join(tc.root(m), ack.PartUUID)
			if ack.MountPath != want {
				t.Errorf("mounted at %q, want %q", ack.MountPath, want)
			}
		})
	}
}

// The mock's startup sweep: same discovery, same verification, and it finds a
// disk claimed before the "reboot" rather than one it just formatted.
func TestMock_MountClaimedDataFindsADiskAfterARestart(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
	cmd := claimCmd(spare.DevicePath, spare.Fingerprint, "media library")
	cmd.Purpose = proto.StoragePurposeData
	ack, err := m.Claim(context.Background(), cmd)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	// The reboot: the mount table is empty and the mount point is gone, but
	// the disk and its marker are still there — which is the whole reason the
	// marker is the record and the mount is not.
	st, err := m.loadState()
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	st.Mounts = nil
	if err := m.saveState(st); err != nil {
		t.Fatalf("saveState: %v", err)
	}
	if err := os.RemoveAll(ack.MountPath); err != nil {
		t.Fatalf("clear the mount point: %v", err)
	}

	mounts, err := m.MountClaimedData(context.Background())
	if err != nil {
		t.Fatalf("MountClaimedData: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("swept %d disks, want 1: %+v", len(mounts), mounts)
	}
	if mounts[0].Err != nil {
		t.Fatalf("the claimed data disk was skipped: %v", mounts[0].Err)
	}
	if mounts[0].MountPath != filepath.Join(m.DataMountRoot(), ack.PartUUID) {
		t.Errorf("mounted at %q, want it under the data root %q", mounts[0].MountPath, m.DataMountRoot())
	}
	if _, err := VerifyDataMarker(mounts[0].MountPath, ack.PartUUID); err != nil {
		t.Errorf("the re-mounted disk does not verify: %v", err)
	}
}

// A backup target is not swept: the sweep is §6's, and mounting an archive
// disk at boot would put a removable disk's filesystem live for no reason.
func TestMock_MountClaimedDataIgnoresTheBackupTarget(t *testing.T) {
	ctx := context.Background()
	m := newTestMock(t, defaultMockMachine())
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
	if _, err := m.Claim(ctx, claimCmd(spare.DevicePath, spare.Fingerprint, "backup")); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	mounts, err := m.MountClaimedData(ctx)
	if err != nil {
		t.Fatalf("MountClaimedData: %v", err)
	}
	if len(mounts) != 0 {
		t.Errorf("the sweep touched a backup target: %+v", mounts)
	}

	// And it never asked about one. The ack the sweep works from carries no
	// backup set, because it enumerated for the data purpose alone — nothing
	// mounts anything in this backend, so the narrowing is invisible here, but
	// it is the same line that keeps the backup disk unmounted on hardware and
	// the two backends have to agree on it.
	swept, err := m.enumerate(ctx, dataOnlyScan)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	for _, c := range swept.Candidates {
		if c.HasBackupSet || c.BackupSet != nil {
			t.Errorf("the sweep's enumeration reported a backup set on %s", c.DevicePath)
		}
	}
	// The picker's enumeration is the one that still has to see it.
	full, err := m.Enumerate(ctx)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	var seen bool
	for _, c := range full.Candidates {
		if c.HasBackupSet && c.BackupSet != nil {
			seen = true
		}
	}
	if !seen {
		t.Error("the operator-facing enumeration lost the backup target")
	}
}

// TestReadMarkerFileRefusesAnOversizedMarkerWithoutReadingItAll pins the bound
// that gosec's G304 at this call site made me look at: enumeration reads
// markers off disks nobody has confirmed anything about, so an oversized marker
// has to be refused by NOT READING IT, not by measuring it afterwards. A
// length check after os.ReadFile is a memory-exhaustion lever on a Pi 4.
//
// The proxy for "did not read it all" is the error text: the old code could
// only report the true size, because it had the whole file. This one reports
// the cap, because it deliberately never learned the size.
func TestReadMarkerFileRefusesAnOversizedMarkerWithoutReadingItAll(t *testing.T) {
	dir := t.TempDir()
	name := ".rasputin-data-set.json"

	big := make([]byte, markerMaxBytes+4096)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(filepath.Join(dir, name), big, 0o600); err != nil {
		t.Fatal(err)
	}

	var set proto.StorageDataSet
	err := readMarkerFile(dir, name, &set)
	if err == nil {
		t.Fatal("an oversized marker was accepted; the bound is not doing anything")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("refusal should name the cap it enforced, got: %v", err)
	}
	if strings.Contains(err.Error(), strconv.Itoa(len(big))) {
		t.Fatalf("refusal quotes the file's true size (%d), which means the whole file was read: %v", len(big), err)
	}
}

// TestReadMarkerFileAcceptsAMarkerExactlyAtTheCap is the other half: the
// LimitReader takes markerMaxBytes+1 so that "exactly at the cap" and "one over"
// are distinguishable. Without the +1 a marker of exactly markerMaxBytes would
// be refused as though it were too big.
func TestReadMarkerFileAcceptsAMarkerExactlyAtTheCap(t *testing.T) {
	dir := t.TempDir()
	name := ".rasputin-data-set.json"

	set := proto.StorageDataSet{MarkerVersion: proto.StorageMarkerVersion, ClusterID: "c1"}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	// Pad the JSON with trailing spaces up to exactly the cap. Trailing
	// whitespace is still valid JSON, so this stays parseable at the boundary.
	pad := make([]byte, markerMaxBytes-len(body))
	for i := range pad {
		pad[i] = ' '
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(body, pad...), 0o600); err != nil {
		t.Fatal(err)
	}

	var got proto.StorageDataSet
	if err := readMarkerFile(dir, name, &got); err != nil {
		t.Fatalf("a marker of exactly markerMaxBytes was refused: %v", err)
	}
	if got.ClusterID != "c1" {
		t.Fatalf("marker at the cap parsed wrong: %+v", got)
	}
}
