package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The real backend's whole shell-out surface goes through one seam, so these
// tests answer the question that matters about a destructive code path:
// WHICH COMMANDS DID IT RUN? A refusal that returns the right error while
// having already run mkfs is not a refusal, and no amount of asserting on error
// values would notice.

type fakeCall struct {
	name  string
	args  []string
	stdin string
}

// fakeShell records every command and answers the read-only ones from canned
// output. Anything destructive succeeds silently — the point is that the test
// can then assert it was never reached.
type fakeShell struct {
	calls []fakeCall
	// lsblkJSON answers lsblk until sfdisk runs, afterJSON answers it after.
	// Two states because a claim re-reads the disk to find the partition it
	// just created.
	lsblkJSON string
	afterJSON string
	formatted bool
	partUUID  string
	// failCmd, when set, makes that command fail.
	failCmd string
}

func (f *fakeShell) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	base := filepath.Base(name)
	f.calls = append(f.calls, fakeCall{name: base, args: args, stdin: string(stdin)})
	if f.failCmd != "" && base == f.failCmd {
		return nil, errors.New("simulated failure of " + base)
	}
	switch base {
	case "lsblk":
		if f.formatted && f.afterJSON != "" {
			return []byte(f.afterJSON), nil
		}
		return []byte(f.lsblkJSON), nil
	case "sfdisk":
		f.formatted = true
		return nil, nil
	case "blkid":
		return []byte(f.partUUID + "\n"), nil
	default:
		return nil, nil
	}
}

func (f *fakeShell) ran(cmd string) bool {
	for _, c := range f.calls {
		if c.name == cmd {
			return true
		}
	}
	return false
}

func (f *fakeShell) names() []string {
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.name)
	}
	return out
}

// assertNothingWasWritten is the assertion these tests exist for.
func (f *fakeShell) assertNothingWasWritten(t *testing.T) {
	t.Helper()
	for _, destructive := range []string{"wipefs", "sfdisk", "mkfs.ext4"} {
		if f.ran(destructive) {
			t.Fatalf("a REFUSED claim ran %s — commands were %v", destructive, f.names())
		}
	}
}

// A two-NVMe controlplane: nvme0n1 carries /boot, / and /var/lib/rasputin;
// nvme1n1 is blank; a loop device and a USB stick are also attached. Shaped
// after real `lsblk --json --bytes` output, nulls included.
const twoNVMeLsblk = `{
   "blockdevices": [
      {"name":"loop0","kname":"loop0","path":"/dev/loop0","type":"loop","size":"67108864","model":null,"serial":null,"wwn":null,"tran":null,"rm":false,"fstype":"squashfs","label":null,"partuuid":null,"mountpoint":"/snap/x"},
      {"name":"nvme0n1","kname":"nvme0n1","path":"/dev/nvme0n1","type":"disk","size":500107862016,"model":"CT500P3SSD8","serial":"SN-BOOT-0001","wwn":"eui.0001","tran":"nvme","rm":false,"fstype":null,"label":null,"partuuid":null,"mountpoint":null,
        "children":[
          {"name":"nvme0n1p1","kname":"nvme0n1p1","path":"/dev/nvme0n1p1","type":"part","size":536870912,"fstype":"vfat","label":"ESP","partuuid":"aaaa-1","mountpoint":"/boot"},
          {"name":"nvme0n1p2","kname":"nvme0n1p2","path":"/dev/nvme0n1p2","type":"part","size":4294967296,"fstype":"squashfs","label":"rootfs-0","partuuid":"aaaa-2","mountpoint":"/"},
          {"name":"nvme0n1p3","kname":"nvme0n1p3","path":"/dev/nvme0n1p3","type":"part","size":429496729600,"fstype":"ext4","label":"persistent","partuuid":"aaaa-3","mountpoint":"/var/lib/rasputin"}
        ]},
      {"name":"nvme1n1","kname":"nvme1n1","path":"/dev/nvme1n1","type":"disk","size":2000398934016,"model":"CT2000P3SSD8","serial":"SN-SPARE-0002","wwn":"eui.0002","tran":"nvme","rm":false,"fstype":null,"label":null,"partuuid":null,"mountpoint":null},
      {"name":"sda","kname":"sda","path":"/dev/sda","type":"disk","size":"64023257088","model":"SanDisk Ultra","serial":"USB-0003","wwn":null,"tran":"usb","rm":"1","fstype":null,"label":null,"partuuid":null,"mountpoint":null,
        "children":[
          {"name":"sda1","kname":"sda1","path":"/dev/sda1","type":"part","size":"64023257088","fstype":"exfat","label":"MYSTUFF","partuuid":"cccc-1","mountpoint":null}
        ]}
   ]
}`

// The same machine after nvme1n1 has been claimed.
const claimedLsblk = `{
   "blockdevices": [
      {"name":"nvme1n1","kname":"nvme1n1","path":"/dev/nvme1n1","type":"disk","size":2000398934016,"model":"CT2000P3SSD8","serial":"SN-SPARE-0002","wwn":"eui.0002","tran":"nvme","rm":false,
        "children":[
          {"name":"nvme1n1p1","kname":"nvme1n1p1","path":"/dev/nvme1n1p1","type":"part","size":2000397885440,"fstype":"ext4","label":"RASPUTIN-BACKUP","partuuid":"9d0f4a2b-01","mountpoint":null}
        ]}
   ]
}`

// newTestBlockDev wires the backend to a fake shell and a fabricated
// /proc + /sys describing the same two-NVMe machine.
func newTestBlockDev(t *testing.T, sh *fakeShell) *BlockDevBackend {
	t.Helper()
	sys := newFakeSys(t)
	sys.addDisk("nvme0n1", "259:0")
	sys.addPartition("nvme0n1", "nvme0n1p1", "259:1")
	sys.addPartition("nvme0n1", "nvme0n1p2", "259:2")
	sys.addPartition("nvme0n1", "nvme0n1p3", "259:3")
	sys.addDisk("nvme1n1", "259:8")
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
	b.mountRoot = filepath.Join(t.TempDir(), "mounts")
	if err := os.MkdirAll(b.mountRoot, 0o700); err != nil {
		t.Fatalf("mkdir mount root: %v", err)
	}
	return b
}

func bdCandidate(t *testing.T, ack *proto.StorageEnumerateAck, path string) proto.StorageCandidate {
	t.Helper()
	for _, c := range ack.Candidates {
		if c.DevicePath == path {
			return c
		}
	}
	t.Fatalf("no candidate %s in %+v", path, ack.Candidates)
	return proto.StorageCandidate{}
}

func TestBlockDev_EnumerateParsesAndProtects(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk}
	b := newTestBlockDev(t, sh)

	ack, err := b.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if ack.Backend != "blockdev" {
		t.Errorf("backend = %q", ack.Backend)
	}
	if len(ack.Candidates) != 3 {
		t.Fatalf("candidates = %d (%v), want 3 — the loop device is not a candidate",
			len(ack.Candidates), ack.Candidates)
	}
	boot := bdCandidate(t, ack, "/dev/nvme0n1")
	if !boot.Protected {
		t.Fatal("the disk holding /, /boot and /var/lib/rasputin is not protected")
	}
	if !strings.Contains(boot.ProtectedReason, "persistent") || !strings.Contains(boot.ProtectedReason, "boot") {
		t.Errorf("reason should name every protecting mount, got %q", boot.ProtectedReason)
	}
	if len(boot.Partitions) != 3 {
		t.Errorf("partitions = %d, want 3 — the confirmation dialog shows current contents", len(boot.Partitions))
	}

	spare := bdCandidate(t, ack, "/dev/nvme1n1")
	if spare.Protected {
		t.Error("the blank NVMe is protected — it is the legitimate backup target")
	}
	if spare.Fingerprint == "" || spare.Fingerprint == boot.Fingerprint {
		t.Errorf("fingerprints are missing or collide: spare=%q boot=%q", spare.Fingerprint, boot.Fingerprint)
	}

	// The USB stick has no WWN and its serial is present, so identity is not
	// weak; sizes and the "1"/"0" rm spelling decode either way.
	usb := bdCandidate(t, ack, "/dev/sda")
	if !usb.Removable {
		t.Error(`rm:"1" did not decode as removable`)
	}
	if usb.SizeBytes != 64023257088 {
		t.Errorf("string-encoded size did not decode: %d", usb.SizeBytes)
	}
	if usb.Transport != proto.StorageTransportUSB {
		t.Errorf("transport = %q", usb.Transport)
	}
}

// Enumeration must fail outright rather than list candidates it cannot mark.
// An unmarked boot disk in a picker with a destructive confirm button next to
// it is the failure mode; "no disks" is merely an inconvenience.
func TestBlockDev_EnumerateFailsWhenProtectionCannotBeResolved(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk}
	b := newTestBlockDev(t, sh)
	b.prot.mountinfoPath = filepath.Join(t.TempDir(), "gone")

	if ack, err := b.Enumerate(context.Background()); err == nil {
		t.Fatalf("Enumerate succeeded with no mount table: %+v", ack)
	}
	if sh.ran("lsblk") {
		t.Error("lsblk ran before the protected set resolved — protection is the first question, not the second")
	}
}

func TestBlockDev_ClaimRefusesTheBootDiskAndWritesNothing(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk}
	b := newTestBlockDev(t, sh)
	boot := bdCandidate(t, mustEnumerate(t, b), "/dev/nvme0n1")
	sh.calls = nil

	_, err := b.Claim(context.Background(), claimCmd("/dev/nvme0n1", boot.Fingerprint, "backup"))
	if !errors.Is(err, ErrProtected) {
		t.Fatalf("want ErrProtected, got %v", err)
	}
	sh.assertNothingWasWritten(t)
	// The refusal comes from the live mount walk, so it does not even need to
	// have asked lsblk anything.
	if sh.ran("lsblk") {
		t.Errorf("the protected check should short-circuit before lsblk; ran %v", sh.names())
	}
}

func TestBlockDev_ClaimRefusesADriftedFingerprintAndWritesNothing(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk}
	b := newTestBlockDev(t, sh)
	sh.calls = nil

	_, err := b.Claim(context.Background(), claimCmd("/dev/nvme1n1", "a-fingerprint-from-another-disk", "backup"))
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("want ErrFingerprintMismatch, got %v", err)
	}
	sh.assertNothingWasWritten(t)
}

func TestBlockDev_ClaimRefusesAnEmptyFingerprintBeforeRunningAnything(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk}
	b := newTestBlockDev(t, sh)

	_, err := b.Claim(context.Background(), claimCmd("/dev/nvme1n1", "", "backup"))
	if !errors.Is(err, ErrNoFingerprint) {
		t.Fatalf("want ErrNoFingerprint, got %v", err)
	}
	if len(sh.calls) != 0 {
		t.Errorf("an unfingerprinted claim ran %v", sh.names())
	}
}

// If the protected set cannot be resolved, the claim refuses. It never falls
// back to "assume nothing is protected", which is the shape of every disaster
// this package is written against.
func TestBlockDev_ClaimRefusesWhenProtectionCannotBeResolved(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk}
	b := newTestBlockDev(t, sh)
	spare := bdCandidate(t, mustEnumerate(t, b), "/dev/nvme1n1")
	b.prot.mountinfoPath = filepath.Join(t.TempDir(), "gone")
	sh.calls = nil

	if _, err := b.Claim(context.Background(), claimCmd("/dev/nvme1n1", spare.Fingerprint, "backup")); err == nil {
		t.Fatal("claim proceeded without being able to identify the boot disk")
	}
	sh.assertNothingWasWritten(t)
}

// A device path that is not a device path is refused before it can be handed to
// anything as an argument. "-rf" or a path with ".." reaching out of /dev are
// the shapes that matter.
func TestBlockDev_ClaimRefusesUnDevicePaths(t *testing.T) {
	for _, bad := range []string{"", "-rf", "/etc/passwd", "/dev/../etc/passwd", "nvme1n1", "/dev/nvme1n1;reboot"} {
		t.Run(bad, func(t *testing.T) {
			sh := &fakeShell{lsblkJSON: twoNVMeLsblk}
			b := newTestBlockDev(t, sh)
			if _, err := b.Claim(context.Background(), claimCmd(bad, "fp", "backup")); err == nil {
				t.Fatalf("claim accepted %q", bad)
			}
			if len(sh.calls) != 0 {
				t.Errorf("ran %v for %q", sh.names(), bad)
			}
		})
	}
}

func TestBlockDev_MountRefusesUnUUIDs(t *testing.T) {
	for _, bad := range []string{"", "-o", "../../etc", "a b"} {
		sh := &fakeShell{lsblkJSON: twoNVMeLsblk}
		b := newTestBlockDev(t, sh)
		if _, err := b.Mount(context.Background(), bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("Mount(%q) = %v, want ErrNotFound", bad, err)
		}
	}
}

// The claim's command sequence, in order, and the sfdisk script it feeds in.
func TestBlockDev_ClaimFormatsInTheRightOrder(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk, afterJSON: claimedLsblk, partUUID: "9d0f4a2b-01"}
	b := newTestBlockDev(t, sh)
	spare := bdCandidate(t, mustEnumerate(t, b), "/dev/nvme1n1")
	sh.calls = nil

	ack, err := b.Claim(context.Background(), claimCmd("/dev/nvme1n1", spare.Fingerprint, "weekly archive"))
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	wantOrder := []string{"wipefs", "sfdisk", "mkfs.ext4", "blkid", "mount"}
	if !isSubsequence(sh.names(), wantOrder) {
		t.Fatalf("commands %v do not contain %v in order", sh.names(), wantOrder)
	}
	var sfdisk fakeCall
	for _, c := range sh.calls {
		if c.name == "sfdisk" {
			sfdisk = c
		}
	}
	if !strings.Contains(sfdisk.stdin, "label: gpt") {
		t.Errorf("sfdisk script does not create a GPT: %q", sfdisk.stdin)
	}
	var mkfs fakeCall
	for _, c := range sh.calls {
		if c.name == "mkfs.ext4" {
			mkfs = c
		}
	}
	if !containsArg(mkfs.args, proto.StorageBackupLabel) {
		t.Errorf("mkfs did not apply the %s label: %v", proto.StorageBackupLabel, mkfs.args)
	}
	if !containsArg(mkfs.args, "/dev/nvme1n1p1") {
		t.Errorf("mkfs was pointed at %v, not the partition sfdisk created", mkfs.args)
	}

	if ack.PartUUID != "9d0f4a2b-01" {
		t.Errorf("partUUID = %q, want the one blkid reported", ack.PartUUID)
	}
	if ack.MountPath != filepath.Join(b.mountRoot, "9d0f4a2b-01") {
		t.Errorf("mount path = %q", ack.MountPath)
	}
	if ack.Fingerprint == spare.Fingerprint {
		t.Error("the post-format fingerprint equals the pre-format one — a replayed claim would reformat")
	}

	// The marker landed, and it is what makes the disk self-describing after an
	// orphaned claim.
	set, err := readMarker(ack.MountPath)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if set.PartUUID != ack.PartUUID || set.MarkerVersion != proto.StorageMarkerVersion {
		t.Errorf("marker = %+v", set)
	}
	if set.Label != "weekly archive" {
		t.Errorf("marker label = %q", set.Label)
	}
}

// A partition of the target mounted somewhere we did not put it means the disk
// is in use by something else. Refuse, and say so, rather than letting mkfs
// report "device or resource busy" three commands later.
func TestBlockDev_ClaimRefusesADiskMountedElsewhere(t *testing.T) {
	inUse := strings.Replace(twoNVMeLsblk,
		`{"name":"nvme1n1","kname":"nvme1n1","path":"/dev/nvme1n1","type":"disk","size":2000398934016,"model":"CT2000P3SSD8","serial":"SN-SPARE-0002","wwn":"eui.0002","tran":"nvme","rm":false,"fstype":null,"label":null,"partuuid":null,"mountpoint":null}`,
		`{"name":"nvme1n1","kname":"nvme1n1","path":"/dev/nvme1n1","type":"disk","size":2000398934016,"model":"CT2000P3SSD8","serial":"SN-SPARE-0002","wwn":"eui.0002","tran":"nvme","rm":false,
          "children":[{"name":"nvme1n1p1","kname":"nvme1n1p1","path":"/dev/nvme1n1p1","type":"part","size":2000397885440,"fstype":"ext4","label":"media","partuuid":"bbbb-1","mountpoint":"/srv/media"}]}`,
		1)
	if inUse == twoNVMeLsblk {
		t.Fatal("test fixture did not substitute")
	}
	sh := &fakeShell{lsblkJSON: inUse}
	b := newTestBlockDev(t, sh)
	spare := bdCandidate(t, mustEnumerate(t, b), "/dev/nvme1n1")
	sh.calls = nil

	_, err := b.Claim(context.Background(), claimCmd("/dev/nvme1n1", spare.Fingerprint, "backup"))
	if err == nil {
		t.Fatal("claimed a disk with a live mount on it")
	}
	if !strings.Contains(err.Error(), "/srv/media") {
		t.Errorf("the refusal should name the mount that blocked it: %v", err)
	}
	sh.assertNothingWasWritten(t)
}

func TestBlockDev_InspectAnAbsentTargetIsAnAnswer(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk}
	b := newTestBlockDev(t, sh)
	ack, err := b.Inspect(context.Background(), "not-attached")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !ack.OK || ack.Present {
		t.Errorf("want OK and not present, got %+v", ack)
	}
}

// lsblk must never be handed a path that could parse as an option.
func TestBlockDev_LsblkSeparatesOptionsFromOperands(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk}
	b := newTestBlockDev(t, sh)
	if _, err := b.lsblk(context.Background(), "/dev/nvme1n1"); err != nil {
		t.Fatalf("lsblk: %v", err)
	}
	last := sh.calls[len(sh.calls)-1]
	if !containsArg(last.args, "--") {
		t.Errorf("lsblk args %v have no -- separator", last.args)
	}
	if last.args[len(last.args)-1] != "/dev/nvme1n1" {
		t.Errorf("the device is not the final operand: %v", last.args)
	}
}

func TestBlockDev_NameIsBlockdev(t *testing.T) {
	b := newTestBlockDev(t, &fakeShell{lsblkJSON: twoNVMeLsblk})
	if b.Name() != "blockdev" {
		t.Errorf("Name() = %q", b.Name())
	}
}

// ---------------------------------------------------------------------------
// lsblk decoding
// ---------------------------------------------------------------------------

func TestParseLsblk_ToleratesScalarSpellings(t *testing.T) {
	body := `{"blockdevices":[
	  {"name":"sda","type":"disk","size":"1024","rm":"1"},
	  {"name":"sdb","type":"disk","size":2048,"rm":true},
	  {"name":"sdc","type":"disk","size":null,"rm":null}
	]}`
	out, err := parseLsblk([]byte(body))
	if err != nil {
		t.Fatalf("parseLsblk: %v", err)
	}
	if out.BlockDevices[0].Size != 1024 || !bool(out.BlockDevices[0].RM) {
		t.Errorf("string spellings: %+v", out.BlockDevices[0])
	}
	if out.BlockDevices[1].Size != 2048 || !bool(out.BlockDevices[1].RM) {
		t.Errorf("native spellings: %+v", out.BlockDevices[1])
	}
	if out.BlockDevices[2].Size != 0 || bool(out.BlockDevices[2].RM) {
		t.Errorf("nulls: %+v", out.BlockDevices[2])
	}
}

func TestParseLsblk_RejectsGarbage(t *testing.T) {
	if _, err := parseLsblk([]byte("not json")); err == nil {
		t.Error("parseLsblk accepted non-JSON")
	}
}

func TestIsCandidateDisk(t *testing.T) {
	cases := []struct {
		dev  lsblkDevice
		want bool
	}{
		{lsblkDevice{Name: "nvme1n1", KName: "nvme1n1", Type: "disk", Size: 1 << 40}, true},
		{lsblkDevice{Name: "sda", KName: "sda", Type: "disk", Size: 1 << 30}, true},
		{lsblkDevice{Name: "sda1", KName: "sda1", Type: "part", Size: 1 << 30}, false},
		{lsblkDevice{Name: "loop0", KName: "loop0", Type: "disk", Size: 1 << 20}, false},
		{lsblkDevice{Name: "dm-0", KName: "dm-0", Type: "disk", Size: 1 << 30}, false},
		{lsblkDevice{Name: "md0", KName: "md0", Type: "disk", Size: 1 << 30}, false},
		{lsblkDevice{Name: "sr0", KName: "sr0", Type: "rom", Size: 1 << 30}, false},
		{lsblkDevice{Name: "mmcblk0", KName: "mmcblk0", Type: "disk", Size: 0}, false},
	}
	for _, tc := range cases {
		if got := isCandidateDisk(tc.dev); got != tc.want {
			t.Errorf("isCandidateDisk(%s/%s) = %v, want %v", tc.dev.Type, tc.dev.Name, got, tc.want)
		}
	}
}

func TestTransportOf(t *testing.T) {
	cases := map[string]string{
		"usb": "usb", "nvme": "nvme", "sata": "sata", "ata": "sata",
		"mmc": "mmc", "virtio": "virtual", "": "unknown", "weird": "unknown",
	}
	for in, want := range cases {
		if got := transportOf(in); got != want {
			t.Errorf("transportOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustEnumerate(t *testing.T, b *BlockDevBackend) *proto.StorageEnumerateAck {
	t.Helper()
	ack, err := b.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	return ack
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// isSubsequence reports whether want appears in got in order (other commands
// may be interleaved).
func isSubsequence(got, want []string) bool {
	i := 0
	for _, g := range got {
		if i < len(want) && g == want[i] {
			i++
		}
	}
	return i == len(want)
}
