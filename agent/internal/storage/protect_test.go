package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSys builds a sysfs tree on disk with real symlinks, so the production
// resolver runs unmodified — same EvalSymlinks, same "partition" file probe,
// same slaves walk. No root, no disks, and nothing that can depend on the
// machine the test runs on.
type fakeSys struct {
	t    *testing.T
	root string // the /sys equivalent
}

func newFakeSys(t *testing.T) *fakeSys {
	t.Helper()
	root := filepath.Join(t.TempDir(), "sys")
	for _, d := range []string{"dev/block", "class/block", "devices"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	return &fakeSys{t: t, root: root}
}

// link wires /sys/dev/block/<majMin> and /sys/class/block/<name> at a device
// directory given relative to /sys/devices.
func (f *fakeSys) link(name, majMin, rel string) {
	f.t.Helper()
	if err := os.Symlink(filepath.Join("../../devices", rel), filepath.Join(f.root, "dev/block", majMin)); err != nil {
		f.t.Fatalf("symlink dev/block/%s: %v", majMin, err)
	}
	if err := os.Symlink(filepath.Join("../../devices", rel), filepath.Join(f.root, "class/block", name)); err != nil {
		f.t.Fatalf("symlink class/block/%s: %v", name, err)
	}
}

func (f *fakeSys) addDisk(name, majMin string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(f.root, "devices", name), 0o755); err != nil {
		f.t.Fatalf("mkdir device %s: %v", name, err)
	}
	f.link(name, majMin, name)
}

func (f *fakeSys) addPartition(disk, name, majMin string) {
	f.t.Helper()
	dir := filepath.Join(f.root, "devices", disk, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatalf("mkdir partition %s: %v", name, err)
	}
	// The kernel writes the partition index here; only its presence matters.
	if err := os.WriteFile(filepath.Join(dir, "partition"), []byte("1\n"), 0o644); err != nil {
		f.t.Fatalf("write partition file: %v", err)
	}
	f.link(name, majMin, filepath.Join(disk, name))
}

// addStacked builds a dm/md device whose slaves are the named partitions,
// given as "disk/partition".
func (f *fakeSys) addStacked(name, majMin string, slaves []string) {
	f.t.Helper()
	dir := filepath.Join(f.root, "devices", name, "slaves")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatalf("mkdir stacked %s: %v", name, err)
	}
	for _, s := range slaves {
		if err := os.Symlink(filepath.Join("../..", s), filepath.Join(dir, filepath.Base(s))); err != nil {
			f.t.Fatalf("symlink slave %s: %v", s, err)
		}
	}
	f.link(name, majMin, name)
}

// mountinfoFile writes a /proc/self/mountinfo with the given (majMin, mountPoint,
// source) triples, in real kernel line shape including the variable optional
// fields and the "-" separator.
func mountinfoFile(t *testing.T, lines [][3]string) string {
	t.Helper()
	var b strings.Builder
	for i, l := range lines {
		fmt.Fprintf(&b, "%d 1 %s / %s rw,relatime shared:%d - ext4 %s rw\n",
			30+i, l[0], l[1], i+1, l[2])
	}
	path := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write mountinfo: %v", err)
	}
	return path
}

func testProtector(t *testing.T, sys *fakeSys, mountinfo string) *protector {
	t.Helper()
	p := newProtector()
	p.sysfsRoot = sys.root
	p.mountinfoPath = mountinfo
	return p
}

// The base case, and the one the whole feature turns on: a mounted PARTITION
// protects its PARENT DISK. Protecting only the partition would leave the disk
// itself claimable, and claiming a disk repartitions it.
func TestProtector_PartitionProtectsItsParentDisk(t *testing.T) {
	sys := newFakeSys(t)
	sys.addDisk("nvme0n1", "259:0")
	sys.addPartition("nvme0n1", "nvme0n1p1", "259:1")
	sys.addPartition("nvme0n1", "nvme0n1p3", "259:3")
	sys.addDisk("nvme1n1", "259:8")

	mi := mountinfoFile(t, [][3]string{
		{"259:1", "/boot", "/dev/nvme0n1p1"},
		{"259:3", "/", "/dev/nvme0n1p3"},
	})
	got, err := testProtector(t, sys, mi).resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := got["/dev/nvme0n1"]; !ok {
		t.Fatalf("the disk holding / and /boot is not protected: %+v", got)
	}
	if _, ok := got["/dev/nvme1n1"]; ok {
		t.Errorf("the second, unmounted NVMe was protected — it is the legitimate backup target: %+v", got)
	}
}

// §4.8's core hazard, stated as a test: two NVMes, and which one is called
// nvme0n1 is decided by probe order. The resolver is handed the SAME machine
// with the boot mount on the OTHER major:minor, and must follow the mount.
//
// A resolver that keyed on the name would pass one of these two and destroy a
// cluster on the other.
func TestProtector_FollowsTheMountNotTheName(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bootMajor string
		wantDisk  string
		wantFree  string
	}{
		{"boot on nvme0n1", "259:3", "/dev/nvme0n1", "/dev/nvme1n1"},
		{"boot on nvme1n1 after a renumber", "259:11", "/dev/nvme1n1", "/dev/nvme0n1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sys := newFakeSys(t)
			sys.addDisk("nvme0n1", "259:0")
			sys.addPartition("nvme0n1", "nvme0n1p3", "259:3")
			sys.addDisk("nvme1n1", "259:8")
			sys.addPartition("nvme1n1", "nvme1n1p3", "259:11")

			mi := mountinfoFile(t, [][3]string{{tc.bootMajor, "/", "/dev/whatever"}})
			got, err := testProtector(t, sys, mi).resolve()
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if _, ok := got[tc.wantDisk]; !ok {
				t.Errorf("%s should be protected, got %+v", tc.wantDisk, got)
			}
			if _, ok := got[tc.wantFree]; ok {
				t.Errorf("%s should be claimable, got %+v", tc.wantFree, got)
			}
		})
	}
}

// The persistent partition is protected as hard as the boot medium: losing
// /var/lib/rasputin loses the SQLite DB, the trust dir and the mesh CA key.
func TestProtector_PersistentPartitionOnItsOwnDisk(t *testing.T) {
	sys := newFakeSys(t)
	sys.addDisk("sda", "8:0")
	sys.addPartition("sda", "sda1", "8:1")
	sys.addDisk("sdb", "8:16")
	sys.addPartition("sdb", "sdb1", "8:17")

	mi := mountinfoFile(t, [][3]string{
		{"8:1", "/", "/dev/sda1"},
		{"8:17", DefaultPersistentDir, "/dev/sdb1"},
	})
	got, err := testProtector(t, sys, mi).resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want both disks protected, got %+v", got)
	}
	if !strings.Contains(got["/dev/sdb"].reason, "persistent") {
		t.Errorf("reason for the data disk should name the persistent partition, got %q", got["/dev/sdb"].reason)
	}
}

// No separate /var/lib/rasputin mount: the longest-prefix rule must fall back
// to whichever mount actually carries the directory, which on a single-partition
// box is "/". Without this the persistent data would be unprotected on exactly
// the layout a developer runs.
func TestProtector_PersistentDirWithoutItsOwnMount(t *testing.T) {
	sys := newFakeSys(t)
	sys.addDisk("sda", "8:0")
	sys.addPartition("sda", "sda1", "8:1")

	mi := mountinfoFile(t, [][3]string{{"8:1", "/", "/dev/sda1"}})
	got, err := testProtector(t, sys, mi).resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	pd, ok := got["/dev/sda"]
	if !ok {
		t.Fatalf("root disk not protected: %+v", got)
	}
	if !strings.Contains(pd.reason, "root filesystem") || !strings.Contains(pd.reason, "persistent") {
		t.Errorf("both reasons should be recorded for one disk, got %q", pd.reason)
	}
}

// LUKS / LVM / md: the mount's major:minor is the stacked device, and the disks
// that would actually be destroyed are underneath it. Every one of them is
// protected, or a persistent partition on a mirror leaves half the mirror
// offered as a backup target.
func TestProtector_StackedDeviceProtectsEveryUnderlyingDisk(t *testing.T) {
	sys := newFakeSys(t)
	sys.addDisk("sda", "8:0")
	sys.addPartition("sda", "sda2", "8:2")
	sys.addDisk("sdb", "8:16")
	sys.addPartition("sdb", "sdb2", "8:18")
	sys.addDisk("sdc", "8:32")
	sys.addStacked("dm-0", "253:0", []string{"sda/sda2", "sdb/sdb2"})

	mi := mountinfoFile(t, [][3]string{{"253:0", "/", "/dev/mapper/root"}})
	got, err := testProtector(t, sys, mi).resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, want := range []string{"/dev/sda", "/dev/sdb"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s carries the stacked root and must be protected: %+v", want, got)
		}
	}
	if _, ok := got["/dev/dm-0"]; ok {
		t.Error("dm-0 was recorded as a protected DISK — no candidate ever has that name, so it protects nothing")
	}
	if _, ok := got["/dev/sdc"]; ok {
		t.Error("sdc holds nothing and should be claimable")
	}
}

// An unresolvable mount is an ERROR, never an empty protected set. "I cannot
// tell which disk I boot from" and "nothing needs protecting" must never be the
// same answer, because the caller acts on the second by formatting.
func TestProtector_UnresolvableMountIsAnError(t *testing.T) {
	sys := newFakeSys(t)
	sys.addDisk("sda", "8:0")
	mi := mountinfoFile(t, [][3]string{{"99:99", "/", "/dev/nowhere"}})
	if got, err := testProtector(t, sys, mi).resolve(); err == nil {
		t.Fatalf("resolve succeeded with an unresolvable root mount: %+v", got)
	}
}

func TestProtector_EmptyMountinfoIsAnError(t *testing.T) {
	sys := newFakeSys(t)
	mi := mountinfoFile(t, nil)
	if got, err := testProtector(t, sys, mi).resolve(); err == nil {
		t.Fatalf("resolve succeeded on an empty mountinfo: %+v", got)
	}
}

func TestProtector_MissingMountinfoIsAnError(t *testing.T) {
	sys := newFakeSys(t)
	p := testProtector(t, sys, filepath.Join(t.TempDir(), "absent"))
	if got, err := p.resolve(); err == nil {
		t.Fatalf("resolve succeeded with no mountinfo at all: %+v", got)
	}
}

// A whole disk mounted directly (no partition table) still protects itself.
func TestProtector_WholeDiskMountedDirectly(t *testing.T) {
	sys := newFakeSys(t)
	sys.addDisk("sda", "8:0")
	mi := mountinfoFile(t, [][3]string{{"8:0", "/", "/dev/sda"}})
	got, err := testProtector(t, sys, mi).resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := got["/dev/sda"]; !ok {
		t.Fatalf("want /dev/sda protected, got %+v", got)
	}
}

func TestCarryingMount_LongestPrefixWins(t *testing.T) {
	entries := []mountEntry{
		{mountPoint: "/", source: "root"},
		{mountPoint: "/var", source: "var"},
		{mountPoint: "/var/lib/rasputin", source: "data"},
	}
	cases := map[string]string{
		"/var/lib/rasputin":             "data",
		"/var/lib/rasputin/agent-state": "data",
		"/var/log":                      "var",
		"/boot":                         "root",
		"/":                             "root",
	}
	for path, want := range cases {
		got, ok := carryingMount(entries, path)
		if !ok {
			t.Fatalf("%s: no carrying mount", path)
		}
		if got.source != want {
			t.Errorf("%s: carried by %q, want %q", path, got.source, want)
		}
	}
}

// "/varsomething" must not match the "/var" mount. Prefix matching on raw
// strings would say it does, and would then protect the wrong disk — or, worse,
// fail to protect the right one.
func TestCarryingMount_DoesNotMatchASiblingPrefix(t *testing.T) {
	entries := []mountEntry{
		{mountPoint: "/", source: "root"},
		{mountPoint: "/var", source: "var"},
	}
	got, ok := carryingMount(entries, "/varsomething")
	if !ok || got.source != "root" {
		t.Errorf("/varsomething carried by %q (ok=%v), want root", got.source, ok)
	}
}

func TestUnescapeOctal(t *testing.T) {
	cases := map[string]string{
		`/mnt/my\040disk`: "/mnt/my disk",
		`/plain/path`:     "/plain/path",
		`/a\011b`:         "/a\tb",
		`/trailing\`:      `/trailing\`,
		`/not\09x`:        `/not\09x`,
	}
	for in, want := range cases {
		if got := unescapeOctal(in); got != want {
			t.Errorf("unescapeOctal(%q) = %q, want %q", in, got, want)
		}
	}
}

// A mount point containing a space arrives octal-escaped. If it were not
// unescaped the path would not match and the disk under it would go
// unprotected.
func TestProtector_OctalEscapedMountPoint(t *testing.T) {
	sys := newFakeSys(t)
	sys.addDisk("sda", "8:0")
	sys.addPartition("sda", "sda1", "8:1")
	path := filepath.Join(t.TempDir(), "mountinfo")
	body := "30 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		`31 1 8:1 / /mnt/my\040disk rw,relatime shared:2 - ext4 /dev/sda1 rw` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write mountinfo: %v", err)
	}
	p := testProtector(t, sys, path)
	entries, err := p.readMountinfo()
	if err != nil {
		t.Fatalf("readMountinfo: %v", err)
	}
	if len(entries) != 2 || entries[1].mountPoint != "/mnt/my disk" {
		t.Fatalf("mount point not unescaped: %+v", entries)
	}
}
