package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// The protected set: the disks that must never be formatted, resolved by
// walking BACK from the live mounts to their parent block device.
//
// ⚠️ THE ONE RULE: never key on a device name. `nvme0n1` and `nvme1n1` are
// assigned in probe order, which is not stable across boots, and a controlplane
// with two identical NVMes in a Geekworm x1004 offers no transport, bus or size
// difference to fall back on. A protection rule that says "skip nvme0n1" is a
// coin flip that force-formats the cluster half the time.
//
// What IS stable, for the lifetime of a boot, is the major:minor the kernel
// reports for a mounted filesystem in /proc/self/mountinfo, and the sysfs
// topology that says which whole disk that device belongs to. So: read the live
// mounts, take their major:minor, walk sysfs up to the whole disk. The answer is
// a fact about what is mounted right now, which is the question §4.8 actually
// asks — and it is re-asked immediately before the format rather than reused
// from the enumerate the operator was looking at.

// defaultCriticalMounts are the mount points whose backing disk is protected on
// top of the persistent data directory.
//
// "/" is here because on the appliance it is the read-only squashfs rootfs and
// on a dev box it is everything. The boot mounts differ per platform — GRUB's
// ESP on the n100, /boot/firmware on a Pi — so all the plausible spellings are
// listed and the ones that do not exist are simply absent from mountinfo.
var defaultCriticalMounts = []string{
	"/",
	"/boot",
	"/boot/efi",
	"/boot/firmware",
	"/efi",
}

// DefaultPersistentDir is the appliance's writable partition — the one holding
// the SQLite DB, the trust dir, Docker and the obs stores. Losing it loses the
// cluster's identity, so it is protected exactly as hard as the boot medium.
const DefaultPersistentDir = "/var/lib/rasputin"

// protector resolves the protected set. Every path it reads is a field so the
// whole thing is testable against a fabricated sysfs tree — no root, no real
// disks, and no ability for a test to accidentally depend on the machine it
// runs on.
type protector struct {
	mountinfoPath string // /proc/self/mountinfo
	sysfsRoot     string // /sys
	persistentDir string // /var/lib/rasputin
	// criticalMounts is defaultCriticalMounts unless a test overrides it.
	criticalMounts []string
}

func newProtector() *protector {
	return &protector{
		mountinfoPath:  "/proc/self/mountinfo",
		sysfsRoot:      "/sys",
		persistentDir:  DefaultPersistentDir,
		criticalMounts: defaultCriticalMounts,
	}
}

// mountEntry is one line of /proc/self/mountinfo, reduced to what matters here.
type mountEntry struct {
	majMin     string // "259:2"
	mountPoint string // "/var/lib/rasputin"
	source     string // "/dev/nvme0n1p3" — informational only, never authoritative
	fsType     string
}

// protectedDisk is one entry in the protected set.
type protectedDisk struct {
	// devicePath is the whole disk, e.g. "/dev/nvme0n1".
	devicePath string
	// reason is operator-facing prose naming the mount that protects it.
	reason string
}

// resolve returns the protected set keyed by whole-disk device path.
//
// An error here is NOT "assume nothing is protected". Callers must treat it as
// a refusal: if the agent cannot say which disk it is running from, it has no
// business formatting any of them.
func (p *protector) resolve() (map[string]protectedDisk, error) {
	entries, err := p.readMountinfo()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p.mountinfoPath, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s listed no mounts", p.mountinfoPath)
	}

	wanted := append([]string{}, p.criticalMounts...)
	if p.persistentDir != "" {
		wanted = append(wanted, p.persistentDir)
	}

	out := map[string]protectedDisk{}
	for _, path := range wanted {
		ent, ok := carryingMount(entries, path)
		if !ok {
			// No mount carries this path — e.g. a platform with no separate
			// /boot. Nothing to protect from it. "/" always matches, so an
			// empty result overall is impossible on a real system and is
			// caught below.
			continue
		}
		disks, err := p.wholeDisksFor(ent.majMin)
		if err != nil {
			return nil, fmt.Errorf("resolve the disk behind %s (%s): %w", path, ent.majMin, err)
		}
		for _, d := range disks {
			reason := describeProtection(path, ent, p.persistentDir)
			if prev, seen := out[d]; seen {
				// One disk can hold several protected mounts. Keep both
				// reasons — "it is the boot disk AND holds /var/lib/rasputin"
				// is more informative than either alone.
				if !strings.Contains(prev.reason, reason) {
					prev.reason += "; " + reason
					out[d] = prev
				}
				continue
			}
			out[d] = protectedDisk{devicePath: d, reason: reason}
		}
	}

	if len(out) == 0 {
		// Every real Linux system has a "/" whose backing device resolves. An
		// empty set means the resolution machinery did not work, not that the
		// machine has nothing to protect, and treating it as "nothing to
		// protect" is how you format the boot disk.
		return nil, fmt.Errorf("resolved no protected disks from %s — refusing to treat that as 'nothing is protected'", p.mountinfoPath)
	}
	return out, nil
}

// describeProtection renders the operator-facing reason.
func describeProtection(path string, ent mountEntry, persistentDir string) string {
	switch {
	case path == persistentDir:
		return fmt.Sprintf("holds the mounted persistent partition (%s)", ent.mountPoint)
	case path == "/":
		return fmt.Sprintf("holds the mounted root filesystem (%s)", ent.mountPoint)
	default:
		return fmt.Sprintf("holds the mounted boot partition (%s)", ent.mountPoint)
	}
}

// carryingMount returns the mount entry that actually carries path — the entry
// whose mount point is the longest prefix of it.
//
// The longest-prefix rule is what makes this work on both layouts without a
// per-platform table: /var/lib/rasputin on its own partition matches its own
// entry, and /var/lib/rasputin on a box with no separate data partition matches
// "/" and protects the root disk, which is the correct answer in both cases.
func carryingMount(entries []mountEntry, path string) (mountEntry, bool) {
	path = filepath.Clean(path)
	best := mountEntry{}
	bestLen := -1
	for _, e := range entries {
		mp := filepath.Clean(e.mountPoint)
		if mp != "/" && !strings.HasPrefix(path, mp+"/") && path != mp {
			continue
		}
		if len(mp) > bestLen {
			best, bestLen = e, len(mp)
		}
	}
	return best, bestLen >= 0
}

// readMountinfo parses /proc/self/mountinfo.
//
// mountinfo rather than /proc/mounts because only mountinfo carries the
// major:minor, and major:minor is the only field in either file that is a
// kernel fact rather than a string the mounter chose. The source column ("/dev/…")
// is recorded for logging and is never used to decide anything: it is whatever
// path was passed to mount(8), which on a bind mount or a stale /dev entry can
// name a device that is not the one carrying the filesystem.
//
// Line shape (Documentation/filesystems/proc.rst):
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime shared:1 - ext3 /dev/root rw,errors=continue
//	|  |  |    |     |     |          |          | |    |         |
//	0  1  2    3     4     5          6..n       - fs   source    superopts
//
// Fields 6..n are optional and variable in number, terminated by a lone "-".
func (p *protector) readMountinfo() ([]mountEntry, error) {
	b, err := os.ReadFile(p.mountinfoPath)
	if err != nil {
		return nil, err
	}
	var out []mountEntry
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(f) {
			continue
		}
		out = append(out, mountEntry{
			majMin:     f[2],
			mountPoint: unescapeOctal(f[4]),
			fsType:     f[sep+1],
			source:     unescapeOctal(f[sep+2]),
		})
	}
	return out, nil
}

// unescapeOctal undoes the \OOO escaping the kernel applies to space, tab,
// newline and backslash in mountinfo paths. Without it a mount point under a
// directory with a space in its name would silently fail to match.
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 4
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// maxSlaveDepth bounds the stacked-device walk. Three layers is already more
// than anything Rasputin ships (dm-crypt over LVM over md); the bound is set
// well above that and exists so a cyclic or pathological sysfs tree cannot hang
// the agent inside the very code path that gates a destructive operation.
const maxSlaveDepth = 8

// wholeDisksFor maps a mounted filesystem's major:minor onto the whole disk (or
// disks) that ultimately carry it.
//
// Three cases, and the third is the one that matters:
//
//   - a partition (…/nvme0n1/nvme0n1p3, has a "partition" file) → its parent
//     directory is the disk.
//   - a whole disk (…/sda) → itself.
//   - a STACKED device (dm-0, md0) → its "slaves" directory names the devices
//     underneath, and each of those is resolved the same way. An md RAID1 of two
//     disks protects BOTH; an LVM volume protects every PV it sits on. Without
//     this, a persistent partition on LUKS or LVM would resolve to "dm-0",
//     match no candidate, and the disk actually holding it would be offered for
//     formatting.
func (p *protector) wholeDisksFor(majMin string) ([]string, error) {
	set := map[string]bool{}
	start := filepath.Join(p.sysfsRoot, "dev", "block", majMin)
	dir, err := filepath.EvalSymlinks(start)
	if err != nil {
		return nil, fmt.Errorf("no sysfs entry for %s: %w", majMin, err)
	}
	if err := p.collectDisks(dir, set, 0); err != nil {
		return nil, err
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("no whole disk found behind %s", majMin)
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// collectDisks walks one sysfs block directory down to whole disks.
func (p *protector) collectDisks(dir string, set map[string]bool, depth int) error {
	if depth > maxSlaveDepth {
		return fmt.Errorf("sysfs slave chain deeper than %d below %s", maxSlaveDepth, dir)
	}
	// Stacked device? Follow every slave. Checked FIRST: a dm/md device can
	// also look like a whole disk, and answering "dm-0" would protect a name no
	// candidate ever has.
	if slaves, err := os.ReadDir(filepath.Join(dir, "slaves")); err == nil && len(slaves) > 0 {
		for _, s := range slaves {
			child, err := filepath.EvalSymlinks(filepath.Join(p.sysfsRoot, "class", "block", s.Name()))
			if err != nil {
				// Fall back to the sysfs-relative link inside slaves/ before
				// giving up — /sys/class/block is absent in some minimal
				// containers.
				child, err = filepath.EvalSymlinks(filepath.Join(dir, "slaves", s.Name()))
				if err != nil {
					return fmt.Errorf("resolve slave %s of %s: %w", s.Name(), filepath.Base(dir), err)
				}
			}
			if err := p.collectDisks(child, set, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	// A partition carries a "partition" file holding its index; its parent
	// directory is the whole disk.
	if _, err := os.Stat(filepath.Join(dir, "partition")); err == nil {
		set["/dev/"+filepath.Base(filepath.Dir(dir))] = true
		return nil
	}
	set["/dev/"+filepath.Base(dir)] = true
	return nil
}
