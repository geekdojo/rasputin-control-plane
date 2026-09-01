package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// BlockDevBackend is the real backend: util-linux on a Linux host.
//
// Every external command goes through the run seam below rather than
// exec.CommandContext directly. That is not indirection for its own sake — it
// is what makes the output parsing, the refusal ordering, and the exact command
// sequence a destructive claim issues testable without root and without a disk
// to lose. `rauc.go` isolates its CLI the same way (a resolved binary path held
// as a field, pointed at a shim by tests); this goes one step further because
// what needs asserting here is not just "we parsed the output" but "we did not
// run mkfs".
type BlockDevBackend struct {
	stateDir string
	// run is the command seam. stdin is written to the child's standard input
	// (sfdisk takes its script that way); combined output comes back.
	run runner
	// prot resolves the protected set from live mounts. Its paths are fields,
	// so a test can hand it a fabricated /proc and /sys.
	prot *protector
	// mountRoot is where claimed targets are mounted. /run is tmpfs, so the
	// mount points vanish on reboot, which is correct: a mount is not a
	// durable fact and must be re-established from the partition UUID.
	mountRoot string
	// tools maps a logical tool name to its resolved absolute path.
	tools map[string]string
}

// runner is the shell-out seam. Implementations must not use a shell.
type runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

// DefaultMountRoot is where claimed targets are mounted.
const DefaultMountRoot = "/run/rasputin/storage"

// requiredTools must all be present for the real backend to be usable. Missing
// any one of them means falling through to the mock rather than discovering the
// gap halfway through a repartition.
var requiredTools = []string{"lsblk", "blkid", "wipefs", "sfdisk", "mkfs.ext4", "mount", "umount"}

// optionalTools improve reliability but are not worth refusing over. udevadm
// settle is how we wait for the kernel to publish the partition node sfdisk
// just created; without it we poll instead.
var optionalTools = []string{"udevadm", "partprobe"}

// ToolingAvailable reports whether every required tool is on PATH — the signal
// main.go autodetects on, mirroring the updater's `exec.LookPath("rauc")`.
// Kept next to requiredTools so the check and the list cannot drift.
func ToolingAvailable() bool {
	return len(MissingTools()) == 0
}

// MissingTools lists the required tools that are NOT on PATH, in requiredTools
// order. Empty means the real backend can run.
//
// This exists because "storage is unavailable" is not an actionable sentence
// and "wipefs is not on PATH" is. On 2026-09-01 an OS image shipped without
// wipefs; ToolingAvailable() went false, the agent silently fell back to the
// mock, and storage.enumerate answered with fixture disks on real hardware. The
// bool could not have said which tool to add to the image — this can, and the
// startup fault now quotes it.
func MissingTools() []string {
	var missing []string
	for _, t := range requiredTools {
		if _, err := exec.LookPath(t); err != nil {
			missing = append(missing, t)
		}
	}
	return missing
}

// NewBlockDevBackend resolves the block tooling and constructs the backend.
// Returns an error when any required tool is missing — callers fall through to
// MockBackend then, exactly as the updater falls through when rauc is absent.
func NewBlockDevBackend(stateDir string) (*BlockDevBackend, error) {
	tools := map[string]string{}
	for _, t := range requiredTools {
		p, err := exec.LookPath(t)
		if err != nil {
			return nil, fmt.Errorf("blockdev backend: %s not on PATH: %w", t, err)
		}
		tools[t] = p
	}
	for _, t := range optionalTools {
		if p, err := exec.LookPath(t); err == nil {
			tools[t] = p
		}
	}
	return newBlockDevBackend(stateDir, tools, execRunner), nil
}

// newBlockDevBackend is the lower-level constructor tests use to inject a
// runner and a fabricated sysfs.
func newBlockDevBackend(stateDir string, tools map[string]string, run runner) *BlockDevBackend {
	return &BlockDevBackend{
		stateDir:  stateDir,
		run:       run,
		prot:      newProtector(),
		mountRoot: DefaultMountRoot,
		tools:     tools,
	}
}

// execRunner is the production runner: exec, no shell, combined output.
func execRunner(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(stdin) > 0 {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", filepath.Base(name), strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (b *BlockDevBackend) Name() string { return "blockdev" }

// tool returns the resolved path for a tool, or the bare name if it was never
// resolved (tests inject a runner that ignores the path anyway).
func (b *BlockDevBackend) tool(name string) string {
	if p, ok := b.tools[name]; ok && p != "" {
		return p
	}
	return name
}

// safeDevicePath and safePartUUID reject anything that is not obviously a
// device path or a UUID.
//
// Not injection guards — nothing here goes near a shell — but ARGUMENT guards.
// A value beginning with "-" would be read by lsblk, wipefs or mkfs as an
// option rather than an operand, and the difference between "an operand we
// refused" and "a flag we did not expect" is the difference between a refusal
// and a surprise. The values also arrive over NATS from the api, so validating
// them here keeps the trust boundary at the agent rather than at the caller.
var (
	safeDevicePath = regexp.MustCompile(`^/dev/[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$`)
	safePartUUID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
)

func checkDevicePath(p string) error {
	if !safeDevicePath.MatchString(p) || strings.Contains(p, "..") {
		return fmt.Errorf("%w: %q is not a device path", ErrDeviceAbsent, p)
	}
	return nil
}

func checkPartUUID(u string) error {
	if !safePartUUID.MatchString(u) {
		return fmt.Errorf("%w: %q is not a partition UUID", ErrNotFound, u)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Enumerate
// ---------------------------------------------------------------------------

// Enumerate lists candidate whole disks. Mutates nothing.
//
// The protected set is resolved FIRST and a failure to resolve it fails the
// whole call. Listing candidates while unable to say which disk we boot from
// would put an unmarked boot disk in front of an operator and a destructive
// confirm button next to it.
func (b *BlockDevBackend) Enumerate(ctx context.Context) (*proto.StorageEnumerateAck, error) {
	protected, err := b.prot.resolve()
	if err != nil {
		return nil, fmt.Errorf("resolve the protected set: %w", err)
	}
	devices, err := b.lsblk(ctx, "")
	if err != nil {
		return nil, err
	}
	ack := &proto.StorageEnumerateAck{
		OK:      true,
		Backend: b.Name(),
		Ts:      time.Now().UTC(),
	}
	for _, d := range devices.BlockDevices {
		if !isCandidateDisk(d) {
			continue
		}
		c := b.candidateFrom(ctx, d, protected)
		ack.Candidates = append(ack.Candidates, c)
	}
	return ack, nil
}

// candidateFrom builds one candidate from an lsblk disk node.
func (b *BlockDevBackend) candidateFrom(ctx context.Context, d lsblkDevice, protected map[string]protectedDisk) proto.StorageCandidate {
	path := d.Path
	if path == "" {
		path = "/dev/" + d.KName
	}
	c := proto.StorageCandidate{
		DevicePath: path,
		Model:      strings.TrimSpace(d.Model),
		Serial:     strings.TrimSpace(d.Serial),
		WWN:        strings.TrimSpace(d.WWN),
		SizeBytes:  uint64(d.Size),
		Transport:  proto.StorageTransport(transportOf(d.Tran)),
		Removable:  bool(d.RM),
	}
	for _, p := range d.Children {
		if p.Type != "part" {
			continue
		}
		pp := p.Path
		if pp == "" {
			pp = "/dev/" + p.KName
		}
		c.Partitions = append(c.Partitions, proto.StoragePartition{
			DevicePath: pp,
			PartUUID:   strings.TrimSpace(p.PartUUID),
			FSType:     strings.TrimSpace(p.FSType),
			Label:      strings.TrimSpace(p.Label),
			SizeBytes:  uint64(p.Size),
			Mountpoint: strings.TrimSpace(p.MountPoint),
		})
	}
	if pd, ok := protected[path]; ok {
		c.Protected = true
		c.ProtectedReason = pd.reason
	}
	// A backup set is looked for only on partitions already carrying our
	// filesystem label. Mounting every partition of every attached disk to peek
	// at its root would be an enumeration with side effects, and the disks that
	// can carry a Rasputin set are exactly the disks Rasputin labelled.
	if set := b.readBackupSet(ctx, c.Partitions); set != nil {
		c.HasBackupSet = true
		c.BackupSet = set
	}
	stampFingerprint(&c)
	return c
}

// readBackupSet looks for the marker on any partition labelled
// StorageBackupLabel. Best-effort and read-only: a partition that will not
// mount, or mounts without a marker, simply yields nothing.
func (b *BlockDevBackend) readBackupSet(ctx context.Context, parts []proto.StoragePartition) *proto.StorageBackupSet {
	for _, p := range parts {
		if p.Label != proto.StorageBackupLabel {
			continue
		}
		if p.Mountpoint != "" {
			if set, err := readMarker(p.Mountpoint); err == nil {
				return set
			}
			continue
		}
		set, err := b.peek(ctx, p.DevicePath)
		if err != nil {
			log.Printf("rasputin-agent: storage: peek %s: %v", p.DevicePath, err)
			continue
		}
		if set != nil {
			return set
		}
	}
	return nil
}

// peek mounts a partition READ-ONLY at a scratch mount point, reads the marker,
// and unmounts. Read-only is not a nicety: enumeration runs against a disk the
// operator has not confirmed anything about, and one of those disks may be the
// only copy of the archive being restored (#291).
func (b *BlockDevBackend) peek(ctx context.Context, devicePath string) (*proto.StorageBackupSet, error) {
	if err := checkDevicePath(devicePath); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(b.mountRoot, "peek-")
	if err != nil {
		if err = os.MkdirAll(b.mountRoot, 0o700); err != nil {
			return nil, err
		}
		if dir, err = os.MkdirTemp(b.mountRoot, "peek-"); err != nil {
			return nil, err
		}
	}
	defer os.Remove(dir)
	if _, err := b.run(ctx, nil, b.tool("mount"), "-o", "ro,noexec,nosuid,nodev", devicePath, dir); err != nil {
		return nil, err
	}
	defer func() {
		if _, err := b.run(ctx, nil, b.tool("umount"), dir); err != nil {
			log.Printf("rasputin-agent: storage: umount %s: %v", dir, err)
		}
	}()
	return readMarker(dir)
}

// ---------------------------------------------------------------------------
// Claim — the destructive verb
// ---------------------------------------------------------------------------

// Claim formats devicePath and claims it as a backup target.
//
// The order below is the whole safety argument, and it is the order the saga
// depends on: api/internal/jobs has no compensation, so a step that gets past
// its refusals and then fails leaves the disk formatted. Everything answerable
// is answered before the first byte is written, and after that there is nothing
// left that can decide to stop.
func (b *BlockDevBackend) Claim(ctx context.Context, cmd proto.StorageClaimCmd) (*proto.StorageClaimAck, error) {
	devicePath, fingerprint, label := cmd.DevicePath, cmd.Fingerprint, cmd.Label
	if err := checkDevicePath(devicePath); err != nil {
		return nil, err
	}
	// (0) An absent fingerprint is a refusal, not a wildcard.
	if strings.TrimSpace(fingerprint) == "" {
		return nil, ErrNoFingerprint
	}

	// (a) Re-resolve the protected set from LIVE MOUNTS. Not from the enumerate
	// the operator was looking at — that snapshot is as old as their hesitation,
	// and a reboot in between could have renumbered the very disks it named.
	protected, err := b.prot.resolve()
	if err != nil {
		return nil, fmt.Errorf("resolve the protected set: %w", err)
	}
	if pd, ok := protected[devicePath]; ok {
		return nil, protectedError(devicePath, pd.reason)
	}

	// (b) Re-derive the candidate and its fingerprint against live hardware.
	devices, err := b.lsblk(ctx, devicePath)
	if err != nil {
		return nil, err
	}
	var node *lsblkDevice
	for i := range devices.BlockDevices {
		d := devices.BlockDevices[i]
		if d.Path == devicePath || "/dev/"+d.KName == devicePath {
			node = &devices.BlockDevices[i]
			break
		}
	}
	if node == nil {
		return nil, fmt.Errorf("%w: %s", ErrDeviceAbsent, devicePath)
	}
	if node.Type != "disk" {
		return nil, fmt.Errorf("%w: %s is a %q", ErrNotWholeDisk, devicePath, node.Type)
	}
	cand := b.candidateFrom(ctx, *node, protected)
	// Belt and braces: candidateFrom stamps Protected from the same map, but
	// the check is repeated against the candidate so a future bug in the
	// stamping cannot quietly turn the guard off.
	if cand.Protected {
		return nil, protectedError(devicePath, cand.ProtectedReason)
	}
	if cand.Fingerprint != fingerprint {
		return nil, fmt.Errorf("%w: confirmed %s, found %s", ErrFingerprintMismatch, short(fingerprint), short(cand.Fingerprint))
	}

	// (c) Anything of ours already mounted off this disk is released; anything
	// mounted ELSEWHERE means the disk is in use by something we did not put
	// there, and we stop. mkfs would fail anyway — refusing here makes the
	// reason legible instead of surfacing as "device or resource busy".
	for _, p := range cand.Partitions {
		if p.Mountpoint == "" {
			continue
		}
		if !strings.HasPrefix(filepath.Clean(p.Mountpoint)+"/", filepath.Clean(b.mountRoot)+"/") {
			return nil, fmt.Errorf("%s is mounted at %s — unmount it before claiming %s",
				p.DevicePath, p.Mountpoint, devicePath)
		}
		if _, err := b.run(ctx, nil, b.tool("umount"), p.Mountpoint); err != nil {
			return nil, fmt.Errorf("release our own mount at %s: %w", p.Mountpoint, err)
		}
	}

	// ---- past this line the disk is being rewritten ----

	if _, err := b.run(ctx, nil, b.tool("wipefs"), "-a", devicePath); err != nil {
		return nil, fmt.Errorf("wipe signatures on %s: %w", devicePath, err)
	}
	// One GPT partition spanning the disk. type= is the Linux filesystem GUID;
	// name= is the GPT partition NAME, which is not the filesystem label and is
	// not the identifier either — the identifier is the PARTUUID the kernel
	// mints below.
	script := "label: gpt\nname=\"rasputin-backup\", type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n"
	if _, err := b.run(ctx, []byte(script), b.tool("sfdisk"), "--wipe", "always", devicePath); err != nil {
		return nil, fmt.Errorf("write partition table on %s: %w", devicePath, err)
	}
	b.settle(ctx, devicePath)

	part, err := b.firstPartition(ctx, devicePath)
	if err != nil {
		return nil, err
	}
	if _, err := b.run(ctx, nil, b.tool("mkfs.ext4"), "-F", "-m", "0", "-L", proto.StorageBackupLabel, part); err != nil {
		return nil, fmt.Errorf("mkfs on %s: %w", part, err)
	}
	b.settle(ctx, devicePath)

	partUUID, err := b.partUUIDOf(ctx, part)
	if err != nil {
		return nil, err
	}
	mountPath, err := b.mountPartition(ctx, part, partUUID)
	if err != nil {
		return nil, err
	}

	// The marker carries everything the command was given, including the two
	// WRAPPED §4.6 key blobs. A disk that records its own key custody is one a
	// replacement controlplane can adopt and actually open; one that records
	// only a key-id names a key nobody can produce.
	set := markerFrom(cmd, partUUID, time.Now().UTC())
	if err := writeMarker(mountPath, set); err != nil {
		return nil, fmt.Errorf("write marker on %s: %w", mountPath, err)
	}

	// The post-format fingerprint. It differs from the one in the command by
	// construction — the partition table it hashes is what was just replaced —
	// and that difference is what makes a replayed claim refuse.
	after := b.fingerprintOf(ctx, devicePath, protected)

	ack := &proto.StorageClaimAck{
		OK:          true,
		DevicePath:  devicePath,
		PartUUID:    partUUID,
		Label:       label,
		FSLabel:     proto.StorageBackupLabel,
		FSType:      "ext4",
		MountPath:   mountPath,
		SizeBytes:   cand.SizeBytes,
		Fingerprint: after,
		BackupSet:   set,
	}
	return ack, nil
}

// short trims a fingerprint for an error message. The full 64 hex characters in
// a refusal string help nobody; the first twelve are plenty to tell two apart.
func short(fp string) string {
	if len(fp) > 12 {
		return fp[:12] + "…"
	}
	return fp
}

// settle waits for udev to publish the nodes sfdisk/mkfs just changed. Without
// it the partition device can still be absent when we go looking for it, which
// on a fast NVMe is a race that fires perhaps one time in twenty.
func (b *BlockDevBackend) settle(ctx context.Context, devicePath string) {
	if p, ok := b.tools["partprobe"]; ok {
		if _, err := b.run(ctx, nil, p, devicePath); err != nil {
			log.Printf("rasputin-agent: storage: partprobe %s: %v", devicePath, err)
		}
	}
	if u, ok := b.tools["udevadm"]; ok {
		if _, err := b.run(ctx, nil, u, "settle", "--timeout=30"); err != nil {
			log.Printf("rasputin-agent: storage: udevadm settle: %v", err)
		}
	}
}

// firstPartition re-reads the disk and returns its single partition.
func (b *BlockDevBackend) firstPartition(ctx context.Context, devicePath string) (string, error) {
	devices, err := b.lsblk(ctx, devicePath)
	if err != nil {
		return "", err
	}
	for _, d := range devices.BlockDevices {
		for _, c := range d.Children {
			if c.Type != "part" {
				continue
			}
			if c.Path != "" {
				return c.Path, nil
			}
			return "/dev/" + c.KName, nil
		}
	}
	return "", fmt.Errorf("no partition appeared on %s after sfdisk", devicePath)
}

// partUUIDOf reads a partition's PARTUUID — the identifier §4.8 keys the target
// by, minted by the kernel when the GPT entry was written.
func (b *BlockDevBackend) partUUIDOf(ctx context.Context, part string) (string, error) {
	out, err := b.run(ctx, nil, b.tool("blkid"), "-s", "PARTUUID", "-o", "value", part)
	if err != nil {
		return "", fmt.Errorf("read PARTUUID of %s: %w", part, err)
	}
	uuid := strings.TrimSpace(string(out))
	if uuid == "" {
		return "", fmt.Errorf("blkid reported no PARTUUID for %s", part)
	}
	if err := checkPartUUID(uuid); err != nil {
		return "", err
	}
	return uuid, nil
}

// fingerprintOf re-derives one disk's fingerprint. Best-effort: an empty string
// means "we could not re-read it", which is recorded as such rather than as a
// fingerprint that would later compare unequal for the wrong reason.
func (b *BlockDevBackend) fingerprintOf(ctx context.Context, devicePath string, protected map[string]protectedDisk) string {
	devices, err := b.lsblk(ctx, devicePath)
	if err != nil {
		return ""
	}
	for _, d := range devices.BlockDevices {
		if d.Path == devicePath || "/dev/"+d.KName == devicePath {
			c := b.candidateFrom(ctx, d, protected)
			return c.Fingerprint
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Mount / Inspect
// ---------------------------------------------------------------------------

// Mount mounts a claimed target by partition UUID.
func (b *BlockDevBackend) Mount(ctx context.Context, partUUID string) (string, error) {
	if err := checkPartUUID(partUUID); err != nil {
		return "", err
	}
	part, existing, err := b.findByPartUUID(ctx, partUUID)
	if err != nil {
		return "", err
	}
	if existing != "" {
		return existing, nil
	}
	return b.mountPartition(ctx, part, partUUID)
}

// mountPartition mounts part at mountRoot/<partUUID>.
//
// nodev,nosuid,noexec because the contents are an archive written by a previous
// installation of this software and, after a restore-before-first-boot, are the
// first thing a replacement controlplane reads off a disk it has never seen.
func (b *BlockDevBackend) mountPartition(ctx context.Context, part, partUUID string) (string, error) {
	dir := filepath.Join(b.mountRoot, partUUID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if _, err := b.run(ctx, nil, b.tool("mount"), "-o", "noexec,nosuid,nodev", part, dir); err != nil {
		return "", fmt.Errorf("mount %s at %s: %w", part, dir, err)
	}
	return dir, nil
}

// findByPartUUID locates the partition carrying partUUID. Returns the device
// path and, when it is already mounted, its current mount point.
//
// Resolution is by scanning lsblk for the PARTUUID rather than by stat-ing
// /dev/disk/by-partuuid/<uuid>: the by-partuuid symlinks are udev's, so they are
// absent in a container and stale for a few milliseconds after a repartition,
// and "the symlink is not there yet" would read as "the operator unplugged the
// disk".
func (b *BlockDevBackend) findByPartUUID(ctx context.Context, partUUID string) (device string, mountPoint string, err error) {
	devices, err := b.lsblk(ctx, "")
	if err != nil {
		return "", "", err
	}
	protected, perr := b.prot.resolve()
	if perr != nil {
		return "", "", fmt.Errorf("resolve the protected set: %w", perr)
	}
	for _, d := range devices.BlockDevices {
		for _, c := range d.Children {
			if strings.TrimSpace(c.PartUUID) != partUUID {
				continue
			}
			parent := d.Path
			if parent == "" {
				parent = "/dev/" + d.KName
			}
			// Refuse to touch a partition on a protected disk even here. This
			// verb is not destructive, but a claimed-target UUID that resolves
			// onto the boot disk means something is badly wrong, and mounting
			// it would hand the backup writer a path on the boot medium.
			if pd, ok := protected[parent]; ok {
				return "", "", protectedError(parent, pd.reason)
			}
			path := c.Path
			if path == "" {
				path = "/dev/" + c.KName
			}
			return path, strings.TrimSpace(c.MountPoint), nil
		}
	}
	return "", "", fmt.Errorf("%w: %s", ErrNotFound, partUUID)
}

// Inspect reports a claimed target's marker and free space.
//
// A target that is simply not attached comes back OK with Present false: the
// operator unplugged their backup disk, which is an answer the UI should render
// plainly, not an agent failure.
func (b *BlockDevBackend) Inspect(ctx context.Context, partUUID string) (*proto.StorageInspectAck, error) {
	if err := checkPartUUID(partUUID); err != nil {
		return nil, err
	}
	part, mountPoint, err := b.findByPartUUID(ctx, partUUID)
	if errors.Is(err, ErrNotFound) {
		return &proto.StorageInspectAck{
			OK: true, PartUUID: partUUID, Present: false,
			Refusal: proto.StorageRefusalNotFound,
			Detail:  "no attached disk carries that partition UUID",
		}, nil
	}
	if err != nil {
		return nil, err
	}
	if mountPoint == "" {
		if mountPoint, err = b.mountPartition(ctx, part, partUUID); err != nil {
			return nil, err
		}
	}
	ack := &proto.StorageInspectAck{
		OK:         true,
		Present:    true,
		PartUUID:   partUUID,
		DevicePath: part,
		MountPath:  mountPoint,
		FSType:     "ext4",
		FSLabel:    proto.StorageBackupLabel,
	}
	if du, derr := disk.UsageWithContext(ctx, mountPoint); derr == nil {
		ack.TotalBytes = du.Total
		ack.FreeBytes = du.Free
	}
	if set, merr := readMarker(mountPoint); merr == nil {
		ack.BackupSet = set
	}
	return ack, nil
}

// lsblk runs lsblk over one device, or the whole machine when devicePath is
// empty.
func (b *BlockDevBackend) lsblk(ctx context.Context, devicePath string) (*lsblkOutput, error) {
	args := []string{"--json", "--bytes", "--output", lsblkColumns}
	if devicePath != "" {
		if err := checkDevicePath(devicePath); err != nil {
			return nil, err
		}
		// "--" so a path can never be read as an option, however checkDevicePath
		// evolves.
		args = append(args, "--", devicePath)
	}
	out, err := b.run(ctx, nil, b.tool("lsblk"), args...)
	if err != nil {
		return nil, fmt.Errorf("lsblk: %w", err)
	}
	return parseLsblk(out)
}

// ---------------------------------------------------------------------------
// Marker file
// ---------------------------------------------------------------------------

// readMarker reads StorageMarkerFile from a mounted target.
func readMarker(mountPath string) (*proto.StorageBackupSet, error) {
	b, err := os.ReadFile(filepath.Join(mountPath, proto.StorageMarkerFile))
	if err != nil {
		return nil, err
	}
	// Bound the read: the marker is a few hundred bytes and arrives from a disk
	// somebody else may have written.
	if len(b) > 64*1024 {
		return nil, fmt.Errorf("marker on %s is %d bytes — refusing to parse it", mountPath, len(b))
	}
	var set proto.StorageBackupSet
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("parse marker on %s: %w", mountPath, err)
	}
	if n, err := countGenerations(mountPath); err == nil {
		set.Generations = n
	}
	return &set, nil
}

// GenerationsDir is where §4.4's retained archive generations live under the
// target's mount point. Counted so the adopt-or-wipe prompt can say how much
// the operator is about to destroy — "wipe" should be a decision, not a shrug.
const GenerationsDir = "generations"

func countGenerations(mountPath string) (int, error) {
	ents, err := os.ReadDir(filepath.Join(mountPath, GenerationsDir))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() {
			n++
		}
	}
	return n, nil
}

// writeMarker writes StorageMarkerFile durably: temp file, fsync, rename, then
// fsync the directory. The marker is what makes the disk self-describing, and a
// disk that is formatted but whose marker never reached the platter is the one
// case §4.8's recovery story does not cover.
func writeMarker(mountPath string, set *proto.StorageBackupSet) error {
	payload, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	final := filepath.Join(mountPath, proto.StorageMarkerFile)
	tmp, err := os.CreateTemp(mountPath, ".marker-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		return err
	}
	if d, err := os.Open(mountPath); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
