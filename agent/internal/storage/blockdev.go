package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// mountRoots is where claimed targets are mounted, PER PURPOSE, seeded
	// from proto's spec table. It replaced a single field for §6.5: a backup
	// mount belongs on tmpfs, where it is job-scoped and vanishes on reboot,
	// and a data mount belongs on the persistent partition, where it survives
	// one. Held as a field, like prot's paths, so a test can point every root
	// at a temp dir.
	mountRoots map[proto.StoragePurpose]string
	// scratchRoot is where peek makes its throwaway read-only mount points.
	// NOT a purpose root: peek runs against a disk whose purpose is not known
	// yet — reading the marker is how it finds out — and the mount lives for
	// the length of one read. tmpfs is right for that whatever the disk turns
	// out to be.
	scratchRoot string
	// tools maps a logical tool name to its resolved absolute path.
	tools map[string]string
}

// runner is the shell-out seam. Implementations must not use a shell.
type runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

// defaultMountRoots is the per-purpose root table, read straight out of proto
// so the agent spells no mount root of its own. A purpose the table does not
// know cannot be mounted at all, which is the same fail-closed answer
// StoragePurposeSpecFor gives the format path.
func defaultMountRoots() map[proto.StoragePurpose]string {
	roots := make(map[proto.StoragePurpose]string, len(proto.AllStoragePurposes))
	for _, p := range proto.AllStoragePurposes {
		spec, err := proto.StoragePurposeSpecFor(p)
		if err != nil {
			continue
		}
		roots[p] = spec.MountRoot
	}
	return roots
}

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
		stateDir:    stateDir,
		run:         run,
		prot:        newProtector(),
		mountRoots:  defaultMountRoots(),
		scratchRoot: proto.StorageBackupMountRoot,
		tools:       tools,
	}
}

// mountRootFor is where a target of this purpose is mounted. A purpose with no
// root is an error rather than a guess: mounting a disk somewhere nobody
// expects it is how an app comes to write to the boot medium believing it is
// on the data disk (§6.3).
func (b *BlockDevBackend) mountRootFor(purpose proto.StoragePurpose) (string, error) {
	root, ok := b.mountRoots[purpose]
	if !ok || root == "" {
		return "", fmt.Errorf("%w: no mount root is defined for purpose %q", ErrBadPurpose, purpose)
	}
	return root, nil
}

// isOurMount reports whether a path is one of OUR mount points — under any
// purpose's root, plus the scratch root peek uses.
//
// Claim asks this about every mounted partition on the disk it is about to
// format: ours are released, anything else means the disk is in use by
// something we did not put there and the claim stops. Before §6.5 there was
// one root and this was a single HasPrefix; with two, checking only the backup
// root would read a mounted data disk as "in use by a stranger".
func (b *BlockDevBackend) isOurMount(path string) bool {
	clean := filepath.Clean(path) + "/"
	roots := make([]string, 0, len(b.mountRoots)+1)
	for _, r := range b.mountRoots {
		roots = append(roots, r)
	}
	roots = append(roots, b.scratchRoot)
	for _, root := range roots {
		if root == "" {
			continue
		}
		if strings.HasPrefix(clean, filepath.Clean(root)+"/") {
			return true
		}
	}
	return false
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

// markerScan is the set of purposes an enumeration will MOUNT a partition to
// read the marker of. Everything else about an enumeration is unaffected: the
// disks, their partitions, the labels lsblk reports and the protected set are
// the same list whatever is in here.
//
// It exists because reading a marker is not a read. readClaimedSets peeks —
// it mounts the partition read-only, reads the file and unmounts — so the
// purposes in this set decide which filesystems on the machine are made live
// for a moment, and §6.5's startup sweep is a caller that wants exactly one of
// them. See enumerate.
type markerScan []proto.StoragePurpose

// wants reports whether p's marker is in scope for this scan. A nil or empty
// scan wants nothing, which is the fail-closed direction: the mistake this
// guards is a scan that mounts MORE than the caller asked for.
func (s markerScan) wants(p proto.StoragePurpose) bool {
	for _, want := range s {
		if want == p {
			return true
		}
	}
	return false
}

// Enumerate lists candidate whole disks. Mutates nothing.
//
// This is the OPERATOR-FACING enumeration — the storage.enumerate verb behind
// the disk picker — and it looks for every purpose's marker, because the
// picker has to tell an unclaimed disk from a backup target from a data disk
// before the operator confirms a format. Narrowing THIS would hide a claimed
// disk from the one screen whose whole job is to show what is on it.
func (b *BlockDevBackend) Enumerate(ctx context.Context) (*proto.StorageEnumerateAck, error) {
	return b.enumerate(ctx, proto.AllStoragePurposes)
}

// enumerate is Enumerate with the marker-reading NARROWED to scan.
//
// The narrowing is not an optimisation. Reading a marker means mounting the
// partition read-only and unmounting it again (peek), so an enumeration has
// the side effect of briefly making every Rasputin-labelled filesystem on the
// machine live — including the §4 backup target, which on a controlplane is
// usually a removable disk holding the only copy of the archives.
//
// That is the right trade for the picker, which is answering "what is on this
// machine" for an operator standing in front of it. It is the wrong trade for
// §6.5's startup sweep, which wants data disks and would otherwise mount the
// backup target on every boot — a behaviour §4's shipped path never had and
// nobody asked for. So the sweep says which purpose it came for.
//
// There is deliberately no second scanner. One discovery path finds Rasputin's
// disks by filesystem label, confirms each by its marker and resolves the
// protected set from live mounts; a parallel one would be a second answer to
// "which disks are ours" and the two would drift.
//
// The protected set is resolved FIRST and a failure to resolve it fails the
// whole call. Listing candidates while unable to say which disk we boot from
// would put an unmarked boot disk in front of an operator and a destructive
// confirm button next to it.
func (b *BlockDevBackend) enumerate(ctx context.Context, scan markerScan) (*proto.StorageEnumerateAck, error) {
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
		c := b.candidateFrom(ctx, d, protected, scan)
		ack.Candidates = append(ack.Candidates, c)
	}
	return ack, nil
}

// candidateFrom builds one candidate from an lsblk disk node. scan says which
// purposes' markers are read; everything else it reports is independent of it.
func (b *BlockDevBackend) candidateFrom(ctx context.Context, d lsblkDevice, protected map[string]protectedDisk, scan markerScan) proto.StorageCandidate {
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
	// A claimed set is looked for only on partitions already carrying one of our
	// filesystem labels. Mounting every partition of every attached disk to peek
	// at its root would be an enumeration with side effects, and the disks that
	// can carry a Rasputin set are exactly the disks Rasputin labelled.
	backup, data := b.readClaimedSets(ctx, c.Partitions, scan)
	if backup != nil {
		c.HasBackupSet = true
		c.BackupSet = backup
	}
	if data != nil {
		c.HasDataSet = true
		c.DataSet = data
	}
	stampFingerprint(&c)
	return c
}

// readClaimedSets looks for a Rasputin marker on the candidate's partitions and
// reports what it found, PER PURPOSE.
//
// Only partitions carrying one of our filesystem labels are looked at, for the
// reason given at the call site. Since §6 the label also decides WHICH of the
// two markers to read: a data disk reported as a backup set would arrive at
// §4.8's adopt-or-wipe prompt, which offers the operator a choice about an
// archive that disk does not hold. The label is still only a hint — nothing
// destructive keys off it, and a mislabelled disk yields nothing rather than
// the wrong thing.
//
// Best-effort and read-only throughout: a partition that will not mount, or
// mounts without a marker, simply yields nothing.
//
// scan is the caller's answer to "which purposes did you come for", and it is
// applied HERE, before the peek, because the peek is the side effect: a
// purpose outside the scan is never mounted at all, not mounted and then
// discarded. §6.5's startup sweep passes data alone so a controlplane's backup
// target is not made live on every boot.
func (b *BlockDevBackend) readClaimedSets(ctx context.Context, parts []proto.StoragePartition, scan markerScan) (*proto.StorageBackupSet, *proto.StorageDataSet) {
	var backup *proto.StorageBackupSet
	var data *proto.StorageDataSet
	for _, p := range parts {
		purpose, ok := proto.StoragePurposeForFSLabel(p.Label)
		if !ok || !scan.wants(purpose) {
			continue
		}
		// One answer per purpose: the first partition that yields a marker
		// wins, as it did when backup was the only purpose there was.
		if (purpose == proto.StoragePurposeBackup && backup != nil) ||
			(purpose == proto.StoragePurposeData && data != nil) {
			continue
		}
		read := func(mountPath string) error {
			switch purpose {
			case proto.StoragePurposeBackup:
				set, err := readMarker(mountPath)
				if err != nil {
					return err
				}
				backup = set
			case proto.StoragePurposeData:
				set, err := readDataMarker(mountPath)
				if err != nil {
					return err
				}
				data = set
			}
			return nil
		}
		if p.Mountpoint != "" {
			// Already mounted by somebody: read it where it is rather than
			// mounting the same filesystem a second time.
			_ = read(p.Mountpoint)
			continue
		}
		if err := b.peek(ctx, p.DevicePath, read); err != nil {
			log.Printf("rasputin-agent: storage: peek %s: %v", p.DevicePath, err)
		}
	}
	return backup, data
}

// peek mounts a partition READ-ONLY at a scratch mount point, hands the mount
// point to read, and unmounts. Read-only is not a nicety: enumeration runs
// against a disk the operator has not confirmed anything about, and one of
// those disks may be the only copy of the archive being restored (#291).
//
// It takes a callback rather than returning a marker because there are two
// marker types now and a method cannot be generic over them. What must not
// change is that the unmount happens whatever the callback does.
func (b *BlockDevBackend) peek(ctx context.Context, devicePath string, read func(mountPath string) error) error {
	if err := checkDevicePath(devicePath); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(b.scratchRoot, "peek-")
	if err != nil {
		if err = os.MkdirAll(b.scratchRoot, 0o700); err != nil {
			return err
		}
		if dir, err = os.MkdirTemp(b.scratchRoot, "peek-"); err != nil {
			return err
		}
	}
	defer os.Remove(dir)
	if _, err := b.run(ctx, nil, b.tool("mount"), "-o", "ro,noexec,nosuid,nodev", devicePath, dir); err != nil {
		return err
	}
	defer func() {
		if _, err := b.run(ctx, nil, b.tool("umount"), dir); err != nil {
			log.Printf("rasputin-agent: storage: umount %s: %v", dir, err)
		}
	}()
	return read(dir)
}

// ---------------------------------------------------------------------------
// Claim — the destructive verb
// ---------------------------------------------------------------------------

// Claim formats devicePath and claims it for the command's purpose.
//
// The order below is the whole safety argument, and it is the order the saga
// depends on: api/internal/jobs has no compensation, so a step that gets past
// its refusals and then fails leaves the disk formatted. Everything answerable
// is answered before the first byte is written, and after that there is nothing
// left that can decide to stop.
//
// The purpose changes three constants and nothing else about that order. Every
// refusal below runs identically for a §6 data claim and a §4.8 backup claim,
// which is the property §6.1 and §6.5 both insist on: a data disk is the disk
// an operator is MOST likely to arrive with full.
func (b *BlockDevBackend) Claim(ctx context.Context, cmd proto.StorageClaimCmd) (*proto.StorageClaimAck, error) {
	devicePath, fingerprint, label := cmd.DevicePath, cmd.Fingerprint, cmd.Label
	if err := checkDevicePath(devicePath); err != nil {
		return nil, err
	}
	// (0) An absent fingerprint is a refusal, not a wildcard.
	if strings.TrimSpace(fingerprint) == "" {
		return nil, ErrNoFingerprint
	}
	// (0b) And so is a purpose this build does not implement, or one carrying
	// key custody it has no business carrying. Resolved here, at the top, so
	// that a command this agent will not act on costs the disk nothing.
	spec, err := claimSpec(cmd)
	if err != nil {
		return nil, err
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
	// Every purpose. This is the re-verification a DESTRUCTIVE claim is about
	// to act on, and it has to see the disk exactly as the picker the operator
	// confirmed against saw it — §4.8's adopt-or-wipe question is asked of a
	// backup set found right here.
	cand := b.candidateFrom(ctx, *node, protected, proto.AllStoragePurposes)
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
		if !b.isOurMount(p.Mountpoint) {
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
	// One GPT partition spanning the disk. type= is the Linux filesystem GUID
	// and is the same whatever the disk is for; name= is the GPT partition
	// NAME, which comes from the purpose's spec and is not the filesystem label
	// and not the identifier either — the identifier is the PARTUUID the kernel
	// mints below.
	script := fmt.Sprintf("label: gpt\nname=%q, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n", spec.PartName)
	if _, err := b.run(ctx, []byte(script), b.tool("sfdisk"), "--wipe", "always", devicePath); err != nil {
		return nil, fmt.Errorf("write partition table on %s: %w", devicePath, err)
	}
	b.settle(ctx, devicePath)

	part, err := b.firstPartition(ctx, devicePath)
	if err != nil {
		return nil, err
	}
	// The label comes from the spec for the same reason the GPT name does. -F
	// because the device was just repartitioned and mkfs must not stop to ask;
	// -m 0 because reserving 5% of an archive or a media disk for root is
	// tens of gigabytes spent on nothing.
	if _, err := b.run(ctx, nil, b.tool("mkfs.ext4"), "-F", "-m", "0", "-L", spec.FSLabel, part); err != nil {
		return nil, fmt.Errorf("mkfs on %s: %w", part, err)
	}
	b.settle(ctx, devicePath)

	partUUID, err := b.partUUIDOf(ctx, part)
	if err != nil {
		return nil, err
	}
	// Mounted under the purpose's own root, with the purpose's own options —
	// the spec resolved at the top of this function, not re-derived from the
	// label we just wrote.
	mountPath, err := b.mountPartition(ctx, part, partUUID, spec)
	if err != nil {
		return nil, err
	}

	// The marker is what makes the disk self-describing, and WHICH marker
	// follows from the purpose.
	//
	// A backup target's carries everything the command was given, including the
	// two WRAPPED §4.6 key blobs: a disk that records its own key custody is one
	// a replacement controlplane can adopt and actually open, while one that
	// records only a key-id names a key nobody can produce. A data disk's
	// carries identity and nothing else — there is no archive on it to encrypt,
	// and claimSpec has already refused a command that tried to put custody
	// there.
	now := time.Now().UTC()
	var backupSet *proto.StorageBackupSet
	var dataSet *proto.StorageDataSet
	switch spec.Purpose {
	case proto.StoragePurposeBackup:
		backupSet = markerFrom(cmd, partUUID, now)
		err = writeMarker(mountPath, spec.MarkerFile, backupSet)
	case proto.StoragePurposeData:
		dataSet = dataMarkerFrom(cmd, partUUID, now)
		err = writeMarker(mountPath, spec.MarkerFile, dataSet)
	default:
		// Unreachable while claimSpec and the spec table agree, and here
		// anyway: a purpose that reached this line with no marker defined for
		// it would leave a formatted disk that cannot say what it is, which is
		// the one case §4.8's recovery story does not cover.
		return nil, fmt.Errorf("%w: no marker is defined for purpose %q", ErrBadPurpose, spec.Purpose)
	}
	if err != nil {
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
		Purpose:     spec.Purpose,
		FSLabel:     spec.FSLabel,
		FSType:      "ext4",
		MountPath:   mountPath,
		SizeBytes:   cand.SizeBytes,
		Fingerprint: after,
		BackupSet:   backupSet,
		DataSet:     dataSet,
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
			c := b.candidateFrom(ctx, d, protected, proto.AllStoragePurposes)
			return c.Fingerprint
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Mount / Inspect
// ---------------------------------------------------------------------------

// Mount mounts a claimed target by partition UUID.
//
// The root and the options now come from the target's PURPOSE (§6.5), which
// this verb is not told — the partition UUID is the whole address, and adding
// a purpose to StorageMountCmd would mean an agent below
// proto.StorageClaimPurposeMinAgentVersion mounting a data disk at the backup
// root, which is the skew this change exists to close. So the purpose is read
// off the filesystem LABEL lsblk observed.
//
// That is the label's blessed use, and only that use: readClaimedSets already
// decides which of the two markers to read the same way. Nothing destructive
// follows from it, and a partition whose label is none of ours falls back to
// backup — the answer every claimed target gave before §6, so a disk claimed
// by an older agent still mounts where it always did.
//
// The important property is that it is ONE answer per disk however the mount
// was reached. If the api's inspect mounted a data disk at /run while the
// startup sweep mounted it at /var/lib/rasputin/data, the same filesystem
// would be live at two paths and only one of them would survive a reboot.
func (b *BlockDevBackend) Mount(ctx context.Context, partUUID string) (string, error) {
	if err := checkPartUUID(partUUID); err != nil {
		return "", err
	}
	found, err := b.findByPartUUID(ctx, partUUID)
	if err != nil {
		return "", err
	}
	if found.mountPoint != "" {
		return found.mountPoint, nil
	}
	spec, err := mountSpecForLabel(found.fsLabel)
	if err != nil {
		return "", err
	}
	return b.mountPartition(ctx, found.devicePath, partUUID, spec)
}

// mountSpecForLabel resolves the purpose spec to mount a partition under from
// the filesystem label lsblk saw. An unrecognised label means backup, which is
// what every claimed target was before §6 — see Mount.
func mountSpecForLabel(fsLabel string) (proto.StoragePurposeSpec, error) {
	purpose, ok := proto.StoragePurposeForFSLabel(strings.TrimSpace(fsLabel))
	if !ok {
		purpose = proto.StoragePurposeBackup
	}
	return proto.StoragePurposeSpecFor(purpose)
}

// mountPartition mounts part at the purpose's root, as <root>/<partUUID>.
//
// Both the root and the options are the purpose's (§6.5, proto's spec table):
// a backup target lands job-scoped on tmpfs with noexec, a data disk lands
// durably beside the persistent partition WITHOUT it. The reasoning for each
// lives on the proto constants, which is the only place either is spelled.
func (b *BlockDevBackend) mountPartition(ctx context.Context, part, partUUID string, spec proto.StoragePurposeSpec) (string, error) {
	root, err := b.mountRootFor(spec.Purpose)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, partUUID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if _, err := b.run(ctx, nil, b.tool("mount"), "-o", spec.MountOptions, part, dir); err != nil {
		return "", fmt.Errorf("mount %s at %s: %w", part, dir, err)
	}
	return dir, nil
}

// claimedPartition is what findByPartUUID resolved: the partition carrying a
// claimed target's UUID, and what the kernel says is actually on it.
type claimedPartition struct {
	devicePath string
	// mountPoint is non-empty when the partition is already mounted.
	mountPoint string
	// fsType and fsLabel are what lsblk OBSERVED, carried out of the lookup so
	// Inspect can report them instead of asserting them. They used to be the
	// literals "ext4" and StorageBackupLabel at the Inspect call site, which
	// was true only while backup was the only purpose a claim could have.
	fsType  string
	fsLabel string
}

// findByPartUUID locates the partition carrying partUUID.
//
// Resolution is by scanning lsblk for the PARTUUID rather than by stat-ing
// /dev/disk/by-partuuid/<uuid>: the by-partuuid symlinks are udev's, so they are
// absent in a container and stale for a few milliseconds after a repartition,
// and "the symlink is not there yet" would read as "the operator unplugged the
// disk".
func (b *BlockDevBackend) findByPartUUID(ctx context.Context, partUUID string) (claimedPartition, error) {
	devices, err := b.lsblk(ctx, "")
	if err != nil {
		return claimedPartition{}, err
	}
	protected, perr := b.prot.resolve()
	if perr != nil {
		return claimedPartition{}, fmt.Errorf("resolve the protected set: %w", perr)
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
			// it would hand the backup writer a path on the boot medium. Not
			// conditioned on the purpose, and §6.5 says it never may be.
			if pd, ok := protected[parent]; ok {
				return claimedPartition{}, protectedError(parent, pd.reason)
			}
			path := c.Path
			if path == "" {
				path = "/dev/" + c.KName
			}
			return claimedPartition{
				devicePath: path,
				mountPoint: strings.TrimSpace(c.MountPoint),
				fsType:     strings.TrimSpace(c.FSType),
				fsLabel:    strings.TrimSpace(c.Label),
			}, nil
		}
	}
	return claimedPartition{}, fmt.Errorf("%w: %s", ErrNotFound, partUUID)
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
	found, err := b.findByPartUUID(ctx, partUUID)
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
	mountPoint := found.mountPoint
	if mountPoint == "" {
		spec, serr := mountSpecForLabel(found.fsLabel)
		if serr != nil {
			return nil, serr
		}
		if mountPoint, err = b.mountPartition(ctx, found.devicePath, partUUID, spec); err != nil {
			// Attached and not mountable is its own answer, distinct from
			// "not attached" and from "the agent could not look": the health
			// poll renders it UNMOUNTED (#398). Present says the partition is
			// there; OK=false says it could not be used.
			return &proto.StorageInspectAck{
				OK: false, Present: true, PartUUID: partUUID, DevicePath: found.devicePath,
				Refusal: refusalFor(err),
				Detail:  fmt.Sprintf("%s is attached but could not be mounted: %v", found.devicePath, err),
			}, nil
		}
	}
	// FSType and FSLabel are what lsblk saw, not what a claim of one particular
	// purpose would have written. The two used to be the constants "ext4" and
	// StorageBackupLabel, which reported the truth only because backup was the
	// only purpose there was; with §6's second purpose the same two literals
	// would report a data disk as a backup one.
	ack := &proto.StorageInspectAck{
		OK:         true,
		Present:    true,
		PartUUID:   partUUID,
		DevicePath: found.devicePath,
		MountPath:  mountPoint,
		FSType:     found.fsType,
		FSLabel:    found.fsLabel,
	}
	if du, derr := disk.UsageWithContext(ctx, mountPoint); derr == nil {
		ack.TotalBytes = du.Total
		ack.FreeBytes = du.Free
	}
	// Both markers are looked for rather than the one the label implies, and
	// the label is exactly why: §4.8 demoted it to a hint, so a target whose
	// label was changed underneath us is the target whose marker is the only
	// thing still saying what it is. Inspect writes nothing, so looking for a
	// file that is not there costs one failed open — this is not the
	// destructive path where guessing would matter.
	if set, merr := readMarker(mountPoint); merr == nil {
		ack.BackupSet = set
	}
	if set, merr := readDataMarker(mountPoint); merr == nil {
		ack.DataSet = set
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

// markerMaxBytes bounds a marker file. A marker is a few hundred bytes; the
// cap is generous by three orders of magnitude and still small enough that a
// hostile one cannot matter.
const markerMaxBytes = 64 * 1024

// readMarkerFile reads one marker file off a mounted target into set.
//
// Shared by both markers so the bound is applied to both. It is not
// belt-and-braces: enumeration reads markers off disks the operator has
// confirmed nothing about, so this is untrusted input from a filesystem
// somebody else wrote, and a marker is a few hundred bytes.
//
// The bound is enforced by READING AT MOST markerMaxBytes+1, never by checking
// the length afterwards. os.ReadFile would pull the whole file into memory
// first and only then discover it was too big, which on a Pi 4 hands any disk
// the operator plugs in a memory-exhaustion lever — and enumeration runs
// against exactly such disks, before anyone has confirmed anything about them.
// The +1 is what distinguishes "exactly at the cap" from "over it".
func readMarkerFile(mountPath, name string, set any) error {
	f, err := os.Open(filepath.Join(mountPath, name))
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := io.ReadAll(io.LimitReader(f, markerMaxBytes+1))
	if err != nil {
		return fmt.Errorf("read marker %s on %s: %w", name, mountPath, err)
	}
	if len(b) > markerMaxBytes {
		return fmt.Errorf("marker %s on %s is larger than %d bytes — refusing to parse it", name, mountPath, markerMaxBytes)
	}
	if err := json.Unmarshal(b, set); err != nil {
		return fmt.Errorf("parse marker %s on %s: %w", name, mountPath, err)
	}
	return nil
}

// readMarker reads StorageMarkerFile — the §4.8 backup set — from a mounted
// target.
func readMarker(mountPath string) (*proto.StorageBackupSet, error) {
	var set proto.StorageBackupSet
	if err := readMarkerFile(mountPath, proto.StorageMarkerFile, &set); err != nil {
		return nil, err
	}
	if n, err := countGenerations(mountPath); err == nil {
		set.Generations = n
	}
	return &set, nil
}

// readDataMarker reads StorageDataMarkerFile — the §6 data set — from a mounted
// disk.
//
// No generation count: generations are §4.4's retained archives and a data disk
// holds none. The count exists so §4.8's adopt-or-wipe prompt can say how much
// a wipe destroys, and §6.1 deliberately does not give a data disk that prompt.
func readDataMarker(mountPath string) (*proto.StorageDataSet, error) {
	var set proto.StorageDataSet
	if err := readMarkerFile(mountPath, proto.StorageDataMarkerFile, &set); err != nil {
		return nil, err
	}
	return &set, nil
}

// GenerationsDir is where §4.4's retained archive generations live under the
// target's mount point. Counted so the adopt-or-wipe prompt can say how much
// the operator is about to destroy — "wipe" should be a decision, not a shrug.
//
// Aliased to the wire constant rather than spelled twice: the backup verbs in
// archive.go write into this directory and the api names it in a manifest, so a
// second literal here is a way for the writer and the counter to disagree about
// where generations live.
const GenerationsDir = proto.BackupGenerationsDir

func countGenerations(mountPath string) (int, error) {
	ents, err := os.ReadDir(filepath.Join(mountPath, GenerationsDir))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		// `.partial-*` is a write that crashed mid-copy, not a generation.
		// Counting one would tell the operator a wipe destroys more than it
		// does, which is the wrong direction for a number whose whole job is to
		// make a destructive choice legible.
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			n++
		}
	}
	return n, nil
}

// writeMarker writes a marker file durably: temp file, fsync, rename, then
// fsync the directory. The marker is what makes the disk self-describing, and a
// disk that is formatted but whose marker never reached the platter is the one
// case §4.8's recovery story does not cover.
//
// name and set travel together — the caller passes the purpose spec's
// MarkerFile and the matching set type — because the durable-write dance below
// is the load-bearing part and there must be exactly one copy of it, not one
// per marker type.
func writeMarker(mountPath, name string, set any) error {
	payload, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	final := filepath.Join(mountPath, name)
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
