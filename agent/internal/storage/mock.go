package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// MockBackend simulates a machine's disks with file-backed state under
// <stateDir>/storage/. State lives at <stateDir>/storage/state.json and claimed
// targets are mounted (as ordinary directories) under
// <stateDir>/storage/mounts/<partUUID>, so a dev control plane gets a real,
// writable path to hand the ingest endpoint.
//
// ⚠️ THIS IS NOT A STUB, AND IT IS NOT A CONVENIENCE.
//
// The failure this whole subsystem exists to prevent — pick the wrong disk,
// force-format it, destroy the cluster the backup was for — cannot be rehearsed
// on hardware. So the mock models the things the safety rules are ABOUT: disks
// with identity, partitions, and a live mount table. Protected is DERIVED from
// those mounts here exactly as the real backend derives it from
// /proc/self/mountinfo; it is never a flag somebody set on a disk.
//
// The consequence worth stating: kernel names are assigned per enumeration from
// NameOrder, a permutation the tests can flip. Flipping it renames the disks
// without moving anything, which is precisely the reboot-renumbering hazard
// §4.8 is written against, and it turns "protection follows the mount and not
// the name" from a claim in a comment into an assertion in a test.
//
// Failure injection, mirroring the updater's RASPUTIN_UPDATE_FAIL_MODE:
//
//	RASPUTIN_STORAGE_FAIL_MODE=none       — happy path (default)
//	RASPUTIN_STORAGE_FAIL_MODE=enumerate  — Enumerate returns an error
//	RASPUTIN_STORAGE_FAIL_MODE=claim      — Claim fails AFTER its refusals pass
//	                                        and after the format, i.e. the
//	                                        orphaned-claim case §4.8 recovers
//	                                        from by re-enumerating
//	RASPUTIN_STORAGE_FAIL_MODE=mount      — Mount returns an error
type MockBackend struct {
	stateDir  string
	mountRoot string
	mu        sync.Mutex
	// newUUID mints partition UUIDs. A field so tests get deterministic ones.
	newUUID func() string
	// now is the clock, for the same reason.
	now func() time.Time
	// criticalMounts / persistentDir mirror the real protector's notion of what
	// is protected, so both backends answer the same question.
	criticalMounts []string
	persistentDir  string
}

// mockState is the simulated machine, persisted between agent restarts so a dev
// control plane's claimed target survives a restart the way a real one does.
type mockState struct {
	Disks []mockDisk `json:"disks"`
	// Mounts is the live mount table: which partition is mounted where. The
	// protected set is computed from this and nothing else.
	Mounts []mockMount `json:"mounts"`
	// NameOrder is a permutation of indices into Disks giving the order kernel
	// names are handed out this boot. Nil means natural order. Flipping it
	// simulates the unstable nvme enumeration order that makes device names
	// unusable as identity.
	NameOrder []int `json:"nameOrder,omitempty"`
}

// mockDisk is one simulated whole disk. It carries identity and contents; it
// carries NO device path and NO protected flag, because both are derived.
type mockDisk struct {
	// Family is the kernel-name family: "nvme", "sd" or "mmcblk". It decides
	// what the disk gets CALLED, never what may be done to it.
	Family    string                 `json:"family"`
	Model     string                 `json:"model,omitempty"`
	Serial    string                 `json:"serial,omitempty"`
	WWN       string                 `json:"wwn,omitempty"`
	SizeBytes uint64                 `json:"sizeBytes"`
	Transport proto.StorageTransport `json:"transport"`
	Removable bool                   `json:"removable,omitempty"`

	Partitions []mockPartition `json:"partitions,omitempty"`
}

type mockPartition struct {
	PartUUID  string                  `json:"partUuid"`
	FSType    string                  `json:"fsType,omitempty"`
	Label     string                  `json:"label,omitempty"`
	SizeBytes uint64                  `json:"sizeBytes"`
	BackupSet *proto.StorageBackupSet `json:"backupSet,omitempty"`
}

type mockMount struct {
	MountPoint string `json:"mountPoint"`
	PartUUID   string `json:"partUuid"`
}

// NewMockBackend opens (and seeds, on first run) a MockBackend rooted at
// stateDir.
func NewMockBackend(stateDir string) (*MockBackend, error) {
	root := filepath.Join(stateDir, "storage")
	if err := os.MkdirAll(filepath.Join(root, "mounts"), 0o700); err != nil {
		return nil, err
	}
	m := &MockBackend{
		stateDir:       root,
		mountRoot:      filepath.Join(root, "mounts"),
		newUUID:        randomPartUUID,
		now:            func() time.Time { return time.Now().UTC() },
		criticalMounts: defaultCriticalMounts,
		persistentDir:  DefaultPersistentDir,
	}
	if _, err := m.loadState(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		st, err := m.seed()
		if err != nil {
			return nil, err
		}
		if err := m.saveState(st); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *MockBackend) Name() string { return "mock" }

// MountRoot is where this mock puts claimed targets. Exposed for the dev api,
// which otherwise has no way to know the path is not /run/rasputin/storage.
func (m *MockBackend) MountRoot() string { return m.mountRoot }

func (m *MockBackend) statePath() string { return filepath.Join(m.stateDir, "state.json") }

func (m *MockBackend) loadState() (*mockState, error) {
	b, err := os.ReadFile(m.statePath())
	if err != nil {
		return nil, err
	}
	var st mockState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (m *MockBackend) saveState(st *mockState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath())
}

// seed builds the first-run machine.
//
// It is a two-NVMe controlplane plus a USB stick, because that is the hardware
// §4.8 is written against (the Geekworm x1004 the BitScope sits in, the
// LattePanda) and the configuration in which a name-keyed exclusion rule
// destroys the cluster. Both NVMes are the same transport and neither is
// removable, so nothing but the mount table can tell them apart — which is the
// point.
//
// There is deliberately NO env var naming a seed file to load. A bench that
// wants a different machine edits <stateDir>/storage/state.json, which is the
// same JSON, is already the thing the mock reads on every call, and does not
// hand the agent an arbitrary env-supplied path to open.
func (m *MockBackend) seed() (*mockState, error) {
	return defaultMockMachine(), nil
}

// defaultMockMachine is the seeded dev machine. Factored out so tests start
// from the shipped default and mutate it, rather than each re-describing a
// plausible machine and drifting from what a dev box actually sees.
func defaultMockMachine() *mockState {
	return &mockState{
		Disks: []mockDisk{
			{
				Family: "nvme", Model: "CT500P3SSD8", Serial: "SN-BOOT-0001",
				WWN: "eui.0001", SizeBytes: 500 << 30, Transport: proto.StorageTransportNVMe,
				Partitions: []mockPartition{
					{PartUUID: "boot-esp-0001", FSType: "vfat", Label: "ESP", SizeBytes: 512 << 20},
					{PartUUID: "boot-root-0001", FSType: "squashfs", Label: "rootfs-0", SizeBytes: 4 << 30},
					{PartUUID: "boot-data-0001", FSType: "ext4", Label: "persistent", SizeBytes: 400 << 30},
				},
			},
			{
				// Same transport, same vendor family, not removable: nothing
				// but the mount table distinguishes it from the boot disk.
				Family: "nvme", Model: "CT2000P3SSD8", Serial: "SN-SPARE-0002",
				WWN: "eui.0002", SizeBytes: 2000 << 30, Transport: proto.StorageTransportNVMe,
			},
			{
				Family: "sd", Model: "SanDisk Ultra", Serial: "USB-0003",
				SizeBytes: 64 << 30, Transport: proto.StorageTransportUSB, Removable: true,
				Partitions: []mockPartition{
					{PartUUID: "usb-part-0003", FSType: "exfat", Label: "MYSTUFF", SizeBytes: 64 << 30},
				},
			},
		},
		Mounts: []mockMount{
			{MountPoint: "/boot", PartUUID: "boot-esp-0001"},
			{MountPoint: "/", PartUUID: "boot-root-0001"},
			{MountPoint: DefaultPersistentDir, PartUUID: "boot-data-0001"},
		},
	}
}

// ---------------------------------------------------------------------------
// Naming — deliberately unstable
// ---------------------------------------------------------------------------

// deviceNames assigns a kernel name to every disk for THIS enumeration, in
// NameOrder sequence.
//
// The names are a function of the order, not of the disk. That is the whole
// hazard modelled in one function: the same physical disk is /dev/nvme0n1 on one
// boot and /dev/nvme1n1 on the next, with nothing about the disk having changed.
func (st *mockState) deviceNames() []string {
	order := st.NameOrder
	if len(order) != len(st.Disks) {
		order = make([]int, len(st.Disks))
		for i := range order {
			order[i] = i
		}
	}
	names := make([]string, len(st.Disks))
	counters := map[string]int{}
	for _, idx := range order {
		if idx < 0 || idx >= len(st.Disks) {
			continue
		}
		fam := st.Disks[idx].Family
		if fam == "" {
			fam = "sd"
		}
		n := counters[fam]
		counters[fam] = n + 1
		names[idx] = mockDeviceName(fam, n)
	}
	// Any disk the order forgot still needs a name.
	for i := range names {
		if names[i] == "" {
			fam := st.Disks[i].Family
			if fam == "" {
				fam = "sd"
			}
			n := counters[fam]
			counters[fam] = n + 1
			names[i] = mockDeviceName(fam, n)
		}
	}
	return names
}

func mockDeviceName(family string, n int) string {
	if n < 0 {
		n = 0
	}
	switch family {
	case "nvme":
		return fmt.Sprintf("/dev/nvme%dn1", n)
	case "mmcblk":
		return fmt.Sprintf("/dev/mmcblk%d", n)
	default:
		return "/dev/sd" + sdSuffix(n)
	}
}

// sdSuffix renders the kernel's sd naming: a…z, then aa…az, ba… and so on.
// Written as a base-26 loop over a letter table rather than 'a'+n, so a machine
// with more than 26 disks produces "sdaa" rather than a name outside the
// alphabet — and so the arithmetic cannot overflow a rune.
func sdSuffix(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	out := ""
	for {
		out = string(letters[n%26]) + out
		n = n/26 - 1
		if n < 0 {
			return out
		}
	}
}

// partitionName renders the nth partition of a disk, honouring the p-suffix
// convention nvme and mmcblk use and sd does not.
func partitionName(disk string, n int) string {
	base := filepath.Base(disk)
	if strings.HasPrefix(base, "nvme") || strings.HasPrefix(base, "mmcblk") {
		return fmt.Sprintf("%sp%d", disk, n)
	}
	return fmt.Sprintf("%s%d", disk, n)
}

// ---------------------------------------------------------------------------
// Protection — derived from the mount table, exactly as the real backend does
// ---------------------------------------------------------------------------

// protectedSet returns the indices of disks that hold a critical mount, with
// the reason.
//
// It walks the SAME longest-prefix rule as protect.go's carryingMount, over the
// same critical paths, and resolves a mount to a disk through the partition
// UUID — the mock's stand-in for major:minor. What it must never do is look at
// a device name, because the whole point of the mock is to prove the production
// path does not either.
func (m *MockBackend) protectedSet(st *mockState) map[int]string {
	entries := make([]mountEntry, 0, len(st.Mounts))
	byPoint := map[string]string{}
	for _, mt := range st.Mounts {
		entries = append(entries, mountEntry{mountPoint: mt.MountPoint, source: mt.PartUUID})
		byPoint[filepath.Clean(mt.MountPoint)] = mt.PartUUID
	}
	wanted := append([]string{}, m.criticalMounts...)
	if m.persistentDir != "" {
		wanted = append(wanted, m.persistentDir)
	}
	out := map[int]string{}
	for _, path := range wanted {
		ent, ok := carryingMount(entries, path)
		if !ok {
			continue
		}
		partUUID := byPoint[filepath.Clean(ent.mountPoint)]
		idx, found := diskHolding(st, partUUID)
		if !found {
			continue
		}
		reason := describeProtection(path, ent, m.persistentDir)
		if prev, seen := out[idx]; seen {
			if !strings.Contains(prev, reason) {
				out[idx] = prev + "; " + reason
			}
			continue
		}
		out[idx] = reason
	}
	return out
}

// diskHolding returns the index of the disk carrying partUUID.
func diskHolding(st *mockState, partUUID string) (int, bool) {
	if partUUID == "" {
		return 0, false
	}
	for i, d := range st.Disks {
		for _, p := range d.Partitions {
			if p.PartUUID == partUUID {
				return i, true
			}
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Backend implementation
// ---------------------------------------------------------------------------

func (m *MockBackend) Enumerate(ctx context.Context) (*proto.StorageEnumerateAck, error) {
	if os.Getenv("RASPUTIN_STORAGE_FAIL_MODE") == "enumerate" {
		return nil, errors.New("simulated enumerate failure (RASPUTIN_STORAGE_FAIL_MODE=enumerate)")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.loadState()
	if err != nil {
		return nil, err
	}
	return m.enumerateLocked(st), nil
}

func (m *MockBackend) enumerateLocked(st *mockState) *proto.StorageEnumerateAck {
	names := st.deviceNames()
	protected := m.protectedSet(st)
	mountedAt := map[string]string{}
	for _, mt := range st.Mounts {
		mountedAt[mt.PartUUID] = mt.MountPoint
	}
	ack := &proto.StorageEnumerateAck{OK: true, Backend: m.Name(), Ts: m.now()}
	for i, d := range st.Disks {
		c := proto.StorageCandidate{
			DevicePath: names[i],
			Model:      d.Model,
			Serial:     d.Serial,
			WWN:        d.WWN,
			SizeBytes:  d.SizeBytes,
			Transport:  d.Transport,
			Removable:  d.Removable,
		}
		if c.Transport == "" {
			c.Transport = proto.StorageTransportUnknown
		}
		for n, p := range d.Partitions {
			c.Partitions = append(c.Partitions, proto.StoragePartition{
				DevicePath: partitionName(names[i], n+1),
				PartUUID:   p.PartUUID,
				FSType:     p.FSType,
				Label:      p.Label,
				SizeBytes:  p.SizeBytes,
				Mountpoint: mountedAt[p.PartUUID],
			})
			if p.BackupSet != nil {
				c.HasBackupSet = true
				set := *p.BackupSet
				c.BackupSet = &set
			}
		}
		if reason, ok := protected[i]; ok {
			c.Protected = true
			c.ProtectedReason = reason
		}
		stampFingerprint(&c)
		ack.Candidates = append(ack.Candidates, c)
	}
	return ack
}

// Claim formats a simulated disk. The refusal order matches blockdev.Claim
// line for line — that is the property the tests are actually protecting, since
// a mock whose refusals differ from production tests nothing.
func (m *MockBackend) Claim(ctx context.Context, devicePath, fingerprint, label string) (*proto.StorageClaimAck, error) {
	if strings.TrimSpace(fingerprint) == "" {
		return nil, ErrNoFingerprint
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.loadState()
	if err != nil {
		return nil, err
	}

	// (a) Re-resolve protection from the live mount table. Re-read, re-derived,
	// not carried over from the enumerate the caller saw.
	names := st.deviceNames()
	protected := m.protectedSet(st)
	idx := -1
	for i, n := range names {
		if n == devicePath {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("%w: %s", ErrDeviceAbsent, devicePath)
	}
	if reason, ok := protected[idx]; ok {
		return nil, protectedError(devicePath, reason)
	}

	// (b) Re-compute the fingerprint against current state.
	current := m.enumerateLocked(st)
	var cand *proto.StorageCandidate
	for i := range current.Candidates {
		if current.Candidates[i].DevicePath == devicePath {
			cand = &current.Candidates[i]
			break
		}
	}
	if cand == nil {
		return nil, fmt.Errorf("%w: %s", ErrDeviceAbsent, devicePath)
	}
	if cand.Protected {
		return nil, protectedError(devicePath, cand.ProtectedReason)
	}
	if cand.Fingerprint != fingerprint {
		return nil, fmt.Errorf("%w: confirmed %s, found %s", ErrFingerprintMismatch, short(fingerprint), short(cand.Fingerprint))
	}

	// ---- past this line the disk is being rewritten ----

	partUUID := m.newUUID()
	set := &proto.StorageBackupSet{
		MarkerVersion: proto.StorageMarkerVersion,
		PartUUID:      partUUID,
		Label:         label,
		CreatedAt:     m.now(),
	}
	st.Disks[idx].Partitions = []mockPartition{{
		PartUUID:  partUUID,
		FSType:    "ext4",
		Label:     proto.StorageBackupLabel,
		SizeBytes: st.Disks[idx].SizeBytes,
		BackupSet: set,
	}}
	// Any prior mount of a partition that no longer exists is gone with it.
	st.Mounts = keepMounts(st)
	if err := m.saveState(st); err != nil {
		return nil, err
	}

	if os.Getenv("RASPUTIN_STORAGE_FAIL_MODE") == "claim" {
		// The orphaned-claim case: the disk IS formatted and the caller is told
		// the step failed. §4.8 needs no compensation for this — the disk is
		// self-describing, so re-enumerating finds it and the operator adopts
		// it. Injectable so that recovery path can be exercised.
		return nil, errors.New("simulated claim failure after format (RASPUTIN_STORAGE_FAIL_MODE=claim)")
	}

	mountPath, err := m.mountLocked(st, partUUID)
	if err != nil {
		return nil, err
	}

	after := m.enumerateLocked(st)
	fpAfter := ""
	for _, c := range after.Candidates {
		if c.DevicePath == devicePath {
			fpAfter = c.Fingerprint
		}
	}
	return &proto.StorageClaimAck{
		OK:          true,
		DevicePath:  devicePath,
		PartUUID:    partUUID,
		Label:       label,
		FSLabel:     proto.StorageBackupLabel,
		FSType:      "ext4",
		MountPath:   mountPath,
		SizeBytes:   st.Disks[idx].SizeBytes,
		Fingerprint: fpAfter,
		BackupSet:   set,
	}, nil
}

// keepMounts drops mount entries whose partition no longer exists.
func keepMounts(st *mockState) []mockMount {
	live := map[string]bool{}
	for _, d := range st.Disks {
		for _, p := range d.Partitions {
			live[p.PartUUID] = true
		}
	}
	out := st.Mounts[:0:0]
	for _, mt := range st.Mounts {
		if live[mt.PartUUID] {
			out = append(out, mt)
		}
	}
	return out
}

func (m *MockBackend) Mount(ctx context.Context, partUUID string) (string, error) {
	if os.Getenv("RASPUTIN_STORAGE_FAIL_MODE") == "mount" {
		return "", errors.New("simulated mount failure (RASPUTIN_STORAGE_FAIL_MODE=mount)")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.loadState()
	if err != nil {
		return "", err
	}
	path, err := m.mountLocked(st, partUUID)
	if err != nil {
		return "", err
	}
	return path, m.saveState(st)
}

// mountLocked mounts a claimed target and records it in the mount table. The
// caller holds m.mu and is responsible for persisting st.
func (m *MockBackend) mountLocked(st *mockState, partUUID string) (string, error) {
	if err := checkPartUUID(partUUID); err != nil {
		return "", err
	}
	idx, ok := diskHolding(st, partUUID)
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, partUUID)
	}
	// Same defence as the real backend: a claimed-target UUID that resolves
	// onto a protected disk means something is badly wrong, and mounting it
	// would hand the backup writer a path on the boot medium.
	if reason, prot := m.protectedSet(st)[idx]; prot {
		return "", protectedError(st.deviceNames()[idx], reason)
	}
	dir := filepath.Join(m.mountRoot, partUUID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for i, mt := range st.Mounts {
		if mt.PartUUID == partUUID {
			st.Mounts[i].MountPoint = dir
			return dir, nil
		}
	}
	st.Mounts = append(st.Mounts, mockMount{MountPoint: dir, PartUUID: partUUID})
	return dir, nil
}

func (m *MockBackend) Inspect(ctx context.Context, partUUID string) (*proto.StorageInspectAck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.loadState()
	if err != nil {
		return nil, err
	}
	idx, ok := diskHolding(st, partUUID)
	if !ok {
		return &proto.StorageInspectAck{
			OK: true, PartUUID: partUUID, Present: false,
			Refusal: proto.StorageRefusalNotFound,
			Detail:  "no attached disk carries that partition UUID",
		}, nil
	}
	mountPath, err := m.mountLocked(st, partUUID)
	if err != nil {
		return nil, err
	}
	if err := m.saveState(st); err != nil {
		return nil, err
	}
	ack := &proto.StorageInspectAck{
		OK:         true,
		Present:    true,
		PartUUID:   partUUID,
		DevicePath: st.deviceNames()[idx],
		MountPath:  mountPath,
	}
	for _, p := range st.Disks[idx].Partitions {
		if p.PartUUID != partUUID {
			continue
		}
		ack.FSType = p.FSType
		ack.FSLabel = p.Label
		ack.TotalBytes = p.SizeBytes
		// A believable made-up number. Real backends statfs.
		ack.FreeBytes = p.SizeBytes / 2
		if p.BackupSet != nil {
			set := *p.BackupSet
			if n, err := countGenerations(mountPath); err == nil {
				set.Generations = n
			}
			ack.BackupSet = &set
		}
	}
	return ack, nil
}

// randomPartUUID mints a GPT-shaped partition UUID.
func randomPartUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on any platform the agent runs on; if it
		// somehow did, a time-derived value is still unique enough to key a
		// mock target and is better than panicking inside a claim.
		return fmt.Sprintf("mock-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}
