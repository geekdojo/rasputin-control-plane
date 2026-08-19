package updater

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// ---- grubenv codec ----------------------------------------------------------

func TestGrubenvRoundTrip(t *testing.T) {
	kv := map[string]string{
		"ORDER": "B A",
		"A_OK":  "1", "A_TRY": "0",
		"B_OK": "1", "B_TRY": "1",
	}
	block, err := encodeGrubenv(kv, grubenvSize)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(block) != grubenvSize {
		t.Fatalf("block size = %d, want %d", len(block), grubenvSize)
	}
	if got := string(block[:len(grubenvSignature)]); got != grubenvSignature {
		t.Fatalf("missing signature, got %q", got)
	}
	// Trailing bytes must be '#' padding.
	if block[len(block)-1] != grubenvPadByte {
		t.Fatalf("last byte = %q, want padding", block[len(block)-1])
	}
	back := parseGrubenv(block)
	for k, want := range kv {
		if back[k] != want {
			t.Errorf("round-trip %s = %q, want %q", k, back[k], want)
		}
	}
}

func TestParseGrubenvCorruptDegradesToEmpty(t *testing.T) {
	// No signature, junk content: must not panic, returns best-effort map.
	got := parseGrubenv([]byte("garbage without signature\n"))
	if len(got) != 0 {
		t.Fatalf("expected empty map for unsigned junk, got %v", got)
	}
}

func TestEncodeGrubenvOverflow(t *testing.T) {
	kv := map[string]string{"BIG": string(make([]byte, 2048))}
	if _, err := encodeGrubenv(kv, grubenvSize); err == nil {
		t.Fatal("expected overflow error for oversized entries")
	}
}

// writeGrubenv must overwrite in place, preserving the file size (the GRUB
// save_env block-stability guarantee) and not recreating the inode.
func TestWriteGrubenvInPlacePreservesSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grubenv")
	// Pre-create a 1024-byte grubenv, as provisioning would.
	init, _ := encodeGrubenv(map[string]string{"ORDER": "A B", "A_OK": "1"}, grubenvSize)
	if err := os.WriteFile(path, init, 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)

	kv, err := readGrubenv(path)
	if err != nil {
		t.Fatal(err)
	}
	st := decodeAB(kv)
	st.order = []string{"B", "A"}
	st.ok["B"] = true
	if err := writeGrubenv(path, encodeAB(kv, st)); err != nil {
		t.Fatalf("write: %v", err)
	}
	after, _ := os.Stat(path)
	if before.Size() != after.Size() {
		t.Fatalf("size changed %d → %d (breaks GRUB save_env block list)", before.Size(), after.Size())
	}
	got := decodeAB(mustRead(t, path))
	if got.order[0] != "B" || !got.ok["B"] {
		t.Fatalf("state not persisted: %+v", got)
	}
}

func TestWriteGrubenvMissingFileErrors(t *testing.T) {
	err := writeGrubenv(filepath.Join(t.TempDir(), "nope"), map[string]string{"A_OK": "1"})
	if err == nil {
		t.Fatal("expected error writing to non-existent grubenv (must be pre-created)")
	}
}

func mustRead(t *testing.T, path string) map[string]string {
	t.Helper()
	kv, err := readGrubenv(path)
	if err != nil {
		t.Fatal(err)
	}
	return kv
}

// ---- slot math --------------------------------------------------------------

// Current-layout `block info`: p1 ESP (RASPUTINEFI vfat), p2 SEED (RASPUTIN-FW
// vfat, its own basic-data partition), p3 active squashfs (/rom), p4 inactive
// squashfs, p5 rootfs_data ext4. The seed's own partition shifts the rootfs
// numbers down one vs the legacy layout — everything resolves by label/mount,
// so that's fine (grub PARTLABEL, fstab label, block-info type/mount).
const benchBlockInfo = `/dev/nvme0n1p1: UUID="FE83-1305" LABEL="RASPUTINEFI" VERSION="FAT16" TYPE="vfat"
/dev/nvme0n1p2: UUID="AB12-CD34" LABEL="RASPUTIN-FW" VERSION="FAT16" TYPE="vfat"
/dev/nvme0n1p3: UUID="51056db3-397a8a76-74c1d738-d627d629" VERSION="4.0" MOUNT="/rom" TYPE="squashfs"
/dev/nvme0n1p4: UUID="51056db3-397a8a76-74c1d738-d627d629" VERSION="4.0" TYPE="squashfs"
/dev/nvme0n1p5: UUID="df1368c8-442e-4c78-a8e6-88ee060259e3" LABEL="rootfs_data" VERSION="1.0" MOUNT="/overlay" TYPE="ext4"`

// Legacy single-partition layout (pre-2026-08 firewalls): the ESP itself is
// labelled RASPUTIN-FW and carries the seed; no separate RASPUTINEFI partition.
const legacyBlockInfo = `/dev/nvme0n1p1: UUID="FE83-1305" LABEL="RASPUTIN-FW" VERSION="FAT16" TYPE="vfat"
/dev/nvme0n1p2: UUID="51056db3-397a8a76-74c1d738-d627d629" VERSION="4.0" MOUNT="/rom" TYPE="squashfs"
/dev/nvme0n1p3: UUID="51056db3-397a8a76-74c1d738-d627d629" VERSION="4.0" TYPE="squashfs"
/dev/nvme0n1p4: UUID="df1368c8-442e-4c78-a8e6-88ee060259e3" LABEL="rootfs_data" VERSION="1.0" MOUNT="/overlay" TYPE="ext4"`

func TestParseSquashfsSlots(t *testing.T) {
	active, inactive := parseSquashfsSlots(benchBlockInfo)
	if active != "/dev/nvme0n1p3" {
		t.Errorf("active = %q, want /dev/nvme0n1p3 (the /rom mount)", active)
	}
	if inactive != "/dev/nvme0n1p4" {
		t.Errorf("inactive = %q, want /dev/nvme0n1p4 (the other squashfs)", inactive)
	}
}

func TestParseESPDevice(t *testing.T) {
	// Current layout: the ESP is RASPUTINEFI, NOT the RASPUTIN-FW seed on p2.
	if dev := parseESPDevice(benchBlockInfo); dev != "/dev/nvme0n1p1" {
		t.Errorf("ESP = %q, want /dev/nvme0n1p1 (vfat RASPUTINEFI)", dev)
	}
	// The make-or-break: with both labels present, grubenv must land on the ESP
	// (RASPUTINEFI), never the seed (RASPUTIN-FW). A regression here silently
	// corrupts the seed and never activates a slot.
	if dev := parseESPDevice(benchBlockInfo); dev == "/dev/nvme0n1p2" {
		t.Fatal("parseESPDevice picked the RASPUTIN-FW SEED partition — grubenv would corrupt the seed and slot activation would fail")
	}
	// Legacy single-partition firewall: fall back to the RASPUTIN-FW ESP.
	if dev := parseESPDevice(legacyBlockInfo); dev != "/dev/nvme0n1p1" {
		t.Errorf("legacy ESP = %q, want /dev/nvme0n1p1 (vfat RASPUTIN-FW, no RASPUTINEFI present)", dev)
	}
	// No ESP line → empty (caller errors).
	if dev := parseESPDevice(`/dev/sda2: TYPE="ext4"`); dev != "" {
		t.Errorf("expected no ESP, got %q", dev)
	}
}

func TestBootedSlotFromCmdline(t *testing.T) {
	cases := map[string]proto.UpdateSlot{
		"root=PARTLABEL=rootfs-0 rootfstype=squashfs ro": proto.SlotA,
		"root=PARTLABEL=rootfs-1 ro":                     proto.SlotB,
		"rasputin.slot=A console=ttyS0":                  proto.SlotA,
		"rasputin.slot=B":                                proto.SlotB,
		"root=/dev/sda2 ro":                              proto.SlotUnknown,
	}
	for cmdline, want := range cases {
		if got := bootedSlotFromCmdline(cmdline); got != want {
			t.Errorf("bootedSlotFromCmdline(%q) = %v, want %v", cmdline, got, want)
		}
	}
}

// ---- full install → activate → mark-good / mark-bad through injected seams ---

// newTestBackend wires an OpenWrtABBackend with a pre-created grubenv, a fake
// /proc/cmdline booting slot A, and in-memory seams. Returns the backend and a
// helper to read the current A/B state.
func newTestBackend(t *testing.T) (*OpenWrtABBackend, func() abState, *[]int) {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "bundles"), 0o755); err != nil {
		t.Fatal(err)
	}
	grubenvPath := filepath.Join(dir, "grubenv")
	init, _ := encodeGrubenv(map[string]string{
		"ORDER": "A B", "A_OK": "1", "A_TRY": "0", "B_OK": "1", "B_TRY": "0",
	}, grubenvSize)
	if err := os.WriteFile(grubenvPath, init, 0o644); err != nil {
		t.Fatal(err)
	}
	cmdlinePath := filepath.Join(dir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("root=PARTLABEL=rootfs-0 ro\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	reboots := &[]int{}
	b := &OpenWrtABBackend{
		stateDir:    stateDir,
		grubenvPath: grubenvPath,
		procCmdline: cmdlinePath,
		versionFile: filepath.Join(dir, "image-version"),
		resolveDevice: func(slot string) (string, error) {
			// Return a temp file standing in for the slot's block device.
			return filepath.Join(dir, "slot-"+slot+".dev"), nil
		},
		writeSlot: func(ctx context.Context, src, dev string, _ func(string, int)) error {
			data, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			return os.WriteFile(dev, data, 0o644)
		},
		verifySig: func(ctx context.Context, _ string) error { return nil },
	}
	b.doReboot = func(delay int) { *reboots = append(*reboots, delay) }

	read := func() abState { return decodeAB(mustRead(t, grubenvPath)) }
	return b, read, reboots
}

func TestInstallActivatesInactiveSlotWithoutTouchingRollback(t *testing.T) {
	b, read, _ := newTestBackend(t)
	ctx := context.Background()

	// Stage a fake artifact + version sidecar.
	art := b.bundlePath("2026.07.0")
	if err := os.WriteFile(art, []byte("SQUASHFS-BYTES"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(art+".version", []byte("2026.07.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ver, err := b.Install(ctx, "2026.07.0", art, proto.SlotB, nil)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if ver != "2026.07.0" {
		t.Errorf("version = %q, want 2026.07.0 (from sidecar)", ver)
	}

	st := read()
	if st.order[0] != "B" {
		t.Errorf("ORDER head = %q, want B (activated)", st.order[0])
	}
	if !st.ok["B"] || st.try["B"] {
		t.Errorf("slot B should be OK+untried, got ok=%v try=%v", st.ok["B"], st.try["B"])
	}
	// Rollback target (A) must stay good.
	if !st.ok["A"] {
		t.Error("slot A OK flag was cleared — rollback target lost")
	}
	// The device got the artifact bytes.
	dev := filepath.Join(filepath.Dir(b.grubenvPath), "slot-B.dev")
	if data, _ := os.ReadFile(dev); string(data) != "SQUASHFS-BYTES" {
		t.Errorf("slot device content = %q, want artifact bytes", data)
	}
}

func TestMarkGoodResetsRunningSlotCounter(t *testing.T) {
	b, read, _ := newTestBackend(t)
	// Simulate a consumed try on the running slot (A).
	kv := mustRead(t, b.grubenvPath)
	st := decodeAB(kv)
	st.try["A"] = true
	if err := writeGrubenv(b.grubenvPath, encodeAB(kv, st)); err != nil {
		t.Fatal(err)
	}
	if err := b.MarkGood(context.Background(), "x"); err != nil {
		t.Fatalf("mark-good: %v", err)
	}
	got := read()
	if !got.ok["A"] || got.try["A"] {
		t.Errorf("after mark-good slot A should be OK+untried, got ok=%v try=%v", got.ok["A"], got.try["A"])
	}
}

func TestMarkGoodOnBootResetsConsumedTry(t *testing.T) {
	b, read, reboots := newTestBackend(t)
	// grub.cfg consumed a try on the running slot (A) this boot.
	kv := mustRead(t, b.grubenvPath)
	st := decodeAB(kv)
	st.try["A"] = true
	if err := writeGrubenv(b.grubenvPath, encodeAB(kv, st)); err != nil {
		t.Fatal(err)
	}
	if err := b.MarkGoodOnBoot(context.Background()); err != nil {
		t.Fatalf("boot mark-good: %v", err)
	}
	got := read()
	if !got.ok["A"] || got.try["A"] {
		t.Errorf("after boot mark-good running slot A should be OK+untried, got ok=%v try=%v", got.ok["A"], got.try["A"])
	}
	if len(*reboots) != 0 {
		t.Errorf("boot mark-good must not reboot, got %d", len(*reboots))
	}
}

func TestMarkBadClearsRunningSlotAndReboots(t *testing.T) {
	b, read, reboots := newTestBackend(t)
	if err := b.MarkBad(context.Background(), "x", "health failed"); err != nil {
		t.Fatalf("mark-bad: %v", err)
	}
	got := read()
	if got.ok["A"] {
		t.Error("after mark-bad running slot A should have OK=0 so GRUB boots B")
	}
	if len(*reboots) != 1 {
		t.Errorf("mark-bad should trigger exactly one reboot, got %d", len(*reboots))
	}
}

func TestPrecheckReportsBootedSlotAndVersion(t *testing.T) {
	b, _, _ := newTestBackend(t)
	if err := os.WriteFile(b.versionFile, []byte("2026.06.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ack, err := b.Precheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ack.OK || ack.ActiveSlot != proto.SlotA || ack.InactiveSlot != proto.SlotB {
		t.Errorf("precheck = %+v, want OK active=a inactive=b", ack)
	}
	if ack.CurrentVersion != "2026.06.0" {
		t.Errorf("version = %q, want 2026.06.0", ack.CurrentVersion)
	}
	if ack.Backend != "openwrt-ab" {
		t.Errorf("backend = %q, want openwrt-ab", ack.Backend)
	}
}

// Reboot clamps delaySeconds to a 3s default outside the (0, 30] window and
// passes the effective delay through to doReboot (both the return value and the
// scheduled reboot). Guards both bounds of the
// `delaySeconds <= 0 || delaySeconds > 30` clamp (openwrt_ab.go:358):
//   - 358:18 boundary (`<= 0` → `< 0`) and negation (`<= 0` → `> 0`): the in=0
//     case would slip through unclamped (returns 0) or wrongly clamp in=5.
//   - 358:39 boundary (`> 30` → `>= 30`) and negation (`> 30` → `<= 30`): the
//     in=30 case would be wrongly clamped to 3, and in=31 slip through as 31.
func TestRebootClampsDelaySeconds(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{in: 0, want: 3},   // non-positive → default
		{in: 5, want: 5},   // inside the window → unchanged
		{in: 30, want: 30}, // upper bound is inclusive
		{in: 31, want: 3},  // above the window → default
	}
	for _, c := range cases {
		b, _, reboots := newTestBackend(t)
		got, err := b.Reboot(context.Background(), "bundle", c.in)
		if err != nil {
			t.Fatalf("Reboot(%d): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("Reboot(%d) returned %d, want %d", c.in, got, c.want)
		}
		if len(*reboots) != 1 || (*reboots)[0] != c.want {
			t.Errorf("Reboot(%d) scheduled reboots %v, want [%d]", c.in, *reboots, c.want)
		}
	}
}

// installedVersion feeds ADR-0005 Decision 2's conjunct (c). Returning the
// bundle's sha256 when no version is available made that comparison
// permanently unsatisfiable: on e3bench 2026-08-12 the node correctly reported
// "2026.08.2-dev.83" and verify compared it against "7dc0657846367cec…", so
// EVERY openwrt-ab update failed with version_mismatch. Empty is the honest
// answer — conjunct (c) is three-valued and degrades on unknown (Decision 3).
func TestInstalledVersion_UnknownIsEmptyNotTheBundleHash(t *testing.T) {
	dir := t.TempDir()
	b := &OpenWrtABBackend{}
	localPath := filepath.Join(dir, "bundle.rootfs")

	// The bundle sha is no longer even reachable from here — the parameter that
	// carried it is gone, which is the strongest form the fix can take. Kept as
	// a value to compare against so the test still says what went wrong.
	const bundleID = "7dc0657846367cec8c9f328e513e4d3af297864119186651605632e4f72e16ea"
	got := b.installedVersion(localPath)
	if got == bundleID {
		t.Fatal("returned the bundle sha as a version — a wrong answer wearing a right answer's type; conjunct (c) can only ever fail on it")
	}
	if got != "" {
		t.Errorf("installedVersion = %q, want \"\" so the api keeps its own manifest version (#86)", got)
	}

	// And when the sidecar IS present it must be preferred — the fix must not
	// make a knowable version unknowable.
	if err := os.WriteFile(localPath+".version", []byte(" 2026.08.2-dev.83 \n"), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	if got := b.installedVersion(localPath); got != "2026.08.2-dev.83" {
		t.Errorf("installedVersion = %q, want the sidecar value trimmed", got)
	}
}

// ---- defaultWriteSlot -------------------------------------------------------

// defaultWriteSlot streams a squashfs into the raw inactive-slot device — the
// byte-mover of an OpenWrt A/B install. Its copy must be exact and its 10→90
// progress sweep must actually track the write. Nothing exercised it before
// (production tests inject a mock writeSlot), so a wrong buffer copy or a broken
// progress calc would ship silently.
func TestDefaultWriteSlotCopiesExactlyAndReportsProgress(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "bundle.rootfs")
	dst := filepath.Join(dir, "slot.img")

	// Span more than one 1 MiB read buffer, with distinctive non-repeating
	// content, so a truncated/offset copy OR an early loop break (mistaking a
	// mid-stream nil error for EOF) leaves the destination the wrong size.
	content := make([]byte, (1<<20)+4096)
	for i := range content {
		content[i] = byte(i*7 + 3)
	}
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	// The device must already exist: defaultWriteSlot opens it O_WRONLY, no create.
	if err := os.WriteFile(dst, nil, 0o644); err != nil {
		t.Fatalf("create dst: %v", err)
	}

	type step struct {
		phase string
		pct   int
	}
	var steps []step
	progress := func(phase string, pct int) { steps = append(steps, step{phase, pct}) }

	if err := defaultWriteSlot(context.Background(), src, dst, progress); err != nil {
		t.Fatalf("defaultWriteSlot: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("copied %d bytes, want an exact %d-byte copy of the source", len(got), len(content))
	}
	if len(steps) == 0 {
		t.Fatal("no progress reported; the install UI would show a frozen bar")
	}
	for _, s := range steps {
		if s.phase != "write" {
			t.Errorf("progress phase = %q, want \"write\"", s.phase)
		}
	}
	// After the last chunk written==total, so the sweep is pinned at its top end:
	// 10 + 80*written/total = 90. This exact value is what kills the arithmetic
	// mutations in 10+int(80*written/total) (e.g. + to -, * to /) and the
	// "total > 0" guard being dropped.
	if last := steps[len(steps)-1].pct; last != 90 {
		t.Errorf("final progress = %d, want 90 (10 + 80*written/total at written==total)", last)
	}
}

// A cancelled context must abort the write before it moves bytes — an install
// that keeps streaming to the inactive slot after the saga gave up is exactly
// the kind of half-written slot the A/B design exists to avoid.
func TestDefaultWriteSlotHonorsContextCancellation(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "bundle.rootfs")
	dst := filepath.Join(dir, "slot.img")
	if err := os.WriteFile(src, make([]byte, 2048), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := os.WriteFile(dst, nil, 0o644); err != nil {
		t.Fatalf("create dst: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before the first loop turn

	err := defaultWriteSlot(ctx, src, dst, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// The per-iteration ctx.Err() gate must fire first: nothing should reach the slot.
	if got, _ := os.ReadFile(dst); len(got) != 0 {
		t.Errorf("wrote %d bytes to the slot after cancellation, want 0", len(got))
	}
}
