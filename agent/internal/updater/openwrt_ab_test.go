package updater

import (
	"context"
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
