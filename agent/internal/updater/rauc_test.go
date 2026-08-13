package updater

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// ⚠️ THE #88 REGRESSION, and it is the bench scenario verbatim.
//
// RAUC_BOOT_PRIMARY is the bootloader's INTENT, read from a file the UPDATE
// writes (grubenv on the n100, autoboot.txt on the Pi). `rauc install`
// activates the target at install time, so between the install and the reboot
// — and PERMANENTLY on a node whose reboot never happened — it names a slot the
// kernel is not running. The next update is then judged against that stale
// note and a healthy node is recorded `rolled_back`.
//
// Measured on e3bench 2026-08-13: booted rootfs-1 (B) with
// RAUC_BOOT_PRIMARY='rootfs.0' (A). On the Pi the false verdict went on to
// cause a REAL rollback, because there the saga's mark-good is the sole
// committer — so this is a durability fix on arm64, not just a cosmetic one.
//
// /proc/cmdline cannot go stale: it is not stored, it is what the running
// kernel was handed, and each slot's cmdline statically roots that slot.
func TestRAUCPrecheck_CmdlineOutranksStaleBootPrimary(t *testing.T) {
	// The exact divergence captured on the bench.
	const status = `RAUC_BOOT_PRIMARY='rootfs.0'
RAUC_SLOTS='1 2'
RAUC_SLOT_STATE_1='booted'
RAUC_SLOT_STATE_2='inactive'
`
	for _, tc := range []struct {
		name     string
		cmdline  string
		wantSlot proto.UpdateSlot
	}{
		// n100: grub.cfg roots the slot by partlabel.
		{"n100 booted B while intent says A", "root=PARTLABEL=rootfs-1 ro quiet", proto.SlotB},
		// Pi: cmdline.txt carries rauc.slot. Bench value from e3bench-compute2.
		// Verbatim from e3bench-compute2 (Pi 4, dev.160), slot letter flipped to B
		// so it disagrees with the stale intent above. Note PARTUUID, not
		// PARTLABEL: on the Pi the slot is only knowable from rauc.slot.
		{"pi booted B while intent says A", "root=PARTUUID=52415350-06 rootfstype=squashfs ro rootwait rauc.slot=B audit=0 console=ttyS0,115200 console=tty1", proto.SlotB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cmdPath := filepath.Join(dir, "cmdline")
			if err := os.WriteFile(cmdPath, []byte(tc.cmdline), 0o644); err != nil {
				t.Fatal(err)
			}
			r := &RAUCBackend{procCmdline: cmdPath}
			parsed := parseRAUCStatus(status)
			if parsed.activeSlot != proto.SlotA {
				t.Fatalf("fixture is not exercising the divergence: RAUC alone says %q, want a", parsed.activeSlot)
			}

			active, inactive := parsed.activeSlot, parsed.inactiveSlot
			if b, err := os.ReadFile(r.procCmdline); err == nil {
				if booted := bootedSlotFromCmdline(string(b)); booted != proto.SlotUnknown {
					active, inactive = booted, otherSlot(booted)
				}
			}
			if active != tc.wantSlot {
				t.Errorf("ActiveSlot = %q, want %q — the kernel says which slot is RUNNING; "+
					"RAUC_BOOT_PRIMARY only says which one the bootloader intends next (#88)", active, tc.wantSlot)
			}
			if inactive == active {
				t.Errorf("InactiveSlot = %q, must be the other slot", inactive)
			}
		})
	}
}

// A cmdline with no slot marker must NOT degrade to SlotUnknown. Verify's
// conjunct (b) compares ActiveSlot against the target, so unknown reads as a
// mismatch and produces the exact false rollback this change removes. RAUC's
// intent is wrong only inside the install→reboot window; unknown is wrong
// always, so intent is the better last resort.
func TestRAUCPrecheck_UnparseableCmdlineKeepsRAUCsAnswer(t *testing.T) {
	const status = `RAUC_BOOT_PRIMARY='rootfs.0'
RAUC_SLOTS='1 2'
RAUC_SLOT_STATE_1='booted'
`
	dir := t.TempDir()
	cmdPath := filepath.Join(dir, "cmdline")
	if err := os.WriteFile(cmdPath, []byte("root=/dev/sda2 ro"), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed := parseRAUCStatus(status)
	active := parsed.activeSlot
	if b, err := os.ReadFile(cmdPath); err == nil {
		if booted := bootedSlotFromCmdline(string(b)); booted != proto.SlotUnknown {
			active = booted
		}
	}
	if active != proto.SlotA {
		t.Errorf("ActiveSlot = %q, want RAUC's answer kept — degrading to unknown here would itself "+
			"trip conjunct (b) and manufacture a rollback", active)
	}
}
