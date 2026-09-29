package updater

import (
	"context"
	"encoding/json"
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

// realPiCP1Status is verbatim `rauc status --output-format=shell` stdout from
// the e12bench controlplane cp-1 (Raspberry Pi 5, rauc 1.13, image
// 2026.09.4-dev.222, captured 2026-09-16) after its self-update committed:
// booted from B (rootfs.1, /proc/cmdline rauc.slot=B), primary rootfs.1, both
// slots good, no rauc-trial.pending marker. The Pi slot devices are
// by-partuuid paths, so the device says nothing about which slot is which: the
// slot names come only from RAUC_SYSTEM_SLOTS. It is the only verbatim
// capture from a Pi 5 on rauc 1.13 in the tree.
const realPiCP1Status = `RAUC_SYSTEM_COMPATIBLE='rasputin-rpi-arm64'
RAUC_SYSTEM_VARIANT='(null)'
RAUC_SYSTEM_BOOTED_BOOTNAME='B'
RAUC_BOOT_PRIMARY='rootfs.1'
RAUC_SYSTEM_SLOTS='rootfs.1 rootfs.0'
RAUC_SLOTS='1 2'
RAUC_SLOT_STATE_1='booted'
RAUC_SLOT_CLASS_1='rootfs'
RAUC_SLOT_DEVICE_1='/dev/disk/by-partuuid/52415350-06'
RAUC_SLOT_TYPE_1='raw'
RAUC_SLOT_BOOTNAME_1='B'
RAUC_SLOT_PARENT_1=''
RAUC_SLOT_MOUNTPOINT_1=''
RAUC_SLOT_BOOT_STATUS_1='good'
RAUC_SLOT_STATE_2='inactive'
RAUC_SLOT_CLASS_2='rootfs'
RAUC_SLOT_DEVICE_2='/dev/disk/by-partuuid/52415350-05'
RAUC_SLOT_TYPE_2='raw'
RAUC_SLOT_BOOTNAME_2='A'
RAUC_SLOT_PARENT_2=''
RAUC_SLOT_MOUNTPOINT_2=''
RAUC_SLOT_BOOT_STATUS_2='good'
RAUC_REPOS=''
`

// realPiCP1Cmdline is cp-1's /proc/cmdline from the same capture.
const realPiCP1Cmdline = "reboot=w coherent_pool=1M 8250.nr_uarts=1 pci=pcie_bus_safe snd_bcm2835.enable_compat_alsa=0 snd_bcm2835.enable_hdmi=1 bcm2708_fb.fbwidth=1920 bcm2708_fb.fbheight=1080 bcm2708_fb.fbdepth=16 bcm2708_fb.fbswap=1 smsc95xx.macaddr=98:FE:54:02:A1:A0 vc_mem.mem_base=0x3fc00000 vc_mem.mem_size=0x40000000  root=PARTUUID=52415350-06 rootfstype=squashfs ro rootwait rauc.slot=B audit=0 cgroup_enable=memory cgroup_memory=1 console=ttyS0,115200 console=tty1\n"

// realPiComputeStatus is the same capture from e12bench cp-compute1 (Raspberry
// Pi, rauc 1.13, image 2026.09.2-dev.216, 2026-09-16): booted from A
// (rootfs.0, rauc.slot=A), primary rootfs.0, both slots good, no marker. The
// second sample: the other slot booted, the same index→name order.
const realPiComputeStatus = `RAUC_SYSTEM_COMPATIBLE='rasputin-rpi-arm64'
RAUC_SYSTEM_VARIANT='(null)'
RAUC_SYSTEM_BOOTED_BOOTNAME='A'
RAUC_BOOT_PRIMARY='rootfs.0'
RAUC_SYSTEM_SLOTS='rootfs.1 rootfs.0'
RAUC_SLOTS='1 2'
RAUC_SLOT_STATE_1='inactive'
RAUC_SLOT_CLASS_1='rootfs'
RAUC_SLOT_DEVICE_1='/dev/disk/by-partuuid/52415350-06'
RAUC_SLOT_TYPE_1='raw'
RAUC_SLOT_BOOTNAME_1='B'
RAUC_SLOT_PARENT_1=''
RAUC_SLOT_MOUNTPOINT_1=''
RAUC_SLOT_BOOT_STATUS_1='good'
RAUC_SLOT_STATE_2='booted'
RAUC_SLOT_CLASS_2='rootfs'
RAUC_SLOT_DEVICE_2='/dev/disk/by-partuuid/52415350-05'
RAUC_SLOT_TYPE_2='raw'
RAUC_SLOT_BOOTNAME_2='A'
RAUC_SLOT_PARENT_2=''
RAUC_SLOT_MOUNTPOINT_2=''
RAUC_SLOT_BOOT_STATUS_2='good'
RAUC_REPOS=''
`

// TC-517-43: the agent's whole precheck path on the Pi controlplane, against a
// fake rauc that prints cp-1's real capture and cp-1's real /proc/cmdline: the
// ack says B is active and A inactive, and carries no bootCommitted key — that
// fact existed only for the bus TLS ladder (geekdojo/geekdojo-brain#517).
func TestRAUCPrecheck_PiControlplaneSlots(t *testing.T) {
	if runtimeIsWindows() {
		t.Skip("fake-rauc shim is /bin/sh; skipped on Windows")
	}
	dir := t.TempDir()
	capture := filepath.Join(dir, "status.txt")
	if err := os.WriteFile(capture, []byte(realPiCP1Status), 0o600); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(dir, "rauc")
	if err := writeFile755(shim, "#!/bin/sh\ncat '"+capture+"'\n"); err != nil {
		t.Fatal(err)
	}
	cmdline := filepath.Join(dir, "cmdline")
	if err := os.WriteFile(cmdline, []byte(realPiCP1Cmdline), 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := newRAUCBackend(t.TempDir(), shim)
	if err != nil {
		t.Fatal(err)
	}
	b.procCmdline = cmdline

	ack, err := b.Precheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ack.OK || ack.ActiveSlot != proto.SlotB || ack.InactiveSlot != proto.SlotA {
		t.Fatalf("ack = %+v, want OK on B with A inactive", ack)
	}
	raw, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"bootCommitted", "bootCommittedDetail"} {
		if _, ok := keys[k]; ok {
			t.Errorf("the precheck ack still carries %q: %s", k, raw)
		}
	}
}
