package updater

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// realN100Status is the verbatim capture in rauc_test.go's
// TestParseRAUCStatus_RealImageOutputHasNoVersion (e3bench controlplane,
// 2026-08-12): booted from A (rootfs.0), primary rootfs.0, both slots good.
const realN100Status = `RAUC_SYSTEM_COMPATIBLE='rasputin-n100'
RAUC_SYSTEM_VARIANT='(null)'
RAUC_SYSTEM_BOOTED_BOOTNAME='A'
RAUC_BOOT_PRIMARY='rootfs.0'
RAUC_SYSTEM_SLOTS='rootfs.1 rootfs.0'
RAUC_SLOTS='1 2'
RAUC_SLOT_STATE_1='inactive'
RAUC_SLOT_CLASS_1='rootfs'
RAUC_SLOT_DEVICE_1='/dev/disk/by-partlabel/rootfs-1'
RAUC_SLOT_TYPE_1='raw'
RAUC_SLOT_BOOTNAME_1='B'
RAUC_SLOT_BOOT_STATUS_1='good'
RAUC_SLOT_STATE_2='booted'
RAUC_SLOT_CLASS_2='rootfs'
RAUC_SLOT_DEVICE_2='/dev/disk/by-partlabel/rootfs-0'
RAUC_SLOT_TYPE_2='raw'
RAUC_SLOT_BOOTNAME_2='A'
RAUC_SLOT_BOOT_STATUS_2='good'
RAUC_REPOS=''
`

// realPiCP1Status is verbatim `rauc status --output-format=shell` stdout from
// the e12bench controlplane cp-1 (Raspberry Pi 5, rauc 1.13, image
// 2026.09.4-dev.222, captured 2026-09-16) after its self-update committed:
// booted from B (rootfs.1, /proc/cmdline rauc.slot=B), primary rootfs.1, both
// slots good, no rauc-trial.pending marker. The Pi slot devices are
// by-partuuid paths, so the device says nothing about which slot is which: the
// slot names come only from RAUC_SYSTEM_SLOTS. This is the capture that
// exposed geekdojo-brain#448's Pi controlplane stuck in bus TLS offer.
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

func TestRAUCBootCommitted(t *testing.T) {
	cases := []struct {
		name    string
		status  string
		booted  proto.UpdateSlot
		pending bool
		want    bool
		why     string
	}{
		{"real capture: primary booted and good", realN100Status, proto.SlotA, false, true, "primary and good"},
		{"primary as a bootname", strings.Replace(realN100Status, "RAUC_BOOT_PRIMARY='rootfs.0'", "RAUC_BOOT_PRIMARY='A'", 1), proto.SlotA, false, true, "primary and good"},
		{"installed, not rebooted: primary is the other slot", strings.Replace(realN100Status, "RAUC_BOOT_PRIMARY='rootfs.0'", "RAUC_BOOT_PRIMARY='rootfs.1'", 1), proto.SlotA, false, false, "next boot leaves"},
		{"booted slot marked bad", strings.Replace(realN100Status, "RAUC_SLOT_BOOT_STATUS_2='good'", "RAUC_SLOT_BOOT_STATUS_2='bad'", 1), proto.SlotA, false, false, `"bad"`},
		{"Pi tryboot trial pending", realN100Status, proto.SlotA, true, false, "trial is pending"},
		{"booted slot unknown", realN100Status, proto.SlotUnknown, false, false, "unknown"},
		{"no primary", strings.Replace(realN100Status, "RAUC_BOOT_PRIMARY='rootfs.0'\n", "", 1), proto.SlotA, false, false, "no primary"},
		{"booted slot not described", realN100Status, proto.SlotB, false, false, "primary slot is rootfs.0, not the booted rootfs.1"},
		{"empty output", "", proto.SlotA, false, false, "no slot"},

		// Raspberry Pi (tryboot backend, by-partuuid devices): real captures.
		{"Pi cp-1 real capture: committed on B", realPiCP1Status, proto.SlotB, false, true, "slot rootfs.1 is primary and good"},
		{"Pi compute real capture: committed on A", realPiComputeStatus, proto.SlotA, false, true, "slot rootfs.0 is primary and good"},
		{"Pi trial pending", realPiCP1Status, proto.SlotB, true, false, "trial is pending"},
		{"Pi booted not primary", strings.Replace(realPiCP1Status, "RAUC_BOOT_PRIMARY='rootfs.1'", "RAUC_BOOT_PRIMARY='rootfs.0'", 1), proto.SlotB, false, false, "primary slot is rootfs.0, not the booted rootfs.1"},
		{"Pi kernel booted the non-primary slot", realPiCP1Status, proto.SlotA, false, false, "primary slot is rootfs.1, not the booted rootfs.0"},
		{"Pi booted slot marked bad", strings.Replace(realPiCP1Status, "RAUC_SLOT_BOOT_STATUS_1='good'", "RAUC_SLOT_BOOT_STATUS_1='bad'", 1), proto.SlotB, false, false, `the booted slot rootfs.1 has boot status "bad"`},
		{"Pi primary as a bootname", strings.Replace(realPiCP1Status, "RAUC_BOOT_PRIMARY='rootfs.1'", "RAUC_BOOT_PRIMARY='B'", 1), proto.SlotB, false, true, "primary and good"},
		// Slot names come from RAUC_SYSTEM_SLOTS alone. Without it nothing
		// names a slot, and unparseable must read as not committed.
		{"no slot names: not committed", strings.Replace(realPiCP1Status, "RAUC_SYSTEM_SLOTS='rootfs.1 rootfs.0'\n", "", 1), proto.SlotB, false, false, "no slot rootfs.1"},
		{"n100 device paths do not name slots", strings.Replace(realN100Status, "RAUC_SYSTEM_SLOTS='rootfs.1 rootfs.0'\n", "", 1), proto.SlotA, false, false, "no slot rootfs.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, why := raucBootCommitted(tc.status, tc.booted, tc.pending)
			if got != tc.want || !strings.Contains(why, tc.why) {
				t.Fatalf("raucBootCommitted = (%t, %q), want (%t, containing %q)", got, why, tc.want, tc.why)
			}
		})
	}
}

// An unreadable marker must not read as "no trial".
func TestFileExists_UncertaintyIsPresence(t *testing.T) {
	dir := t.TempDir()
	if fileExists(filepath.Join(dir, "absent")) {
		t.Fatal("absent file reported present")
	}
	p := filepath.Join(dir, "present")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !fileExists(p) {
		t.Fatal("present file reported absent")
	}
	if !fileExists(filepath.Join(p, "child-of-a-file")) {
		t.Fatal("an unstat-able path (ENOTDIR) read as absent")
	}
}

// The mock's lifecycle: fresh = committed; after a simulated install the
// pending slot holds it back; after the reboot the new slot is a trial until
// MarkGood.
func TestMockBootCommitted(t *testing.T) {
	st := &mockState{ActiveSlot: proto.SlotA, InactiveSlot: proto.SlotB, Marks: map[proto.UpdateSlot]proto.UpdateSlotState{proto.SlotA: proto.SlotStateGood}}
	if ok, why := mockBootCommitted(st); !ok {
		t.Fatalf("fresh state not committed: %s", why)
	}
	st.PendingSlot = proto.SlotB
	if ok, _ := mockBootCommitted(st); ok {
		t.Fatal("committed with an install pending")
	}
	st.PendingSlot, st.ActiveSlot, st.InactiveSlot = "", proto.SlotB, proto.SlotA
	st.Marks[proto.SlotB] = proto.SlotStateActive
	if ok, _ := mockBootCommitted(st); ok {
		t.Fatal("committed while trialling the new slot")
	}
	st.Marks[proto.SlotB] = proto.SlotStateGood
	if ok, why := mockBootCommitted(st); !ok {
		t.Fatalf("not committed after mark-good: %s", why)
	}
}

// The agent's whole precheck path on the Pi controlplane, against a fake rauc
// that prints cp-1's real capture and cp-1's real /proc/cmdline: the ack must
// say committed, because this is the bit bus TLS waits on (geekdojo-brain#448).
func TestRAUCPrecheck_PiControlplaneCommitted(t *testing.T) {
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
	oldMarker := trialPendingMarker
	trialPendingMarker = filepath.Join(dir, "rauc-trial.pending")
	t.Cleanup(func() { trialPendingMarker = oldMarker })

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
	if ack.BootCommitted == nil || !*ack.BootCommitted {
		t.Fatalf("BootCommitted = %s (%q), want true: cp-1 booted B, B is primary and good, no trial marker", fmtCommitted(ack.BootCommitted), ack.BootCommittedDetail)
	}

	// The same node with a tryboot trial armed is not committed.
	if err := os.WriteFile(trialPendingMarker, []byte("B\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ack, err = b.Precheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ack.BootCommitted == nil || *ack.BootCommitted || !strings.Contains(ack.BootCommittedDetail, "trial is pending") {
		t.Fatalf("BootCommitted = %s (%q), want false with a trial pending", fmtCommitted(ack.BootCommitted), ack.BootCommittedDetail)
	}
}

func fmtCommitted(b *bool) string {
	if b == nil {
		return "nil"
	}
	return strconv.FormatBool(*b)
}
