package updater

import (
	"os"
	"path/filepath"
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
