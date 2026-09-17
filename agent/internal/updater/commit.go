package updater

import (
	"fmt"
	"os"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Is the build this node runs COMMITTED on its A/B slot?
//
// The controlplane asks, over update.precheck, before its bus TLS starts
// handing out pins (geekdojo/geekdojo-brain#448). A delivered pin cannot be
// taken back over the bus, so a build that could still be rolled back to a
// pre-TLS one must not start distributing it. "Committed" therefore means: a
// plain reboot boots this same slot again, and no trial is armed or running.
//
// The rules, per bootloader, come from the OS image (rasputin-os):
//
//   - GRUB (n100): `rauc status` names the primary slot (RAUC_BOOT_PRIMARY,
//     the head of grubenv ORDER) and each slot's boot status (<bootname>_OK).
//     Committed iff the primary IS the booted slot and the booted slot is
//     good. An install that activated the other slot moves the primary, so
//     "installed, not yet rebooted" reads as not committed. After a trial
//     boot rasputin-mark-good.service marks the slot good at OS-up, so this
//     rule alone cannot see a saga that is about to mark it BAD; the api adds
//     the job-ledger half (no self-update in flight) for exactly that.
//   - Raspberry Pi tryboot: while a trial is pending the backend reports the
//     pending slot as primary and presumes it good, so primary==booted and
//     good does not distinguish a trial from a commit. The trial marker on the
//     selector FAT (rauc-trial.pending) does: present means a trial is armed
//     or running, and the next plain reboot may land on the other slot.
//
// Anything unparseable is reported as NOT committed, with the reason.

// trialPendingMarker is the Pi tryboot backend's "trial armed, not committed"
// marker (rpi-tryboot-backend.sh PENDING). Package var so tests can point it
// elsewhere; it sits beside trybootMarker on the same FAT.
var trialPendingMarker = "/run/rasputin-seed/rauc-trial.pending"

// raucBootCommitted decides commit from `rauc status --output-format=shell`
// output and the slot the kernel says it booted.
func raucBootCommitted(statusOut string, booted proto.UpdateSlot, trialPending bool) (bool, string) {
	kv := parseRAUCShell(statusOut)
	slots := raucSlots(kv)
	bootedName := map[proto.UpdateSlot]string{proto.SlotA: "rootfs.0", proto.SlotB: "rootfs.1"}[booted]
	if bootedName == "" {
		return false, "the booted slot is unknown"
	}
	var bootedSlot *raucSlot
	for i := range slots {
		if slots[i].name == bootedName {
			bootedSlot = &slots[i]
		}
	}
	if bootedSlot == nil {
		return false, fmt.Sprintf("rauc status describes no slot %s", bootedName)
	}
	primary := kv["RAUC_BOOT_PRIMARY"]
	if primary == "" {
		return false, "rauc status names no primary slot"
	}
	// RAUC prints the primary as a slot name; accept a bootname too.
	if primary != bootedSlot.name && primary != bootedSlot.bootname {
		return false, fmt.Sprintf("the bootloader's primary slot is %s, not the booted %s: an update is installed and the next boot leaves this build", primary, bootedSlot.name)
	}
	if bootedSlot.status != "good" {
		return false, fmt.Sprintf("the booted slot %s has boot status %q, not good", bootedSlot.name, bootedSlot.status)
	}
	if trialPending {
		return false, "a tryboot trial is pending on the selector FAT: this build is not committed until the update saga marks it good"
	}
	return true, fmt.Sprintf("slot %s is primary and good, and no trial is pending", bootedSlot.name)
}

// fileExists reports whether path exists. An unreadable stat reads as present:
// for a "trial pending" marker, uncertainty must not read as committed.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

// mockBootCommitted is the mock backend's model of the same fact: no install
// pending and the active slot marked good. A fresh mock state is committed; a
// simulated reboot into a new slot marks it active (a trial) until MarkGood.
func mockBootCommitted(st *mockState) (bool, string) {
	if st.PendingSlot != "" && st.PendingSlot != proto.SlotUnknown {
		return false, fmt.Sprintf("mock: an install to slot %s is pending", st.PendingSlot)
	}
	if mark := st.Marks[st.ActiveSlot]; mark != proto.SlotStateGood {
		return false, fmt.Sprintf("mock: active slot %s is %q, not good", st.ActiveSlot, mark)
	}
	return true, fmt.Sprintf("mock: active slot %s is good and nothing is pending", st.ActiveSlot)
}
