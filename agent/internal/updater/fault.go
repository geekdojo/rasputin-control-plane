package updater

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Fault injection for the update path.
//
// WHY THIS EXISTS. Three failure shapes in the update saga cannot be produced
// by any healthy update, and every one of them is a shape the control plane
// claims to handle:
//
//   - a node that ACKS the reboot and then does not reboot — bench node c13,
//     the false-rollback class the whole verify contract exists to kill;
//   - a node that reboots and is never seen again — bench node c08, the
//     stranded-node case behind #57 / #72;
//   - a node that comes back but fails its health battery — the mark-bad
//     branch, which unconfirms inventory rather than recording a version.
//
// Before this seam existed each of those meant hand-hacking a bench node over
// SSH, which is unrepeatable by construction, so all three sat in "reasoned
// about, not run" for weeks. They are now dispatchable from the control plane
// like any other update.
//
// WHY IT IS IN THE RELEASE BINARY rather than behind a build tag. A build tag
// means the bench exercises a different binary than production — the fault
// paths would be the only thing tested and the shipped code would be the only
// thing that matters, which is exactly backwards. Arming this requires root on
// the node (to write node.env) plus a deliberate restart; anyone holding that
// can already do strictly worse by hand. The cost of the tag is a bench that
// cannot prove anything about what ships.
//
// It is off unless explicitly armed, it announces itself loudly at startup on
// every armed boot, and an unrecognised value is a hard failure rather than a
// silent no-op — a typo must not read as "no fault injected".
type Fault string

const (
	// FaultNone is the unset, shipping default.
	FaultNone Fault = ""

	// FaultNoReboot acks the reboot RPC, publishes the rebooting event, and
	// then does not reboot. The agent keeps answering prechecks on the SAME
	// boot id, which is precisely what c13 looked like from the api's side.
	// Expected outcome: step 5 polls until its deadline and fails with "node
	// never rebooted: still answering on boot <id>" — and writes NO rolled_back
	// row, because not-rebooted-yet and rebooted-and-reverted are opposites.
	FaultNoReboot Fault = "no-reboot"

	// FaultDieAfterReboot reboots normally but arms a one-shot marker first.
	// On the next start the agent consumes the marker and comes up MUTE: no
	// registration, no update subscriptions. The node is running and healthy
	// and the control plane can never see it again — c08.
	// Expected outcome: verify cannot reach the node, inventory is unconfirmed
	// rather than optimistically written, and the update check reports
	// needs_attention instead of green.
	FaultDieAfterReboot Fault = "die-after-reboot"

	// FaultFailHealth answers diag.health as unhealthy. The node reboots and
	// verifies normally, then fails conjunct (d).
	// Expected outcome: mark-bad is sent, the row is rolled_back, and inventory
	// is UNCONFIRMED rather than recording either version — the node is on the
	// new slot but about to revert, so both available answers are wrong.
	FaultFailHealth Fault = "fail-health"
)

// FaultEnv is the environment variable that arms fault injection. On the
// appliance it is set in /var/lib/rasputin/node.env and takes effect on the
// next agent start.
const FaultEnv = "RASPUTIN_DEBUG_UPDATE_FAULT"

// muteMarkerName is written next to the agent's other state so it survives the
// reboot it is meant to span, and is consumed on the far side.
const muteMarkerName = "fault-mute-after-reboot"

// FaultFromEnv reads the armed fault, or FaultNone when unset.
//
// An unrecognised value returns an error rather than defaulting to "no fault":
// a mistyped fault that silently injects nothing turns a test that proves
// something into a test that proves nothing while still reporting success.
func FaultFromEnv() (Fault, error) {
	raw := strings.TrimSpace(os.Getenv(FaultEnv))
	switch Fault(raw) {
	case FaultNone:
		return FaultNone, nil
	case FaultNoReboot, FaultDieAfterReboot, FaultFailHealth:
		return Fault(raw), nil
	default:
		return FaultNone, &UnknownFaultError{Value: raw}
	}
}

// UnknownFaultError is returned for an unrecognised FaultEnv value.
type UnknownFaultError struct{ Value string }

func (e *UnknownFaultError) Error() string {
	return "unknown " + FaultEnv + " value " + quote(e.Value) + " (expected one of: " +
		string(FaultNoReboot) + ", " + string(FaultDieAfterReboot) + ", " + string(FaultFailHealth) + ")"
}

func quote(s string) string { return `"` + s + `"` }

// Announce logs an armed fault. Called once at startup and deliberately shouty:
// a node silently carrying a fault injector is worse than no injector at all,
// and this line is what a confused operator greps for first.
func (f Fault) Announce() {
	if f == FaultNone {
		return
	}
	log.Printf("rasputin-agent: ⚠️  UPDATE FAULT INJECTION ARMED: %s=%s — this node will deliberately "+
		"misbehave during its next update. Unset it in node.env and restart to disarm.", FaultEnv, f)
}

// ArmMuteAfterReboot writes the one-shot marker consumed by TakeMuteAfterReboot.
// Best-effort: a marker we could not write means the fault does not fire, which
// is loud in the test rather than silently wrong.
func ArmMuteAfterReboot(stateDir string) error {
	return os.WriteFile(filepath.Join(stateDir, muteMarkerName), []byte("armed\n"), 0o644)
}

// TakeMuteAfterReboot reports whether the marker was present and removes it, so
// the fault fires for exactly one boot. Consuming it here rather than leaving it
// in place matters: a node that stayed mute forever would need a hand-fix to
// rejoin, and the point is to reproduce c08, not to brick a bench node.
func TakeMuteAfterReboot(stateDir string) bool {
	path := filepath.Join(stateDir, muteMarkerName)
	if _, err := os.Stat(path); err != nil {
		return false
	}
	if err := os.Remove(path); err != nil {
		// Removing failed, so the next boot would be mute too. Say so rather
		// than leaving a node quietly stuck.
		log.Printf("rasputin-agent: ⚠️  could not consume %s (%v) — this node will stay MUTE until it is deleted by hand", path, err)
	}
	return true
}
