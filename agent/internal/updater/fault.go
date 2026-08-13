package updater

import (
	"log"
	"os"
	"strings"
)

// Fault injection for the update path.
//
// WHY THIS EXISTS. Two failure shapes in the update saga cannot be produced by
// any healthy update, and both are shapes the control plane claims to handle:
//
//   - a node that ACKS the reboot and then does not reboot — bench node c13,
//     the false-rollback class the whole verify contract exists to kill;
//   - a node that comes back but fails its health battery — the mark-bad
//     branch, which unconfirms inventory rather than recording a version.
//
// Before this seam existed each of those meant hand-hacking a bench node over
// SSH, which is unrepeatable by construction, so both sat in "reasoned about,
// not run" for weeks. They are now dispatchable from the control plane like
// any other update.
//
// WHAT IS DELIBERATELY NOT HERE. There was a third fault, die-after-reboot,
// which armed an on-disk marker before rebooting so the agent came back mute —
// bench node c08, the node that reboots and is never seen again. It is gone,
// and the reasons are worth keeping because they are the reasons not to add
// another one like it:
//
//   - It was the only fault carrying state across a process boundary, and that
//     state promptly diverged from where startup looked for it. The fault
//     silently never fired and the round it was meant to break returned a clean
//     `committed` in 63 seconds — a test that proved nothing while reporting
//     success. See PR #113, which fixed the path and did not fix the design.
//   - It was the only fault whose trigger was not the environment variable, so
//     a stale marker could mute a node with the seam disarmed.
//   - It was unnecessary. `systemctl mask rasputin-agent` before dispatch
//     produces c08 with no product code at all, and produces it more faithfully:
//     a real c08 node did not answer diag.ping either, whereas a mute agent
//     still did.
//
// The rule that falls out: a fault may not outlive the process that arms it. If
// a scenario needs to span a reboot, it belongs in the bench procedure, not in
// the shipped binary.
//
// WHY WHAT REMAINS IS IN THE RELEASE BINARY rather than behind a build tag. A
// build tag means the bench exercises a different binary than production — the
// fault paths would be the only thing tested and the shipped code would be the
// only thing that matters, which is exactly backwards. The cost of the tag is a
// bench that cannot prove anything about what ships.
//
// The seam is off unless explicitly armed, it refuses to arm at all on a
// non-dev image, and it announces itself loudly at startup on every armed boot.
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

// Arm resolves the armed fault for this process. It is the ONLY way to arm one.
//
// ⚠️ It cannot fail and it cannot exit, and that is the entire point.
//
// The first version of this returned an error on an unrecognised value and the
// caller called log.Fatalf on it, reasoning that a mistyped fault which
// silently injects nothing turns a test that proves something into a test that
// proves nothing. That reasoning was about bench integrity and was never
// re-checked against a customer appliance, where rasputin-agent.service carries
// Restart=always / RestartSec=2 and node.env is hand-edited to flip channels. A
// single typo there does not fail a test — it permanently prevents the agent
// from starting, on a box reachable only by SSH. The seam existed to find that
// class of bug and shipped one instead.
//
// So the signature refuses the mistake rather than documenting it: there is no
// error for a caller to be fatal on, and no exported parse the caller could
// reach around this. Bench integrity is preserved by the two gates below, both
// of which log loudly, plus Announce — and the bench procedure confirms the
// ARMED line before dispatching, because a fault that failed to arm produces a
// clean `committed` for EVERY fault, not just the one that got it wrong once.
//
// imageVersion is the running OS image (host.ImageVersion()). A fault will not
// arm on a released image; only -dev. builds and unversioned dev checkouts.
func Arm(imageVersion string) Fault {
	raw := strings.TrimSpace(os.Getenv(FaultEnv))
	if raw == "" {
		return FaultNone
	}

	fault, err := parseFault(raw)
	if err != nil {
		log.Printf("rasputin-agent: ⚠️  %v — NO fault is armed and this node will behave normally. "+
			"If you are running a bench round, fix %s and restart before dispatching.", err, FaultEnv)
		return FaultNone
	}

	// A released image must not be faultable at all, however node.env got
	// edited. The bench runs -dev. images by definition, so this costs the
	// seam nothing and takes an appliance out of reach of it entirely.
	if !isDevImage(imageVersion) {
		log.Printf("rasputin-agent: ⚠️  %s=%s IGNORED: fault injection is refused on the released image %q "+
			"(only -dev. builds). This node will behave normally.", FaultEnv, fault, imageVersion)
		return FaultNone
	}

	return fault
}

// parseFault maps a raw value to a Fault. Unexported: see Arm.
func parseFault(raw string) (Fault, error) {
	switch Fault(raw) {
	case FaultNoReboot, FaultFailHealth:
		return Fault(raw), nil
	default:
		return FaultNone, &UnknownFaultError{Value: raw}
	}
}

// isDevImage reports whether v is a pre-release build rather than a released
// image. An EMPTY version is a dev checkout with no /etc/rasputin/image-version
// at all — not an appliance — so it is allowed; an appliance always has one.
func isDevImage(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || strings.Contains(v, "-dev.")
}

// UnknownFaultError describes an unrecognised FaultEnv value. It is a diagnostic
// carried into a log line, never a reason to stop the agent — see Arm.
type UnknownFaultError struct{ Value string }

func (e *UnknownFaultError) Error() string {
	return "unknown " + FaultEnv + " value " + quote(e.Value) + " (expected one of: " +
		string(FaultNoReboot) + ", " + string(FaultFailHealth) + ")"
}

func quote(s string) string { return `"` + s + `"` }

// Announce logs an armed fault. Called once at startup and deliberately shouty:
// a node silently carrying a fault injector is worse than no injector at all,
// and this line is what a confused operator greps for first — and what the
// bench procedure checks before dispatching a round.
func (f Fault) Announce() {
	if f == FaultNone {
		return
	}
	log.Printf("rasputin-agent: ⚠️  UPDATE FAULT INJECTION ARMED: %s=%s — this node will deliberately "+
		"misbehave during its next update. Unset it in node.env and restart to disarm.", FaultEnv, f)
}
