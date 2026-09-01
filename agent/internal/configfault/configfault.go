// Package configfault records operator-configuration mistakes that the agent
// deliberately survives.
//
// WHY THIS EXISTS, and it is a scar rather than a design.
//
// Every environment-selected backend used to reject an unrecognised value with
// log.Fatalf. The reasoning was sound in isolation — silently running `mock`
// where `rauc` was asked for is its own hazard, and refusing to start is the
// honest response to "I cannot do what you asked". What it missed is that the
// two failures are not symmetric on an appliance:
//
//   - a node running the WRONG backend is visible, reachable, and fixable from
//     the control plane;
//   - a node that will not start is none of those. rasputin-agent.service pairs
//     Restart=always with RestartSec=2, node.env lives on the persistent
//     partition and is hand-edited (that is how an update channel gets flipped),
//     and / is read-only squashfs. One typo therefore does not fail loudly — it
//     permanently prevents the agent from starting, on a box whose only
//     remaining door is SSH. systemd eventually gives up with "Start request
//     repeated too quickly" and leaves the unit dead, which is worse, not
//     better.
//
// CONFIRMED ON HARDWARE 2026-07-28 on tp-cp1, with an env pin naming a BMC
// backend the installed image did not have. The sharpest detail from that
// write-up: rasputin-api keeps running, so **the control plane still serves its
// UI while the node it runs on has no agent at all** — it looks healthy and is
// not. Six sites carried this shape; a seventh was added and removed during the
// E5 fault-injection campaign by an author who had that write-up available.
//
// THE RESOLUTION, and why it is not simply "degrade quietly". Degrading alone
// would trade a dead node for a lying one — an operator who pinned `turingpi`
// and silently got BMC-off has been misled in a quieter way, which is exactly
// the objection bmc-settings' S-4 ("an env pin FREEZES the selection") raises.
// So a rejected value is not just survived, it is REPORTED: recorded here,
// shouted at startup, and carried to the control plane in the registration
// event's metadata. The subsystem is disabled rather than silently substituted,
// so nothing runs that the operator did not ask for.
//
// Set.Reject is the only way to record one, and it always logs. There is no way
// to reject a value quietly — that is the property this package exists to hold.
//
// # The second fault kind: a real backend whose prerequisites are absent
//
// Reject answers "the operator asked for something that does not exist".
// Unavailable answers the other half, added after a second hardware incident:
// "the operator asked for nothing, and the real backend cannot run here."
//
// Every environment-selected backend used to autodetect its way to `mock` when
// the real one's prerequisites were missing. CONFIRMED ON HARDWARE 2026-09-01
// on e3bench, a real n100 controlplane: `wipefs` was missing from the OS image,
// so storage.ToolingAvailable() returned false, autodetectStorageBackend()
// returned "mock", and storage.enumerate answered with the mock's FIXTURE
// DISKS — three drives that do not exist in that machine, one of them carrying
// a plausible exfat volume. The operator would have been shown those disks in
// the backup-target picker and could have confirmed a DESTRUCTIVE FORMAT
// against a device that was not there. The reply carried `"backend":"mock"`
// and `"ok":true`; nothing else said the answer was fiction.
//
// That is a strictly worse failure than either of the ones above, because it is
// not a degradation — it is a confident, plausible, wrong answer. A disabled
// subsystem tells you it is disabled. A mock tells you about a machine that
// does not exist.
//
// So mock is now OPT-IN AND NEVER INFERRED: it is selected only when the
// operator names it (RASPUTIN_*_BACKEND=mock). When the real backend's
// prerequisites are absent and nothing was asked for, the subsystem is
// DISABLED and the missing prerequisite is named — same survive-and-report
// contract as Reject, same registration metadata, same UI badge. The agent
// still starts, still heartbeats, still holds the mesh and serves updates; it
// simply refuses to invent the part it cannot see.
package configfault

import (
	"fmt"
	"log"
	"strings"
)

// Fault is one rejected configuration value.
type Fault struct {
	// Variable is the environment variable that carried the bad value.
	Variable string `json:"variable"`
	// Value is what the operator actually typed. Echoed back so the fix does
	// not require reading the source.
	Value string `json:"value"`
	// Expected lists the values that would have been accepted.
	Expected []string `json:"expected,omitempty"`
	// Missing names the absent prerequisite when this fault came from
	// Unavailable rather than Reject — "wipefs not on PATH", "/etc/config/
	// firewall not present". Empty for a rejected value, and it is what
	// distinguishes the two kinds: Value is what the operator typed, Missing
	// is what the machine does not have.
	//
	// Additive: consumers that predate it read the same detail from Effect,
	// which always names the prerequisite too.
	Missing string `json:"missing,omitempty"`

	// Effect names, in the operator's terms, what this node can no longer do.
	// The point of the whole package: "unknown backend" is a fact about a
	// string, "OS updates are disabled on this node" is a fact about the fleet.
	Effect string `json:"effect"`
}

func (f Fault) String() string {
	if f.Missing != "" {
		s := fmt.Sprintf("no usable backend for %s: %s", f.Variable, f.Missing)
		if len(f.Expected) > 0 {
			s += " (would have needed " + strings.Join(f.Expected, "|") + ")"
		}
		return s + " — " + f.Effect
	}
	s := fmt.Sprintf("%s=%q is not recognised", f.Variable, f.Value)
	if len(f.Expected) > 0 {
		s += " (expected " + strings.Join(f.Expected, "|") + ")"
	}
	return s + " — " + f.Effect
}

// Set collects the faults found during one agent startup. The zero value is
// ready to use. Not safe for concurrent use: it is populated once, on the
// startup path, before any handler is subscribed.
type Set struct {
	faults []Fault
}

// Reject records a bad value and announces it. Both, always — a fault nobody
// can see is the failure mode this package was written to prevent, and the
// startup log is the first thing anyone greps.
//
// effect must describe the CONSEQUENCE, not the cause: the operator already
// knows they typed something, what they need is to be told what stopped working
// because of it.
func (s *Set) Reject(variable, value string, expected []string, effect string) {
	f := Fault{Variable: variable, Value: value, Expected: expected, Effect: effect}
	s.faults = append(s.faults, f)
	log.Printf("rasputin-agent: ⚠️  CONFIG FAULT: %s. The agent is starting anyway so this node stays "+
		"reachable and can be fixed; correct it in /var/lib/rasputin/node.env and restart the agent.", f)
}

// Unavailable records that the real backend cannot run on this node and that
// NOTHING was substituted for it. Like Reject it always logs, and for the same
// reason — but the remedy is different, so the wording is too: Reject tells the
// operator to fix a typo in node.env, Unavailable tells them what the image or
// the machine is missing.
//
// missing must name the absent prerequisite concretely enough to act on ("wipefs
// not on PATH"), because that is the sentence the 2026-09-01 incident needed and
// did not have. effect, as with Reject, describes the CONSEQUENCE.
//
// This is deliberately NOT a fallback to mock. A mock here would answer with
// fixture disks, fixture slots or a fixture tailnet, and an operator cannot tell
// a confident wrong answer from a right one. Disabled is legible; fiction is not.
func (s *Set) Unavailable(variable string, expected []string, missing, effect string) {
	f := Fault{Variable: variable, Expected: expected, Missing: missing, Effect: effect}
	s.faults = append(s.faults, f)
	log.Printf("rasputin-agent: ⚠️  SUBSYSTEM UNAVAILABLE: %s. No mock was substituted — a mock would "+
		"report hardware this node does not have. The agent is starting anyway so this node stays "+
		"reachable; install the missing prerequisite, or set %s=mock explicitly if this is a dev box.",
		f, variable)
}

// Any reports whether anything was rejected.
func (s *Set) Any() bool { return len(s.faults) > 0 }

// List returns the recorded faults.
func (s *Set) List() []Fault { return s.faults }

// Metadata renders the faults for the registration event, which carries
// map[string]any. Returns nil when there is nothing wrong, so a healthy node
// adds no key at all rather than an empty one.
func (s *Set) Metadata() []map[string]any {
	if len(s.faults) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(s.faults))
	for _, f := range s.faults {
		m := map[string]any{
			"variable": f.Variable,
			"value":    f.Value,
			"expected": f.Expected,
			"effect":   f.Effect,
		}
		// Additive, and omitted on a rejected value so the shape older
		// consumers were written against is byte-for-byte unchanged.
		if f.Missing != "" {
			m["missing"] = f.Missing
		}
		out = append(out, m)
	}
	return out
}

// Summary is a one-line rendering for the final startup log line, so an
// operator tailing the journal sees the count without scrolling back.
func (s *Set) Summary() string {
	if len(s.faults) == 0 {
		return ""
	}
	names := make([]string, 0, len(s.faults))
	for _, f := range s.faults {
		names = append(names, f.Variable)
	}
	return fmt.Sprintf("%d configuration fault(s): %s", len(s.faults), strings.Join(names, ", "))
}
