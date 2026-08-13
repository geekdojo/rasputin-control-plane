package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The verify contract — ADR-0005 Decision 2.
//
// `verified(node, target)` is the conjunction of four things:
//
//	a. the answering agent is on a DIFFERENT boot than the one told to reboot
//	b. ActiveSlot == the target slot
//	c. the reported image version == the version the bundle installed
//	d. the health battery passes            (step 7 / healthCheckAndCommit)
//
// (a)–(c) live here; (d) is a separate step because it can mark the slot bad.
//
// Before this existed, only (b) was checked — and it was evaluated against
// whatever answered first. The pre-reboot agent answers a precheck perfectly
// well for the seconds systemd takes to tear it down, so a healthy node that
// HAD booted the new slot got prechecked on the old one and recorded as a
// bootloader rollback. That is bench node c13 from the 2026-07-12 24-node run,
// and it is the failure this contract exists to make impossible.
//
// Every conjunct is THREE-valued, never two. "Unknown" is a real answer — a
// mixed-version fleet is the normal case for this feature, not an edge case
// (Decision 3), so an absent boot id or an unreportable version degrades the
// verdict instead of failing it. What is never allowed is silence: an unknown
// is logged, carried on the result, and surfaced.

// bootIdentity is conjunct (a).
type bootIdentity string

const (
	// bootDiffers: proven new boot. The only value that satisfies (a).
	bootDiffers bootIdentity = "differs"
	// bootSame: the agent answering is the SAME boot we told to reboot. Not a
	// rollback — the reboot simply has not happened yet — and conflating the
	// two is the c13 bug.
	bootSame bootIdentity = "same"
	// bootUnknown: one side reported no boot id. Degrade to (b)+(c)+(d).
	bootUnknown bootIdentity = "unknown"
)

// versionMatch is conjunct (c).
type versionMatch string

const (
	versionMatches  versionMatch = "matches"
	versionMismatch versionMatch = "mismatch"
	versionUnknown  versionMatch = "unknown"
)

// verifyRequest is the input to the contract. A struct rather than six more
// positional arguments because both callers — saga step 6 and the self-update
// reconciler — assemble it from different places, and PriorBootID in particular
// is easy to pass in the wrong slot when it is one string among several.
type verifyRequest struct {
	NodeID       string
	BundleSHA256 string
	JobID        string
	// PriorBootID is the boot identity captured at precheck, BEFORE the reboot
	// RPC. "" means it could not be captured — a pre-bootId agent, or a saga
	// whose step result was lost — and is treated as unknown, never as a
	// mismatch.
	PriorBootID string
}

// verifyResult carries the verdict of each conjunct alongside the ack, so a
// caller can tell a clean pass from a pass that had to degrade. Surfacing the
// degradation on the wire (the `unverifiedBoot` flag on canary and per-node
// reports) is #71; this is the value it will read.
type verifyResult struct {
	Ack     proto.UpdatePrecheckAck
	Boot    bootIdentity
	Version versionMatch
}

// Degraded reports whether the verdict rests on fewer than all of (a)-(c) —
// i.e. some conjunct could not be evaluated. A degraded pass is still a pass
// (Decision 3: fan-out proceeds), but it is a weaker claim and must say so.
func (r verifyResult) Degraded() bool {
	return r.UnverifiedBoot() || r.UnverifiedVersion()
}

// UnverifiedBoot / UnverifiedVersion are Degraded() split into the two things
// an operator can act on differently. An unverified BOOT usually means a
// pre-bootId agent, which the next rollout fixes by itself; an unverified
// VERSION means the node could not say what it is running, which does not
// self-heal and is worth a look. Collapsing them into one flag would put those
// two on the same line.
func (r verifyResult) UnverifiedBoot() bool    { return r.Boot == bootUnknown }
func (r verifyResult) UnverifiedVersion() bool { return r.Version == versionUnknown }

// classifyBoot evaluates conjunct (a).
func classifyBoot(prior, current string) bootIdentity {
	if prior == "" || current == "" {
		return bootUnknown
	}
	if prior == current {
		return bootSame
	}
	return bootDiffers
}

// classifyVersion evaluates conjunct (c). `expected` is the version the install
// step recorded for the target slot; `reported` is what the booted node says it
// is running.
func classifyVersion(expected, reported string) versionMatch {
	if expected == "" || reported == "" {
		return versionUnknown
	}
	if expected == reported {
		return versionMatches
	}
	return versionMismatch
}

// waitForNewBoot blocks until the node answers a precheck from a DIFFERENT boot
// than req.PriorBootID, and is the mechanism that replaces "wait for a
// node.registered event, then trust whoever answers".
//
// Why polling and not the event: the registration subscription was created
// inside step 6, i.e. AFTER the reboot RPC returned, so any registration
// published by the still-running old system satisfied it. It also had the
// mirror-image failure — a node that re-registered BEFORE the subscription
// landed was missed entirely and the step burned its full five-minute timeout.
// Polling has neither property: it cannot be satisfied early by the old boot
// (the boot id says so) and it cannot miss a fast reboot (the next poll finds
// it). Decision 2's second corollary.
//
// regCh, when non-nil, is a pure LATENCY optimisation: a registration means
// "something changed, look now" and shortcuts the poll interval. It is never
// evidence on its own, which is the whole point.
//
// THE INVARIANT, and the reason the degraded branch below is not a shortcut:
// verify must never be satisfiable by state that exists BEFORE the reboot. That
// is easy to get wrong here because `rauc install` activates the target slot at
// INSTALL time, so the still-running pre-reboot agent already answers with
// ActiveSlot == the target. Conjunct (b) is therefore not merely uninformative
// before the reboot — it is affirmatively true. Something else has to prove the
// reboot happened, and this function is the only thing that does.
//
// With no prior boot id there is nothing to compare against, so the identity
// test cannot run and the verdict is bootUnknown either way (Decision 3 — that
// path is every existing cluster's first rollout). What it must NOT do is
// return early: an earlier version of this waited only for the agent to answer,
// which the pre-reboot agent does immediately, so a node was recorded committed
// ~46s before it finished rebooting (bench e3bench 2026-08-12, #83). Two
// independent post-reboot proofs replace that, either of which is sufficient:
//
//   - the answering agent reports a boot id at all. The pre-reboot agent
//     demonstrably did not (that is WHY PriorBootID is empty), so a non-empty
//     one can only come from the image we just installed;
//   - the agent stopped answering and then answered again. Backend-agnostic,
//     and the only evidence available when the target image also predates
//     bootId — a downgrade, or an older bundle deployed deliberately.
//
// Neither can be produced by a node that has not rebooted, which is the whole
// requirement. If neither ever appears the step times out saying so, instead of
// passing on evidence it does not have.
func waitForNewBoot(ctx context.Context, nc *nats.Conn, req verifyRequest, regCh <-chan *nats.Msg, lg logFn) (bootIdentity, error) {
	const pollInterval = 2 * time.Second
	const rpcTimeout = 5 * time.Second

	degraded := req.PriorBootID == ""
	if degraded {
		lg.log("warn", "no pre-reboot boot id captured; waiting for the node to go away and come back (verify will be degraded)")
	} else {
		lg.log("info", fmt.Sprintf("waiting for a boot other than %s", short(req.PriorBootID)))
	}

	// Three facts, deliberately kept apart, because the deadline verdict below
	// is a different answer for each combination of them.
	//
	// ⚠️ answeringPriorBoot is about the LAST answer, not about "ever". It used
	// to be a latch called sameBootSeen that was set on the first prior-boot ack
	// and never cleared — and the reboot RPC carries a delay, so the pre-reboot
	// agent legitimately answers for the first seconds of EVERY update. Any node
	// that then rebooted and vanished was therefore reported as "node never
	// rebooted: still answering", which is the exact opposite of what happened.
	// Bench e3bench 2026-08-13, the first time c08 was ever run: the node was up
	// on the target slot with a new boot id while the control plane said it had
	// never rebooted. See #90.
	answeringPriorBoot := false
	// everAnswered / wentQuiet are genuine latches — they record that something
	// happened, and nothing later can unhappen it.
	everAnswered := false
	wentQuiet := false
	for {
		rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
		msg, err := nc.RequestWithContext(rctx, proto.UpdatePrecheckSubject(req.NodeID), mustJSON(proto.UpdatePrecheckCmd{}))
		cancel()
		switch {
		case err != nil:
			if !wentQuiet {
				wentQuiet = true
				lg.log("info", "node stopped answering — the reboot is under way")
			}
			// The node is not answering NOW, so whatever it last said about its
			// boot is history. Clearing this is the #90 fix.
			answeringPriorBoot = false
		default:
			var ack proto.UpdatePrecheckAck
			if json.Unmarshal(msg.Data, &ack) == nil {
				everAnswered = true
				if degraded {
					switch {
					case ack.BootID != "":
						lg.log("info", fmt.Sprintf("node is up on boot %s, which the pre-reboot agent could not report — rebooted", short(ack.BootID)))
						return bootUnknown, nil
					case wentQuiet:
						lg.log("info", "node went away and came back; its agent still reports no boot id — verify will be degraded")
						return bootUnknown, nil
					}
					// Still answering, still silent about its identity: this is
					// the pre-reboot agent. Keep waiting — accepting it here is
					// exactly the bug (#83).
				} else {
					switch classifyBoot(req.PriorBootID, ack.BootID) {
					case bootDiffers:
						lg.log("info", fmt.Sprintf("node is up on a new boot (%s)", short(ack.BootID)))
						return bootDiffers, nil
					case bootUnknown:
						// Prior WAS reported and this answer is not, so the thing
						// answering is not the process that answered precheck — a
						// live process cannot forget its own boot id. The reboot is
						// proven; the comparison just cannot be made.
						lg.log("warn", "node answered without a boot id (pre-bootId agent); verify will be degraded")
						return bootUnknown, nil
					case bootSame:
						answeringPriorBoot = true
					}
				}
			}
		}

		select {
		case <-ctx.Done():
			// Four distinct failures, and telling them apart IS the deliverable
			// — this message is the only thing an operator has to go on, and
			// naming the wrong one sends them to the wrong machine. Ordered
			// most-specific first.
			switch {
			case answeringPriorBoot:
				// Answering RIGHT NOW on the boot we told to reboot: alive and
				// well, it simply never rebooted. c13. This is the only shape
				// that earns the bootSame verdict.
				return bootSame, fmt.Errorf("node never rebooted: still answering on boot %s after %w",
					short(req.PriorBootID), ctx.Err())
			case degraded && !wentQuiet:
				// The degraded flavour of the same observation, and the case
				// that used to pass in 2ms. No identity to name, so name the
				// evidence instead.
				return bootUnknown, fmt.Errorf("node never rebooted: it answered prechecks throughout and never went quiet: %w", ctx.Err())
			case everAnswered:
				// It answered, then went silent and stayed silent. THE c08
				// SHAPE: the reboot almost certainly happened — that is what
				// stopped the answers — and the node never came back to say so.
				// Emphatically NOT "still answering", and not a rollback either:
				// nothing here says which slot it is on, only that we cannot ask.
				return bootUnknown, fmt.Errorf(
					"node stopped answering and never came back — it rebooted or died and did not return: %w", ctx.Err())
			}
			// Never heard from it at all in this step. Different from c08: the
			// node was already unreachable when we started waiting, so the
			// reboot RPC's ack may be the last true thing we know.
			return bootUnknown, fmt.Errorf("node never answered after the reboot was issued: %w", ctx.Err())
		case <-regCh:
			// Registration is a hint that something changed — poll immediately
			// rather than sitting out the interval.
		case <-time.After(pollInterval):
		}
	}
}
