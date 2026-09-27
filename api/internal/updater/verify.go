package updater

import (
	"context"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bootverify"
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

// bootIdentity is conjunct (a). The type, its values and the code that decides
// them live in api/internal/bootverify, which the node.reboot and bmc.power
// jobs share; the names below are this package's spelling of them.
type bootIdentity = bootverify.Identity

const (
	// bootDiffers: proven new boot. The only value that satisfies (a).
	bootDiffers = bootverify.Differs
	// bootSame: the agent answering is the SAME boot we told to reboot. Not a
	// rollback — the reboot simply has not happened yet — and conflating the
	// two is the c13 bug.
	bootSame = bootverify.Same
	// bootUnknown: one side reported no boot id. Degrade to (b)+(c)+(d).
	bootUnknown = bootverify.Unknown
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
	return bootverify.Classify(prior, current)
}

// classifyVersion evaluates conjunct (c). `expected` is the version the install
// step recorded for the target slot; `reported` is what the booted node says it
// is running; `bundleSHA` is the content hash of the bundle being installed.
//
// The three-valued result is deliberately asymmetric — an ABSENT value degrades
// (Decision 3), a DIFFERENT one fails — and that is only safe while `expected`
// is trustworthy. #92 showed it is not: a pre-#111 agent echoes the bundle's
// sha256 as its version, the install step recorded it, and conjunct (c) then
// compared a real CalVer against a hash and failed every firewall update.
//
// So a value that IS the bundle's content hash is treated as UNKNOWN rather
// than as a mismatch. It is not a version at all, and "we cannot tell" is the
// honest reading of it — which lets a fleet carrying older agents degrade
// instead of failing outright, exactly as Decision 3 intends for the
// mixed-version case that is the norm here.
//
// This is belt and braces, not the fix: SetNodeUpdateSlots now refuses to
// overwrite a manifest version with the echo at all, so new rows never hold a
// hash. This clause covers the rows already written before that landed, and
// any agent that finds a new way to report nonsense.
func classifyVersion(expected, reported, bundleSHA string) versionMatch {
	if expected == "" || reported == "" {
		return versionUnknown
	}
	if bundleSHA != "" && strings.EqualFold(expected, bundleSHA) {
		return versionUnknown
	}
	if expected == reported {
		return versionMatches
	}
	return versionMismatch
}

// waitForNewBoot blocks until the node answers a precheck from a DIFFERENT boot
// than req.PriorBootID. The mechanism — and the long account of why it is the
// way it is — is bootverify.WaitForNewBoot, shared with the node.reboot and
// bmc.power jobs. The update saga asks through update.precheck.
func waitForNewBoot(ctx context.Context, nc *nats.Conn, req verifyRequest, regCh <-chan *nats.Msg, lg logFn) (bootIdentity, error) {
	return bootverify.WaitForNewBoot(ctx, bootverify.PrecheckProbe(nc, req.NodeID), req.PriorBootID, regCh, bootverify.Logger(lg))
}

// pollCancelledByStep is bootverify.PollCancelledByStep.
func pollCancelledByStep(ctx context.Context, err error) bool {
	return bootverify.PollCancelledByStep(ctx, err)
}
