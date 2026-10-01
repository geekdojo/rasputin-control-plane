// Package bootverify is the control plane's ONE way of deciding that a node
// restarted: the node answers on a boot identity different from the one it had
// before it was told to.
//
// It was written for the update saga (ADR-0005 Decisions 1-3) and lived in
// api/internal/updater. It is a package of its own because the update saga is
// not the only thing that restarts a node and then has to say whether it
// worked: the node.reboot job and the bmc.power job's reset and cycle need the
// identical answer, and each of them used to accept weaker evidence — a
// re-registration, a BMC's ack — that a node which never restarted satisfies
// (geekdojo/geekdojo-brain#616, #617). One implementation, three callers.
//
// Boot identity is the kernel's per-boot UUID. It is compared for EQUALITY
// only. It is not a timestamp and nothing here reads a clock to decide
// anything: the wait ends when a fact is observed, and the deadline that
// bounds it fails naming the fact that never came true.
package bootverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Identity is the verdict of comparing two boot identities. It is THREE-valued,
// never two: "unknown" is a real answer, because a fleet is mixed-version by
// definition and an agent that predates boot identity reports none.
type Identity string

const (
	// Differs: proven new boot. The only value that proves a reboot.
	Differs Identity = "differs"
	// Same: the agent answering is the SAME boot we told to reboot. Not a
	// rollback — the reboot simply has not happened yet — and conflating the
	// two is the c13 bug.
	Same Identity = "same"
	// Unknown: one side reported no boot id, so the comparison cannot be made.
	Unknown Identity = "unknown"
)

// Classify compares the boot identity captured before a restart with the one
// answering now.
func Classify(prior, current string) Identity {
	if prior == "" || current == "" {
		return Unknown
	}
	if prior == current {
		return Same
	}
	return Differs
}

// Logger receives the wait's progress lines; a job passes its step log. nil is
// safe and logs nothing.
type Logger func(level, msg string)

func (l Logger) log(level, msg string) {
	if l != nil {
		l(level, msg)
	}
}

// ErrUnreadable is returned by a Probe when something answered and the answer
// could not be read. It is neither silence nor an identity.
var ErrUnreadable = errors.New("the node's answer could not be read")

// Probe asks a node which boot is answering.
type Probe struct {
	// Answers names what the node is answering, in the plural, for the
	// deadline verdict: "prechecks", "pings".
	Answers string
	// Ask returns the boot identity of whatever answered. "" with a nil error
	// means the node answered and reported no identity (an agent that predates
	// it). An error means nothing usable answered; ErrUnreadable means
	// something did and it could not be read.
	Ask func(ctx context.Context) (bootID string, err error)
}

func (p Probe) answers() string {
	if p.Answers == "" {
		return "probes"
	}
	return p.Answers
}

// PrecheckProbe asks through update.precheck. It is the update saga's probe:
// the saga needs the precheck anyway, and every agent with boot identity
// reports it there.
func PrecheckProbe(nc *nats.Conn, nodeID string) Probe {
	return Probe{
		Answers: "prechecks",
		Ask: func(ctx context.Context) (string, error) {
			return askPrecheck(ctx, nc, nodeID)
		},
	}
}

func askPrecheck(ctx context.Context, nc *nats.Conn, nodeID string) (string, error) {
	cmd, err := json.Marshal(proto.UpdatePrecheckCmd{})
	if err != nil {
		return "", err
	}
	msg, err := nc.RequestWithContext(ctx, proto.UpdatePrecheckSubject(nodeID), cmd)
	if err != nil {
		return "", err
	}
	var ack proto.UpdatePrecheckAck
	if json.Unmarshal(msg.Data, &ack) != nil {
		return "", ErrUnreadable
	}
	return ack.BootID, nil
}

// NodeProbe asks through diag.ping, the one command every agent answers
// whatever its role and whether or not it has an update backend. It is the
// probe for restarts that are not updates: node.reboot and bmc.power.
//
// An agent that predates the boot identity on diag.ping answers the ping
// without one. For that agent only, the identity is then asked for through
// update.precheck, which has carried it for longer; if nothing on the node
// answers that, the node answered and its identity is unknown.
func NodeProbe(nc *nats.Conn, nodeID string) Probe {
	return Probe{
		Answers: "pings",
		Ask: func(ctx context.Context) (string, error) {
			cmd, err := json.Marshal(proto.DiagPingCmd{})
			if err != nil {
				return "", err
			}
			msg, err := nc.RequestWithContext(ctx, proto.NodeCmdSubject(nodeID, "diag.ping"), cmd)
			if err != nil {
				return "", err
			}
			var pong proto.DiagPongEvt
			if json.Unmarshal(msg.Data, &pong) != nil {
				return "", ErrUnreadable
			}
			if pong.BootID != "" {
				return pong.BootID, nil
			}
			id, err := askPrecheck(ctx, nc, nodeID)
			switch {
			case err == nil:
				return id, nil
			case errors.Is(err, nats.ErrNoResponders):
				// Nothing on this node answers update.precheck: it has no
				// update backend. It answered the ping, and has no identity
				// to give.
				return "", nil
			}
			// The ping was answered and the second question was not settled
			// either way. Reading that as "no identity" would let one slow
			// reply pass for an agent that forgot its boot, so it is reported
			// as an answer that could not be read, which moves nothing.
			return "", fmt.Errorf("%w: diag.ping carried no boot id and update.precheck failed: %v", ErrUnreadable, err)
		},
	}
}

// WaitForNewBoot blocks until the node answers probe from a DIFFERENT boot than
// priorBootID, and is the mechanism that replaces "wait for a node.registered
// event, then trust whoever answers".
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
// hint, when non-nil, is a pure LATENCY optimisation: a registration means
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
// test cannot run and the verdict is Unknown either way (Decision 3 — that
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
func WaitForNewBoot(ctx context.Context, probe Probe, priorBootID string, hint <-chan *nats.Msg, lg Logger) (Identity, error) {
	const pollInterval = 2 * time.Second
	const rpcTimeout = 5 * time.Second

	degraded := priorBootID == ""
	if degraded {
		lg.log("warn", "no pre-reboot boot id captured; waiting for the node to go away and come back (verify will be degraded)")
	} else {
		lg.log("info", fmt.Sprintf("waiting for a boot other than %s", proto.ShortFingerprint(priorBootID)))
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

	// deadlineVerdict names the failure from those three facts once the step's
	// deadline has fired. Four distinct failures, and telling them apart IS the
	// deliverable — this message is the only thing an operator has to go on,
	// and naming the wrong one sends them to the wrong machine. Ordered
	// most-specific first.
	deadlineVerdict := func() (Identity, error) {
		switch {
		case answeringPriorBoot:
			// Answering on the boot we told to reboot, in the last answer we
			// got: alive and well, it simply never rebooted. c13. This is the
			// only shape that earns the Same verdict.
			return Same, fmt.Errorf("node never rebooted: still answering on boot %s after %w",
				proto.ShortFingerprint(priorBootID), ctx.Err())
		case degraded && !wentQuiet:
			// The degraded flavour of the same observation, and the case
			// that used to pass in 2ms. No identity to name, so name the
			// evidence instead.
			return Unknown, fmt.Errorf("node never rebooted: it answered %s throughout and never went quiet: %w", probe.answers(), ctx.Err())
		case everAnswered:
			// It answered, then went silent and stayed silent. THE c08
			// SHAPE: the reboot almost certainly happened — that is what
			// stopped the answers — and the node never came back to say so.
			// Emphatically NOT "still answering", and not a rollback either:
			// nothing here says which slot it is on, only that we cannot ask.
			return Unknown, fmt.Errorf(
				"node stopped answering and never came back — it rebooted or died and did not return: %w", ctx.Err())
		}
		// Never heard from it at all in this step. Different from c08: the
		// node was already unreachable when we started waiting, so the
		// reboot RPC's ack may be the last true thing we know.
		return Unknown, fmt.Errorf("node never answered after the reboot was issued: %w", ctx.Err())
	}

	for {
		rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
		bootID, err := probe.Ask(rctx)
		cancel()
		if PollCancelledByStep(ctx, err) {
			// The step's deadline ended this poll, not the node. Nothing was
			// observed, so nothing is recorded: the verdict stands on the last
			// poll that actually completed. Counting this as "went quiet" is
			// what reported a node answering on its old boot — cut off one
			// slow answer short — as c08, naming a failure it did not have.
			return deadlineVerdict()
		}
		switch {
		case errors.Is(err, ErrUnreadable):
			// Something answered and it could not be read. That is neither
			// silence nor an identity, so it moves nothing.
		case err != nil:
			// A poll that failed on its own terms — no responders, the
			// per-request timeout, a bus error — with the step still running.
			if !wentQuiet {
				wentQuiet = true
				lg.log("info", "node stopped answering — the reboot is under way")
			}
			// The node is not answering NOW, so whatever it last said about its
			// boot is history. Clearing this is the #90 fix.
			answeringPriorBoot = false
		default:
			everAnswered = true
			if degraded {
				switch {
				case bootID != "":
					lg.log("info", fmt.Sprintf("node is up on boot %s, which the pre-reboot agent could not report — rebooted", proto.ShortFingerprint(bootID)))
					return Unknown, nil
				case wentQuiet:
					lg.log("info", "node went away and came back; its agent still reports no boot id — verify will be degraded")
					return Unknown, nil
				}
				// Still answering, still silent about its identity: this is
				// the pre-reboot agent. Keep waiting — accepting it here is
				// exactly the bug (#83).
			} else {
				switch Classify(priorBootID, bootID) {
				case Differs:
					lg.log("info", fmt.Sprintf("node is up on a new boot (%s)", proto.ShortFingerprint(bootID)))
					return Differs, nil
				case Unknown:
					// Prior WAS reported and this answer is not, so the thing
					// answering is not the process that answered before — a
					// live process cannot forget its own boot id. The reboot is
					// proven; the comparison just cannot be made.
					lg.log("warn", "node answered without a boot id (pre-bootId agent); verify will be degraded")
					return Unknown, nil
				case Same:
					answeringPriorBoot = true
				}
			}
		}

		select {
		case <-ctx.Done():
			return deadlineVerdict()
		case <-hint:
			// Registration is a hint that something changed — poll immediately
			// rather than sitting out the interval.
		case <-time.After(pollInterval):
		}
	}
}

// PollCancelledByStep reports whether a failed poll was ended by the STEP's own
// bound — ctx's deadline or cancellation — rather than by anything the node or
// the bus did. Only the second kind is an observation.
//
// Both bounds surface as context errors, and the per-request timeout is a
// child of ctx, so the error value alone cannot tell them apart:
//
//   - ctx still live, err a context error: the per-request timeout fired. The
//     node had the full rpcTimeout to answer and did not — a real failure.
//   - ctx done, err a context error: the step's bound cut the poll off while
//     the node may well have been answering. Not an observation.
//   - any other error (no responders, connection closed, a timeout reported
//     by the bus) completed on its own terms and is an observation, even if
//     ctx happens to expire a moment later.
//
// If the per-request timeout and the step deadline land together, the poll is
// treated as cut off: the step is over either way, and the verdict then rests
// on the last poll that completed rather than on one that did not.
func PollCancelledByStep(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() == nil {
		return false
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// RestartBound bounds the wait for a node to answer on a new boot. It is the
// update saga's bound for the same wait, for the same reason: it has to
// outlast a real boot on the slowest node. It decides nothing by itself — the
// wait ends when a new boot answers, and when the bound is reached instead
// the wait fails naming what was observed.
const RestartBound = 5 * time.Minute

// ErrRestartUnverified is wrapped by every VerifyRestart failure in which the
// node was heard from again and the restart still could not be proven.
var ErrRestartUnverified = errors.New("restart not verified")

// VerifyRestart waits for nodeID to answer on a boot identity different from
// priorBootID and returns nil only when it has. It is the one verification
// every restart that is not an update goes through — the node.reboot job (as
// VerifyReboot) and the bmc.power job's reset and cycle — and it is the update
// saga's mechanism (WaitForNewBoot) with the one rule those jobs add:
//
// ONLY a different boot identity is proof. The update saga lets an unknown
// identity through as a degraded pass, because it has two further conjuncts
// (slot and version) and a fleet's first rollout has no identities at all. A
// plain restart has no further conjuncts, so an unknown identity proves
// nothing and is a failure that says so.
//
// The caller's ctx bounds the wait. The outcome rests on facts only:
//
//   - a new boot identity passes, whatever else was heard first;
//   - a DEFINITIVE reboot_failed event (the agent established that its reboot
//     command failed and no shutdown was under way) ends the wait early with
//     the node's own account — it is the node stating, as a fact, that it is
//     still up on the boot it was told to leave;
//   - a reboot_failed event WITHOUT that is not evidence and ends nothing. It
//     is what an agent up to CP dev.182 sends when its reboot command is
//     killed by the very shutdown it started, for a node that is in fact
//     rebooting (geekdojo/geekdojo-brain#616, cp-compute1 on the bench). It is
//     logged, and carried into the failure if the wait fails anyway.
func VerifyRestart(ctx context.Context, nc *nats.Conn, nodeID, priorBootID string, lg Logger) (Identity, error) {
	return verifyRestart(ctx, nc, nodeID, priorBootID, lg, false)
}

// VerifyReboot is VerifyRestart for a reboot the node's own agent performs —
// the node.reboot job — with one more fact that ends the wait: the node going
// CRITICAL. That is the control plane's existing presence derivation
// (inventory.DeriveStatus) reaching OFFLINE (heartbeat lapsed, mesh not showing
// the machine) or OFF BUS (heartbeat lapsed, mesh still showing it) — the
// states the node-offline alert raises as crit — published by the inventory
// service as its transition on rasputin.inventory.<id>.offline / .off-bus.
//
// Why it is an honest failure: a node told to reboot mutes its heartbeat and
// then either comes back on a new boot or does not. Reaching the critical tier
// without a new boot answering means the cluster, by its own definition, has
// lost the node and the reboot has not been shown to have happened. The job
// says exactly that — "not verified", naming the state — and does not claim
// the node did not reboot. Stale, the warning tier every reboot passes
// through, is not critical and ends nothing.
//
// It is not read for a BMC reset or cycle (VerifyRestart): cutting power is a
// different outage, whose account the bmc job gives itself.
func VerifyReboot(ctx context.Context, nc *nats.Conn, nodeID, priorBootID string, lg Logger) (Identity, error) {
	return verifyRestart(ctx, nc, nodeID, priorBootID, lg, true)
}

// criticalChanges are the presence transitions into the node-offline alert's
// crit state (alerts.nodeAlerts).
var criticalChanges = []proto.InventoryChangeType{proto.InventoryOffline, proto.InventoryOffBus}

func verifyRestart(ctx context.Context, nc *nats.Conn, nodeID, priorBootID string, lg Logger, readCritical bool) (Identity, error) {
	hint := make(chan *nats.Msg, 1)
	regSub, err := nc.Subscribe(proto.NodeRegisteredSubject(nodeID), func(m *nats.Msg) {
		select {
		case hint <- m:
		default:
		}
	})
	if err != nil {
		return Unknown, fmt.Errorf("subscribe registered: %w", err)
	}
	defer func() { _ = regSub.Unsubscribe() }()

	wctx, stop := context.WithCancel(ctx)
	defer stop()

	failed := make(chan proto.SystemRebootFailedEvt, 1)
	var mu sync.Mutex
	var undefinitive string // the latest report that is not evidence
	failSub, err := nc.Subscribe(proto.NodeEvtSubject(nodeID, "reboot_failed"), func(m *nats.Msg) {
		var ev proto.SystemRebootFailedEvt
		_ = json.Unmarshal(m.Data, &ev)
		if !ev.Definitive {
			detail := reportDetail(ev)
			mu.Lock()
			first := undefinitive == ""
			undefinitive = detail
			mu.Unlock()
			if first {
				lg.log("warn", fmt.Sprintf("%s reported that its reboot command ended (%s) without establishing that "+
					"no shutdown was under way — the report of an agent whose reboot was killed by its own shutdown. "+
					"It is not evidence; waiting for the boot identity", nodeID, detail))
			}
			return
		}
		select {
		case failed <- ev:
			stop()
		default:
		}
	})
	if err != nil {
		return Unknown, fmt.Errorf("subscribe reboot_failed: %w", err)
	}
	defer func() { _ = failSub.Unsubscribe() }()

	critical := make(chan proto.InventoryChangeEvt, 1)
	if readCritical {
		for _, change := range criticalChanges {
			sub, err := nc.Subscribe(proto.InventoryChangedSubject(nodeID, string(change)), func(m *nats.Msg) {
				var ev proto.InventoryChangeEvt
				_ = json.Unmarshal(m.Data, &ev)
				ev.Change = change // the subject is the fact; the payload only describes it
				select {
				case critical <- ev:
					stop()
				default:
				}
			})
			if err != nil {
				return Unknown, fmt.Errorf("subscribe %s: %w", change, err)
			}
			defer func() { _ = sub.Unsubscribe() }()
		}
	}

	verdict, werr := WaitForNewBoot(wctx, NodeProbe(nc, nodeID), priorBootID, hint, lg)

	// A new boot answered: that is the proof, whatever was heard before it.
	if werr == nil && verdict == Differs {
		return verdict, nil
	}
	select {
	case ev := <-failed:
		return Same, fmt.Errorf("%w: %s reported that its reboot command failed with no shutdown under way, "+
			"and it is still on boot %s: %s",
			ErrRestartUnverified, nodeID, bootForMessage(priorBootID), reportDetail(ev))
	case ev := <-critical:
		return verdict, fmt.Errorf("%w: %s went %s without answering on a boot other than %s",
			ErrRestartUnverified, nodeID, criticalForMessage(ev), bootForMessage(priorBootID))
	default:
	}
	mu.Lock()
	reported := undefinitive
	mu.Unlock()
	if werr != nil {
		if reported != "" {
			werr = fmt.Errorf("%w (earlier, the node reported, without establishing that no shutdown was under way: %s)",
				werr, reported)
		}
		return verdict, werr
	}
	// WaitForNewBoot passed on something weaker than a changed identity: the
	// node reported none before, or none after.
	if priorBootID == "" {
		return verdict, fmt.Errorf("%w: %s answered again, but it reported no boot identity before the command, "+
			"so there is nothing to show it restarted", ErrRestartUnverified, nodeID)
	}
	return verdict, fmt.Errorf("%w: %s was on boot %s and answered again WITHOUT a boot identity, "+
		"so there is nothing to show it restarted", ErrRestartUnverified, nodeID, bootForMessage(priorBootID))
}

func reportDetail(ev proto.SystemRebootFailedEvt) string {
	if ev.Detail == "" {
		return "the agent gave no detail"
	}
	return ev.Detail
}

// criticalForMessage names the critical state the node reached, in the words
// the nodes page and the node-offline alert use.
func criticalForMessage(ev proto.InventoryChangeEvt) string {
	var state string
	if ev.Change == proto.InventoryOffBus {
		state = "OFF BUS (critical: its heartbeat lapsed; the mesh still shows the machine)"
	} else {
		state = "OFFLINE (critical: its heartbeat lapsed and the mesh does not show the machine)"
	}
	if !ev.Node.LastSeen.IsZero() {
		state += fmt.Sprintf(", last heard from at %s", ev.Node.LastSeen.UTC().Format(time.RFC3339))
	}
	return state
}

func bootForMessage(id string) string {
	if id == "" {
		return "(unknown)"
	}
	return proto.ShortFingerprint(id)
}
