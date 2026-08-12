package updater

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Self-update: how the control plane updates *itself* without a human.
//
// A node.update targeting the controlplane runs steps 1–5 (validate → install →
// reboot) on the api that's being replaced; the reboot then kills that api
// mid-saga. So phase 2 (verify the booted slot, health-check, commit-or-rollback)
// can't run inline the way it does for a remote node — the *new* api, booted on
// the new slot, has to finish the job.
//
// Mechanism: SelfUpdateRecoverDecider tells the runner to DEFER (not fail) such a
// job at startup; ResumeSelfUpdates then drives phase 2 from the new api and
// closes the job. The verify/commit logic is shared with saga steps 6–7
// (verifyBootedSlot / healthCheckAndCommit) so there's one implementation.
//
// This is a deliberate point-solution for the one workflow that spans the api's
// own reboot; generalizing to durable/resumable sagas is architecture O-8.

// logFn is a nil-safe step/recovery logger.
type logFn func(level, msg string)

func (l logFn) log(level, msg string) {
	if l != nil {
		l(level, msg)
	}
}

// verifyBootedSlot evaluates conjuncts (a), (b) and (c) of the verify contract
// against a fresh precheck. See verify.go for the contract itself; (d), the
// health battery, is step 7 because it can mark the slot bad.
//
// Shared by saga step 6 and the self-update reconciler, so there is exactly one
// implementation of what "verified" means — which is the point of naming it
// (ADR-0005 Decision 2).
//
// It is also the one place that reconciles INVENTORY from the update outcome
// (ADR-0005 Decision 4) — see reconcileInventoryVersion. This is the right site
// because it is where the post-reboot precheck answer is in hand: the version
// the node is ACTUALLY running, read off the rootfs it actually booted.
func verifyBootedSlot(ctx context.Context, nc *nats.Conn, store *Store, inv *inventory.Store, req verifyRequest, lg logFn) (verifyResult, error) {
	nodeID, bundleSHA, jobID := req.NodeID, req.BundleSHA256, req.JobID
	var res verifyResult
	preMsg, err := nc.RequestWithContext(ctx, proto.UpdatePrecheckSubject(nodeID), mustJSON(proto.UpdatePrecheckCmd{}))
	if err != nil {
		// THE c08 CASE, exactly. We told this node to reboot and it never came
		// back to answer — so whatever inventory currently holds is a version
		// from a boot that may no longer exist, and the last thing that wrote it
		// was an optimistic registration on a slot the node may have left. Drop
		// the confirmation; keep the value as the only clue an operator has.
		unconfirmInventoryVersion(ctx, inv, nodeID, "node did not answer after the reboot", lg)
		return res, fmt.Errorf("post-reboot precheck: %w", err)
	}
	var pre proto.UpdatePrecheckAck
	_ = json.Unmarshal(preMsg.Data, &pre)
	res.Ack = pre

	expected, err := store.GetNodeUpdate(ctx, jobID)
	if err != nil || expected == nil {
		return res, errors.New("update row missing at verify time")
	}

	// ----- conjunct (a): a DIFFERENT boot than the one we told to reboot -----
	//
	// Checked first, and deliberately WITHOUT recording a rollback, because the
	// two failures look identical from the slot alone and are opposites: a node
	// that has not rebooted yet is still on the old slot, which the (b) check
	// below would call a bootloader rollback. That misdiagnosis is c13 — a
	// healthy node marked rolled_back and left uncommitted.
	res.Boot = classifyBoot(req.PriorBootID, pre.BootID)
	if res.Boot == bootSame {
		unconfirmInventoryVersion(ctx, inv, nodeID,
			"the pre-reboot agent is still answering; what it runs next is not yet decided", lg)
		return res, fmt.Errorf("pre_reboot_agent_answered: still on boot %s — the node has not rebooted, this is NOT a rollback",
			short(pre.BootID))
	}

	// Recorded before the branch so BOTH outcomes carry it: a rolled-back node
	// whose verify was degraded is exactly as interesting as a committed one.
	res.Version = classifyVersion(expected.ToVersion, pre.CurrentVersion)
	if err := store.SetNodeUpdateVerifyGaps(ctx, jobID, res.UnverifiedBoot(), res.UnverifiedVersion()); err != nil {
		lg.log("warn", fmt.Sprintf("record verify gaps for %s: %v", nodeID, err))
	}

	if pre.ActiveSlot != expected.ToSlot {
		now := time.Now().UTC()
		_ = store.UpdateNodeUpdate(ctx, jobID, NodeUpdateRolledBack,
			pre.ActiveSlot, pre.CurrentVersion, "bootloader rolled back to previous slot", now)
		// THE c08 FIX. Before this, a rolled-back node kept reporting the
		// version it was MEANT to reach: the agent registered on the new slot,
		// inventory took that value last-write-wins, the bootloader then
		// reverted, and nothing wrote inventory again unless the node
		// re-registered — which c08, genuinely stuck, never did. The row stayed
		// wrong indefinitely, and releases/check.go reads that column, so the
		// node rendered as up-to-date. ADR-0005 Decision 4.
		reconcileInventoryVersion(ctx, inv, nodeID, pre.CurrentVersion, lg)
		publishChange(nc, proto.UpdateChangeEvt{
			NodeID:            nodeID,
			JobID:             jobID,
			BundleID:          bundleSHA,
			Change:            proto.UpdateRolledBack,
			FromSlot:          expected.ToSlot,
			ToSlot:            pre.ActiveSlot,
			Version:           pre.CurrentVersion,
			Reason:            "bootloader watchdog or post-install init failure",
			UnverifiedBoot:    res.UnverifiedBoot(),
			UnverifiedVersion: res.UnverifiedVersion(),
			Ts:                now,
		})
		return res, fmt.Errorf("bootloader_rolled_back: came up on slot %s, expected %s",
			pre.ActiveSlot, expected.ToSlot)
	}

	// ----- conjunct (c): the reported version is the one we installed --------
	//
	// Free: the value has always been in hand here and was simply discarded.
	// A node on the right slot running the wrong version is not a rollback and
	// not a success — most likely the slot was written by something other than
	// this update. Inventory is CONFIRMED to what it actually reports, because
	// that part we do know.
	if res.Version == versionMismatch {
		reconcileInventoryVersion(ctx, inv, nodeID, pre.CurrentVersion, lg)
		return res, fmt.Errorf("version_mismatch: booted slot %s reports %q, expected %q",
			pre.ActiveSlot, pre.CurrentVersion, expected.ToVersion)
	}
	// Same reconciliation on the success branch, for the same reason: the
	// precheck answer is fresher evidence than the registration event that
	// preceded it, and making the write unconditional keeps "the update outcome
	// is authoritative at the moment it is decided" one invariant rather than a
	// rollback special case.
	reconcileInventoryVersion(ctx, inv, nodeID, pre.CurrentVersion, lg)
	lg.log("info", fmt.Sprintf("verified: slot %s, version %s, boot %s, version-check %s",
		pre.ActiveSlot, pre.CurrentVersion, res.Boot, res.Version))
	if res.Degraded() {
		// Decision 3: a degraded verify still passes — refusing would mean no
		// existing cluster could ever adopt the feature — but it is a weaker
		// claim and never a silent one. #71 carries this onto the wire.
		lg.log("warn", fmt.Sprintf("verify DEGRADED (boot=%s version=%s): passed on the conjuncts that could be evaluated",
			res.Boot, res.Version))
	}
	return res, nil
}

// reconcileInventoryVersion writes a verified running version back to
// nodes.image_version, closing the gap that made inventory a pure last-write-
// wins cache of an agent self-report (ADR-0005 Decision 4).
//
// The precedence it establishes: the update outcome is authoritative for the
// node's version AT THE MOMENT IT IS DECIDED, and the agent's self-report is
// authoritative afterwards. So a registration that lands after this write
// legitimately wins — that is the design, not a race to guard against. What is
// fixed is the case where no such registration ever comes.
//
// Never fatal. An agent that answers but names no version leaves the value in
// place and loses its CONFIRMATION instead — blanking image_version would swap
// a wrong answer for a differently-wrong one, while an unconfirmed row says the
// true thing: this is the last thing we were told, and we now know not to trust
// it.
func reconcileInventoryVersion(ctx context.Context, inv *inventory.Store, nodeID, version string, lg logFn) {
	if inv == nil {
		return
	}
	if version == "" {
		unconfirmInventoryVersion(ctx, inv, nodeID, "the node reported no image version", lg)
		return
	}
	if err := inv.ConfirmImageVersion(ctx, nodeID, version, time.Now().UTC()); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			lg.log("warn", fmt.Sprintf("inventory has no row for %s; version %s not reconciled", nodeID, version))
			return
		}
		lg.log("warn", fmt.Sprintf("reconcile inventory version for %s: %v", nodeID, err))
		return
	}
	lg.log("info", fmt.Sprintf("inventory reconciled: %s is confirmed running %s", nodeID, version))
}

// unconfirmInventoryVersion records that we can no longer vouch for what a node
// is running, without pretending to know what it is instead (ADR-0005
// Decision 4). Called from every terminal path that ends without a verified
// version in hand.
//
// The reason is logged rather than persisted: the durable record of WHY lives
// in node_updates, which already carries the terminal status and its detail for
// this job. Inventory only needs to stop asserting a version it cannot stand
// behind — duplicating the narrative here would give two places to disagree.
func unconfirmInventoryVersion(ctx context.Context, inv *inventory.Store, nodeID, reason string, lg logFn) {
	if inv == nil {
		return
	}
	if err := inv.UnconfirmImageVersion(ctx, nodeID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No row to doubt. Not worth a warning — a node that left inventory
			// mid-update is already visible in the job's own failure.
			return
		}
		lg.log("warn", fmt.Sprintf("unconfirm inventory version for %s: %v", nodeID, err))
		return
	}
	lg.log("warn", fmt.Sprintf("inventory version for %s is no longer confirmed: %s", nodeID, reason))
}

// probeHealth runs the post-reboot health gate: diag.health (role-aware — the
// firewall verifies its data plane, not just liveness) with a diag.ping fallback
// for agents too old to answer diag.health. Returns (healthy, human detail).
func probeHealth(ctx context.Context, nc *nats.Conn, nodeID, jobID string) (bool, string) {
	hcmd, _ := json.Marshal(proto.DiagHealthCmd{JobID: jobID})
	resp, err := nc.RequestWithContext(ctx, proto.NodeCmdSubject(nodeID, "diag.health"), hcmd)
	if errors.Is(err, nats.ErrNoResponders) {
		// Agent predates diag.health — fall back to diag.ping liveness.
		pcmd, _ := json.Marshal(proto.DiagPingCmd{JobID: jobID})
		if _, perr := nc.RequestWithContext(ctx, proto.NodeCmdSubject(nodeID, "diag.ping"), pcmd); perr != nil {
			return false, "diag.ping (fallback) failed: " + perr.Error()
		}
		return true, "liveness ok (agent has no diag.health)"
	}
	if err != nil {
		return false, "diag.health request failed: " + err.Error()
	}
	var ack proto.DiagHealthAck
	if uerr := json.Unmarshal(resp.Data, &ack); uerr != nil {
		return false, "diag.health decode failed: " + uerr.Error()
	}
	if !ack.OK {
		if ack.Detail != "" {
			return false, ack.Detail
		}
		return false, "unhealthy"
	}
	return true, "healthy"
}

// healthCheckAndCommit runs the post-reboot health check (diag.health, role-aware)
// and either mark-good + records committed, or mark-bad + records rolled_back.
// Returns the mark-good ack on success. Shared by saga step 7 and the self-update
// reconciler.
func healthCheckAndCommit(ctx context.Context, nc *nats.Conn, store *Store, inv *inventory.Store, nodeID, bundleSHA, jobID string, lg logFn) (json.RawMessage, error) {
	if healthy, detail := probeHealth(ctx, nc, nodeID, jobID); !healthy {
		lg.log("warn", "health check failed ("+detail+"); sending mark-bad")
		bad, _ := json.Marshal(proto.UpdateMarkBadCmd{BundleID: bundleSHA, Reason: detail})
		_, _ = nc.RequestWithContext(ctx, proto.UpdateMarkBadSubject(nodeID), bad)

		now := time.Now().UTC()
		// mark-bad means the node is still running the new slot but will revert
		// on its next boot, so every version available right now is about to be
		// wrong: the running one records a version the node is about to leave,
		// and the old one asserts a revert that has not happened yet. So we
		// assert neither and drop the confirmation instead — the state this
		// column was added for. (#57 left this path untouched precisely because
		// the schema could not yet say "unconfirmed".)
		unconfirmInventoryVersion(ctx, inv, nodeID,
			"health check failed; the node will revert on its next boot", lg)
		_ = store.UpdateNodeUpdate(ctx, jobID, NodeUpdateRolledBack,
			proto.SlotUnknown, "", "health check failed: "+detail, now)
		publishChange(nc, proto.UpdateChangeEvt{
			NodeID:   nodeID,
			JobID:    jobID,
			BundleID: bundleSHA,
			Change:   proto.UpdateRolledBack,
			Reason:   "post-reboot health check failed: " + detail,
			Ts:       now,
		})
		return nil, fmt.Errorf("health check failed (%s), mark-bad sent", detail)
	}

	good, _ := json.Marshal(proto.UpdateMarkGoodCmd{BundleID: bundleSHA})
	gm, err := nc.RequestWithContext(ctx, proto.UpdateMarkGoodSubject(nodeID), good)
	if err != nil {
		return nil, fmt.Errorf("mark-good rpc: %w", err)
	}
	var ack proto.UpdateMarkGoodAck
	_ = json.Unmarshal(gm.Data, &ack)
	if !ack.OK {
		return nil, fmt.Errorf("mark-good rejected: %s", ack.Detail)
	}

	row, _ := store.GetNodeUpdate(ctx, jobID)
	now := time.Now().UTC()
	toSlot := proto.SlotUnknown
	toVersion := ""
	unverifiedBoot, unverifiedVersion := false, false
	if row != nil {
		toSlot = row.ToSlot
		toVersion = row.ToVersion
		// Read back what verify recorded on this row rather than re-deriving
		// it: step 7 runs as its own step and does not carry the verifyResult,
		// and the row is where the gaps were durably written.
		unverifiedBoot, unverifiedVersion = row.UnverifiedBoot, row.UnverifiedVersion
	}
	_ = store.UpdateNodeUpdate(ctx, jobID, NodeUpdateCommitted, toSlot, toVersion, "", now)
	publishChange(nc, proto.UpdateChangeEvt{
		NodeID:            nodeID,
		JobID:             jobID,
		BundleID:          bundleSHA,
		Change:            proto.UpdateCommitted,
		ToSlot:            toSlot,
		Version:           toVersion,
		UnverifiedBoot:    unverifiedBoot,
		UnverifiedVersion: unverifiedVersion,
		Ts:                now,
	})
	if unverifiedBoot || unverifiedVersion {
		// Once per node per run, on the terminal event — ADR-0005 Decision 3's
		// "the api logs it once per node per run". The warn during verify says
		// it is happening; this says it is what the operator ended up with.
		lg.log("warn", fmt.Sprintf("update committed DEGRADED on %s (unverifiedBoot=%v unverifiedVersion=%v): green, but on fewer conjuncts than a fully-verified node",
			nodeID, unverifiedBoot, unverifiedVersion))
	} else {
		lg.log("info", "update committed")
	}
	return json.Marshal(ack)
}

// SelfUpdateRecoverDecider returns the runner recover policy that DEFERS (rather
// than fails) an in-flight node.update for selfNodeID that has already passed
// its reboot step — i.e. the controlplane that rebooted to activate the new
// slot. ResumeSelfUpdates owns finishing those. Everything else fails as usual.
func SelfUpdateRecoverDecider(selfNodeID string) func(*jobs.Job, []*jobs.JobStep) jobs.RecoverDecision {
	return func(j *jobs.Job, steps []*jobs.JobStep) jobs.RecoverDecision {
		if selfNodeID == "" || j.Kind != "node.update" {
			return jobs.RecoverFail
		}
		var spec UpdateSpec
		if err := json.Unmarshal(j.Spec, &spec); err != nil || spec.NodeID != selfNodeID {
			return jobs.RecoverFail
		}
		if rebootDone(steps) {
			return jobs.RecoverDefer
		}
		return jobs.RecoverFail
	}
}

func rebootDone(steps []*jobs.JobStep) bool {
	for _, s := range steps {
		if s.Name == "reboot" && s.Status == jobs.StepSucceeded {
			return true
		}
	}
	return false
}

// ResumeSelfUpdates finishes any control-plane self-update left in flight when
// the api rebooted onto the new slot. Call once at startup, AFTER Recover (which
// deferred these via SelfUpdateRecoverDecider). Non-blocking: each candidate is
// reconciled in its own goroutine, which waits (bounded) for the co-located
// agent to reconnect, then verifies the booted slot + health and commits or
// records the rollback — closing the user-initiated job with no human step.
func ResumeSelfUpdates(ctx context.Context, store *Store, inv *inventory.Store, jobStore *jobs.Store, runner *jobs.Runner, nc *nats.Conn, selfNodeID string) {
	if selfNodeID == "" {
		return
	}
	running, err := jobStore.ListJobsByStatus(ctx, []jobs.Status{jobs.StatusRunning})
	if err != nil {
		log.Printf("updater: resume self-update: list jobs: %v", err)
		return
	}
	for _, j := range running {
		if j.Kind != "node.update" {
			continue
		}
		var spec UpdateSpec
		if json.Unmarshal(j.Spec, &spec) != nil || spec.NodeID != selfNodeID {
			continue
		}
		steps, _ := jobStore.ListSteps(ctx, j.ID)
		if !rebootDone(steps) {
			continue
		}
		// The pre-reboot boot identity, recovered from the PERSISTED precheck
		// step result. The in-memory sc.PriorResults that step 6 reads died
		// with the old api — this path is the api finishing a job across its
		// own reboot — but the step result itself is durable (JobStep.Result),
		// so the value survives exactly the reboot it exists to span.
		// ADR-0005 Decision 1.
		priorBootID := priorPrecheckBootID(map[string]json.RawMessage{
			"precheck": stepResult(steps, "precheck"),
		})
		go reconcileSelfUpdate(ctx, store, inv, runner, nc, spec, j.ID, priorBootID)
	}
}

// stepResult returns the recorded result of the named step, or nil if the step
// is absent or never recorded one.
func stepResult(steps []*jobs.JobStep, name string) json.RawMessage {
	for _, s := range steps {
		if s.Name == name {
			return s.Result
		}
	}
	return nil
}

func reconcileSelfUpdate(ctx context.Context, store *Store, inv *inventory.Store, runner *jobs.Runner, nc *nats.Conn, spec UpdateSpec, jobID, priorBootID string) {
	log.Printf("updater: resuming self-update %s after reboot", jobID)
	wctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	if err := waitForAgent(wctx, nc, spec.NodeID); err != nil {
		runner.FinishDeferred(ctx, jobID, false, "agent did not reconnect after self-update reboot: "+err.Error())
		return
	}
	req := verifyRequest{
		NodeID:       spec.NodeID,
		BundleSHA256: spec.BundleSHA256,
		JobID:        jobID,
		PriorBootID:  priorBootID,
	}
	res, err := verifyBootedSlot(wctx, nc, store, inv, req, nil)
	if err != nil {
		// verifyBootedSlot already recorded + published the rollback.
		runner.FinishDeferred(ctx, jobID, false, err.Error())
		return
	}
	// No waitForNewBoot here, deliberately: this path runs in a NEW api process
	// that came up on the new slot, so the box demonstrably rebooted — the race
	// step 6 has to defend against cannot occur. The conjunct is still
	// EVALUATED (verifyBootedSlot does it from the ack), so a self-update that
	// somehow answered on the old boot is still caught.
	log.Printf("updater: self-update %s verified (boot=%s version=%s degraded=%v)",
		jobID, res.Boot, res.Version, res.Degraded())
	if _, err := healthCheckAndCommit(wctx, nc, store, inv, spec.NodeID, spec.BundleSHA256, jobID, nil); err != nil {
		runner.FinishDeferred(ctx, jobID, false, err.Error())
		return
	}
	runner.FinishDeferred(ctx, jobID, true, "")
	log.Printf("updater: self-update %s committed", jobID)
}

// waitForAgent blocks until the node's agent answers a precheck (it reconnects
// to the bus shortly after the api restarts), or ctx expires.
//
// ⚠️ "The agent answered" is NOT evidence that the node rebooted, and this must
// never be used as if it were: the pre-reboot agent answers prechecks perfectly
// well for as long as it is running, and on an update it is also already
// reporting the TARGET slot (rauc activates at install time). Using this in
// step 6's degraded branch is what made #83 record a node committed 46s before
// it finished rebooting. It is sound in reconcileSelfUpdate and only there,
// because that caller runs in an api process that came up on the new slot — the
// reboot is proven by the fact that this code is executing at all. Everything
// else wants waitForNewBoot.
func waitForAgent(ctx context.Context, nc *nats.Conn, nodeID string) error {
	for {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := nc.RequestWithContext(rctx, proto.UpdatePrecheckSubject(nodeID), mustJSON(proto.UpdatePrecheckCmd{}))
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
