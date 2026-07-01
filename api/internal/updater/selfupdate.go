package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

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

// verifyBootedSlot prechecks nodeID and compares the booted slot to the target
// recorded in the node_update row for jobID. On a mismatch (bootloader rolled
// back, or the new slot never booted) it records + publishes a rollback and
// returns an error; on a match it returns the precheck ack. Shared by saga
// step 6 and the self-update reconciler.
func verifyBootedSlot(ctx context.Context, nc *nats.Conn, store *Store, nodeID, bundleSHA, jobID string, lg logFn) (proto.UpdatePrecheckAck, error) {
	var pre proto.UpdatePrecheckAck
	preMsg, err := nc.RequestWithContext(ctx, proto.UpdatePrecheckSubject(nodeID), mustJSON(proto.UpdatePrecheckCmd{}))
	if err != nil {
		return pre, fmt.Errorf("post-reboot precheck: %w", err)
	}
	_ = json.Unmarshal(preMsg.Data, &pre)

	expected, err := store.GetNodeUpdate(ctx, jobID)
	if err != nil || expected == nil {
		return pre, errors.New("update row missing at verify time")
	}
	if pre.ActiveSlot != expected.ToSlot {
		now := time.Now().UTC()
		_ = store.UpdateNodeUpdate(ctx, jobID, NodeUpdateRolledBack,
			pre.ActiveSlot, pre.CurrentVersion, "bootloader rolled back to previous slot", now)
		publishChange(nc, proto.UpdateChangeEvt{
			NodeID:   nodeID,
			JobID:    jobID,
			BundleID: bundleSHA,
			Change:   proto.UpdateRolledBack,
			FromSlot: expected.ToSlot,
			ToSlot:   pre.ActiveSlot,
			Version:  pre.CurrentVersion,
			Reason:   "bootloader watchdog or post-install init failure",
			Ts:       now,
		})
		return pre, fmt.Errorf("bootloader_rolled_back: came up on slot %s, expected %s",
			pre.ActiveSlot, expected.ToSlot)
	}
	lg.log("info", fmt.Sprintf("node up on slot %s (version %s)", pre.ActiveSlot, pre.CurrentVersion))
	return pre, nil
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
func healthCheckAndCommit(ctx context.Context, nc *nats.Conn, store *Store, nodeID, bundleSHA, jobID string, lg logFn) (json.RawMessage, error) {
	if healthy, detail := probeHealth(ctx, nc, nodeID, jobID); !healthy {
		lg.log("warn", "health check failed ("+detail+"); sending mark-bad")
		bad, _ := json.Marshal(proto.UpdateMarkBadCmd{BundleID: bundleSHA, Reason: detail})
		_, _ = nc.RequestWithContext(ctx, proto.UpdateMarkBadSubject(nodeID), bad)

		now := time.Now().UTC()
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
	if row != nil {
		toSlot = row.ToSlot
		toVersion = row.ToVersion
	}
	_ = store.UpdateNodeUpdate(ctx, jobID, NodeUpdateCommitted, toSlot, toVersion, "", now)
	publishChange(nc, proto.UpdateChangeEvt{
		NodeID:   nodeID,
		JobID:    jobID,
		BundleID: bundleSHA,
		Change:   proto.UpdateCommitted,
		ToSlot:   toSlot,
		Version:  toVersion,
		Ts:       now,
	})
	lg.log("info", "update committed")
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
func ResumeSelfUpdates(ctx context.Context, store *Store, jobStore *jobs.Store, runner *jobs.Runner, nc *nats.Conn, selfNodeID string) {
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
		go reconcileSelfUpdate(ctx, store, runner, nc, spec, j.ID)
	}
}

func reconcileSelfUpdate(ctx context.Context, store *Store, runner *jobs.Runner, nc *nats.Conn, spec UpdateSpec, jobID string) {
	log.Printf("updater: resuming self-update %s after reboot", jobID)
	wctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	if err := waitForAgent(wctx, nc, spec.NodeID); err != nil {
		runner.FinishDeferred(ctx, jobID, false, "agent did not reconnect after self-update reboot: "+err.Error())
		return
	}
	if _, err := verifyBootedSlot(wctx, nc, store, spec.NodeID, spec.BundleSHA256, jobID, nil); err != nil {
		// verifyBootedSlot already recorded + published the rollback.
		runner.FinishDeferred(ctx, jobID, false, err.Error())
		return
	}
	if _, err := healthCheckAndCommit(wctx, nc, store, spec.NodeID, spec.BundleSHA256, jobID, nil); err != nil {
		runner.FinishDeferred(ctx, jobID, false, err.Error())
		return
	}
	runner.FinishDeferred(ctx, jobID, true, "")
	log.Printf("updater: self-update %s committed", jobID)
}

// waitForAgent blocks until the node's agent answers a precheck (it reconnects
// to the bus shortly after the api restarts), or ctx expires.
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
