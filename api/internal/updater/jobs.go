package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// UpdateSpec is the spec body the api accepts for a node.update job.
type UpdateSpec struct {
	NodeID       string `json:"nodeId"`
	BundleSHA256 string `json:"bundleSha256"`
}

// Config controls the saga's environment-dependent knobs.
type Config struct {
	// PublicBaseURL is the URL prefix the agent uses to fetch bundles.
	// In dev: "http://localhost:8080". In production: the api's tailnet
	// hostname. The saga appends "/api/bundles/{sha256}".
	PublicBaseURL string
	// SelfNodeID is the control plane's own node id (RASPUTIN_SELF_NODE_ID),
	// or "" in dev. A non-empty value marks a provisioned appliance and lets
	// the download step refuse to hand a REMOTE node a loopback bundle URL —
	// the symptom of a misderived localhost public-base-url (e.g.
	// RASPUTIN_CLUSTER_ID unset in node.env after an in-place update), which
	// would otherwise fail opaquely on the agent as "connection refused".
	// See control-plane #75.
	SelfNodeID string
}

// UpdateWorkflow returns the seven-step node.update saga.
//
//  1. validate                    — spec sanity + bundle exists in store
//  2. precheck                    — RPC agent: which slot would we write?
//  3. download                    — RPC agent: pull bundle from PublicBaseURL
//  4. install                     — RPC agent: rauc install → inactive slot
//  5. reboot                      — sub-before-RPC for the reboot event
//  6. wait_online_and_verify_slot — wait for a NEW boot, then verify (a)(b)(c)
//  7. health_check_and_commit     — diag.health, then mark-good (or mark-bad)
//
// The store is updated in steps 1, 5, 6, 7 so the UI's Updates view can
// follow progress without subscribing to NATS.
func UpdateWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn, cfg Config) jobs.Workflow {
	return jobs.Workflow{
		Kind: "node.update",
		Steps: []jobs.WorkflowStep{
			{Name: "validate", Timeout: 2 * time.Second, Do: updateValidate(store, inv)},
			{Name: "precheck", Timeout: 10 * time.Second, Do: updatePrecheck()},
			{Name: "download", Timeout: 10 * time.Minute, Do: updateDownload(store, cfg)},
			{Name: "install", Timeout: 10 * time.Minute, Do: updateInstall(store)},
			{Name: "reboot", Timeout: 15 * time.Second, Do: updateReboot()},
			{Name: "wait_online_and_verify_slot", Timeout: 5 * time.Minute, Do: updateWaitOnlineAndVerifySlot(store, inv)},
			{Name: "health_check_and_commit", Timeout: 30 * time.Second, Retries: 1, Do: updateHealthCheckAndCommit(store, inv)},
		},
		OnTerminal: finalizeNodeUpdateRow(store),
	}
}

// finalizeNodeUpdateRow gives the per-node row a terminal status on every path
// (ADR-0005 Decision 5, #53).
//
// The row only ever reached a terminal status on the verify/commit path:
// verifyBootedSlot writes rolled_back, healthCheckAndCommit writes committed.
// A saga that failed at download, install, or verify propagated its error to
// the runner, which failed the JOB and never touched the row — so the Updates
// page rendered a failed run as one still in progress, indefinitely. Bench
// 2026-08-12: a firewall update that failed conjunct (c) at step 5 left exactly
// that, and the same shape was recorded in 2026-06-22 and 2026-06-28.
//
// Only ever writes to a row still in_progress. That single guard is what makes
// the hook safe to fire on every terminal transition including success: a
// committed or rolled_back row is a verdict this hook has no business
// overwriting, and preserving it matters most in the case that motivated the
// whole feature — a node marked rolled_back must not be relabelled `failed`
// just because the job also ended in error.
func finalizeNodeUpdateRow(store *Store) func(context.Context, string, bool, string) {
	return func(ctx context.Context, jobID string, success bool, errMsg string) {
		row, err := store.GetNodeUpdate(ctx, jobID)
		if err != nil || row == nil {
			return // not a per-node update, or the row was never created
		}
		if row.Status != NodeUpdateInProgress {
			return // already has a verdict — committed, rolled_back, failed
		}
		if errMsg == "" {
			// A job that succeeded while its row is still in_progress means a
			// step stopped the workflow early without recording an outcome.
			// Say so rather than inventing one.
			errMsg = "job ended without recording a per-node outcome"
		}
		if err := store.UpdateNodeUpdate(ctx, jobID, NodeUpdateFailed,
			row.ToSlot, row.ToVersion, errMsg, time.Now().UTC()); err != nil {
			log.Printf("updater: finalize node_update %s: %v", jobID, err)
			return
		}
		log.Printf("updater: node_update %s finalized as failed (%s)", jobID, errMsg)
	}
}

// ReconcileStrandedRows finalizes in_progress rows whose job is already
// terminal. Called at api start.
//
// The hook above closes the path going forward, but it cannot reach back: rows
// stranded before it existed, or by a process that died between failing the job
// and firing the hook, stay in_progress forever and there is no later event to
// catch them. This is the one-shot sweep that clears them, and it is
// deliberately NOT a timeout reaper — it decides nothing from a clock, only
// from a job that has already reached a terminal state, so it cannot race a
// legitimately slow install (ADR-0005 Decision 5: a reaper "must not be the
// primary mechanism").
func ReconcileStrandedRows(ctx context.Context, store *Store, jobStore *jobs.Store) error {
	rows, err := store.ListInProgressNodeUpdates(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		j, err := jobStore.GetJob(ctx, row.JobID)
		if err != nil || j == nil {
			continue
		}
		if j.Status != jobs.StatusFailed && j.Status != jobs.StatusSucceeded {
			continue // still genuinely running — leave it alone
		}
		msg := j.Error
		if msg == "" {
			msg = "job reached a terminal state without recording a per-node outcome"
		}
		if err := store.UpdateNodeUpdate(ctx, row.JobID, NodeUpdateFailed,
			row.ToSlot, row.ToVersion, msg, time.Now().UTC()); err != nil {
			log.Printf("updater: reconcile stranded %s: %v", row.JobID, err)
			continue
		}
		log.Printf("updater: reconciled stranded node_update %s (job already %s)", row.JobID, j.Status)
	}
	return nil
}

func parseSpec(raw json.RawMessage) (*UpdateSpec, error) {
	var spec UpdateSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	if spec.NodeID == "" {
		return nil, errors.New("nodeId is required")
	}
	if spec.BundleSHA256 == "" {
		return nil, errors.New("bundleSha256 is required")
	}
	return &spec, nil
}

// ----- Step 1: validate ---------------------------------------------------

func updateValidate(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		node, err := inv.Get(sc.Ctx, spec.NodeID)
		if err != nil {
			return nil, fmt.Errorf("inventory: %w", err)
		}
		if node == nil {
			return nil, fmt.Errorf("node %s not registered", spec.NodeID)
		}
		bundle, err := store.GetBundle(sc.Ctx, spec.BundleSHA256)
		if err != nil {
			return nil, fmt.Errorf("bundle lookup: %w", err)
		}
		if bundle == nil {
			return nil, fmt.Errorf("bundle %s not found", spec.BundleSHA256)
		}
		// Persist the in-progress row so the UI sees something immediately.
		now := time.Now().UTC()
		row := &NodeUpdate{
			JobID:        sc.JobID,
			NodeID:       spec.NodeID,
			BundleSHA256: spec.BundleSHA256,
			FromSlot:     proto.SlotUnknown,
			ToSlot:       proto.SlotUnknown,
			ToVersion:    bundle.Version,
			Status:       NodeUpdateInProgress,
			StartedAt:    now,
		}
		if err := store.CreateNodeUpdate(sc.Ctx, row); err != nil {
			return nil, fmt.Errorf("persist update row: %w", err)
		}
		publishChange(sc.NATS, proto.UpdateChangeEvt{
			NodeID:   spec.NodeID,
			JobID:    sc.JobID,
			BundleID: spec.BundleSHA256,
			Change:   proto.UpdateStarted,
			Version:  bundle.Version,
			Ts:       now,
		})
		sc.Log("info", fmt.Sprintf("update %s → %s on %s", short(spec.BundleSHA256), bundle.Version, spec.NodeID))
		return json.Marshal(map[string]string{"version": bundle.Version})
	}
}

// ----- Step 2: precheck ---------------------------------------------------

func updatePrecheck() jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		cmd, _ := json.Marshal(proto.UpdatePrecheckCmd{})
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.UpdatePrecheckSubject(spec.NodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("precheck rpc: %w", err)
		}
		var ack proto.UpdatePrecheckAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("decode precheck ack: %w", err)
		}
		if !ack.OK {
			return nil, fmt.Errorf("precheck failed: %s", ack.Detail)
		}
		// The whole ack is the step result, so the PRE-REBOOT boot identity is
		// captured here and threaded to step 6 through sc.PriorResults without
		// any extra plumbing — this step is the last point in the saga at which
		// the old boot is guaranteed to still be the one answering. ADR-0005
		// Decision 1 ("capture the pre-reboot bootId in step 2").
		sc.Log("info", fmt.Sprintf("active=%s inactive=%s current=%s backend=%s bootId=%s",
			ack.ActiveSlot, ack.InactiveSlot, ack.CurrentVersion, ack.Backend, bootIDForLog(ack.BootID)))
		return json.Marshal(ack)
	}
}

// ----- Step 3: download ---------------------------------------------------

func updateDownload(store *Store, cfg Config) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		bundle, err := store.GetBundle(sc.Ctx, spec.BundleSHA256)
		if err != nil || bundle == nil {
			return nil, fmt.Errorf("bundle missing at download time")
		}
		bundleURL := cfg.PublicBaseURL + "/api/bundles/" + spec.BundleSHA256
		// Guardrail: a loopback bundle URL only reaches the api from its OWN
		// co-located node (dev single-box, or a self-update). Handing it to a
		// REMOTE node strands that node dialing its own loopback — the api
		// derived a localhost public-base-url (RASPUTIN_CLUSTER_ID unset in
		// node.env). Fail here, loudly and with the fix, instead of letting the
		// agent fail deep in the download with an opaque "connection refused".
		// Disabled in dev (SelfNodeID == "") and for the api's own node. #75.
		if remoteLoopbackBundleURL(bundleURL, cfg.SelfNodeID, spec.NodeID) {
			return nil, fmt.Errorf("refusing to send loopback bundle URL %q to remote node %s: the control plane derived a localhost public-base-url — set RASPUTIN_CLUSTER_ID (or RASPUTIN_PUBLIC_BASE_URL) in /var/lib/rasputin/node.env and restart rasputin-api (control-plane #75)", bundleURL, spec.NodeID)
		}
		cmd, _ := json.Marshal(proto.UpdateDownloadCmd{
			BundleID:       spec.BundleSHA256,
			URL:            bundleURL,
			ExpectedSHA256: spec.BundleSHA256,
			SizeBytes:      bundle.SizeBytes,
		})
		sc.Log("info", fmt.Sprintf("agent fetching %s (%d bytes)", bundleURL, bundle.SizeBytes))
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.UpdateDownloadSubject(spec.NodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("download rpc: %w", err)
		}
		var ack proto.UpdateDownloadAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, err
		}
		if !ack.OK {
			return nil, fmt.Errorf("download failed: %s", ack.Detail)
		}
		if ack.SHA256 != spec.BundleSHA256 {
			return nil, fmt.Errorf("sha mismatch: expected %s got %s", spec.BundleSHA256, ack.SHA256)
		}
		publishChange(sc.NATS, proto.UpdateChangeEvt{
			NodeID:   spec.NodeID,
			JobID:    sc.JobID,
			BundleID: spec.BundleSHA256,
			Change:   proto.UpdateDownloaded,
			Ts:       time.Now().UTC(),
		})
		sc.Log("info", fmt.Sprintf("downloaded to %s", ack.LocalPath))
		// Stash the local path for the install step.
		return json.Marshal(map[string]any{"spec": spec, "localPath": ack.LocalPath})
	}
}

// remoteLoopbackBundleURL reports whether handing bundleURL to targetNodeID
// would strand a REMOTE node with a loopback URL it cannot reach. selfNodeID
// == "" (dev / not a provisioned appliance) disables the check; the api's own
// co-located node is always fine. See control-plane #75.
func remoteLoopbackBundleURL(bundleURL, selfNodeID, targetNodeID string) bool {
	if selfNodeID == "" || targetNodeID == selfNodeID {
		return false
	}
	return IsLoopbackURL(bundleURL)
}

// IsLoopbackURL reports whether raw's host is a loopback name or address —
// "localhost", 127.0.0.0/8, or ::1. The api's dev-default public-base-url is
// "http://localhost:8080", so the "localhost" name (which net.ParseIP rejects)
// must count. Exported so the api's startup identity check can reuse it.
func IsLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ----- Step 4: install ----------------------------------------------------

func updateInstall(store *Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		// Reuse the precheck step's already-published ack instead of
		// re-issuing the RPC. The saga records each step's result in
		// sc.PriorResults; here we want the "precheck" entry (the step
		// name in jobs.go above). Fall through to a fresh RPC if the
		// prior result is missing (e.g. step renamed or the install
		// runs out-of-band).
		var pre proto.UpdatePrecheckAck
		if raw, ok := sc.PriorResults["precheck"]; ok && len(raw) > 0 {
			if err := json.Unmarshal(raw, &pre); err != nil {
				return nil, fmt.Errorf("decode cached precheck ack: %w", err)
			}
		} else {
			sc.Log("warn", "precheck result not cached; re-issuing RPC")
			preMsg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.UpdatePrecheckSubject(spec.NodeID), mustJSON(proto.UpdatePrecheckCmd{}))
			if err != nil {
				return nil, fmt.Errorf("re-precheck: %w", err)
			}
			if err := json.Unmarshal(preMsg.Data, &pre); err != nil {
				return nil, fmt.Errorf("decode re-precheck ack: %w", err)
			}
		}
		if pre.InactiveSlot == "" || pre.InactiveSlot == proto.SlotUnknown {
			return nil, errors.New("agent reported no inactive slot")
		}

		// LocalPath is empty: the agent caches the bundle by BundleID
		// during step 3 and resolves the path itself at install time.
		// Keeping LocalPath in the wire type lets a future api implementation
		// override the resolution (e.g. for pre-staged content on shared
		// storage), but the v0 flow doesn't need it.
		cmd, _ := json.Marshal(proto.UpdateInstallCmd{
			BundleID:   spec.BundleSHA256,
			TargetSlot: pre.InactiveSlot,
		})
		sc.Log("info", fmt.Sprintf("installing to slot %s", pre.InactiveSlot))
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.UpdateInstallSubject(spec.NodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("install rpc: %w", err)
		}
		var ack proto.UpdateInstallAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, err
		}
		if !ack.OK {
			return nil, fmt.Errorf("install failed: %s", ack.Detail)
		}

		// The ack's TargetSlot is a pure ECHO of the slot we just asked for, and
		// it becomes conjunct (b)'s expected side. ADR-0005 Decision 2's third
		// corollary — the node must not own both sides of its own check.
		//
		// This is NOT the #92 shape, and the difference decides the fix. There
		// the api held an independent, signed answer (the release manifest), so
		// it could simply refuse the echo. Here it holds nothing: `TargetSlot`
		// was set from `pre.InactiveSlot`, which the AGENT reported at precheck.
		// Both sides of the round trip originate on the node, so preferring one
		// over the other only swaps an earlier claim for a later one.
		//
		// What IS worth having is noticing when the two disagree. A backend that
		// resolves its own inactive slot (openwrt-ab does, via `block info`)
		// could install somewhere other than where it was sent, and today that
		// divergence is silently recorded as if it were the plan. So:
		//
		//   - silent agent  → keep what we asked for. Writing "" would blank
		//     to_slot (the slots are not COALESCEd), and conjunct (b) reads a
		//     blank expected slot as a MISMATCH — i.e. a healthy node recorded
		//     as a bootloader rollback, which is precisely the c13 harm the
		//     contract exists to prevent.
		//   - disagreeing agent → fail here, loudly, before the reboot. The
		//     install has already happened, so the honest report is "we do not
		//     know which slot is about to boot", and a verify built on the wrong
		//     expected slot would call the result a rollback either way.
		switch {
		case ack.TargetSlot == "" || ack.TargetSlot == proto.SlotUnknown:
			ack.TargetSlot = pre.InactiveSlot
		case ack.TargetSlot != pre.InactiveSlot:
			return nil, fmt.Errorf(
				"agent installed to slot %s but was told to use %s — refusing to record a target the api did not choose",
				ack.TargetSlot, pre.InactiveSlot)
		}

		// Persist target slot + version.
		_ = store.SetNodeUpdateSlots(sc.Ctx, sc.JobID, pre.ActiveSlot, ack.TargetSlot, pre.CurrentVersion, ack.NewVersion)
		publishChange(sc.NATS, proto.UpdateChangeEvt{
			NodeID:   spec.NodeID,
			JobID:    sc.JobID,
			BundleID: spec.BundleSHA256,
			Change:   proto.UpdateInstalled,
			FromSlot: pre.ActiveSlot,
			ToSlot:   ack.TargetSlot,
			Version:  ack.NewVersion,
			Ts:       time.Now().UTC(),
		})
		sc.Log("info", fmt.Sprintf("installed %s to slot %s", ack.NewVersion, ack.TargetSlot))
		return json.Marshal(ack)
	}
}

// ----- Step 5: reboot -----------------------------------------------------

func updateReboot() jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		// Sub-before-RPC for the rebooting event; same pattern as node.reboot.
		rebootingSubj := proto.NodeEvtSubject(spec.NodeID, "rebooting")
		ch := make(chan *nats.Msg, 1)
		sub, err := sc.NATS.Subscribe(rebootingSubj, func(m *nats.Msg) {
			select {
			case ch <- m:
			default:
			}
		})
		if err != nil {
			return nil, fmt.Errorf("subscribe rebooting: %w", err)
		}
		defer func() { _ = sub.Unsubscribe() }()

		cmd, _ := json.Marshal(proto.UpdateRebootCmd{BundleID: spec.BundleSHA256, DelaySeconds: 3})
		if _, err := sc.NATS.RequestWithContext(sc.Ctx, proto.UpdateRebootSubject(spec.NodeID), cmd); err != nil {
			return nil, fmt.Errorf("reboot rpc: %w", err)
		}
		sc.Log("info", "reboot acked; waiting for rebooting event")
		select {
		case m := <-ch:
			return m.Data, nil
		case <-sc.Ctx.Done():
			return nil, fmt.Errorf("waiting for rebooting event: %w", sc.Ctx.Err())
		}
	}
}

// ----- Step 6: wait_online_and_verify_slot --------------------------------

func updateWaitOnlineAndVerifySlot(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		// The node.registered subscription is now a LATENCY HINT, not the
		// correctness mechanism (ADR-0005 Decision 2). It is still created
		// before anything else so a fast reboot's registration is not missed —
		// but a registration no longer proves the reboot happened, because the
		// pre-reboot system can publish one just as easily. Boot identity does
		// the proving; this only says "look now instead of at the next poll".
		regSubj := proto.NodeRegisteredSubject(spec.NodeID)
		ch := make(chan *nats.Msg, 1)
		sub, err := sc.NATS.Subscribe(regSubj, func(m *nats.Msg) {
			select {
			case ch <- m:
			default:
			}
		})
		if err != nil {
			return nil, fmt.Errorf("subscribe registered: %w", err)
		}
		defer func() { _ = sub.Unsubscribe() }()

		// The boot identity captured before the reboot RPC (step 2's ack).
		// Read from the cached step result ONLY — unlike step 4, there is no
		// re-issue-the-RPC fallback here, because after the reboot an RPC
		// answers with the CURRENT boot, which is the very thing this value
		// exists to be compared against. A missing cache degrades to unknown,
		// exactly like a pre-bootId agent.
		req := verifyRequest{
			NodeID:       spec.NodeID,
			BundleSHA256: spec.BundleSHA256,
			JobID:        sc.JobID,
			PriorBootID:  priorPrecheckBootID(sc.PriorResults),
		}

		// Wait for a DIFFERENT boot to answer. This replaces "wait for a
		// registration event, then trust whoever responds", which the old boot
		// satisfied for the seconds systemd took to tear it down (c13) and
		// which also missed nodes that re-registered before the subscription
		// landed, burning the full timeout.
		if _, err := waitForNewBoot(sc.Ctx, sc.NATS, req, ch, sc.Log); err != nil {
			// ⚠️ INVENTORY MUST BE DOUBTED HERE, and for a while it was not.
			//
			// verifyBootedSlot below opens with an unconfirmInventoryVersion
			// call under a comment reading "THE c08 CASE, exactly" — and it is
			// unreachable in the actual c08 case, because this return fires
			// first. #58 added this gate and #83 hardened it, and each time it
			// got better at refusing bad evidence it moved the stranded-node
			// case further from the handler written for it (#57 / #72). Both
			// halves were bench-validated separately; neither run crossed the
			// boundary, because producing c08 was the scenario never run.
			//
			// Measured cost on the bench 2026-08-13: the node was told to
			// reboot, never came back, the job FAILED — and because
			// image_version_confirmed_at was left standing from an earlier
			// round, releases.Check still counted it toward a green up_to_date.
			// That is verbatim the lie #72 exists to kill. See #90.
			//
			// Every shape waitForNewBoot fails with means the same thing for
			// inventory: we told this node to reboot and never got a verifiable
			// answer, so whatever the row holds is a version from a boot that
			// may no longer be running. Even the c13 shape — still answering on
			// the old boot — belongs here, because the bootloader is already
			// armed for the other slot and what it runs NEXT is not yet decided;
			// verifyBootedSlot's own bootSame branch has always said exactly
			// that. The value stays as the operator's only clue; only the
			// confidence drops.
			// ⚠️ A DETACHED CONTEXT, and it is load-bearing. sc.Ctx is expired —
			// its deadline firing is precisely why waitForNewBoot returned — so
			// passing it here means the UPDATE never runs and unconfirming
			// degrades to a log line nobody reads. The first version of this fix
			// did exactly that and looked correct; the regression test below is
			// what caught it, which is the second time on this path that a fix
			// silently did not fire (see the die-after-reboot marker, #113).
			// Cleanup after a cancellation must never inherit the cancellation.
			uctx, ucancel := context.WithTimeout(context.WithoutCancel(sc.Ctx), 5*time.Second)
			unconfirmInventoryVersion(uctx, inv, spec.NodeID, err.Error(), sc.Log)
			ucancel()
			return nil, err
		}

		// Evaluate the contract: (a) different boot, (b) slot, (c) version.
		// Shared with the self-update reconciler — see selfupdate.go / verify.go.
		res, err := verifyBootedSlot(sc.Ctx, sc.NATS, store, inv, req, sc.Log)
		if err != nil {
			return nil, err
		}
		return json.Marshal(res)
	}
}

// ----- Step 7: health_check_and_commit ------------------------------------

func updateHealthCheckAndCommit(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		// diag.health (role-aware) → mark-good (commit) or mark-bad (rollback). Shared with
		// the self-update reconciler (selfupdate.go).
		return healthCheckAndCommit(sc.Ctx, sc.NATS, store, inv, spec.NodeID, spec.BundleSHA256, sc.JobID, sc.Log)
	}
}

// ----- helpers -----------------------------------------------------------

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// priorPrecheckBootID digs the pre-reboot boot identity out of the precheck
// step's cached result. Every failure mode — no cached result, unparseable
// result, a pre-bootId agent that sent no field — collapses to "", which
// consumers must read as UNKNOWN rather than as a mismatch (ADR-0005
// Decision 3). Deliberately total: a boot identity that could not be captured
// must never be the reason an otherwise-good update is failed.
func priorPrecheckBootID(prior map[string]json.RawMessage) string {
	raw, ok := prior["precheck"]
	if !ok || len(raw) == 0 {
		return ""
	}
	var pre proto.UpdatePrecheckAck
	if err := json.Unmarshal(raw, &pre); err != nil {
		return ""
	}
	return pre.BootID
}

// bootIDForLog renders a boot identity for a log line, naming the empty case
// rather than leaving a blank field an operator has to interpret.
func bootIDForLog(id string) string {
	if id == "" {
		return "(none)"
	}
	return short(id)
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func publishChange(nc *nats.Conn, ev proto.UpdateChangeEvt) {
	payload, err := json.Marshal(ev)
	if err != nil {
		log.Printf("updater: marshal change: %v", err)
		return
	}
	if err := nc.Publish(proto.UpdateChangeSubject(ev.NodeID, ev.Change), payload); err != nil {
		log.Printf("updater: publish change: %v", err)
	}
}
