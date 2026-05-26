package updater

import (
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
}

// UpdateWorkflow returns the seven-step node.update saga.
//
//  1. validate                    — spec sanity + bundle exists in store
//  2. precheck                    — RPC agent: which slot would we write?
//  3. download                    — RPC agent: pull bundle from PublicBaseURL
//  4. install                     — RPC agent: rauc install → inactive slot
//  5. reboot                      — sub-before-RPC for the reboot event
//  6. wait_online_and_verify_slot — wait for re-registration, compare slot
//  7. health_check_and_commit     — diag.ping, then mark-good (or mark-bad)
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
			{Name: "wait_online_and_verify_slot", Timeout: 5 * time.Minute, Do: updateWaitOnlineAndVerifySlot(store)},
			{Name: "health_check_and_commit", Timeout: 30 * time.Second, Retries: 1, Do: updateHealthCheckAndCommit(store)},
		},
	}
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
		sc.Log("info", fmt.Sprintf("active=%s inactive=%s current=%s backend=%s",
			ack.ActiveSlot, ack.InactiveSlot, ack.CurrentVersion, ack.Backend))
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

// ----- Step 4: install ----------------------------------------------------

func updateInstall(store *Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		// Re-fetch the precheck result by requesting it again — cheap.
		preMsg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.UpdatePrecheckSubject(spec.NodeID), mustJSON(proto.UpdatePrecheckCmd{}))
		if err != nil {
			return nil, fmt.Errorf("re-precheck: %w", err)
		}
		var pre proto.UpdatePrecheckAck
		_ = json.Unmarshal(preMsg.Data, &pre)
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

func updateWaitOnlineAndVerifySlot(store *Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
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

		sc.Log("info", "waiting for node to re-register")
		var regBytes []byte
		select {
		case m := <-ch:
			regBytes = m.Data
		case <-sc.Ctx.Done():
			return nil, fmt.Errorf("waiting for re-register: %w", sc.Ctx.Err())
		}

		// Read the active slot the agent now reports. We could parse the
		// metadata from the registration event, but the source of truth is
		// the precheck — re-issue it.
		preMsg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.UpdatePrecheckSubject(spec.NodeID), mustJSON(proto.UpdatePrecheckCmd{}))
		if err != nil {
			return nil, fmt.Errorf("post-reboot precheck: %w", err)
		}
		var pre proto.UpdatePrecheckAck
		_ = json.Unmarshal(preMsg.Data, &pre)

		// Compare with what we expected.
		expected, err := store.GetNodeUpdate(sc.Ctx, sc.JobID)
		if err != nil || expected == nil {
			return nil, errors.New("update row missing at verify time")
		}

		if pre.ActiveSlot != expected.ToSlot {
			// The bootloader rolled us back. Record + publish.
			now := time.Now().UTC()
			_ = store.UpdateNodeUpdate(sc.Ctx, sc.JobID, NodeUpdateRolledBack,
				pre.ActiveSlot, pre.CurrentVersion, "bootloader rolled back to previous slot", now)
			publishChange(sc.NATS, proto.UpdateChangeEvt{
				NodeID:   spec.NodeID,
				JobID:    sc.JobID,
				BundleID: spec.BundleSHA256,
				Change:   proto.UpdateRolledBack,
				FromSlot: expected.ToSlot,
				ToSlot:   pre.ActiveSlot,
				Version:  pre.CurrentVersion,
				Reason:   "bootloader watchdog or post-install init failure",
				Ts:       now,
			})
			return nil, fmt.Errorf("bootloader_rolled_back: came up on slot %s, expected %s",
				pre.ActiveSlot, expected.ToSlot)
		}
		sc.Log("info", fmt.Sprintf("node up on slot %s (version %s)", pre.ActiveSlot, pre.CurrentVersion))
		return regBytes, nil
	}
}

// ----- Step 7: health_check_and_commit ------------------------------------

func updateHealthCheckAndCommit(store *Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		// Health check via diag.ping.
		pingCmd, _ := json.Marshal(proto.DiagPingCmd{JobID: sc.JobID})
		if _, err := sc.NATS.RequestWithContext(sc.Ctx, proto.NodeCmdSubject(spec.NodeID, "diag.ping"), pingCmd); err != nil {
			// Mark bad → agent reboots to old slot.
			sc.Log("warn", "health check failed; sending mark-bad")
			bad, _ := json.Marshal(proto.UpdateMarkBadCmd{BundleID: spec.BundleSHA256, Reason: err.Error()})
			_, _ = sc.NATS.RequestWithContext(sc.Ctx, proto.UpdateMarkBadSubject(spec.NodeID), bad)

			now := time.Now().UTC()
			_ = store.UpdateNodeUpdate(sc.Ctx, sc.JobID, NodeUpdateRolledBack,
				proto.SlotUnknown, "", "health check failed: "+err.Error(), now)
			publishChange(sc.NATS, proto.UpdateChangeEvt{
				NodeID:   spec.NodeID,
				JobID:    sc.JobID,
				BundleID: spec.BundleSHA256,
				Change:   proto.UpdateRolledBack,
				Reason:   "post-reboot health check failed",
				Ts:       now,
			})
			return nil, fmt.Errorf("health check failed, mark-bad sent: %w", err)
		}
		// Mark good → bootloader committed.
		good, _ := json.Marshal(proto.UpdateMarkGoodCmd{BundleID: spec.BundleSHA256})
		gm, err := sc.NATS.RequestWithContext(sc.Ctx, proto.UpdateMarkGoodSubject(spec.NodeID), good)
		if err != nil {
			return nil, fmt.Errorf("mark-good rpc: %w", err)
		}
		var ack proto.UpdateMarkGoodAck
		_ = json.Unmarshal(gm.Data, &ack)
		if !ack.OK {
			return nil, fmt.Errorf("mark-good rejected: %s", ack.Detail)
		}

		// Record commit.
		row, _ := store.GetNodeUpdate(sc.Ctx, sc.JobID)
		now := time.Now().UTC()
		toSlot := proto.SlotUnknown
		toVersion := ""
		if row != nil {
			toSlot = row.ToSlot
			toVersion = row.ToVersion
		}
		_ = store.UpdateNodeUpdate(sc.Ctx, sc.JobID, NodeUpdateCommitted, toSlot, toVersion, "", now)
		publishChange(sc.NATS, proto.UpdateChangeEvt{
			NodeID:   spec.NodeID,
			JobID:    sc.JobID,
			BundleID: spec.BundleSHA256,
			Change:   proto.UpdateCommitted,
			ToSlot:   toSlot,
			Version:  toVersion,
			Ts:       now,
		})
		sc.Log("info", "update committed")
		return json.Marshal(ack)
	}
}

// ----- helpers -----------------------------------------------------------

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
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

