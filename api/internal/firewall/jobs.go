package firewall

import (
	"context"
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

// Managed reports whether the api should manage the firewall node under the
// current deployment mode. It returns false in LAN-peer mode — the existing
// router firewalls and our box is idle, so apply/reconcile no-op rather than
// pushing config or reporting perpetual drift against a stock box. A nil
// Managed (tests, back-compat) is treated as "manage".
type Managed func(ctx context.Context) (bool, error)

// modeGate is the first step of both firewall workflows. In an unmanaged mode
// it stops the saga early (successfully) so no config is pushed and no drift
// is reported.
func modeGate(managed Managed) jobs.WorkflowStep {
	return jobs.WorkflowStep{
		Name:    "mode_gate",
		Timeout: 2 * time.Second,
		Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
			if managed == nil {
				return nil, nil
			}
			ok, err := managed(sc.Ctx)
			if err != nil {
				return nil, fmt.Errorf("mode gate: %w", err)
			}
			if !ok {
				sc.Log("info", "firewall management is disabled for this deployment mode (LAN peer) — skipping")
				return nil, jobs.ErrStopWorkflow
			}
			return nil, nil
		},
	}
}

// ----- ApplyWorkflow ------------------------------------------------------

// ApplyWorkflow pushes the api's intent set to the firewall agent.
//
//  1. mode_gate    — stop early (no-op) if this deployment mode doesn't
//     manage the firewall (LAN peer).
//  2. find_target  — resolve the firewall node id (validates exactly one).
//  3. compile      — load + compile intents to canonical UCI state.
//  4. push         — RPC the agent, persist resulting hash.
//
// Steps don't share data via the runner; each re-reads what it needs.
func ApplyWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn, managed Managed) jobs.Workflow {
	return jobs.Workflow{
		Kind: "firewall.apply",
		Steps: []jobs.WorkflowStep{
			modeGate(managed),
			{Name: "find_target", Timeout: 2 * time.Second, Do: applyFindTarget(inv)},
			{Name: "compile", Timeout: 2 * time.Second, Do: applyCompile(store)},
			{Name: "push", Timeout: 5 * time.Second, Do: applyPush(store, inv, nc)},
		},
	}
}

func applyFindTarget(inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		fws, err := inv.ListByRole(sc.Ctx, proto.RoleFirewall)
		if err != nil {
			return nil, fmt.Errorf("inventory lookup: %w", err)
		}
		if len(fws) == 0 {
			return nil, errors.New("no firewall-role node is registered")
		}
		if len(fws) > 1 {
			return nil, fmt.Errorf("expected exactly one firewall node, found %d", len(fws))
		}
		sc.Log("info", fmt.Sprintf("target firewall node: %s", fws[0].ID))
		return json.Marshal(map[string]string{"nodeId": fws[0].ID})
	}
}

func applyCompile(store *Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		intents, err := store.ListIntents(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("list intents: %w", err)
		}
		state, hash, err := Compile(intents)
		if err != nil {
			return nil, fmt.Errorf("compile: %w", err)
		}
		enabled := 0
		for _, i := range intents {
			if i.Enabled {
				enabled++
			}
		}
		sc.Log("info", fmt.Sprintf("compiled %d enabled intent(s), hash=%s", enabled, hash[:12]))
		return json.Marshal(map[string]any{"state": state, "hash": hash, "intentCount": enabled})
	}
}

func applyPush(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		// Re-find target and re-compile so the step is self-contained.
		fws, err := inv.ListByRole(sc.Ctx, proto.RoleFirewall)
		if err != nil || len(fws) != 1 {
			return nil, fmt.Errorf("firewall node lookup: %w", err)
		}
		nodeID := fws[0].ID

		intents, err := store.ListIntents(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("list intents: %w", err)
		}
		state, intentHash, err := Compile(intents)
		if err != nil {
			return nil, fmt.Errorf("compile: %w", err)
		}

		cmd, err := json.Marshal(proto.FirewallApplyCmd{State: state, IntentHash: intentHash})
		if err != nil {
			return nil, err
		}
		sc.Log("info", fmt.Sprintf("pushing to %s", nodeID))
		msg, err := nc.RequestWithContext(sc.Ctx, proto.FirewallApplySubject(nodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("apply rpc: %w", err)
		}
		var ack proto.FirewallApplyAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("decode ack: %w", err)
		}
		if !ack.OK {
			return nil, errors.New("agent reported apply failed")
		}
		if ack.Hash != intentHash {
			return nil, fmt.Errorf("hash mismatch: intent=%s applied=%s", intentHash, ack.Hash)
		}

		now := time.Now().UTC()
		if err := store.UpdateAfterApply(sc.Ctx, nodeID, intentHash, now); err != nil {
			log.Printf("firewall: persist apply state: %v", err)
		}
		// Publish a "applied" change event for live UI subscribers.
		evPayload, _ := json.Marshal(proto.FirewallChangeEvt{
			NodeID:     nodeID,
			Change:     proto.FirewallApplied,
			IntentHash: intentHash,
			Ts:         now,
		})
		_ = nc.Publish(proto.FirewallChangeSubject(nodeID, proto.FirewallApplied), evPayload)

		sc.Log("info", fmt.Sprintf("applied: hash=%s", intentHash[:12]))
		return json.Marshal(map[string]string{"nodeId": nodeID, "hash": intentHash})
	}
}

// ----- ReconcileWorkflow --------------------------------------------------

// ReconcileWorkflow fetches the firewall agent's observed state, compares it
// against the intent hash the api thinks should be live, and emits a drift
// or in_sync change event accordingly.
func ReconcileWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn, managed Managed) jobs.Workflow {
	return jobs.Workflow{
		Kind: "firewall.reconcile",
		Steps: []jobs.WorkflowStep{
			modeGate(managed),
			{Name: "find_target", Timeout: 2 * time.Second, Do: applyFindTarget(inv)},
			{Name: "fetch_observed", Timeout: 5 * time.Second, Do: reconcileFetch(store, inv, nc)},
			{Name: "compare", Timeout: 2 * time.Second, Do: reconcileCompare(store, inv, nc)},
		},
	}
}

func reconcileFetch(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		fws, err := inv.ListByRole(sc.Ctx, proto.RoleFirewall)
		if err != nil || len(fws) != 1 {
			return nil, fmt.Errorf("firewall node lookup: %w", err)
		}
		nodeID := fws[0].ID
		cmd, _ := json.Marshal(proto.FirewallGetCmd{})
		msg, err := nc.RequestWithContext(sc.Ctx, proto.FirewallGetSubject(nodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("get rpc: %w", err)
		}
		var ack proto.FirewallGetAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("decode ack: %w", err)
		}
		now := time.Now().UTC()
		if err := store.UpdateAfterReconcile(sc.Ctx, nodeID, ack.Hash, now); err != nil {
			log.Printf("firewall: persist reconcile state: %v", err)
		}
		sc.Log("info", fmt.Sprintf("observed hash=%s", short(ack.Hash)))
		return json.Marshal(map[string]string{"nodeId": nodeID, "observedHash": ack.Hash})
	}
}

func reconcileCompare(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		fws, err := inv.ListByRole(sc.Ctx, proto.RoleFirewall)
		if err != nil || len(fws) != 1 {
			return nil, fmt.Errorf("firewall node lookup: %w", err)
		}
		nodeID := fws[0].ID
		state, err := store.GetNodeState(sc.Ctx, nodeID)
		if err != nil {
			return nil, err
		}
		if state == nil {
			return nil, errors.New("no state recorded for node — apply first")
		}

		now := time.Now().UTC()
		var change proto.FirewallChangeType
		if state.Drift {
			change = proto.FirewallDrift
			sc.Log("warn", fmt.Sprintf("DRIFT: intent=%s observed=%s",
				short(state.IntentHash), short(state.ObservedHash)))
		} else {
			change = proto.FirewallInSync
			sc.Log("info", "in sync with intent")
		}
		ev := proto.FirewallChangeEvt{
			NodeID:       nodeID,
			Change:       change,
			IntentHash:   state.IntentHash,
			ObservedHash: state.ObservedHash,
			Ts:           now,
		}
		payload, _ := json.Marshal(ev)
		_ = nc.Publish(proto.FirewallChangeSubject(nodeID, change), payload)

		return json.Marshal(map[string]any{
			"drift":        state.Drift,
			"intentHash":   state.IntentHash,
			"observedHash": state.ObservedHash,
		})
	}
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
