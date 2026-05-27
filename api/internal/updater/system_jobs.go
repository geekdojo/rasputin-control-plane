package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// SystemUpdateConfig is what the saga needs from main beyond what its
// constructor args carry. SelfNodeID is the node hosting this api process;
// if set, the cascade skips it (the operator drives that update manually,
// once the rest of the fleet is verified).
type SystemUpdateConfig struct {
	SelfNodeID string
}

// SystemUpdateWorkflow returns the three-step system.update saga.
//
//  1. plan      — list nodes, filter online, sort by role (compute → storage
//                 → controlplane → firewall), drop self + excluded. Emits
//                 a `planned` change event with the ordered target list.
//  2. cascade   — for each target in order, submit a child node.update job
//                 and wait for its terminal status. On a child failure the
//                 cascade halts; remaining nodes are reported skipped.
//  3. summarize — emit the final `completed` (or `aborted`) change event
//                 with the per-node outcome counts.
//
// Cascade ordering rationale: the firewall update is the riskiest from a
// "did I lose connectivity to my fleet?" perspective. By updating it last
// we ensure the rest of the system is verified-good before we touch the
// firewall — if the firewall update bricks, at least the other nodes are
// already on the new known-good slot. (See wiki updates.md §3.)
func SystemUpdateWorkflow(
	store *Store,
	inv *inventory.Store,
	jobStore *jobs.Store,
	runner *jobs.Runner,
	nc *nats.Conn,
	cfg SystemUpdateConfig,
) jobs.Workflow {
	return jobs.Workflow{
		Kind: "system.update",
		Steps: []jobs.WorkflowStep{
			{Name: "plan", Timeout: 5 * time.Second, Do: systemPlan(store, inv, cfg)},
			{Name: "cascade", Timeout: 2 * time.Hour, Do: systemCascade(store, inv, jobStore, runner, nc, cfg)},
			{Name: "summarize", Timeout: 5 * time.Second, Do: systemSummarize(jobStore, nc)},
		},
	}
}

// systemPlanState is what step 1 stashes for step 2 to read. We don't have
// shared step memory, so we re-derive it by re-running the same plan; the
// stash is purely for observability (returned as step result for the UI).
type systemPlanState struct {
	BundleSHA256 string   `json:"bundleSha256"`
	BundleVer    string   `json:"bundleVersion"`
	Targets      []string `json:"targets"`
	Skipped      []string `json:"skipped"`
	SelfNodeID   string   `json:"selfNodeId,omitempty"`
}

// ----- Step 1: plan -------------------------------------------------------

func systemPlan(store *Store, inv *inventory.Store, cfg SystemUpdateConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		var spec proto.SystemUpdateSpec
		if err := json.Unmarshal(sc.Spec, &spec); err != nil {
			return nil, fmt.Errorf("invalid spec: %w", err)
		}
		if spec.BundleSHA256 == "" {
			return nil, errors.New("bundleSha256 is required")
		}
		bundle, err := store.GetBundle(sc.Ctx, spec.BundleSHA256)
		if err != nil {
			return nil, fmt.Errorf("bundle lookup: %w", err)
		}
		if bundle == nil {
			return nil, fmt.Errorf("bundle %s not found", spec.BundleSHA256)
		}

		all, err := inv.List(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("inventory: %w", err)
		}

		exclude := map[string]struct{}{}
		for _, id := range spec.ExcludeNodes {
			exclude[id] = struct{}{}
		}
		if cfg.SelfNodeID != "" {
			exclude[cfg.SelfNodeID] = struct{}{}
		}

		targets, skipped := planTargets(all, exclude)
		ids := make([]string, len(targets))
		for i, n := range targets {
			ids[i] = n.ID
		}

		state := systemPlanState{
			BundleSHA256: spec.BundleSHA256,
			BundleVer:    bundle.Version,
			Targets:      ids,
			Skipped:      skipped,
			SelfNodeID:   cfg.SelfNodeID,
		}
		sc.Log("info", fmt.Sprintf("plan: %d target(s), %d skipped — order: %v",
			len(targets), len(skipped), ids))
		publishSystemChange(sc.NATS, proto.SystemUpdateChangeEvt{
			ParentJobID: sc.JobID,
			Change:      proto.SystemUpdatePlanned,
			BundleID:    spec.BundleSHA256,
			Detail:      bundle.Version,
			Counts:      &proto.SystemUpdateCounts{Total: len(targets), Skipped: len(skipped)},
			Ts:          time.Now().UTC(),
		})
		return json.Marshal(state)
	}
}

// planTargets returns the ordered list of nodes to update and the ids of
// nodes that were filtered out. Order: compute → storage → controlplane →
// firewall, within each bucket alphabetic by id. Excluded ids and any node
// not currently online are dropped from targets and listed in skipped.
func planTargets(nodes []*proto.Node, exclude map[string]struct{}) (targets []*proto.Node, skipped []string) {
	roleRank := map[proto.NodeRole]int{
		proto.RoleCompute:      0,
		proto.RoleStorage:      1,
		proto.RoleControlPlane: 2,
		proto.RoleFirewall:     3,
	}
	for _, n := range nodes {
		if _, ex := exclude[n.ID]; ex {
			skipped = append(skipped, n.ID+" (excluded)")
			continue
		}
		// Compute status from last_seen — the inventory list endpoint does
		// this on the API side but ListByRole returns it stale.
		if computeStatus(n.LastSeen) != proto.StatusOnline {
			skipped = append(skipped, n.ID+" (not online)")
			continue
		}
		targets = append(targets, n)
	}
	sort.SliceStable(targets, func(i, j int) bool {
		ri, rj := roleRank[targets[i].Role], roleRank[targets[j].Role]
		if ri != rj {
			return ri < rj
		}
		return targets[i].ID < targets[j].ID
	})
	return targets, skipped
}

// ----- Step 2: cascade ----------------------------------------------------

func systemCascade(
	store *Store,
	inv *inventory.Store,
	jobStore *jobs.Store,
	runner *jobs.Runner,
	nc *nats.Conn,
	cfg SystemUpdateConfig,
) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		var spec proto.SystemUpdateSpec
		if err := json.Unmarshal(sc.Spec, &spec); err != nil {
			return nil, fmt.Errorf("invalid spec: %w", err)
		}
		// Re-derive the plan; can't share state across steps directly.
		all, err := inv.List(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("inventory: %w", err)
		}
		exclude := map[string]struct{}{}
		for _, id := range spec.ExcludeNodes {
			exclude[id] = struct{}{}
		}
		if cfg.SelfNodeID != "" {
			exclude[cfg.SelfNodeID] = struct{}{}
		}
		targets, _ := planTargets(all, exclude)

		var (
			succeeded []string
			failed    []string
			remaining []string
		)

		for i, node := range targets {
			// If we already failed once, the remaining nodes are skipped.
			if len(failed) > 0 {
				remaining = append(remaining, node.ID)
				for _, n := range targets[i+1:] {
					remaining = append(remaining, n.ID)
				}
				break
			}

			childSpec, _ := json.Marshal(map[string]string{
				"nodeId":       node.ID,
				"bundleSha256": spec.BundleSHA256,
			})
			child, err := runner.SubmitChild(sc.Ctx, "node.update", childSpec, "system.update", sc.JobID)
			if err != nil {
				failed = append(failed, node.ID)
				sc.Log("error", fmt.Sprintf("submit child for %s: %v", node.ID, err))
				publishSystemChange(nc, proto.SystemUpdateChangeEvt{
					ParentJobID: sc.JobID,
					Change:      proto.SystemUpdateNodeFailed,
					NodeID:      node.ID,
					BundleID:    spec.BundleSHA256,
					Detail:      err.Error(),
					Ts:          time.Now().UTC(),
				})
				continue
			}
			sc.Log("info", fmt.Sprintf("started child %s for %s", child.ID, node.ID))
			publishSystemChange(nc, proto.SystemUpdateChangeEvt{
				ParentJobID: sc.JobID,
				Change:      proto.SystemUpdateNodeStarted,
				NodeID:      node.ID,
				ChildJobID:  child.ID,
				BundleID:    spec.BundleSHA256,
				Ts:          time.Now().UTC(),
			})

			outcome, derr := waitForChild(sc.Ctx, jobStore, child.ID, 30*time.Minute)
			if derr != nil {
				failed = append(failed, node.ID)
				sc.Log("error", fmt.Sprintf("%s: %v", node.ID, derr))
				publishSystemChange(nc, proto.SystemUpdateChangeEvt{
					ParentJobID: sc.JobID,
					Change:      proto.SystemUpdateNodeFailed,
					NodeID:      node.ID,
					ChildJobID:  child.ID,
					BundleID:    spec.BundleSHA256,
					Detail:      derr.Error(),
					Ts:          time.Now().UTC(),
				})
				continue
			}
			if outcome != jobs.StatusSucceeded {
				failed = append(failed, node.ID)
				sc.Log("error", fmt.Sprintf("%s: child terminated %s", node.ID, outcome))
				publishSystemChange(nc, proto.SystemUpdateChangeEvt{
					ParentJobID: sc.JobID,
					Change:      proto.SystemUpdateNodeFailed,
					NodeID:      node.ID,
					ChildJobID:  child.ID,
					BundleID:    spec.BundleSHA256,
					Detail:      fmt.Sprintf("child %s", outcome),
					Ts:          time.Now().UTC(),
				})
				continue
			}
			succeeded = append(succeeded, node.ID)
			sc.Log("info", fmt.Sprintf("%s: updated", node.ID))
			publishSystemChange(nc, proto.SystemUpdateChangeEvt{
				ParentJobID: sc.JobID,
				Change:      proto.SystemUpdateNodeSucceeded,
				NodeID:      node.ID,
				ChildJobID:  child.ID,
				BundleID:    spec.BundleSHA256,
				Ts:          time.Now().UTC(),
			})
		}

		result := map[string]any{
			"succeeded": succeeded,
			"failed":    failed,
			"remaining": remaining,
		}
		raw, _ := json.Marshal(result)
		if len(failed) > 0 {
			return raw, fmt.Errorf("cascade aborted: %d node(s) failed (%v)", len(failed), failed)
		}
		return raw, nil
	}
}

// waitForChild polls the jobs table for a terminal status on the child.
// Returns the final status. Polls every 1s. A NATS-subscribe approach
// would be tighter, but polling has fewer moving parts and the saga step
// timeout is the real ceiling.
func waitForChild(ctx context.Context, jobStore *jobs.Store, childID string, timeout time.Duration) (jobs.Status, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("child %s did not terminate within %s", childID, timeout)
		}
		j, err := jobStore.GetJob(ctx, childID)
		if err != nil {
			return "", fmt.Errorf("get child: %w", err)
		}
		if j == nil {
			return "", fmt.Errorf("child %s not found", childID)
		}
		switch j.Status {
		case jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCancelled:
			return j.Status, nil
		}
	}
}

// ----- Step 3: summarize --------------------------------------------------

func systemSummarize(jobStore *jobs.Store, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		children, err := jobStore.ListChildJobs(sc.Ctx, sc.JobID)
		if err != nil {
			return nil, fmt.Errorf("list children: %w", err)
		}
		var succeeded, failed int
		for _, c := range children {
			switch c.Status {
			case jobs.StatusSucceeded:
				succeeded++
			case jobs.StatusFailed, jobs.StatusCancelled:
				failed++
			}
		}
		counts := &proto.SystemUpdateCounts{
			Total:     len(children),
			Succeeded: succeeded,
			Failed:    failed,
		}
		// We always emit "completed" here even if some nodes failed —
		// that's still cascade-complete from the saga's perspective. The
		// cascade step already returned an error in that case, so the
		// parent job will be marked failed and the UI can tell apart
		// "completed with failures" via the counts. "aborted" is reserved
		// for explicit user cancellation, a v1 feature.
		publishSystemChange(nc, proto.SystemUpdateChangeEvt{
			ParentJobID: sc.JobID,
			Change:      proto.SystemUpdateCompleted,
			Counts:      counts,
			Ts:          time.Now().UTC(),
		})
		sc.Log("info", fmt.Sprintf("cascade complete: %d succeeded, %d failed", succeeded, failed))
		return json.Marshal(counts)
	}
}

// ----- helpers ------------------------------------------------------------

// computeStatus mirrors api/internal/api/handlers.go computeStatus so the
// updater package doesn't depend on api. The 30s/2m thresholds match.
func computeStatus(lastSeen time.Time) proto.NodeStatus {
	gap := time.Since(lastSeen)
	switch {
	case gap < 30*time.Second:
		return proto.StatusOnline
	case gap < 2*time.Minute:
		return proto.StatusStale
	default:
		return proto.StatusOffline
	}
}

func publishSystemChange(nc *nats.Conn, ev proto.SystemUpdateChangeEvt) {
	payload, err := json.Marshal(ev)
	if err != nil {
		log.Printf("updater: marshal system change: %v", err)
		return
	}
	if err := nc.Publish(proto.SystemUpdateChangeSubject(ev.ParentJobID, ev.Change), payload); err != nil {
		log.Printf("updater: publish system change: %v", err)
	}
}
