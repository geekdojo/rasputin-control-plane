package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
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
//     → controlplane → firewall), drop self + excluded. Emits
//     a `planned` change event with the ordered target list.
//  2. cascade   — for each target in order, submit a child node.update job
//     and wait for its terminal status. On a child failure the
//     cascade halts; remaining nodes are reported skipped.
//  3. summarize — emit the final `completed` (or `aborted`) change event
//     with the per-node outcome counts.
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

// plannedTarget is one node and the bundle IT will receive. The bundle is
// per-target rather than per-run because a mixed arm64/amd64 tier takes two
// different artifacts of the same release (ADR-0005 Decision 11).
type plannedTarget struct {
	NodeID       string `json:"nodeId"`
	BundleSHA256 string `json:"bundleSha256"`
	Compatible   string `json:"compatible"`
	node         *proto.Node
}

// systemPlanState is what step 1 stashes for step 2 to read. Both steps build
// it through the same buildPlan call, so the cascade cannot silently disagree
// with the plan the operator was shown.
type systemPlanState struct {
	// BundleSHA256 / BundleVer describe the run as a whole. On a
	// Version-keyed run BundleSHA256 is empty — there is no single bundle,
	// which is the point — and each target carries its own.
	BundleSHA256 string              `json:"bundleSha256,omitempty"`
	BundleVer    string              `json:"bundleVersion"`
	Component    string              `json:"component,omitempty"`
	Targets      []plannedTarget     `json:"targets"`
	Skipped      []proto.SkippedNode `json:"skipped"`
	SelfNodeID   string              `json:"selfNodeId,omitempty"`
}

// targetIDs is the ordered node-id list, for logs and the change event.
func (s systemPlanState) targetIDs() []string {
	ids := make([]string, len(s.Targets))
	for i, t := range s.Targets {
		ids[i] = t.NodeID
	}
	return ids
}

// stranded returns the skips nobody asked for — nodes with no artifact for
// their architecture. The summarize step reads this off the plan's stashed
// result to decide whether the parent may go green (ADR-0005 Decision 11).
func (s systemPlanState) stranded() []proto.SkippedNode {
	var out []proto.SkippedNode
	for _, sk := range s.Skipped {
		if sk.Reason.Stranded() {
			out = append(out, sk)
		}
	}
	return out
}

// ----- The plan -----------------------------------------------------------

// buildPlan resolves a spec into the ordered targets, each with the bundle it
// will receive, plus the reasoned skips. Both the plan and cascade steps call
// it, so the cascade cannot silently act on a different plan than the one the
// operator was shown at `planned`.
//
// Two spec forms:
//
//   - Version (+ Component) — the fleet form. The correct per-arch bundle is
//     resolved FOR EACH NODE. Every arch present in the plan must already be
//     staged; if one is not, this fails LOUDLY here rather than surfacing 40
//     minutes later as a mid-cascade download failure on node fourteen.
//   - BundleSHA256 — the targeted form. One bundle, and nodes whose SKU does
//     not match it are skipped (stranded if it is an arch mismatch).
func buildPlan(
	ctx context.Context,
	store *Store,
	inv *inventory.Store,
	spec proto.SystemUpdateSpec,
	cfg SystemUpdateConfig,
) (systemPlanState, error) {
	if (spec.Version == "") == (spec.BundleSHA256 == "") {
		return systemPlanState{}, errors.New("exactly one of version or bundleSha256 is required")
	}

	all, err := inv.List(ctx)
	if err != nil {
		return systemPlanState{}, fmt.Errorf("inventory: %w", err)
	}
	exclude := map[string]struct{}{}
	for _, id := range spec.ExcludeNodes {
		exclude[id] = struct{}{}
	}
	if cfg.SelfNodeID != "" {
		exclude[cfg.SelfNodeID] = struct{}{}
	}

	if spec.BundleSHA256 != "" {
		bundle, err := store.GetBundle(ctx, spec.BundleSHA256)
		if err != nil {
			return systemPlanState{}, fmt.Errorf("bundle lookup: %w", err)
		}
		if bundle == nil {
			return systemPlanState{}, fmt.Errorf("bundle %s not found", spec.BundleSHA256)
		}
		nodes, skipped := planTargets(all, exclude, bundle.Compatible)
		targets := make([]plannedTarget, len(nodes))
		for i, n := range nodes {
			targets[i] = plannedTarget{
				NodeID: n.ID, BundleSHA256: bundle.SHA256, Compatible: bundle.Compatible, node: n,
			}
		}
		return systemPlanState{
			BundleSHA256: bundle.SHA256, BundleVer: bundle.Version,
			Targets: targets, Skipped: skipped, SelfNodeID: cfg.SelfNodeID,
		}, nil
	}

	compID := spec.Component
	if compID == "" {
		compID = "os"
	}
	comp, ok := releases.ComponentByID(compID)
	if !ok {
		return systemPlanState{}, fmt.Errorf("unknown component %q", compID)
	}

	// Index what is staged for this version by SKU, so the resolution below is
	// a map lookup rather than a query per node.
	staged, err := stagedByCompatible(ctx, store, spec.Version)
	if err != nil {
		return systemPlanState{}, err
	}

	nodes, skipped := planTargets(all, exclude, "") // "" = no single-bundle filter
	var (
		targets []plannedTarget
		// missing maps a SKU with no staged bundle to the nodes that need it.
		// Collected across ALL nodes before failing, so the operator is told
		// everything they have to stage rather than one arch at a time.
		missing     = map[string][]string{}
		missingSKUs []string
	)
	for _, n := range nodes {
		want, known := expectedCompatible(n)
		if !known {
			// planTargets already rejects these when a bundle SKU is given;
			// with no filter they reach here, and they are still stranded.
			skipped = append(skipped, proto.SkippedNode{
				NodeID: n.ID, Reason: proto.SkipNoArtifactForArch,
				Detail: fmt.Sprintf("architecture %q has no known artifact", n.Architecture),
			})
			continue
		}
		if !componentCovers(comp, want) {
			// An OS run reaching the firewall, or the reverse. The designed
			// single-SKU filter (Decision 8) — never a stranding, and the
			// reason it survives keying on a release at all.
			skipped = append(skipped, proto.SkippedNode{
				NodeID: n.ID, Reason: proto.SkipFirewallSKU,
				Detail: fmt.Sprintf("needs %s, this run updates %s", want, comp.Label),
			})
			continue
		}
		b, ok := staged[want]
		if !ok {
			if _, seen := missing[want]; !seen {
				missingSKUs = append(missingSKUs, want)
			}
			missing[want] = append(missing[want], n.ID)
			continue
		}
		targets = append(targets, plannedTarget{
			NodeID: n.ID, BundleSHA256: b.SHA256, Compatible: want, node: n,
		})
	}

	// The staging precondition. Failing here is the whole point: a node that
	// has no artifact staged is not a node to strand quietly, it is an
	// operator error that is one click from being fixed, and finding out
	// mid-cascade is strictly worse than finding out before anything reboots.
	if len(missing) > 0 {
		sort.Strings(missingSKUs)
		parts := make([]string, 0, len(missingSKUs))
		for _, sku := range missingSKUs {
			ids := missing[sku]
			sort.Strings(ids)
			parts = append(parts, fmt.Sprintf("%s (%d node(s): %s)", sku, len(ids), strings.Join(ids, ", ")))
		}
		return systemPlanState{}, fmt.Errorf(
			"%s %s is not staged for every architecture in this cluster — stage %s first",
			comp.Label, spec.Version, strings.Join(parts, "; "))
	}

	return systemPlanState{
		BundleVer: spec.Version, Component: comp.ID,
		Targets: targets, Skipped: skipped, SelfNodeID: cfg.SelfNodeID,
	}, nil
}

// stagedByCompatible indexes the locally-staged bundles of one version by SKU.
// A version has at most one bundle per SKU; a duplicate would mean two
// artifacts claiming the same version and arch, and the first wins
// deterministically because ListBundles orders by upload time descending —
// i.e. the most recently staged.
func stagedByCompatible(ctx context.Context, store *Store, version string) (map[string]*Bundle, error) {
	all, err := store.ListBundles(ctx)
	if err != nil {
		return nil, fmt.Errorf("list bundles: %w", err)
	}
	out := map[string]*Bundle{}
	for _, b := range all {
		if b.Version != version || b.Compatible == "" {
			continue
		}
		if _, seen := out[b.Compatible]; !seen {
			out[b.Compatible] = b
		}
	}
	return out, nil
}

// componentCovers reports whether a SKU belongs to this component's product
// line. The firewall has exactly one SKU; the OS has one per arch, which is
// every SKU that is not the firewall's.
func componentCovers(comp releases.Component, sku string) bool {
	if comp.Kind == releases.KindRootfsAB || comp.Compatible == releases.FirewallCompatible {
		return sku == releases.FirewallCompatible
	}
	return sku != releases.FirewallCompatible
}

// ----- Step 1: plan -------------------------------------------------------

func systemPlan(store *Store, inv *inventory.Store, cfg SystemUpdateConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		var spec proto.SystemUpdateSpec
		if err := json.Unmarshal(sc.Spec, &spec); err != nil {
			return nil, fmt.Errorf("invalid spec: %w", err)
		}
		state, err := buildPlan(sc.Ctx, store, inv, spec, cfg)
		if err != nil {
			return nil, err
		}
		targets, skipped, ids := state.Targets, state.Skipped, state.targetIDs()

		sc.Log("info", fmt.Sprintf("plan: %d target(s), %d skipped — order: %v",
			len(targets), len(skipped), ids))
		// Say the stranded nodes out loud at plan time, not only in the
		// summary. They are the ones an operator would want to act on before
		// the cascade runs for twenty minutes.
		if str := state.stranded(); len(str) > 0 {
			for _, sk := range str {
				sc.Log("warn", fmt.Sprintf("stranded: %s — %s", sk.NodeID, sk.Detail))
			}
		}
		publishSystemChange(sc.NATS, proto.SystemUpdateChangeEvt{
			ParentJobID: sc.JobID,
			Change:      proto.SystemUpdatePlanned,
			BundleID:    state.BundleSHA256, // empty on a release-keyed run
			Detail:      state.BundleVer,
			Counts: &proto.SystemUpdateCounts{
				Total: len(targets), Skipped: len(skipped), Stranded: len(state.stranded()),
			},
			Skipped: skipped,
			Ts:      time.Now().UTC(),
		})
		return json.Marshal(state)
	}
}

// expectedCompatible is the release SKU string a node's OTA artifact must
// carry: the firewall accepts only its own image; every other node takes the
// OS image for its arch. Second return is false when it can't be determined
// (a pre-arch agent that hasn't reported its arch).
func expectedCompatible(n *proto.Node) (string, bool) {
	if n.Role == proto.RoleFirewall {
		return releases.FirewallCompatible, true
	}
	return releases.ArchCompatible(n.Architecture)
}

// skuMismatchReason classifies a node whose expected SKU differs from the
// bundle's. The firewall's image and the OS image are different products, and
// a cascade only ever carries one of them — so either side being the firewall
// SKU makes this the designed single-SKU filter (Decision 8), not a stranding.
// Anything else is two OS artifacts of different arches, which means the node
// wanted an image this run simply does not have.
func skuMismatchReason(want, bundleCompat string) proto.SkipReason {
	if want == releases.FirewallCompatible || bundleCompat == releases.FirewallCompatible {
		return proto.SkipFirewallSKU
	}
	return proto.SkipNoArtifactForArch
}

// planTargets returns the ordered list of nodes to update and the nodes that
// were filtered out, each with the reason it was. Order: compute → storage →
// controlplane → firewall, within each bucket alphabetic by id.
//
// Every skip carries a proto.SkipReason, and the one that matters is
// SkipNoArtifactForArch: three of the four reasons are the plan working as
// designed, and that one is a node left behind. A system.update carries ONE
// bundle, so an OS run skips the firewall (SkipFirewallSKU — this is what
// keeps the firewall's openwrt-ab backend from ever being handed an OS image
// to dd into a slot) but an arm64 node skipped by an amd64 bundle is stranded,
// not excluded. Before ADR-0005 Decision 11 both were a bare id in a list.
//
// bundleCompat "" disables the SKU filter (unknown bundle — fall back to the
// on-node compatible check).
func planTargets(nodes []*proto.Node, exclude map[string]struct{}, bundleCompat string) (targets []*proto.Node, skipped []proto.SkippedNode) {
	roleRank := map[proto.NodeRole]int{
		proto.RoleCompute:      0,
		proto.RoleStorage:      1,
		proto.RoleControlPlane: 2,
		proto.RoleFirewall:     3,
	}
	skip := func(id string, r proto.SkipReason, detail string) {
		skipped = append(skipped, proto.SkippedNode{NodeID: id, Reason: r, Detail: detail})
	}
	for _, n := range nodes {
		if _, ex := exclude[n.ID]; ex {
			skip(n.ID, proto.SkipExcluded, "excluded from this run")
			continue
		}
		// Compute status from last_seen — the inventory list endpoint does
		// this on the API side but ListByRole returns it stale.
		if computeStatus(n.LastSeen) != proto.StatusOnline {
			skip(n.ID, proto.SkipOffline, "not online when the plan was made")
			continue
		}
		if bundleCompat != "" {
			want, known := expectedCompatible(n)
			switch {
			case !known:
				// No artifact can be chosen for this node at all. Previously
				// this fell through and planned the node into whichever bundle
				// the run happened to carry, which fails at install.
				skip(n.ID, proto.SkipNoArtifactForArch,
					fmt.Sprintf("architecture %q has no known artifact", n.Architecture))
				continue
			case want != bundleCompat:
				skip(n.ID, skuMismatchReason(want, bundleCompat),
					fmt.Sprintf("needs %s, bundle is %s", want, bundleCompat))
				continue
			}
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
		// Prefer the plan the operator was actually shown; re-derive only if the
		// step result is missing (an older job resumed after a restart). The
		// re-derivation used to be the ONLY path, which meant the cascade could
		// act on a different plan than the `planned` event advertised if
		// inventory moved between steps.
		var state systemPlanState
		if raw, ok := sc.PriorResults["plan"]; ok {
			if err := json.Unmarshal(raw, &state); err != nil {
				return nil, fmt.Errorf("read plan result: %w", err)
			}
		} else {
			var err error
			if state, err = buildPlan(sc.Ctx, store, inv, spec, cfg); err != nil {
				return nil, err
			}
		}
		targets := state.Targets

		var (
			succeeded []string
			failed    []string
			remaining []string
		)

		for i, target := range targets {
			// If we already failed once, the remaining nodes are skipped.
			if len(failed) > 0 {
				remaining = append(remaining, target.NodeID)
				for _, t := range targets[i+1:] {
					remaining = append(remaining, t.NodeID)
				}
				break
			}

			// The bundle comes from the TARGET, not the spec — that is the
			// whole of Decision 11 at the point it matters. On a mixed tier
			// consecutive iterations hand out different artifacts of the same
			// release.
			childSpec, _ := json.Marshal(map[string]string{
				"nodeId":       target.NodeID,
				"bundleSha256": target.BundleSHA256,
			})
			child, err := runner.SubmitChild(sc.Ctx, "node.update", childSpec, "system.update", sc.JobID)
			if err != nil {
				failed = append(failed, target.NodeID)
				sc.Log("error", fmt.Sprintf("submit child for %s: %v", target.NodeID, err))
				publishSystemChange(nc, proto.SystemUpdateChangeEvt{
					ParentJobID: sc.JobID,
					Change:      proto.SystemUpdateNodeFailed,
					NodeID:      target.NodeID,
					BundleID:    target.BundleSHA256,
					Detail:      err.Error(),
					Ts:          time.Now().UTC(),
				})
				continue
			}
			sc.Log("info", fmt.Sprintf("started child %s for %s (%s)", child.ID, target.NodeID, target.Compatible))
			publishSystemChange(nc, proto.SystemUpdateChangeEvt{
				ParentJobID: sc.JobID,
				Change:      proto.SystemUpdateNodeStarted,
				NodeID:      target.NodeID,
				ChildJobID:  child.ID,
				BundleID:    target.BundleSHA256,
				Ts:          time.Now().UTC(),
			})

			outcome, derr := waitForChild(sc.Ctx, jobStore, nc, child.ID, 30*time.Minute)
			if derr != nil {
				failed = append(failed, target.NodeID)
				sc.Log("error", fmt.Sprintf("%s: %v", target.NodeID, derr))
				publishSystemChange(nc, proto.SystemUpdateChangeEvt{
					ParentJobID: sc.JobID,
					Change:      proto.SystemUpdateNodeFailed,
					NodeID:      target.NodeID,
					ChildJobID:  child.ID,
					BundleID:    target.BundleSHA256,
					Detail:      derr.Error(),
					Ts:          time.Now().UTC(),
				})
				continue
			}
			if outcome != jobs.StatusSucceeded {
				failed = append(failed, target.NodeID)
				sc.Log("error", fmt.Sprintf("%s: child terminated %s", target.NodeID, outcome))
				publishSystemChange(nc, proto.SystemUpdateChangeEvt{
					ParentJobID: sc.JobID,
					Change:      proto.SystemUpdateNodeFailed,
					NodeID:      target.NodeID,
					ChildJobID:  child.ID,
					BundleID:    target.BundleSHA256,
					Detail:      fmt.Sprintf("child %s", outcome),
					Ts:          time.Now().UTC(),
				})
				continue
			}
			succeeded = append(succeeded, target.NodeID)
			sc.Log("info", fmt.Sprintf("%s: updated", target.NodeID))
			publishSystemChange(nc, proto.SystemUpdateChangeEvt{
				ParentJobID: sc.JobID,
				Change:      proto.SystemUpdateNodeSucceeded,
				NodeID:      target.NodeID,
				ChildJobID:  child.ID,
				BundleID:    target.BundleSHA256,
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

// waitForChild blocks until the child job reaches a terminal status,
// then returns it. Subscribes to rasputin.job.<id>.events and treats
// JobSucceeded / JobFailed events as the wake signal — the store is then
// re-read for the authoritative final Status (handles e.g. Cancelled,
// which has no dedicated event today but might one day).
//
// Two safeguards against subscribe-vs-publish races:
//
//  1. We Subscribe BEFORE the initial store read, so an event that fires
//     between our two operations queues on the subscription and isn't
//     lost.
//  2. We Flush after subscribing so the server has acked the SUB before
//     we proceed — without this, a child that completes "instantly" can
//     publish its terminal event before our SUB is processed, and the
//     initial store read would be our only catch.
//
// nc may be nil in tests that don't supply a NATS connection; the loop
// then falls back to a 100ms tick on the store (still faster than the
// old 1s ticker, while keeping the test path simple).
func waitForChild(ctx context.Context, jobStore *jobs.Store, nc *nats.Conn, childID string, timeout time.Duration) (jobs.Status, error) {
	deadline := time.Now().Add(timeout)
	deadlineCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// Set up the wake signal: a buffered chan that receives whenever a
	// terminal-shaped event arrives. Buffer of 1 prevents the subscriber
	// callback from blocking if the consumer is already winding down.
	wake := make(chan struct{}, 1)
	if nc != nil {
		sub, err := nc.Subscribe(proto.JobEventsSubject(childID), func(m *nats.Msg) {
			var ev proto.JobEvent
			if json.Unmarshal(m.Data, &ev) != nil {
				return
			}
			if ev.Type != proto.JobSucceeded && ev.Type != proto.JobFailed {
				return
			}
			select {
			case wake <- struct{}{}:
			default:
			}
		})
		if err != nil {
			return "", fmt.Errorf("subscribe child events: %w", err)
		}
		defer sub.Unsubscribe()
		// Flush so the SUB is observed by the server before we poll the
		// store — closes the "child completed instantly" race.
		_ = nc.Flush()
	}

	for {
		j, err := jobStore.GetJob(deadlineCtx, childID)
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
		// Block until either: a terminal event wakes us, the deadline
		// fires, or the parent ctx is cancelled. Fall-back tick fires
		// every 100ms when nc is nil (in-test) OR every 1s as a belt
		// against an event we missed (e.g. status set via direct DB
		// write that didn't emit).
		fallback := 1 * time.Second
		if nc == nil {
			fallback = 100 * time.Millisecond
		}
		select {
		case <-deadlineCtx.Done():
			if deadlineCtx.Err() == context.DeadlineExceeded {
				return "", fmt.Errorf("child %s did not terminate within %s", childID, timeout)
			}
			return "", deadlineCtx.Err()
		case <-wake:
			// loop and re-read the store
		case <-time.After(fallback):
			// belt-and-suspenders re-read
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
		// Read the plan back off the step-result map so the summary can
		// account for nodes that never became targets. Without this the
		// rollup only ever sees children, and a node that was never planned
		// is invisible to the very report that is supposed to notice it.
		var plan systemPlanState
		if raw, ok := sc.PriorResults["plan"]; ok {
			if err := json.Unmarshal(raw, &plan); err != nil {
				return nil, fmt.Errorf("read plan result: %w", err)
			}
		}
		stranded := plan.stranded()

		counts := &proto.SystemUpdateCounts{
			Total:     len(children),
			Succeeded: succeeded,
			Failed:    failed,
			Skipped:   len(plan.Skipped),
			Stranded:  len(stranded),
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
			Skipped:     plan.Skipped,
			Ts:          time.Now().UTC(),
		})
		sc.Log("info", fmt.Sprintf("cascade complete: %d succeeded, %d failed", succeeded, failed))
		raw, err := json.Marshal(counts)
		if err != nil {
			return nil, err
		}
		// A stranded node fails the parent. Every child may have committed
		// cleanly and the grid may be all green, and the run still did not do
		// what "UPDATE ALL" says on the button — so the honest terminal state
		// is failed, not succeeded. This is the one place where the parent's
		// colour is decided by something other than its children.
		//
		// It runs AFTER the completed event is published, deliberately: the
		// operator needs the report in order to act on the strandings, and a
		// step that errors before publishing would take the report with it.
		if len(stranded) > 0 {
			ids := make([]string, len(stranded))
			for i, sk := range stranded {
				ids[i] = sk.NodeID
			}
			sc.Log("error", fmt.Sprintf("%d node(s) stranded — no artifact for their architecture: %v",
				len(stranded), ids))
			return raw, fmt.Errorf("%d node(s) had no artifact for their architecture and were never updated (%v)",
				len(stranded), ids)
		}
		return raw, nil
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
