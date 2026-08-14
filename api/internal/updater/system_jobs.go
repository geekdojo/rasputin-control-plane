package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
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
	NodeID       string         `json:"nodeId"`
	BundleSHA256 string         `json:"bundleSha256"`
	Compatible   string         `json:"compatible"`
	Tier         proto.NodeRole `json:"tier"`
	// Canary marks this target as the one node whose outcome gates fan-out for
	// its (Tier, Compatible) pair. Decided at PLAN time, not in the cascade, so
	// the `planned` event tells the operator which node is about to carry the
	// risk while there is still time to override it.
	Canary bool `json:"canary,omitempty"`
	node   *proto.Node
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

// canaryIDs is the ordered list of nodes gating a fan-out, one per (tier,
// arch) pair. Named at plan time so the operator can see who is carrying the
// risk before anything reboots.
func (s systemPlanState) canaryIDs() []string {
	var ids []string
	for _, t := range s.Targets {
		if t.Canary {
			ids = append(ids, t.NodeID)
		}
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
				NodeID: n.ID, BundleSHA256: bundle.SHA256, Compatible: bundle.Compatible,
				Tier: n.Role, node: n,
			}
		}
		if err := assignCanaries(targets, spec.CanaryNodes); err != nil {
			return systemPlanState{}, err
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
			NodeID: n.ID, BundleSHA256: b.SHA256, Compatible: want, Tier: n.Role, node: n,
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

	if err := assignCanaries(targets, spec.CanaryNodes); err != nil {
		return systemPlanState{}, err
	}
	return systemPlanState{
		BundleVer: spec.Version, Component: comp.ID,
		Targets: targets, Skipped: skipped, SelfNodeID: cfg.SelfNodeID,
	}, nil
}

// ----- The canary ---------------------------------------------------------

// canaryEligible reports whether a tier nominates a canary at all.
//
// The controlplane and the firewall never do (ADR-0005 Decision 6). Not an
// arbitrary carve-out: a canary is the cheap node you risk on behalf of the
// expensive ones, and neither of these has anything behind it to protect. The
// firewall cascades alone — the component filter means an OS run has no
// firewall target and a firewall run has nothing else (Decision 8) — so a
// "canary" there would be the entire tier gating itself. The controlplane is
// ordered last among the OS tiers precisely because losing it costs the
// operator their view of the fleet; making it the first node to take a new
// image inverts the reason for that ordering.
func canaryEligible(tier proto.NodeRole) bool {
	return tier == proto.RoleCompute || tier == proto.RoleStorage
}

// canaryGroup identifies the unit a canary speaks for: one tier, one arch.
//
// Arch is half the key because "the image is good" is an arch-scoped claim —
// an arm64 canary proves nothing about the amd64 artifact, which is a
// different binary built by a different job (ADR-0005 Decision 11). Tier is
// the other half because tiers advance sequentially and a canary only ever
// authorises the fan-out immediately behind it.
type canaryGroup struct {
	Tier       proto.NodeRole
	Compatible string
}

func (g canaryGroup) String() string { return string(g.Tier) + "/" + g.Compatible }

// assignCanaries marks one canary per (tier, arch) group, in place.
//
// The default pick is the first target in planned order within the group,
// which is deterministic and matches what the `planned` event already shows an
// operator. An id in `overrides` replaces the default pick for its own group.
//
// Every override problem is an error rather than a silent fallback. An
// operator who names a canary has a reason — a node they can afford to lose, a
// node physically in front of them — and quietly canarying a different one is
// worse than refusing the run.
func assignCanaries(targets []plannedTarget, overrides []string) error {
	chosen := map[canaryGroup]int{} // group → index into targets
	byID := map[string]int{}
	for i, t := range targets {
		byID[t.NodeID] = i
		if !canaryEligible(t.Tier) {
			continue
		}
		g := canaryGroup{Tier: t.Tier, Compatible: t.Compatible}
		if _, seen := chosen[g]; !seen {
			chosen[g] = i
		}
	}

	overriddenBy := map[canaryGroup]string{}
	for _, id := range overrides {
		i, ok := byID[id]
		if !ok {
			return fmt.Errorf("canary override %q is not a target of this plan", id)
		}
		t := targets[i]
		if !canaryEligible(t.Tier) {
			return fmt.Errorf("canary override %q is a %s node; the canary is never the controlplane or the firewall",
				id, t.Tier)
		}
		g := canaryGroup{Tier: t.Tier, Compatible: t.Compatible}
		if prev, dup := overriddenBy[g]; dup {
			return fmt.Errorf("canary overrides %q and %q are both in %s; one canary per tier and architecture",
				prev, id, g)
		}
		overriddenBy[g] = id
		chosen[g] = i
	}

	for _, i := range chosen {
		targets[i].Canary = true
	}
	return nil
}

// tierGroup is one tier's slice of the planned order, kept contiguous.
// planTargets already sorts by role, so grouping is a scan rather than a sort
// and the order within a tier is the planned order.
type tierGroup struct {
	Tier    proto.NodeRole
	Targets []plannedTarget
}

func groupByTier(targets []plannedTarget) []tierGroup {
	var out []tierGroup
	for _, t := range targets {
		if n := len(out); n > 0 && out[n-1].Tier == t.Tier {
			out[n-1].Targets = append(out[n-1].Targets, t)
			continue
		}
		out = append(out, tierGroup{Tier: t.Tier, Targets: []plannedTarget{t}})
	}
	return out
}

// split separates a tier into the canaries that gate it and the fan-out behind
// them, preserving planned order in both.
func (g tierGroup) split() (canaries, fanout []plannedTarget) {
	for _, t := range g.Targets {
		if t.Canary {
			canaries = append(canaries, t)
		} else {
			fanout = append(fanout, t)
		}
	}
	return canaries, fanout
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
		// Name the canaries at plan time. They are the nodes that will take the
		// image on behalf of the rest, and this is the last moment an operator
		// can override the pick before one of them reboots.
		if cans := state.canaryIDs(); len(cans) > 0 {
			sc.Log("info", fmt.Sprintf("canaries (one per tier and architecture): %v — fan-out is gated on them", cans))
		}
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
// OS image for its arch. Second return is false when it can't be determined —
// an unrecognized arch, or an agent that never reported one.
//
// That sentence used to be false for the empty case: ArchCompatible grouped
// "" with amd64 and returned true, so a node that never said which arch it
// was got planned into an amd64 cascade with full confidence. The comment and
// the code have been made to agree by fixing the code (#67).
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

// childDriver is the cascade's one dependency on the live world: submitting a
// node.update child and waiting for it to terminate. Split out behind function
// values so the ORDERING logic above it — the canary gate now, bounded fan-out
// and the failure budget next (#74, #75) — is exercisable without a runner, a
// NATS server and a job store. That logic is the part with the interesting
// failure modes and it was previously reachable only through a full saga.
type childDriver struct {
	submit func(sc *jobs.StepCtx, t plannedTarget) (childID string, err error)
	wait   func(sc *jobs.StepCtx, childID string) (jobs.Status, error)
}

func liveChildDriver(jobStore *jobs.Store, runner *jobs.Runner, nc *nats.Conn) childDriver {
	return childDriver{
		submit: func(sc *jobs.StepCtx, t plannedTarget) (string, error) {
			// The bundle comes from the TARGET, not the spec — that is the
			// whole of Decision 11 at the point it matters. On a mixed tier
			// consecutive children are handed different artifacts of the same
			// release.
			childSpec, _ := json.Marshal(map[string]string{
				"nodeId":       t.NodeID,
				"bundleSha256": t.BundleSHA256,
			})
			child, err := runner.SubmitChild(sc.Ctx, "node.update", childSpec, "system.update", sc.JobID)
			if err != nil {
				return "", err
			}
			return child.ID, nil
		},
		wait: func(sc *jobs.StepCtx, childID string) (jobs.Status, error) {
			return waitForChild(sc.Ctx, jobStore, nc, childID, 30*time.Minute)
		},
	}
}

func systemCascade(
	store *Store,
	inv *inventory.Store,
	jobStore *jobs.Store,
	runner *jobs.Runner,
	nc *nats.Conn,
	cfg SystemUpdateConfig,
) jobs.DoFn {
	return systemCascadeWith(store, inv, nc, cfg, liveChildDriver(jobStore, runner, nc))
}

// systemCascadeWith is systemCascade with the child driver injected.
//
// Shape, per ADR-0005 Decisions 6 and 11: tiers run in the planned order,
// sequentially. Within a tier, the canary of each architecture present runs
// FIRST and its outcome gates the fan-out behind it — an arm64 canary cannot
// authorise amd64 nodes, so a mixed tier runs one canary per arch.
//
// ⚠️ ANY canary failure aborts the whole run, not just its own arch's fan-out.
// Decision 11 makes the gate per-arch, and Decision 6 says a canary failure
// means "abort before fan-out; nothing else in the fleet is touched — this is
// the one place abort survives". The per-arch rule is about a canary being
// INSUFFICIENT authority for another arch, not about the two arches failing
// independently; a bad build is far likelier to be a bad release than a bad
// single artifact, and the operator can re-run scoped to the good arch. So the
// two decisions compose as: fan-out for an arch requires that arch's own
// canary, and any canary failing stops everything.
//
// Fan-out itself is still serial and still halts on the first failure. That is
// today's behaviour, deliberately left alone here: the bounded-parallel fan-out
// is #74 and best-effort reporting is #76. This story adds the gate in FRONT of
// fan-out, which makes every intermediate state at least as safe as the one
// before it — the reverse order would land a fleet update that neither aborts
// nor canaries.
//
// A plan stashed by an api that predates this code carries no Tier and no
// Canary on its targets, so it degrades to one unnamed tier with no gate —
// i.e. to exactly the serial halt-on-first cascade it was planned under. That
// is the right answer for a job resumed across an upgrade: finish it the way
// it started rather than invent a canary halfway through.
func systemCascadeWith(
	store *Store,
	inv *inventory.Store,
	nc *nats.Conn,
	cfg SystemUpdateConfig,
	drv childDriver,
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

		maxInFlight := proto.DefaultMaxInFlight
		if spec.MaxInFlight != nil {
			maxInFlight = *spec.MaxInFlight
		}
		if err := maxInFlight.Validate(); err != nil {
			return nil, fmt.Errorf("maxInFlight: %w", err)
		}

		var (
			canaries []string
			// canaryFailure names the gate that stopped the run, so the error
			// can say "the canary caught this" rather than the generic
			// "something failed" — the two ask an operator for different next
			// moves.
			canaryFailure string
		)
		// grid is the per-node report. Every planned target gets a row whether
		// or not it was ever started, which is the difference between a report
		// and a list of things that happened to work.
		//
		// It is also the ONLY tally. The succeeded/failed lists are derived
		// from it in planned order at the end rather than appended as nodes
		// finish, so that a bounded-parallel run reports in a stable order
		// instead of in whatever order the fleet happened to reboot. A grid
		// that reshuffles itself between two runs of the same update is a
		// report an operator cannot diff.
		var gridMu sync.Mutex
		grid := map[string]proto.NodeResult{}

		// runOne submits a child, waits for it, and reports whether the node
		// updated. Every exit path emits the matching node_* event AND writes
		// the node's grid row, so a target can never start and then vanish
		// from the report. Safe to call from several goroutines at once.
		runOne := func(t plannedTarget, isCanary bool) bool {
			row := proto.NodeResult{
				NodeID: t.NodeID, Tier: t.Tier, Compatible: t.Compatible, Canary: isCanary,
			}
			record := func(outcome proto.NodeOutcome, childID, detail string) {
				row.Outcome, row.ChildJobID, row.Detail = outcome, childID, detail
				gridMu.Lock()
				grid[t.NodeID] = row
				gridMu.Unlock()
			}
			evt := func(change proto.SystemUpdateChangeType, childID, detail string) {
				publishSystemChange(nc, proto.SystemUpdateChangeEvt{
					ParentJobID: sc.JobID,
					Change:      change,
					NodeID:      t.NodeID,
					ChildJobID:  childID,
					BundleID:    t.BundleSHA256,
					Detail:      detail,
					Tier:        t.Tier,
					Compatible:  t.Compatible,
					Canary:      isCanary,
					Ts:          time.Now().UTC(),
				})
			}
			role := "target"
			if isCanary {
				role = "canary"
			}

			childID, err := drv.submit(sc, t)
			if err != nil {
				sc.Log("error", fmt.Sprintf("submit child for %s: %v", t.NodeID, err))
				record(proto.NodeOutcomeFailed, "", err.Error())
				evt(proto.SystemUpdateNodeFailed, "", err.Error())
				return false
			}
			sc.Log("info", fmt.Sprintf("started child %s for %s %s (%s)", childID, role, t.NodeID, t.Compatible))
			evt(proto.SystemUpdateNodeStarted, childID, "")

			outcome, derr := drv.wait(sc, childID)
			switch {
			case derr != nil:
				sc.Log("error", fmt.Sprintf("%s: %v", t.NodeID, derr))
				record(proto.NodeOutcomeFailed, childID, derr.Error())
				evt(proto.SystemUpdateNodeFailed, childID, derr.Error())
				return false
			case outcome != jobs.StatusSucceeded:
				sc.Log("error", fmt.Sprintf("%s: child terminated %s", t.NodeID, outcome))
				record(proto.NodeOutcomeFailed, childID, fmt.Sprintf("child %s", outcome))
				evt(proto.SystemUpdateNodeFailed, childID, fmt.Sprintf("child %s", outcome))
				return false
			}
			sc.Log("info", fmt.Sprintf("%s: updated", t.NodeID))
			record(proto.NodeOutcomeSucceeded, childID, "")
			evt(proto.SystemUpdateNodeSucceeded, childID, "")
			return true
		}

		// gateEvt publishes a canary_* verdict for one (tier, arch) pair. This
		// is the fan-out authorisation, distinct from the canary node's own
		// node_* outcome.
		gateEvt := func(change proto.SystemUpdateChangeType, t plannedTarget, detail string) {
			publishSystemChange(nc, proto.SystemUpdateChangeEvt{
				ParentJobID: sc.JobID,
				Change:      change,
				NodeID:      t.NodeID,
				BundleID:    t.BundleSHA256,
				Detail:      detail,
				Tier:        t.Tier,
				Compatible:  t.Compatible,
				Canary:      true,
				Ts:          time.Now().UTC(),
			})
		}

	tiers:
		for _, tier := range groupByTier(targets) {
			tierCanaries, fanout := tier.split()

			for _, c := range tierCanaries {
				canaries = append(canaries, c.NodeID)
				g := canaryGroup{Tier: c.Tier, Compatible: c.Compatible}
				sc.Log("info", fmt.Sprintf("canary for %s: %s — fan-out for this architecture is gated on it", g, c.NodeID))
				if !runOne(c, true) {
					canaryFailure = fmt.Sprintf("%s (%s)", c.NodeID, g)
					gateEvt(proto.SystemUpdateCanaryFailed, c, "fan-out aborted; nothing else was touched")
					sc.Log("error", fmt.Sprintf(
						"canary %s failed for %s — aborting before fan-out; no further node is touched", c.NodeID, g))
					break tiers
				}
				gateEvt(proto.SystemUpdateCanaryPassed, c, "fan-out authorised for this architecture")
			}

			if len(tierCanaries) > 0 && len(fanout) > 0 {
				if err := soak(sc, spec.CanarySoakSeconds); err != nil {
					return nil, err
				}
			}

			// Best-effort fan-out (ADR-0005 Decision 7): every planned target
			// is attempted and a failed node is a red cell, not a wall. A/B
			// rollback is per-node and independent, so one node failing says
			// nothing about the next — and the canary above has already
			// cleared the image, which is what makes carrying on reasonable
			// rather than reckless. The thing that DOES stop a tier once
			// failures pile up is the failure budget, #75.
			//
			// Bounded-parallel, k scoped to THIS tier and clamped against its
			// size (Decision 6). k=1 is the serial cascade exactly.
			k := proto.ClampMaxInFlight(maxInFlight.Resolve(len(tier.Targets)), len(tier.Targets))
			if len(fanout) > 0 {
				sc.Log("info", fmt.Sprintf("%s fan-out: %d node(s), %d at a time (%s of a %d-node tier)",
					tier.Tier, len(fanout), k, maxInFlight, len(tier.Targets)))
			}
			runBounded(fanout, k, func(t plannedTarget) { runOne(t, false) })
		}

		// The whole report, in PLANNED order — not completion order. Under
		// bounded parallelism nodes finish in whatever sequence the fleet
		// reboots in, and a grid that reshuffles between two runs of the same
		// update is one an operator cannot diff. Every tally below is derived
		// from this loop for the same reason.
		var succeeded, failed, remaining []string
		results := make([]proto.NodeResult, 0, len(targets))
		for _, t := range targets {
			row, attempted := grid[t.NodeID]
			if !attempted {
				// Under best-effort this only happens when the canary gate
				// aborted, which is exactly why it is worth its own outcome
				// rather than being folded in with the failures.
				remaining = append(remaining, t.NodeID)
				row = proto.NodeResult{
					NodeID: t.NodeID, Tier: t.Tier, Compatible: t.Compatible, Canary: t.Canary,
					Outcome: proto.NodeOutcomeNotAttempted,
					Detail:  "the run stopped before this node was started; it is untouched",
				}
			}
			switch row.Outcome {
			case proto.NodeOutcomeSucceeded:
				succeeded = append(succeeded, t.NodeID)
			case proto.NodeOutcomeFailed:
				failed = append(failed, t.NodeID)
			}
			results = append(results, row)
		}

		// ⚠️ A node failure does NOT fail this step, and that is a change.
		//
		// A saga stops at its first failed step (`Runner.run`), so a cascade
		// that returned an error took `summarize` down with it — meaning the
		// `completed` event and its counts were never published on precisely
		// the runs that had something to report. updates.md §4 asserts the
		// opposite ("the summarize step still fires"); the doc was describing
		// an intent the code did not implement, and nobody noticed while
		// halt-on-first made a failed run a two-line story.
		//
		// It stops being survivable here: once partial success is the common
		// outcome, the results grid IS the report, and losing it on failure
		// loses the whole feature. So the outcome travels on the step result
		// and `summarize` publishes the report and THEN returns the terminal
		// error — the same pattern the stranded-node check already uses, for
		// the same reason: the operator needs the report in order to act on
		// it. The parent still ends `failed`; only which step said so moves.
		return json.Marshal(cascadeResult{
			Succeeded:     succeeded,
			Failed:        failed,
			Remaining:     remaining,
			Canaries:      canaries,
			CanaryFailure: canaryFailure,
			Results:       results,
		})
	}
}

// cascadeResult is the shape the cascade step returns, read back by summarize.
// The three id lists are kept because they read well in a job-step dump;
// Results is the one that carries tier, arch, canary and the not-attempted
// rows, and is what the UI renders.
type cascadeResult struct {
	Succeeded []string           `json:"succeeded"`
	Failed    []string           `json:"failed"`
	Remaining []string           `json:"remaining"`
	Canaries  []string           `json:"canaries"`
	Results   []proto.NodeResult `json:"results"`
	// CanaryFailure names the gate that stopped the run, empty otherwise. The
	// terminal error reads differently for it: "the canary caught a bad image"
	// and "three nodes in your fleet are unhappy" ask for different next moves.
	CanaryFailure string `json:"canaryFailure,omitempty"`
}

// terminalError is the run's verdict, or nil. Computed here rather than in the
// cascade so the report is published before the saga is failed.
func (r cascadeResult) terminalError() error {
	switch {
	case r.CanaryFailure != "":
		return fmt.Errorf("canary %s failed — aborted before fan-out, %d node(s) untouched",
			r.CanaryFailure, len(r.Remaining))
	case len(r.Failed) > 0:
		// The parent's terminal state is unchanged by best-effort: still
		// failed if any node failed. Deliberate — it preserves the existing
		// green/red UI semantics, and "some of your fleet did not take the
		// update" is not a success however many nodes did.
		return fmt.Errorf("%d of %d node(s) failed (%v)",
			len(r.Failed), len(r.Results), r.Failed)
	}
	return nil
}

// runBounded runs `run` over targets with at most k in flight, in planned
// order of START. It returns when every target has finished.
//
// A plain worker pool rather than anything cleverer: the work items are known
// up front, each takes tens of minutes, and there is nothing to steal or
// rebalance. k=1 walks the list one at a time — byte-for-byte the old serial
// cascade, which is what lets bounded fan-out be described as backwards
// compatible rather than as a rewrite.
//
// No early exit: under best-effort every target is attempted (Decision 7).
// Stopping the tier once failures pile up is the failure budget, #75, and it
// belongs at the point a node is about to START — the semaphore acquire below
// is where that check goes.
func runBounded(targets []plannedTarget, k int, run func(plannedTarget)) {
	if k < 1 {
		k = 1
	}
	sem := make(chan struct{}, k)
	var wg sync.WaitGroup
	for _, t := range targets {
		sem <- struct{}{}
		wg.Add(1)
		go func(t plannedTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			run(t)
		}(t)
	}
	wg.Wait()
}

// soak holds a tier's fan-out after its canaries pass. Zero — the default and
// the expected setting — returns immediately without logging, so the normal
// path reads exactly as it did before the knob existed.
func soak(sc *jobs.StepCtx, seconds int) error {
	if seconds <= 0 {
		return nil
	}
	d := time.Duration(seconds) * time.Second
	sc.Log("info", fmt.Sprintf("canaries passed; soaking %s before fan-out", d))
	select {
	case <-time.After(d):
		return nil
	case <-sc.Ctx.Done():
		return fmt.Errorf("cancelled during the %s canary soak: %w", d, sc.Ctx.Err())
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

		// And the cascade's grid, which is the report itself. Children give a
		// tally; only the grid knows which tier and architecture each node was
		// in, which one was the canary, and — the row a child job can never
		// produce — which planned targets were never started at all.
		var cascade cascadeResult
		if raw, ok := sc.PriorResults["cascade"]; ok {
			if err := json.Unmarshal(raw, &cascade); err != nil {
				return nil, fmt.Errorf("read cascade result: %w", err)
			}
		}

		// The grid is the better source when it exists. Counting children
		// loses any target that has no child — a node whose submission itself
		// failed produces no row to count, and a node the run never reached
		// produces none either, so both vanish from a tally that is supposed
		// to account for the whole plan. The child tally stays as the fallback
		// for a job resumed from before the grid existed.
		total := len(children)
		if len(cascade.Results) > 0 {
			total, succeeded, failed = len(cascade.Results), 0, 0
			for _, r := range cascade.Results {
				switch r.Outcome {
				case proto.NodeOutcomeSucceeded:
					succeeded++
				case proto.NodeOutcomeFailed:
					failed++
				}
			}
		}
		counts := &proto.SystemUpdateCounts{
			Total:        total,
			Succeeded:    succeeded,
			Failed:       failed,
			Skipped:      len(plan.Skipped),
			Stranded:     len(stranded),
			NotAttempted: len(cascade.Remaining),
		}
		// The `completed` event fires whatever the outcome — it is the report,
		// and a report you only get when nothing went wrong is not a report.
		// "aborted" stays reserved for explicit user cancellation (#61).
		publishSystemChange(nc, proto.SystemUpdateChangeEvt{
			ParentJobID: sc.JobID,
			Change:      proto.SystemUpdateCompleted,
			Counts:      counts,
			Skipped:     plan.Skipped,
			Results:     cascade.Results,
			Ts:          time.Now().UTC(),
		})
		if counts.NotAttempted > 0 {
			sc.Log("info", fmt.Sprintf("cascade complete: %d succeeded, %d failed, %d never started",
				succeeded, failed, counts.NotAttempted))
		} else {
			sc.Log("info", fmt.Sprintf("cascade complete: %d succeeded, %d failed", succeeded, failed))
		}
		raw, err := json.Marshal(counts)
		if err != nil {
			return nil, err
		}
		// Everything below decides the PARENT'S colour, and all of it runs
		// after the completed event is published — deliberately, because the
		// operator needs the report in order to act on it and a step that
		// errors before publishing takes the report with it.

		// The cascade's own verdict: a canary abort, or nodes that failed.
		// Raised here rather than in the cascade step so that publishing
		// happens first; the parent ends `failed` either way.
		if err := cascade.terminalError(); err != nil {
			sc.Log("error", err.Error())
			return raw, err
		}

		// A stranded node fails the parent even when every child committed
		// cleanly and the grid is all green: the run still did not do what
		// "UPDATE ALL" says on the button. This is the one place where the
		// parent's colour is decided by something other than its targets.
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
