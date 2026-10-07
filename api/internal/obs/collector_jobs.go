package obs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Per-node collector convergence (Slice 1.2b, observability-stack.md §3.10
// pieces 3-4). Three workflows work together:
//
//   - obs.collectors.reconcile  — periodic (scheduler). Decides which nodes
//     should gain or lose a collector and submits per-node jobs. Modeled on
//     mesh.reconcile's converge_enrollment: fast, idempotent, job-history-driven.
//   - obs.collectors.deploy_node   — render the node's collector compose,
//     presenting its registered collector key, and docker.deploy it via the
//     existing agent command.
//   - obs.collectors.teardown_node — docker.stop the collector.
//
// The reconcile runs whether obs is on or off: on ⇒ converge collectors ONTO
// online compute/storage nodes; off ⇒ tear collectors DOWN so the fleet matches
// the operator's opt-in. Firewall/other roles never get one (no Docker).

const (
	CollectorReconcileKind = "obs.collectors.reconcile"
	CollectorDeployKind    = "obs.collectors.deploy_node"
	CollectorTeardownKind  = "obs.collectors.teardown_node"

	// collectorAppID is the compose app id every collector deploy uses. The
	// agent keys its state dir + compose project (rasp_<appID>) on it, so a
	// fixed id makes redeploys idempotent and the teardown target stable. It's
	// per-node (each node runs its own agent) and can't collide with user apps
	// (those use ULIDs). The collector is deployed via the raw docker.deploy
	// command, NOT the apps Store, so it never shows in the Apps UI — but it
	// does show, correctly, in the node's own Containers drawer.
	collectorAppID = "obs-collector"

	// collectorRedeployInterval is a SAFETY NET, and only that
	// (principles.md: a tick may back up a fact, never decide state).
	//
	// What the collector CARRIES is now decided by facts: the reconcile
	// compares the node's registered collector key and the control plane's
	// trust anchor against what the last successful deploy recorded, and
	// redeploys the moment either differs — it does not wait out this
	// interval. Before, a rotated credential took up to this long to reach a
	// node (geekdojo/geekdojo-brain#515).
	//
	// What it still backs up is the one fact the api cannot see from here:
	// whether the collector CONTAINER is actually running. Nothing reports
	// that, so a container an operator stopped, or one that died, is
	// rediscovered only by redeploying. Reading it needs a docker.status RPC
	// per node on every tick, which is its own change; until then this
	// interval is the self-heal, and it is deliberately long because that is
	// all it is for.
	collectorRedeployInterval = 6 * time.Hour

	// collectorRetryCooldown backs off a node whose last deploy/teardown FAILED,
	// so a persistently broken node produces one failed job per cooldown rather
	// than one every reconcile tick. Mirrors mesh's enrollRetryCooldown.
	collectorRetryCooldown = 30 * time.Minute

	// collectorDeployTimeout bounds the deploy RPC. The first deploy to a node
	// pulls the Alloy image (~tens of MB) before `up -d` returns, so this is
	// generous; steady-state redeploys return in seconds.
	collectorDeployTimeout = 6 * time.Minute
)

// collectorRoles are the node roles that run a collector — Docker-capable only.
// The firewall (OpenWrt, no Docker) is deliberately excluded (§3.7 / §3.10).
var collectorRoles = []proto.NodeRole{proto.RoleCompute, proto.RoleStorage}

// CollectorNodeSpec is the spec body for the per-node deploy/teardown jobs.
type CollectorNodeSpec struct {
	NodeID string `json:"nodeId"`
	// CollectorKey and TrustFingerprint record what the collector this job
	// deploys is meant to carry: the SPKI hash of the node's registered
	// collector key and a fingerprint of what it trusts the api by.
	//
	// They are in the SPEC rather than the result because the reconcile reads
	// them back on every tick, and a job's spec is already in hand there while
	// its step results are separate rows. A succeeded job therefore says what
	// the node is carrying, without a query per job.
	//
	// The deploy step derives the key itself, from inventory, rather than
	// taking it from here: a key that changed between submit and run must not
	// be deployed stale. When it does differ, the next reconcile sees the
	// recorded pair is no longer current and redeploys — one tick later, not
	// never.
	CollectorKey     string `json:"collectorKey,omitempty"`
	TrustFingerprint string `json:"trustFingerprint,omitempty"`
}

// CollectorReconcileDeps is what the reconcile converge step needs.
type CollectorReconcileDeps struct {
	Inv     *inventory.Store
	Jobs    *jobs.Store
	Runner  *jobs.Runner
	Enabled EnabledFn // stored obs opt-in; nil ⇒ treated as enabled
	// Deploy is the same configuration the deploy workflow runs with, so the
	// reconcile derives what a node's collector SHOULD carry with exactly the
	// function that decides what it WILL carry. One derivation, so the two
	// cannot disagree and leave a node redeploying forever. It also carries
	// the controlplane CA, so there is one source of what a collector trusts.
	Deploy CollectorDeployDeps
}

// errNoInventory is wantFor's answer when the reconcile was given no
// inventory to read a node's keys from.
var errNoInventory = errors.New("no inventory to read its registered keys from")

// wantFor is what node nodeID's collector should be carrying now. A node whose
// keys cannot be read has no answer — an error, never a guess — and the
// reconcile leaves that node as it is for the pass (ARCH-FACTS).
func (d CollectorReconcileDeps) wantFor(ctx context.Context, nodeID string) (collectorWant, error) {
	if d.Inv == nil {
		return collectorWant{}, errNoInventory
	}
	keys, err := d.Inv.NodeKeys(ctx, nodeID)
	if err != nil {
		return collectorWant{}, err
	}
	return d.Deploy.wantFor(keys), nil
}

// CollectorReconcileWorkflow converges the collector fleet to match the
// operator's obs opt-in. Single converge step, like mesh's reconcile.
func CollectorReconcileWorkflow(d CollectorReconcileDeps) jobs.Workflow {
	return jobs.Workflow{
		Kind: CollectorReconcileKind,
		Steps: []jobs.WorkflowStep{
			{Name: "converge", Timeout: 15 * time.Second, Do: collectorConverge(d)},
		},
	}
}

// nodeJobState is the per-node view distilled from recent job history.
type nodeJobState struct {
	inflight     bool
	lastSuccess  time.Time
	lastFailedAt time.Time
	// deployed is what the newest SUCCESSFUL deploy's spec recorded it was
	// putting on the node. Zero for a job from a release that recorded
	// nothing, which reads as "unknown" — see collectorWant.matches.
	deployed collectorWant
}

// matches reports whether what is deployed is what should be deployed.
//
// A deploy whose record is empty — written by a release that did not record
// what it deployed — reads as a MATCH, not a mismatch. Treating it as stale
// would redeploy every collector in the fleet on the first tick after an
// upgrade, all at once. It is current until the 6-hour safety net comes round,
// and from that deploy on it carries a record.
func (have collectorWant) matches(want collectorWant) bool {
	if have == (collectorWant{}) {
		return true
	}
	return have == want
}

// scanNodeJobs folds a kind's recent jobs (newest first) into per-node state:
// whether one is in flight, and the newest success / failure timestamps.
func scanNodeJobs(js []*jobs.Job) map[string]*nodeJobState {
	out := map[string]*nodeJobState{}
	get := func(id string) *nodeJobState {
		if out[id] == nil {
			out[id] = &nodeJobState{}
		}
		return out[id]
	}
	for _, j := range js {
		var spec CollectorNodeSpec
		if json.Unmarshal(j.Spec, &spec) != nil || spec.NodeID == "" {
			continue
		}
		st := get(spec.NodeID)
		deployed := collectorWant{key: spec.CollectorKey, trust: spec.TrustFingerprint}
		switch j.Status {
		case jobs.StatusQueued, jobs.StatusRunning:
			st.inflight = true
		case jobs.StatusSucceeded:
			if j.CreatedAt.After(st.lastSuccess) {
				st.lastSuccess = j.CreatedAt
				st.deployed = deployed
			}
		case jobs.StatusFailed:
			if j.CreatedAt.After(st.lastFailedAt) {
				st.lastFailedAt = j.CreatedAt
			}
		}
	}
	return out
}

// collectorActions is what a single converge pass decided to do.
type collectorActions struct {
	deploy   []string
	teardown []string
	skipped  map[string]int
}

// decideCollectorActions is the pure convergence decision — no I/O — so the
// whole matrix is unit-testable with a fixed `now`. Given the inventory, the
// per-node deploy/teardown job history, the obs opt-in, the node registry's
// admission answer and what each node's collector should be carrying, it
// returns which nodes to deploy to (obs on) or tear down (obs off), plus a
// tally of why the rest were skipped. The caller submits the resulting jobs.
//
// want is what the node's collector should present and trust; a deploy whose
// record no longer matches it is redeployed at once rather than waiting out
// the self-heal interval (geekdojo-brain#515). When want has no answer for a
// node (ok false: its keys could not be read), obs-on leaves that node alone
// for the pass, counted under keys_unreadable: deciding a deploy without
// knowing which key the collector presents would act on a guess.
//
// admitted is inventory.Registry.Admitted: a collector is the node's HTTPS
// credential, so it follows the node's join token, not merely its inventory
// row. A node whose token was revoked keeps its row (the revoke cascade
// leaves it in inventory, geekdojo-brain#575) but is no longer admitted by
// the ingress, so deploying a collector it cannot push through would be work
// with no possible outcome. Deciding it from the
// registry is the same fact the ingress enforces, read from the same place
// (geekdojo-brain#585).
func decideCollectorActions(nodes []*proto.Node, deployState, teardownState map[string]*nodeJobState, on bool, now time.Time, admitted func(nodeID string) bool, want func(nodeID string) (collectorWant, bool)) collectorActions {
	act := collectorActions{skipped: map[string]int{}}
	for _, n := range nodes {
		if !slices.Contains(collectorRoles, n.Role) {
			continue
		}
		// Not admitted ⇒ no bus session to dispatch to and an ingress that
		// would refuse the collector anyway; neither a deploy nor a teardown
		// can reach it.
		if !admitted(n.ID) {
			act.skipped["not_admitted"]++
			continue
		}
		online := inventory.ComputeStatus(n.LastSeen) == proto.StatusOnline
		dep := deployState[n.ID]
		tear := teardownState[n.ID]
		// "Has a collector" ⇒ a deploy succeeded and no teardown succeeded
		// since. Used to decide teardown when obs is off.
		hasCollector := dep != nil && !dep.lastSuccess.IsZero() &&
			(tear == nil || dep.lastSuccess.After(tear.lastSuccess))

		if on {
			w, known := want(n.ID)
			switch {
			case !known:
				act.skipped["keys_unreadable"]++
			case !online:
				act.skipped["offline"]++
			case dep != nil && dep.inflight:
				act.skipped["inflight"]++
			case hasCollector && !dep.deployed.matches(w):
				// The node's collector is carrying a key or a trust anchor
				// that is no longer the current one — it registered a new key
				// after a reflash, or the control plane's anchor changed.
				// Redeploy NOW rather than when the interval happens to
				// expire: this is the fact the redeploy exists for.
				act.deploy = append(act.deploy, n.ID)
			case hasCollector && now.Sub(dep.lastSuccess) < collectorRedeployInterval:
				// Current, and within the self-heal window. "fresh" only
				// counts if the node STILL has a running collector: a node
				// whose collector was torn down since its last deploy (obs
				// disabled → re-enabled) has hasCollector=false, so it falls
				// through to redeploy instead of being wrongly skipped — the
				// disable→re-enable bug. This also makes an off→on toggle the
				// reliable way to push a new collector config to the fleet.
				act.skipped["fresh"]++
			case dep != nil && !dep.lastFailedAt.IsZero() && now.Sub(dep.lastFailedAt) < collectorRetryCooldown:
				act.skipped["cooldown"]++
			default:
				act.deploy = append(act.deploy, n.ID)
			}
			continue
		}
		// obs off — tear collectors down to match the opt-in.
		switch {
		case !hasCollector:
			// nothing to do
		case !online:
			// Can't reach it to stop it; it stops with the node and will be
			// torn down when it returns while obs is still off.
			act.skipped["offline"]++
		case tear != nil && tear.inflight:
			act.skipped["inflight"]++
		case tear != nil && !tear.lastFailedAt.IsZero() && now.Sub(tear.lastFailedAt) < collectorRetryCooldown:
			act.skipped["cooldown"]++
		default:
			act.teardown = append(act.teardown, n.ID)
		}
	}
	return act
}

func collectorConverge(d CollectorReconcileDeps) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		on := true
		if d.Enabled != nil {
			v, err := d.Enabled(sc.Ctx)
			if err != nil {
				return nil, fmt.Errorf("read obs enabled: %w", err)
			}
			on = v
		}
		nodes, err := d.Inv.List(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("list inventory: %w", err)
		}
		deploys, err := d.Jobs.ListJobsByKind(sc.Ctx, CollectorDeployKind, 300)
		if err != nil {
			return nil, fmt.Errorf("list deploy jobs: %w", err)
		}
		teardowns, err := d.Jobs.ListJobsByKind(sc.Ctx, CollectorTeardownKind, 300)
		if err != nil {
			return nil, fmt.Errorf("list teardown jobs: %w", err)
		}
		// Each node's want is read once per pass; a node whose keys cannot
		// be read gets one warn line naming it and the error, and is left
		// alone.
		wants := map[string]collectorWant{}
		want := func(nodeID string) (collectorWant, bool) {
			if w, ok := wants[nodeID]; ok {
				return w, true
			}
			w, err := d.wantFor(sc.Ctx, nodeID)
			if err != nil {
				sc.Log("warn", fmt.Sprintf("converge: cannot read node %s's registered keys, so its collector is left as it is this pass: %v", nodeID, err))
				return collectorWant{}, false
			}
			wants[nodeID] = w
			return w, true
		}
		act := decideCollectorActions(nodes,
			scanNodeJobs(deploys), scanNodeJobs(teardowns), on, time.Now().UTC(),
			d.Inv.Registry().Admitted, want)

		submit := func(kind, nodeID string) bool {
			body := CollectorNodeSpec{NodeID: nodeID}
			if kind == CollectorDeployKind {
				// decideCollectorActions deploys only a node whose want it
				// read, so this is the answer it decided on.
				w := wants[nodeID]
				body.CollectorKey, body.TrustFingerprint = w.key, w.trust
			}
			if _, err := d.Runner.Submit(sc.Ctx, kind, body, "obs-collectors-reconcile"); err != nil {
				sc.Log("warn", fmt.Sprintf("converge: submit %s for %s: %v", kind, nodeID, err))
				act.skipped["submit_error"]++
				return false
			}
			return true
		}
		var deployed, tornDown []string
		for _, id := range act.deploy {
			if submit(CollectorDeployKind, id) {
				deployed = append(deployed, id)
			}
		}
		for _, id := range act.teardown {
			if submit(CollectorTeardownKind, id) {
				tornDown = append(tornDown, id)
			}
		}

		switch {
		case len(deployed) > 0:
			sc.Log("info", fmt.Sprintf("converge: deploying collectors to %d node(s): %s",
				len(deployed), strings.Join(deployed, ", ")))
		case len(tornDown) > 0:
			sc.Log("info", fmt.Sprintf("converge: tearing down collectors on %d node(s): %s",
				len(tornDown), strings.Join(tornDown, ", ")))
		}
		return json.Marshal(map[string]any{
			"enabled": on, "deployed": deployed, "tornDown": tornDown, "skipped": act.skipped,
		})
	}
}

// CollectorDeployDeps is what the per-node deploy workflow needs.
type CollectorDeployDeps struct {
	Inv            *inventory.Store
	IngressBaseURL string // from DeriveIngressEndpoint (canonical hostname, not hardcoded)
	ServerName     string
	AlloyImage     string // optional; defaults to the pinned collector image
	// CAPEM is the CA every collector verifies the api's leaf against,
	// by chain and under ServerName — the one source of what a collector
	// trusts. Empty refuses every deploy (fail closed).
	CAPEM string
}

// collectorWant is the pair of facts a node's deployed collector must match.
type collectorWant struct {
	key   string
	trust string
}

// wantFor decides what a node's collector should be carrying right now: its
// registered collector key (empty when it has none, which no deploy accepts)
// and the controlplane CA it trusts the api by. A collector recorded with any other trust fingerprint —
// one deployed by a release that pinned the bus certificate — no longer
// matches, and the reconcile redeploys it.
func (d CollectorDeployDeps) wantFor(keys proto.NodeKeys) collectorWant {
	return collectorWant{key: keys[proto.NodeKeyCollector], trust: proto.TrustFingerprint([]byte(d.CAPEM))}
}

// CollectorDeployWorkflow renders the node's collector compose, presenting
// the node's registered collector key, and deploys it via the existing
// docker.deploy agent command. A node with no registered collector key is
// refused by name.
func CollectorDeployWorkflow(d CollectorDeployDeps) jobs.Workflow {
	return jobs.Workflow{
		Kind: CollectorDeployKind,
		Steps: []jobs.WorkflowStep{
			{Name: "deploy", Timeout: collectorDeployTimeout, Do: collectorDeploy(d)},
		},
	}
}

func collectorDeploy(d CollectorDeployDeps) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		var spec CollectorNodeSpec
		if err := json.Unmarshal(sc.Spec, &spec); err != nil || spec.NodeID == "" {
			return nil, fmt.Errorf("collector deploy: bad spec: %v", err)
		}
		// Guard: the node stopped being admitted, or went offline, between the
		// reconcile and now. Admission is the node registry's answer — a
		// current inventory member holding a live join token — read from
		// memory, which is the same fact the collector ingress will apply to
		// the connection this deploy is about to create. Deploying to a node
		// the ingress would refuse is work with no possible outcome, and a
		// no-op success beats burning the deploy timeout on an RPC that
		// will time out.
		if !d.Inv.Registry().Admitted(spec.NodeID) {
			sc.Log("info", fmt.Sprintf("collector deploy: node %s is not admitted (removed from inventory, or its join tokens revoked); skipping", spec.NodeID))
			return nil, jobs.ErrStopWorkflow
		}
		node, err := d.Inv.Get(sc.Ctx, spec.NodeID)
		if err != nil {
			return nil, fmt.Errorf("collector deploy: inventory lookup: %w", err)
		}
		if node == nil {
			sc.Log("info", fmt.Sprintf("collector deploy: node %s no longer in inventory; skipping", spec.NodeID))
			return nil, jobs.ErrStopWorkflow
		}
		if inventory.ComputeStatus(node.LastSeen) != proto.StatusOnline {
			sc.Log("info", fmt.Sprintf("collector deploy: node %s offline; will retry when it returns", spec.NodeID))
			return nil, jobs.ErrStopWorkflow
		}

		// The collector presents the node's registered collector key and
		// trusts the api by chain to the controlplane CA, under the cluster name. A
		// node with no registered collector key gets no collector: there is
		// no other credential to give it.
		keys, err := d.Inv.NodeKeys(sc.Ctx, spec.NodeID)
		if err != nil {
			return nil, fmt.Errorf("collector deploy: read node keys for %s: %w", spec.NodeID, err)
		}
		want := d.wantFor(keys)
		if want.key == "" {
			return nil, fmt.Errorf("collector deploy: node %s has no registered collector key (its agent predates node keys, or its key report was refused: see the inventory log); not deployed", spec.NodeID)
		}
		sc.Log("info", fmt.Sprintf("collector deploy: %s presents its registered key %s, trust=mesh-ca %s",
			spec.NodeID, proto.ShortFingerprint(strings.TrimPrefix(want.key, proto.BusPinPrefix)),
			proto.ShortFingerprint(want.trust)))
		compose, err := BuildCollectorCompose(CollectorSpec{
			NodeID:          spec.NodeID,
			IngressBaseURL:  d.IngressBaseURL,
			ServerName:      d.ServerName,
			AlloyImage:      d.AlloyImage,
			CAPEM:           d.CAPEM,
			NodeKeyCertPath: proto.NodeCertPath(proto.NodeKeyCollector),
			NodeKeyPath:     proto.NodeKeyPath(proto.NodeKeyCollector),
		})
		if err != nil {
			return nil, fmt.Errorf("collector deploy: build compose for %s: %w", spec.NodeID, err)
		}

		cmd, _ := json.Marshal(proto.AppDeployCmd{
			AppID:       collectorAppID,
			Name:        collectorContainerName,
			ComposeYAML: compose,
		})
		sc.Log("info", fmt.Sprintf("deploying observability collector to %s", spec.NodeID))
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.AppDeploySubject(spec.NodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("collector deploy rpc to %s: %w", spec.NodeID, err)
		}
		var ack proto.AppDeployAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("collector deploy: decode ack: %w", err)
		}
		if !ack.OK || ack.Status == proto.AppStatusFailed {
			detail := ack.Detail
			if detail == "" {
				detail = "agent reported collector deploy failed"
			}
			return nil, errors.New(detail)
		}
		sc.Log("info", fmt.Sprintf("observability collector running on %s", spec.NodeID))
		if want.key != spec.CollectorKey || want.trust != spec.TrustFingerprint {
			// The node's facts moved between submit and run. What was
			// deployed is what this step derived, so the job's spec now
			// understates it; the next reconcile sees that and redeploys.
			sc.Log("info", fmt.Sprintf(
				"collector deploy: %s changed what it should carry between submit and deploy; the next reconcile will redeploy it", spec.NodeID))
		}
		return json.Marshal(map[string]string{"nodeId": spec.NodeID, "status": string(ack.Status)})
	}
}

// CollectorTeardownWorkflow stops the collector on a node.
func CollectorTeardownWorkflow() jobs.Workflow {
	return jobs.Workflow{
		Kind: CollectorTeardownKind,
		Steps: []jobs.WorkflowStep{
			{Name: "stop", Timeout: 1 * time.Minute, Do: collectorTeardown()},
		},
	}
}

func collectorTeardown() jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		var spec CollectorNodeSpec
		if err := json.Unmarshal(sc.Spec, &spec); err != nil || spec.NodeID == "" {
			return nil, fmt.Errorf("collector teardown: bad spec: %v", err)
		}
		cmd, _ := json.Marshal(proto.AppStopCmd{AppID: collectorAppID})
		sc.Log("info", fmt.Sprintf("stopping observability collector on %s", spec.NodeID))
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.AppStopSubject(spec.NodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("collector teardown rpc to %s: %w", spec.NodeID, err)
		}
		var ack proto.AppStopAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("collector teardown: decode ack: %w", err)
		}
		if !ack.OK && ack.Status == proto.AppStatusFailed {
			detail := ack.Detail
			if detail == "" {
				detail = "agent reported collector teardown failed"
			}
			return nil, errors.New(detail)
		}
		sc.Log("info", fmt.Sprintf("observability collector stopped on %s", spec.NodeID))
		return json.Marshal(map[string]string{"nodeId": spec.NodeID, "status": string(ack.Status)})
	}
}
