package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// PushKind is the job kind that applies the console root password hash to
// nodes. Re-runnable: it converges, it does not toggle.
const PushKind = "console.root_push"

// PushSpec is the job's spec. It carries NO secret — only node ids and the
// id of the password to deliver, both of which are safe in the ledger.
type PushSpec struct {
	// NodeIDs limits the push to these nodes. Empty means every node in
	// inventory, the controlplane included (#558).
	NodeIDs []string `json:"nodeIds,omitempty"`
	// Reason is a short human string for the job log ("settings", "enrol
	// of compute3", "password changed").
	Reason string `json:"reason,omitempty"`
}

// Nodes lists the nodes a push targets. Wired to inventory in main.
type Nodes func(ctx context.Context) ([]*proto.Node, error)

// PlanResult is the plan step's result: who is being targeted, and under
// which password id.
type PlanResult struct {
	HashID  string   `json:"hashId"`
	Targets []string `json:"targets"`
	Reason  string   `json:"reason,omitempty"`
}

// DeliverResult is the deliver step's result: one row per target. No hash,
// by construction — the only hash-shaped value here is an id.
//
// Applied counts every node that holds the password afterwards, so it is
// always Changed + Unchanged; the split is what tells an operator whether a
// re-apply wrote anything (#597).
type DeliverResult struct {
	HashID    string       `json:"hashId"`
	Results   []NodeResult `json:"results"`
	Changed   int          `json:"changed"`
	Unchanged int          `json:"unchanged"`
	Applied   int          `json:"applied"`
	Failed    int          `json:"failed"`
}

// NodeOutcome is what delivering the password did to one node.
type NodeOutcome string

const (
	// OutcomeChanged: the node wrote the password.
	OutcomeChanged NodeOutcome = "changed"
	// OutcomeUnchanged: the node already held this password and wrote
	// nothing. It holds the password, so its status is still applied.
	OutcomeUnchanged NodeOutcome = "unchanged"
	// OutcomeFailed: the node does not hold the password; Detail says why.
	OutcomeFailed NodeOutcome = "failed"
)

// unchangedDetail is the Settings row's detail for an unchanged node, so the
// row says a re-apply found nothing to do rather than reading like a write.
const unchangedDetail = "already held this password — nothing was written"

// NodeResult is one node's outcome.
type NodeResult struct {
	NodeID  string      `json:"nodeId"`
	Status  NodeStatus  `json:"status"`
	Outcome NodeOutcome `json:"outcome"`
	// HashID is the password the node holds afterwards, as the node named
	// it; "" when it did not apply one.
	HashID string `json:"hashId,omitempty"`
	// Changed is false when the node already held this password.
	Changed bool `json:"changed,omitempty"`
	// Detail says why on a failure, in the operator's language. Never a
	// hash, never a password.
	Detail string `json:"detail,omitempty"`
}

// deliverFanout bounds how many nodes are asked at once. A cluster is at
// most proto.MaxClusterNodes, so this is about not opening 24 simultaneous
// request-replies on one bus connection, not about scale.
const deliverFanout = 8

// PushWorkflow applies the stored hash to every target node.
//
// Four steps, so that each one has exactly one job and the per-node record
// survives a fleet where some node refused:
//
//	plan     — resolve targets and the password id (fails if none is set)
//	deliver  — one request-reply per node over its own lane, concurrently;
//	           records every node's outcome and SUCCEEDS whatever they were,
//	           because a step that failed here would lose the result rows
//	           (the runner records an error, not a result, on a failed step)
//	record   — persist each outcome so Settings can show it later
//	verify   — fail the job, naming the nodes that did not apply
//
// The hash is read inside deliver, from the store, and put straight into
// the bus command. It is in no spec, no result, no event and no log line.
//
// log is the process logger: the plan, every node's outcome and the delivery
// summary go to the api journal through it, and OnTerminal writes the one
// ERROR record a failed job gets, whichever step or restart failed it (#597).
// now stamps the record step's rows. A nil log or now is a wiring fault and
// panics here, at construction.
func PushWorkflow(store *Store, nodes Nodes, log *slog.Logger, now func() time.Time) jobs.Workflow {
	if log == nil {
		panic("console: PushWorkflow needs a logger; nil was passed")
	}
	if now == nil {
		panic("console: PushWorkflow needs a clock; nil was passed")
	}
	return jobs.Workflow{
		Kind: PushKind,
		Steps: []jobs.WorkflowStep{
			{Name: "plan", Timeout: 10 * time.Second, Do: pushPlan(store, nodes, log)},
			{Name: "deliver", Timeout: 2 * time.Minute, Do: pushDeliver(store, nodes, log)},
			{Name: "record", Timeout: 15 * time.Second, Do: pushRecord(store, now)},
			{Name: "verify", Timeout: 5 * time.Second, Do: pushVerify()},
		},
		OnTerminal: pushTerminal(log),
	}
}

// pushTerminal writes the journal record for a failed push. It is the only
// ERROR record a failed job writes, and it fires from every failure path —
// plan, deliver, record, verify, and a job orphaned by an api restart — so
// no failure is silent and none is logged twice. The hook gets no spec or
// result, so it carries no hash_id; job_id correlates it to the plan record,
// which does. A success writes nothing: the deliver summary already said it.
func pushTerminal(log *slog.Logger) func(ctx context.Context, jobID string, success bool, errMsg string) {
	return func(ctx context.Context, jobID string, success bool, errMsg string) {
		if success {
			return
		}
		log.ErrorContext(ctx, "console: console root password push failed", "job_id", jobID, "error", errMsg)
	}
}

func parsePushSpec(raw json.RawMessage) (*PushSpec, error) {
	var spec PushSpec
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &spec); err != nil {
			return nil, fmt.Errorf("invalid spec: %w", err)
		}
	}
	return &spec, nil
}

// targets resolves the spec against inventory. A spec naming a node that is
// not registered is an error rather than a silent drop: the caller asked for
// that node, and answering "done" without touching it is the silent skip
// #558 forbids.
func targets(ctx context.Context, spec *PushSpec, nodes Nodes) ([]*proto.Node, error) {
	all, err := nodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list inventory: %w", err)
	}
	if len(spec.NodeIDs) == 0 {
		sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
		return all, nil
	}
	byID := make(map[string]*proto.Node, len(all))
	for _, n := range all {
		byID[n.ID] = n
	}
	out := make([]*proto.Node, 0, len(spec.NodeIDs))
	var missing []string
	for _, id := range spec.NodeIDs {
		n, ok := byID[id]
		if !ok {
			missing = append(missing, id)
			continue
		}
		out = append(out, n)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("not registered: %s", strings.Join(missing, ", "))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func pushPlan(store *Store, nodes Nodes, log *slog.Logger) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parsePushSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		hashID, err := store.CurrentHashID(sc.Ctx)
		if err != nil {
			return nil, err
		}
		if hashID == "" {
			return nil, ErrNoPassword
		}
		ns, err := targets(sc.Ctx, spec, nodes)
		if err != nil {
			return nil, err
		}
		if len(ns) == 0 {
			return nil, errors.New("no nodes are registered, so there is nothing to apply the console root password to")
		}
		ids := make([]string, 0, len(ns))
		for _, n := range ns {
			ids = append(ids, n.ID)
		}
		sc.Log("info", fmt.Sprintf("console root password %s → %d node(s): %s", hashID, len(ids), strings.Join(ids, ", ")))
		log.InfoContext(sc.Ctx, "console: pushing the console root password",
			"job_id", sc.JobID, "hash_id", hashID, "reason", spec.Reason, "targets", ids)
		return json.Marshal(PlanResult{HashID: hashID, Targets: ids, Reason: spec.Reason})
	}
}

// pushDeliver is the only place the hash is read. It reads it once, sends
// it to each target over that node's own command lane, and returns per-node
// outcomes — nothing derived from the hash but its id.
func pushDeliver(store *Store, nodes Nodes, log *slog.Logger) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parsePushSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		ns, err := targets(sc.Ctx, spec, nodes)
		if err != nil {
			return nil, err
		}
		hash, hashID, err := store.HashForDispatch(sc.Ctx)
		if err != nil {
			return nil, err
		}
		defer hash.Destroy()
		if store.heldHash != nil {
			store.heldHash(hash)
		}
		if sc.NATS == nil {
			return nil, errors.New("no bus connection")
		}
		cmd, err := rootHashCommand(hash, hashID)
		if err != nil {
			return nil, err
		}

		out := DeliverResult{HashID: hashID, Results: make([]NodeResult, len(ns))}
		sem := make(chan struct{}, deliverFanout)
		var wg sync.WaitGroup
		for i, n := range ns {
			wg.Add(1)
			go func(i int, n *proto.Node) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				out.Results[i] = deliverOne(sc, n, cmd, hashID)
			}(i, n)
		}
		wg.Wait()

		for _, r := range out.Results {
			switch r.Outcome {
			case OutcomeChanged, OutcomeUnchanged:
				out.Applied++
				if r.Outcome == OutcomeChanged {
					out.Changed++
				} else {
					out.Unchanged++
				}
				sc.Log("info", fmt.Sprintf("%s: %s", r.NodeID, r.Outcome))
				log.InfoContext(sc.Ctx, "console: console root password delivered to a node",
					"job_id", sc.JobID, "hash_id", hashID, "node_id", r.NodeID, "outcome", string(r.Outcome))
			default:
				out.Failed++
				sc.Log("warn", fmt.Sprintf("%s: %s — %s", r.NodeID, r.Outcome, r.Detail))
				log.WarnContext(sc.Ctx, "console: console root password not applied on a node",
					"job_id", sc.JobID, "hash_id", hashID, "node_id", r.NodeID, "outcome", string(r.Outcome), "detail", r.Detail)
			}
		}
		sc.Log("info", fmt.Sprintf("console root password %s on %d node(s): %d changed, %d unchanged, %d failed",
			hashID, len(out.Results), out.Changed, out.Unchanged, out.Failed))
		log.InfoContext(sc.Ctx, "console: console root password delivery finished",
			"job_id", sc.JobID, "hash_id", hashID, "changed", out.Changed, "unchanged", out.Unchanged, "failed", out.Failed)
		return json.Marshal(out)
	}
}

// rootHashCommand builds the ConsoleRootHashCmd bus payload: the one place
// the crypt hash leaves its secret.Value.
func rootHashCommand(hash secret.Value, hashID string) ([]byte, error) {
	return json.Marshal(proto.ConsoleRootHashCmd{Hash: string(hash.Reveal()), HashID: hashID})
}

// deliverOne sends the command to one node and reads its answer honestly.
//
// A node that does not answer has three readings, and inventory holds both
// facts needed to tell them apart (proto/agentverbs.go). All three FAIL the
// node — none of them skips it — but each says something different, because
// "update this node's agent" and "this node is unplugged" send the operator
// to different places.
func deliverOne(sc *jobs.StepCtx, n *proto.Node, cmd []byte, hashID string) NodeResult {
	res := NodeResult{NodeID: n.ID, Status: NodeFailed, Outcome: OutcomeFailed}
	msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.NodeCmdSubject(n.ID, proto.ConsoleRootHashVerb), cmd)
	if err != nil {
		res.Detail = explainNoAnswer(n, err)
		return res
	}
	var ack proto.ConsoleRootHashAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		res.Detail = "the node's answer could not be read: " + err.Error()
		return res
	}
	if !ack.OK {
		res.Detail = ack.Detail
		if res.Detail == "" {
			res.Detail = "the agent refused the console root password and gave no reason"
		}
		res.HashID = ack.HashID
		return res
	}
	if ack.HashID != "" && ack.HashID != hashID {
		// An OK for a different password is not a success: the node holds
		// something the operator did not just choose.
		res.Detail = fmt.Sprintf("the agent acknowledged a different password (%s, wanted %s)", ack.HashID, hashID)
		res.HashID = ack.HashID
		return res
	}
	res.Status, res.HashID, res.Changed = NodeApplied, hashID, ack.Changed
	res.Outcome = OutcomeUnchanged
	if ack.Changed {
		res.Outcome = OutcomeChanged
	}
	return res
}

// explainNoAnswer turns a request failure into the sentence the operator
// needs. Mixed fleets are the case this exists for: the verb is new, so a
// fielded agent has no subscription for it and NATS answers "no
// responders" — which is not the same as a node being down, and must not
// read as one.
func explainNoAnswer(n *proto.Node, err error) string {
	if !errors.Is(err, nats.ErrNoResponders) {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
			return "the agent did not answer in time — the node is registered and on the bus, so this is a fault on the node, not an old agent"
		}
		return "could not reach the node: " + err.Error()
	}
	switch n.Status {
	case proto.StatusOnline:
		// Fall through to the agent-version reading below.
	case "":
		// No presence was derived for this node, so the api cannot tell an
		// unplugged node from an old agent. Say that, rather than printing a
		// blank where the status belongs.
		return fmt.Sprintf("the node did not answer %s, and the api could not read its presence, so it cannot say whether the node is offline or its agent is too old", proto.ConsoleRootHashVerb)
	default:
		return fmt.Sprintf("the node is %s — it will receive the console root password when it comes back and registers", n.Status)
	}
	floor, ok := proto.VerbMinAgentVersion(proto.ConsoleRootHashVerb)
	if ok && inventory.AgentPredates(n.AgentVersion, floor) {
		return fmt.Sprintf("the agent on this node is %s, which predates %s — the console root password needs %s or newer. Update the node; until then its console keeps the password its image shipped with.",
			displayVersion(n.AgentVersion), proto.ConsoleRootHashVerb, floor)
	}
	if n.AgentVersion == "" {
		return fmt.Sprintf("the node is online but did not answer %s, and it has reported no agent version, so the api cannot say whether its agent is too old. Update the node.", proto.ConsoleRootHashVerb)
	}
	return fmt.Sprintf("the node is online and its agent (%s) is new enough to answer %s, but it did not — this is a fault on the node.",
		displayVersion(n.AgentVersion), proto.ConsoleRootHashVerb)
}

func displayVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "of an unreported version"
	}
	return v
}

func pushRecord(store *Store, clock func() time.Time) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		raw, ok := sc.PriorResults["deliver"]
		if !ok {
			return nil, errors.New("the deliver step left no result to record")
		}
		var del DeliverResult
		if err := json.Unmarshal(raw, &del); err != nil {
			return nil, fmt.Errorf("decode deliver result: %w", err)
		}
		now := clock().UTC()
		for _, r := range del.Results {
			detail := r.Detail
			if r.Outcome == OutcomeUnchanged {
				detail = unchangedDetail
			}
			if err := store.RecordNode(sc.Ctx, NodeState{
				NodeID: r.NodeID, Status: r.Status, HashID: r.HashID,
				Detail: detail, JobID: sc.JobID, UpdatedAt: now,
			}); err != nil {
				return nil, fmt.Errorf("record %s: %w", r.NodeID, err)
			}
		}
		return json.Marshal(map[string]int{"recorded": len(del.Results)})
	}
}

// pushVerify is what makes a refusing node fail the job. It runs after
// record, so the per-node reasons are durable whatever it decides.
func pushVerify() jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		raw, ok := sc.PriorResults["deliver"]
		if !ok {
			return nil, errors.New("the deliver step left no result to verify")
		}
		var del DeliverResult
		if err := json.Unmarshal(raw, &del); err != nil {
			return nil, fmt.Errorf("decode deliver result: %w", err)
		}
		var failed []string
		for _, r := range del.Results {
			if r.Status != NodeApplied {
				failed = append(failed, fmt.Sprintf("%s (%s)", r.NodeID, r.Detail))
			}
		}
		if len(failed) > 0 {
			return nil, fmt.Errorf("the console root password was not applied on %d of %d node(s): %s",
				len(failed), len(del.Results), strings.Join(failed, "; "))
		}
		return json.Marshal(map[string]int{"applied": del.Applied})
	}
}
