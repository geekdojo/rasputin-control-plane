package nodetrust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// ConvergeKind is the job kind of the convergence pass.
const ConvergeKind = "trust.converge"

// convergeStepTimeout bounds the one step of a pass. Every per-node request
// runs on the step's context, so this is the whole pass's budget, as the
// console root push's deliver step is. A pass it ends still returns its
// result (Converge).
const convergeStepTimeout = 2 * time.Minute

// ErrAgentPredatesVerb is Deliver's answer for an online node whose agent is
// older than the first release that answers trust.install. The caller decides
// what that means: mesh.enroll carries the bundle instead, and trust.converge
// leaves the node to the mesh bridge.
var ErrAgentPredatesVerb = errors.New("the node's agent predates " + proto.TrustInstallVerb)

// Nodes is what the service reads from inventory. *inventory.Store satisfies
// it.
type Nodes interface {
	// List is every registered node.
	List(ctx context.Context) ([]*proto.Node, error)
	// Presence sets each node's Status, read at inventory's own clock.
	Presence(ctx context.Context, nodes []*proto.Node)
	// ExplainNoResponder reads a silent request against the node it names.
	ExplainNoResponder(ctx context.Context, subject string) inventory.NoResponder
}

// Requester sends one request and waits for its answer. *nats.Conn satisfies
// it; it is passed per call because a job step carries its own connection.
type Requester interface {
	RequestWithContext(ctx context.Context, subj string, data []byte) (*nats.Msg, error)
}

// Options are the service's collaborators.
type Options struct {
	// Bundle is the node trust bundle. Required and non-empty: every backend
	// ships at least the controlplane CA.
	Bundle []byte
	// Nodes is inventory. Required.
	Nodes Nodes
	// Log receives per-node failures and the pass summary. Required.
	Log *slog.Logger
}

// Service delivers the node trust bundle.
type Service struct {
	bundle      []byte
	fingerprint string
	cmd         []byte
	nodes       Nodes
	log         *slog.Logger
}

// New builds the service. It refuses an empty bundle, a nil Nodes or a nil
// Log rather than start a service that could only ever deliver nothing.
func New(o Options) (*Service, error) {
	if len(bytes.TrimSpace(o.Bundle)) == 0 {
		return nil, errors.New("nodetrust: no trust bundle to deliver")
	}
	if o.Nodes == nil || o.Log == nil {
		return nil, errors.New("nodetrust: Options needs Nodes and Log")
	}
	cmd, err := json.Marshal(proto.TrustInstallCmd{BundlePEM: o.Bundle})
	if err != nil {
		return nil, fmt.Errorf("nodetrust: encode trust.install: %w", err)
	}
	return &Service{
		bundle:      append([]byte(nil), o.Bundle...),
		fingerprint: proto.TrustFingerprint(o.Bundle),
		cmd:         cmd,
		nodes:       o.Nodes,
		log:         o.Log,
	}, nil
}

// Fingerprint is proto.TrustFingerprint of the bundle the api delivers: what
// every node's report is compared against.
func (s *Service) Fingerprint() string { return s.fingerprint }

// Deliver sends trust.install to nodeID and reads the answer. It succeeds only
// on an OK ack whose fingerprint is the api's: an OK for some other bundle is
// not a delivery. An online agent below the verb's floor is
// ErrAgentPredatesVerb; any other silence carries inventory's reading of it.
func (s *Service) Deliver(ctx context.Context, req Requester, nodeID string) (proto.TrustInstallAck, error) {
	subject := proto.TrustInstallSubject(nodeID)
	msg, err := req.RequestWithContext(ctx, subject, s.cmd)
	if err != nil {
		if errors.Is(err, nats.ErrNoResponders) {
			nr := s.nodes.ExplainNoResponder(ctx, subject)
			if nr.Kind == inventory.SilenceOldAgent {
				return proto.TrustInstallAck{}, fmt.Errorf("%w: %s", ErrAgentPredatesVerb, nr)
			}
			return proto.TrustInstallAck{}, fmt.Errorf("trust.install to %s: %s", nodeID, nr)
		}
		return proto.TrustInstallAck{}, fmt.Errorf("trust.install to %s: %w", nodeID, err)
	}
	var ack proto.TrustInstallAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return proto.TrustInstallAck{}, fmt.Errorf("trust.install to %s: the node's answer could not be read: %w", nodeID, err)
	}
	if !ack.OK {
		detail := ack.Detail
		if detail == "" {
			detail = "the agent refused the trust bundle and gave no reason"
		}
		return ack, fmt.Errorf("trust.install to %s: %s", nodeID, detail)
	}
	if ack.Fingerprint != s.fingerprint {
		return ack, fmt.Errorf("trust.install to %s: the agent acknowledged %s, but the api delivered %s",
			nodeID, proto.ShortFingerprint(ack.Fingerprint), proto.ShortFingerprint(s.fingerprint))
	}
	return ack, nil
}

// ConvergeWorkflow is trust.converge: one step that installs the bundle on
// every registered, online node whose reported fingerprint differs from the
// api's. The scheduler runs it at the mesh reconcile's cadence; a restore
// kicks it at once.
func (s *Service) ConvergeWorkflow() jobs.Workflow {
	return jobs.Workflow{
		Kind: ConvergeKind,
		Steps: []jobs.WorkflowStep{
			{Name: "converge", Timeout: convergeStepTimeout, Do: s.convergeStep},
		},
	}
}

func (s *Service) convergeStep(sc *jobs.StepCtx) (json.RawMessage, error) {
	res, err := s.Converge(sc.Ctx, sc.NATS, sc.Log)
	if err != nil {
		return nil, err
	}
	return json.Marshal(res)
}

// Converge is one pass. A node qualifies when its reported fingerprint is not
// the api's ("none" and "reload-pending" both count), it is online by
// inventory's presence, and its agent answers trust.install. Qualifying nodes
// are asked in parallel, at most deliverFanout at once, as the console root
// push's deliver step does: a changed install restarts tailscaled before the
// agent answers, so one slow node must not hold up the rest. One node's
// failure is logged and counted, and the pass goes on to the rest.
//
// When ctx ends first — the step's deadline — the pass still returns what it
// found and did. Every node whose delivery the end cut off is counted under
// Skipped["deadline"] and named in one WARN, and the result is returned
// without an error, so the job records it rather than dropping it; the next
// pass sends to those nodes again.
//
// feed, when non-nil, receives the job-feed lines; it may be nil.
func (s *Service) Converge(ctx context.Context, req Requester, feed func(level, msg string)) (ConvergeResult, error) {
	if feed == nil {
		feed = func(string, string) {}
	}
	res := NewConvergeResult(s.fingerprint)
	nodes, err := s.nodes.List(ctx)
	if err != nil {
		return res, fmt.Errorf("list inventory: %w", err)
	}
	s.nodes.Presence(ctx, nodes)
	floor, _ := proto.VerbMinAgentVersion(proto.TrustInstallVerb)
	var send []delivery
	for _, n := range nodes {
		t := StateFor(s.fingerprint, n)
		switch t.State {
		case TrustCurrent:
			res.Current = append(res.Current, n.ID)
			continue
		case TrustUnreported:
			res.Unreported = append(res.Unreported, n.ID)
			continue
		}
		res.Stale = append(res.Stale, n.ID)
		if n.Status != proto.StatusOnline {
			res.Skipped["offline"]++
			continue
		}
		if inventory.AgentPredates(n.AgentVersion, floor) {
			res.Skipped["legacy_agent"]++
			continue
		}
		send = append(send, delivery{node: n.ID, was: t.Fingerprint})
	}
	s.deliverAll(ctx, req, send)

	var cut []string
	for _, d := range send {
		switch {
		case d.err == nil:
			feed("info", fmt.Sprintf("%s: trusted %s, now %s (changed=%v)",
				d.node, proto.ShortFingerprint(d.was), proto.ShortFingerprint(d.ack.Fingerprint), d.ack.Changed))
			res.Redelivered = append(res.Redelivered, d.node)
		case d.cut:
			res.Skipped["deadline"]++
			cut = append(cut, d.node)
		default:
			res.Skipped["delivery_failed"]++
			s.log.WarnContext(ctx, "nodetrust: trust.install failed", "node", d.node, "err", d.err.Error())
			feed("warn", fmt.Sprintf("%s: %v", d.node, d.err))
		}
	}
	if len(cut) > 0 {
		sort.Strings(cut)
		s.log.WarnContext(ctx, "nodetrust: trust converge ended before every delivery finished",
			"nodes", strings.Join(cut, ","), "count", len(cut), "err", context.Cause(ctx).Error())
		feed("warn", fmt.Sprintf("pass ended before %d node(s) answered: %s", len(cut), strings.Join(cut, ", ")))
	}
	for _, l := range [][]string{res.Redelivered, res.Stale, res.Current, res.Unreported} {
		sort.Strings(l)
	}
	s.log.InfoContext(ctx, "nodetrust: trust converge finished",
		"fingerprint", proto.ShortFingerprint(s.fingerprint), "installed", len(res.Redelivered), "stale", len(res.Stale),
		"current", len(res.Current), "unreported", len(res.Unreported), "skipped", fmt.Sprint(res.Skipped))
	feed("info", fmt.Sprintf("trust: %d installed, %d stale, %d current, %d unreported (skipped: %v)",
		len(res.Redelivered), len(res.Stale), len(res.Current), len(res.Unreported), res.Skipped))
	return res, nil
}

// deliverFanout bounds how many nodes one pass asks at once, as the console
// root push's deliver step does.
const deliverFanout = 8

// delivery is one node's trust.install within a pass and how it ended.
type delivery struct {
	node string
	was  string // the fingerprint the node reported before the pass
	ack  proto.TrustInstallAck
	err  error
	cut  bool // the pass's context ended before this delivery succeeded
}

// deliverAll runs every delivery, at most deliverFanout at once, and returns
// when all have ended. A delivery that fails once ctx has ended — including
// one that only started after it had, which fails at once — is marked cut
// rather than failed: the node refused nothing, the pass ran out of time.
func (s *Service) deliverAll(ctx context.Context, req Requester, ds []delivery) {
	sem := make(chan struct{}, deliverFanout)
	var wg sync.WaitGroup
	for i := range ds {
		wg.Add(1)
		go func(d *delivery) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d.ack, d.err = s.Deliver(ctx, req, d.node)
			d.cut = d.err != nil && ctx.Err() != nil
		}(&ds[i])
	}
	wg.Wait()
}
