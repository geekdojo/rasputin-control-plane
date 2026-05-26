package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// RebootSpec is the spec body the api accepts for a node.reboot job.
type RebootSpec struct {
	NodeID       string `json:"nodeId"`
	DelaySeconds int    `json:"delaySeconds,omitempty"`
}

const (
	rebootDefaultDelay = 3
	rebootMaxDelay     = 30
)

// RebootWorkflow is a four-step saga that exercises the multi-step path of
// the runner end-to-end:
//
//  1. prepare              — validates spec
//  2. request_and_observe  — RPC reboot to the agent, race-safely waits for
//     the agent's "rebooting" event
//  3. wait_online          — waits for the agent's re-registration event
//  4. health_check         — diag.ping with 2 retries confirms the node came
//     back functional
func RebootWorkflow() Workflow {
	return Workflow{
		Kind: "node.reboot",
		Steps: []WorkflowStep{
			{Name: "prepare", Timeout: 2 * time.Second, Do: rebootPrepare},
			{Name: "request_and_observe", Timeout: 10 * time.Second, Do: rebootRequestAndObserve},
			{Name: "wait_online", Timeout: 60 * time.Second, Do: rebootWaitOnline},
			{Name: "health_check", Timeout: 5 * time.Second, Retries: 2, Do: rebootHealthCheck},
		},
	}
}

func parseRebootSpec(raw json.RawMessage) (*RebootSpec, error) {
	var spec RebootSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	if spec.NodeID == "" {
		return nil, errors.New("nodeId is required")
	}
	if spec.DelaySeconds <= 0 || spec.DelaySeconds > rebootMaxDelay {
		spec.DelaySeconds = rebootDefaultDelay
	}
	return &spec, nil
}

func rebootPrepare(sc *StepCtx) (json.RawMessage, error) {
	spec, err := parseRebootSpec(sc.Spec)
	if err != nil {
		return nil, err
	}
	sc.Log("info", fmt.Sprintf("preparing reboot of %s (delay=%ds)", spec.NodeID, spec.DelaySeconds))
	return json.Marshal(spec)
}

// rebootRequestAndObserve subscribes to the rebooting subject *before*
// issuing the RPC, so the event can't race us between RPC return and
// subscribe-setup.
func rebootRequestAndObserve(sc *StepCtx) (json.RawMessage, error) {
	spec, err := parseRebootSpec(sc.Spec)
	if err != nil {
		return nil, err
	}

	rebootingSub := proto.NodeEvtSubject(spec.NodeID, "rebooting")
	ch := make(chan *nats.Msg, 1)
	sub, err := sc.NATS.Subscribe(rebootingSub, func(m *nats.Msg) {
		select {
		case ch <- m:
		default:
		}
	})
	if err != nil {
		return nil, fmt.Errorf("subscribe %s: %w", rebootingSub, err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	cmd, err := json.Marshal(proto.SystemRebootCmd{DelaySeconds: spec.DelaySeconds})
	if err != nil {
		return nil, err
	}
	sc.Log("info", fmt.Sprintf("sending system.reboot to %s", spec.NodeID))
	reqSubj := proto.NodeCmdSubject(spec.NodeID, "system.reboot")
	if _, err := sc.NATS.RequestWithContext(sc.Ctx, reqSubj, cmd); err != nil {
		return nil, fmt.Errorf("reboot rpc: %w", err)
	}
	sc.Log("info", "agent acked; waiting for rebooting event")

	select {
	case m := <-ch:
		sc.Log("info", "rebooting event received")
		return m.Data, nil
	case <-sc.Ctx.Done():
		return nil, fmt.Errorf("waiting for rebooting event: %w", sc.Ctx.Err())
	}
}

func rebootWaitOnline(sc *StepCtx) (json.RawMessage, error) {
	spec, err := parseRebootSpec(sc.Spec)
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
		return nil, fmt.Errorf("subscribe %s: %w", regSubj, err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	sc.Log("info", fmt.Sprintf("waiting for %s to re-register", spec.NodeID))
	select {
	case m := <-ch:
		sc.Log("info", "node re-registered")
		return m.Data, nil
	case <-sc.Ctx.Done():
		return nil, fmt.Errorf("waiting for re-register: %w", sc.Ctx.Err())
	}
}

func rebootHealthCheck(sc *StepCtx) (json.RawMessage, error) {
	spec, err := parseRebootSpec(sc.Spec)
	if err != nil {
		return nil, err
	}
	cmd, err := json.Marshal(proto.DiagPingCmd{JobID: sc.JobID})
	if err != nil {
		return nil, err
	}
	subj := proto.NodeCmdSubject(spec.NodeID, "diag.ping")
	sc.Log("info", "health-checking via diag.ping")
	msg, err := sc.NATS.RequestWithContext(sc.Ctx, subj, cmd)
	if err != nil {
		return nil, fmt.Errorf("health ping: %w", err)
	}
	sc.Log("info", "node healthy")
	return msg.Data, nil
}
