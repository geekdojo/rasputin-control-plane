package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bootverify"
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

	// rebootVerifyTimeout bounds the wait for the node to answer on a new
	// boot. It is the update saga's bound for the same wait, for the same
	// reason: it has to outlast a real boot on the slowest node. It decides
	// nothing by itself — the step ends when a new boot answers, and when the
	// bound is reached instead it fails naming what was observed.
	rebootVerifyTimeout = 5 * time.Minute
)

// Step names, shared with the step functions that read each other's results.
const (
	rebootStepObserveBoot = "observe_boot"
	rebootStepWaitNewBoot = "wait_new_boot"
)

// RebootObservedBoot is the observe_boot step's result: the boot the node was
// on BEFORE it was told to reboot.
type RebootObservedBoot struct {
	NodeID string `json:"nodeId"`
	// BootID is empty when the node's agent reports no boot identity.
	BootID string `json:"bootId,omitempty"`
}

// RebootVerified is the wait_new_boot step's result.
type RebootVerified struct {
	NodeID      string `json:"nodeId"`
	PriorBootID string `json:"priorBootId"`
	Verdict     string `json:"verdict"`
}

// RebootWorkflow restarts a node's operating system and succeeds only when
// the node proves it restarted.
//
//  1. prepare              — validates the spec
//  2. observe_boot         — asks the node which boot it is on, BEFORE the
//     command, so there is something to compare against
//  3. request_and_observe  — sends system.reboot, fails if the agent refuses
//     it, and waits for the agent's "rebooting" announcement
//  4. wait_new_boot        — waits for the node to answer on a DIFFERENT boot
//     identity
//  5. health_check         — diag.ping confirms the node came back functional
//
// The proof is step 4 and nothing else. The agent's ack, its "rebooting"
// event and its re-registration are all things a node that never restarted
// produces just as well — until geekdojo/geekdojo-brain#616 this job accepted
// the re-registration, and an agent that only simulated its reboots passed
// every time. Boot identity is the mechanism the update saga already used
// (bootverify); this job shares it rather than having one of its own.
func RebootWorkflow() Workflow {
	return Workflow{
		Kind: "node.reboot",
		Steps: []WorkflowStep{
			{Name: "prepare", Timeout: 2 * time.Second, Do: rebootPrepare},
			{Name: rebootStepObserveBoot, Timeout: 10 * time.Second, Retries: 1, Do: rebootObserveBoot},
			{Name: "request_and_observe", Timeout: 10 * time.Second, Do: rebootRequestAndObserve},
			{Name: rebootStepWaitNewBoot, Timeout: rebootVerifyTimeout, Do: rebootWaitNewBoot},
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

// rebootObserveBoot records the boot the node is on before anything is sent to
// it. A node that does not answer cannot be asked to reboot, so that fails
// here, before the command.
func rebootObserveBoot(sc *StepCtx) (json.RawMessage, error) {
	spec, err := parseRebootSpec(sc.Spec)
	if err != nil {
		return nil, err
	}
	bootID, err := bootverify.NodeProbe(sc.NATS, spec.NodeID).Ask(sc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("%s is not answering, so it cannot be asked to reboot: %w", spec.NodeID, err)
	}
	if bootID == "" {
		sc.Log("warn", fmt.Sprintf("%s answered but its agent reports no boot identity; "+
			"the reboot will be sent, and it cannot be verified", spec.NodeID))
	} else {
		sc.Log("info", fmt.Sprintf("%s is on boot %s", spec.NodeID, proto.ShortFingerprint(bootID)))
	}
	return json.Marshal(RebootObservedBoot{NodeID: spec.NodeID, BootID: bootID})
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
	reply, err := sc.NATS.RequestWithContext(sc.Ctx, reqSubj, cmd)
	if err != nil {
		return nil, fmt.Errorf("reboot rpc: %w", err)
	}
	if detail, refused := RebootRefused(reply.Data); refused {
		return nil, fmt.Errorf("%s refused the reboot and was NOT rebooted: %s", spec.NodeID, detail)
	}
	sc.Log("info", "agent acked; waiting for rebooting event")

	select {
	case m := <-ch:
		var ev proto.SystemRebootingEvt
		if json.Unmarshal(m.Data, &ev) == nil && ev.Simulated {
			sc.Log("warn", "the agent is in its dev mock configuration and SIMULATES reboots: "+
				"nothing will restart, and this job will not accept it as a reboot")
		}
		sc.Log("info", "rebooting event received")
		return m.Data, nil
	case <-sc.Ctx.Done():
		return nil, fmt.Errorf("waiting for rebooting event: %w", sc.Ctx.Err())
	}
}

// RebootRefused reads a reboot reply — system.reboot's or update.reboot's, which
// have the same shape — and reports whether the agent REFUSED. Only an explicit ok=false is a refusal. An agent that predates
// refusals replies ok=true, and fake agents in older tests reply with an
// empty object; neither says anything about whether a reboot will happen —
// which is fine, because nothing here treats the ack as evidence.
func RebootRefused(reply []byte) (detail string, refused bool) {
	var ack struct {
		OK     *bool  `json:"ok"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(reply, &ack) != nil || ack.OK == nil || *ack.OK {
		return "", false
	}
	if ack.Detail == "" {
		return "the agent gave no reason", true
	}
	return ack.Detail, true
}

// rebootWaitNewBoot is the proof. It succeeds only when the node answers on a
// boot identity different from the one observe_boot recorded.
func rebootWaitNewBoot(sc *StepCtx) (json.RawMessage, error) {
	spec, err := parseRebootSpec(sc.Spec)
	if err != nil {
		return nil, err
	}
	prior := priorObservedBoot(sc.PriorResults)

	verdict, err := bootverify.VerifyRestart(sc.Ctx, sc.NATS, spec.NodeID, prior, sc.Log)
	if err != nil {
		return nil, err
	}
	sc.Log("info", fmt.Sprintf("%s rebooted: it left boot %s and is answering on a different one",
		spec.NodeID, proto.ShortFingerprint(prior)))
	return json.Marshal(RebootVerified{NodeID: spec.NodeID, PriorBootID: prior, Verdict: string(verdict)})
}

// priorObservedBoot digs the pre-command boot identity out of the
// observe_boot step's cached result. Every failure collapses to "", which is
// UNKNOWN — and an unknown prior boot can never produce a verified reboot.
func priorObservedBoot(prior map[string]json.RawMessage) string {
	raw, ok := prior[rebootStepObserveBoot]
	if !ok || len(raw) == 0 {
		return ""
	}
	var obs RebootObservedBoot
	if err := json.Unmarshal(raw, &obs); err != nil {
		return ""
	}
	return obs.BootID
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
