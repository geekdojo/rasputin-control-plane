package bmc

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Spec is the spec body the api accepts for a bmc.power job.
type Spec struct {
	TargetNodeID string             `json:"targetNodeId"`
	Verb         proto.BMCPowerVerb `json:"verb"`
}

// PowerWorkflow handles all four power verbs (on/off/cycle/reset) and the
// read-only status query in one workflow. The verb is carried in the spec
// so callers don't have to register four near-identical workflows.
//
// Three steps:
//
//  1. validate — spec sanity; target node must exist in inventory (so we
//                refuse typos that would silently no-op).
//  2. dispatch — RPC the BMC host's agent on the per-verb cmd subject.
//                The agent's BMC backend translates verb → hardware op.
//  3. record   — persist the reported state + audit row; publish a
//                BMCChangeEvt the UI's WS subscriber picks up.
func PowerWorkflow(svc *Service, inv *inventory.Store) jobs.Workflow {
	return jobs.Workflow{
		Kind: "bmc.power",
		Steps: []jobs.WorkflowStep{
			{Name: "validate", Timeout: 2 * time.Second, Do: powerValidate(svc, inv)},
			{Name: "dispatch", Timeout: 15 * time.Second, Do: powerDispatch(svc)},
			{Name: "record", Timeout: 2 * time.Second, Do: powerRecord(svc)},
		},
	}
}

func parseSpec(raw json.RawMessage) (*Spec, error) {
	var spec Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	if spec.TargetNodeID == "" {
		return nil, errors.New("targetNodeId is required")
	}
	if !proto.ValidBMCPowerVerb(spec.Verb) {
		return nil, fmt.Errorf("unsupported verb %q", spec.Verb)
	}
	return &spec, nil
}

func powerValidate(svc *Service, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		if svc.cfg.HostNodeID == "" {
			return nil, errors.New("no BMC host node configured")
		}
		// The target must be a known inventory node — protects against
		// typos that would dispatch a hardware op against a phantom id.
		// (Powered-off targets are valid; they just won't have a recent
		// last_seen. Inventory still has the row.)
		node, err := inv.Get(sc.Ctx, spec.TargetNodeID)
		if err != nil {
			return nil, fmt.Errorf("inventory lookup: %w", err)
		}
		if node == nil {
			return nil, fmt.Errorf("target node %q not registered", spec.TargetNodeID)
		}
		sc.Log("info", fmt.Sprintf("bmc.%s on %s (via %s)", spec.Verb, spec.TargetNodeID, svc.cfg.HostNodeID))
		return json.Marshal(spec)
	}
}

func powerDispatch(svc *Service) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		cmd, _ := json.Marshal(proto.BMCPowerCmd{TargetNodeID: spec.TargetNodeID})
		msg, err := sc.NATS.RequestWithContext(sc.Ctx,
			proto.BMCPowerSubject(svc.cfg.HostNodeID, spec.Verb), cmd)
		if err != nil {
			return nil, fmt.Errorf("bmc rpc: %w", err)
		}
		var ack proto.BMCPowerAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("decode ack: %w", err)
		}
		if !ack.OK {
			return nil, fmt.Errorf("bmc rejected: %s", ack.Detail)
		}
		sc.Log("info", fmt.Sprintf("state=%s detail=%s", ack.State, ack.Detail))
		return json.Marshal(ack)
	}
}

func powerRecord(svc *Service) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		// Re-issue a quick status query so the persisted state reflects
		// the actual post-command reality, not the verb's "intent". For
		// `cycle` and `reset`, the post-command state should be `on`; for
		// `off`, `off`; for `on`, `on`. But the BMC is the truth source.
		cmd, _ := json.Marshal(proto.BMCPowerCmd{TargetNodeID: spec.TargetNodeID})
		msg, err := sc.NATS.RequestWithContext(sc.Ctx,
			proto.BMCPowerSubject(svc.cfg.HostNodeID, proto.BMCPowerQuery), cmd)
		state := proto.BMCStateUnknown
		detail := ""
		if err == nil {
			var ack proto.BMCPowerAck
			if json.Unmarshal(msg.Data, &ack) == nil {
				state = ack.State
				detail = ack.Detail
			}
		}
		now := time.Now().UTC()
		if err := svc.store.Upsert(sc.Ctx, &NodeState{
			TargetNodeID:  spec.TargetNodeID,
			PowerState:    state,
			LastCmd:       string(spec.Verb),
			LastCmdAt:     &now,
			LastCmdResult: detail,
			UpdatedAt:     now,
		}); err != nil {
			log.Printf("bmc: persist state: %v", err)
		}
		publishChange(svc, proto.BMCChangeEvt{
			TargetNodeID: spec.TargetNodeID,
			Change:       verbToChange(spec.Verb),
			State:        state,
			Detail:       detail,
			Ts:           now,
		})
		sc.Log("info", fmt.Sprintf("recorded state=%s", state))
		return json.Marshal(map[string]any{
			"targetNodeId": spec.TargetNodeID,
			"verb":         spec.Verb,
			"state":        state,
		})
	}
}

func verbToChange(v proto.BMCPowerVerb) proto.BMCChangeType {
	switch v {
	case proto.BMCPowerOn:
		return proto.BMCPoweredOn
	case proto.BMCPowerOff:
		return proto.BMCPoweredOff
	case proto.BMCPowerCycle:
		return proto.BMCCycled
	case proto.BMCPowerReset:
		return proto.BMCResetSent
	default:
		// Query is read-only and doesn't generate a change event in
		// principle; emit cycled-as-default just so the UI gets a tick.
		return proto.BMCCycled
	}
}

func publishChange(svc *Service, ev proto.BMCChangeEvt) {
	payload, err := json.Marshal(ev)
	if err != nil {
		log.Printf("bmc: marshal change: %v", err)
		return
	}
	if err := svc.nc.Publish(proto.BMCChangeSubject(ev.TargetNodeID, ev.Change), payload); err != nil {
		log.Printf("bmc: publish change: %v", err)
	}
}
