package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bootverify"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Spec is the spec body the api accepts for a bmc.power job.
type Spec struct {
	TargetNodeID string             `json:"targetNodeId"`
	Verb         proto.BMCPowerVerb `json:"verb"`
}

// Step names, shared with the step functions that read each other's results.
const (
	stepObserveBoot = "observe_boot"
	stepDispatch    = "dispatch"
	stepVerify      = "verify"
)

// Evidence names what a bmc.power job's outcome rests on. It is in the job's
// result and in its log, because the two kinds are not the same claim.
type Evidence string

const (
	// EvidenceBootIdentity: the target answered on a different boot identity
	// than it had before the command. The only evidence that a node
	// RESTARTED.
	EvidenceBootIdentity Evidence = "boot-identity"
	// EvidencePowerState: the BMC's own read-back of the power state matched
	// what the verb intended. It is what off and on rest on. For reset and
	// cycle it is the WEAKER evidence, used only when the target had no boot
	// identity to compare — and then the restart is not verified, and the
	// result says so.
	EvidencePowerState Evidence = "power-state-read-back"
	// EvidenceNone: a status query. Nothing was changed, so nothing is
	// claimed.
	EvidenceNone Evidence = "none"
)

// ObservedBoot is the observe_boot step's result: what the target said about
// its boot BEFORE the command.
type ObservedBoot struct {
	TargetNodeID string `json:"targetNodeId"`
	// BootID is empty when the target did not answer or reports no boot
	// identity.
	BootID string `json:"bootId,omitempty"`
	// WhyUnknown says why BootID is empty.
	WhyUnknown string `json:"whyUnknown,omitempty"`
}

// Outcome is the verify step's result, and what the job's final result
// carries.
type Outcome struct {
	TargetNodeID string              `json:"targetNodeId"`
	Verb         proto.BMCPowerVerb  `json:"verb"`
	State        proto.BMCPowerState `json:"state"`
	Evidence     Evidence            `json:"evidence"`
	// RestartVerified is true only when the target came back on a different
	// boot identity. It is false for every outcome resting on the BMC's
	// read-back, whatever the BMC said.
	RestartVerified bool   `json:"restartVerified"`
	PriorBootID     string `json:"priorBootId,omitempty"`
	// Statement is the outcome in one sentence, as recorded against the node.
	Statement string `json:"statement"`
}

// PowerWorkflow handles all four power verbs (on/off/cycle/reset) and the
// read-only status query in one workflow. The verb is carried in the spec
// so callers don't have to register four near-identical workflows.
//
// Five steps:
//
//  1. validate     — spec sanity; target node must exist in inventory (so we
//     refuse typos that would silently no-op).
//  2. observe_boot — for reset and cycle: ask the TARGET which boot it is on,
//     before anything is sent to the BMC.
//  3. dispatch     — RPC the BMC host's agent on the per-verb cmd subject.
//     The agent's BMC backend translates verb → hardware op. Fails when the
//     power state the BMC reads back is not the one the verb intended.
//  4. verify       — for reset and cycle: succeed only when the target comes
//     back on a DIFFERENT boot identity.
//  5. record       — persist the reported state + audit row; publish a
//     BMCChangeEvt the UI's WS subscriber picks up.
//
// WHY STEPS 2 AND 4 EXIST (geekdojo/geekdojo-brain#617). A reset reported
// success and the node had not reset. The job's only evidence was the BMC
// host's ack, and an ack says a command was issued, not that the node named
// lost power: the command can reach the wrong slot, a slot that ignores it,
// or nothing at all, and the ack reads the same. For a BMC whose reset is a
// native verb that never cuts power, the read-back state cannot show a
// restart even in principle. So for the verbs that must restart the target,
// the evidence is the TARGET's own boot identity — decided here, once, for
// every backend, by the same code the node.reboot job uses
// (bootverify.VerifyRestart).
//
// A target with no boot identity to compare — no agent, a dead node being
// revived, an agent that predates boot identity — cannot be verified that way.
// The job then rests on the BMC's read-back and SAYS SO: the result carries
// restartVerified=false and the log says the restart was not verified.
func PowerWorkflow(svc *Service, inv *inventory.Store) jobs.Workflow {
	return jobs.Workflow{
		Kind: "bmc.power",
		Steps: []jobs.WorkflowStep{
			{Name: "validate", Timeout: 2 * time.Second, Do: powerValidate(svc, inv)},
			{Name: stepObserveBoot, Timeout: 10 * time.Second, Do: powerObserveBoot()},
			{Name: stepDispatch, Timeout: 15 * time.Second, Do: powerDispatch(svc)},
			{Name: stepVerify, Timeout: bootverify.RestartBound, Do: powerVerify(svc)},
			{Name: "record", Timeout: 2 * time.Second, Do: powerRecord(svc)},
		},
	}
}

// restarts reports whether verb must restart the target.
func restarts(verb proto.BMCPowerVerb) bool {
	return verb == proto.BMCPowerReset || verb == proto.BMCPowerCycle
}

// intendedState is the power state verb leaves the target in. ok is false for
// the status query, which intends nothing.
func intendedState(verb proto.BMCPowerVerb) (state proto.BMCPowerState, ok bool) {
	switch verb {
	case proto.BMCPowerOn, proto.BMCPowerCycle, proto.BMCPowerReset:
		return proto.BMCStateOn, true
	case proto.BMCPowerOff:
		return proto.BMCStateOff, true
	}
	return "", false
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
		if svc.Host(sc.Ctx) == "" {
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
		// A controlplane target refuses power-OFF whatever the backend
		// can do. This is deliberately NOT a capability question: the
		// hardware honours it perfectly well — on a Turing Pi the
		// controlplane is slot 1 and the BMC cut its power on request
		// (bench 2026-07-28) — it is that the operation is one-way from
		// the operator's seat. The UI that issues power-off is served BY
		// the controlplane, so once it is off nothing is left to issue
		// power-on; recovery means the chassis BMC's own interface or a
		// walk to the rack. A confirmation dialog is the right tool for
		// something the operator can undo, and this they cannot.
		//
		// reset and cycle stay allowed on purpose: they drop the UI and
		// bring it back on their own (~90s on this bench), which is an
		// interruption rather than a one-way door — and recovering a
		// wedged controlplane from the board is a real use for them.
		//
		// Keyed on ROLE, not on a node id or on "is this the BMC host",
		// so it survives the controlplane moving to a different node.
		if node.Role == proto.RoleControlPlane && spec.Verb == proto.BMCPowerOff {
			return nil, fmt.Errorf("refusing bmc power-off on %q: it is the controlplane — powering it off removes the only surface that can power it back on; use reset or cycle, which recover on their own", spec.TargetNodeID)
		}
		// Gate on the capability the verb actually needs: a backend may
		// drive power without offering reset, or vice versa.
		needed := proto.BMCCapPower
		if spec.Verb == proto.BMCPowerReset {
			needed = proto.BMCCapReset
		}
		if err := svc.TargetSupports(sc.Ctx, inv, spec.TargetNodeID, needed); err != nil {
			return nil, err
		}
		sc.Log("info", fmt.Sprintf("bmc.%s on %s (via %s)", spec.Verb, spec.TargetNodeID, svc.Host(sc.Ctx)))
		return json.Marshal(spec)
	}
}

// powerObserveBoot asks the target which boot it is on, before the command.
//
// It never fails the job. A BMC exists for the node whose agent cannot help,
// so a target that does not answer is an ordinary case here, not an error: it
// means boot identity cannot be the evidence, and the step records that and
// why.
func powerObserveBoot() jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		obs := ObservedBoot{TargetNodeID: spec.TargetNodeID}
		if !restarts(spec.Verb) {
			return json.Marshal(obs)
		}
		rctx, cancel := context.WithTimeout(sc.Ctx, 5*time.Second)
		defer cancel()
		bootID, err := bootverify.NodeProbe(sc.NATS, spec.TargetNodeID).Ask(rctx)
		switch {
		case err != nil:
			obs.WhyUnknown = fmt.Sprintf("%s did not answer before the command (%v)", spec.TargetNodeID, err)
		case bootID == "":
			obs.WhyUnknown = fmt.Sprintf("%s answered, and its agent reports no boot identity", spec.TargetNodeID)
		default:
			obs.BootID = bootID
		}
		if obs.BootID == "" {
			sc.Log("warn", fmt.Sprintf("%s. Boot identity cannot be the evidence for this %s: "+
				"its result will rest on the BMC's own read-back of the power state, and the restart will NOT be verified",
				obs.WhyUnknown, spec.Verb))
		} else {
			sc.Log("info", fmt.Sprintf("%s is on boot %s; the %s succeeds only if it comes back on a different one",
				spec.TargetNodeID, proto.ShortFingerprint(obs.BootID), spec.Verb))
		}
		return json.Marshal(obs)
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
			proto.BMCPowerSubject(svc.Host(sc.Ctx), spec.Verb), cmd)
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
		// The BMC's read-back must be the state the verb intended. The ack
		// reports post-op reality by contract, and until
		// geekdojo/geekdojo-brain#617 nothing compared it with anything: an
		// off that left the node on was a success.
		if want, ok := intendedState(spec.Verb); ok && ack.State != want {
			return nil, fmt.Errorf("bmc %s on %s: the BMC reports the node %q afterwards, and %q was intended (%s)",
				spec.Verb, spec.TargetNodeID, stateForMessage(ack.State), want, detailForMessage(ack.Detail))
		}
		return json.Marshal(ack)
	}
}

func stateForMessage(s proto.BMCPowerState) proto.BMCPowerState {
	if s == "" {
		return proto.BMCStateUnknown
	}
	return s
}

func detailForMessage(d string) string {
	if d == "" {
		return "the BMC gave no detail"
	}
	return d
}

// powerVerify decides what the job's outcome rests on, and for reset and cycle
// it is where the job succeeds or fails.
func powerVerify(svc *Service) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		ack := priorAck(sc.PriorResults)
		out := Outcome{TargetNodeID: spec.TargetNodeID, Verb: spec.Verb, State: stateForMessage(ack.State)}

		switch {
		case spec.Verb == proto.BMCPowerQuery:
			out.Evidence = EvidenceNone
			out.Statement = fmt.Sprintf("status: the BMC reports %q", out.State)

		case !restarts(spec.Verb):
			// on / off: dispatch already required the read-back to match.
			out.Evidence = EvidencePowerState
			out.Statement = fmt.Sprintf("%s: the BMC reports %q afterwards, as intended", spec.Verb, out.State)

		default:
			obs := priorObserved(sc.PriorResults)
			out.PriorBootID = obs.BootID
			if obs.BootID == "" {
				why := obs.WhyUnknown
				if why == "" {
					why = fmt.Sprintf("no boot identity was recorded for %s before the command", spec.TargetNodeID)
				}
				out.Evidence = EvidencePowerState
				out.RestartVerified = false
				out.Statement = fmt.Sprintf("%s NOT VERIFIED: %s, so there was no boot identity to compare. "+
					"The BMC reports %q afterwards; that is the only evidence, and it does not show that the node restarted",
					spec.Verb, why, out.State)
				sc.Log("warn", out.Statement)
				break
			}
			if _, err := bootverify.VerifyRestart(sc.Ctx, sc.NATS, spec.TargetNodeID, obs.BootID, sc.Log); err != nil {
				failure := fmt.Errorf("bmc %s on %s was acknowledged by the BMC (it reports %q) and the node did NOT restart: %w",
					spec.Verb, spec.TargetNodeID, out.State, err)
				// Recorded on a context of its own: sc.Ctx may be the very
				// deadline that ended the wait.
				rctx, cancel := context.WithTimeout(context.WithoutCancel(sc.Ctx), 5*time.Second)
				recordOutcome(rctx, svc, spec, out.State, "FAILED: "+failure.Error())
				cancel()
				return nil, failure
			}
			out.Evidence = EvidenceBootIdentity
			out.RestartVerified = true
			out.Statement = fmt.Sprintf("%s verified: %s left boot %s and is answering on a different one",
				spec.Verb, spec.TargetNodeID, proto.ShortFingerprint(obs.BootID))
		}
		if out.Evidence != EvidencePowerState || !restarts(spec.Verb) {
			sc.Log("info", out.Statement)
		}
		return json.Marshal(out)
	}
}

// priorAck is the dispatch step's ack; zero when it is missing.
func priorAck(prior map[string]json.RawMessage) proto.BMCPowerAck {
	var ack proto.BMCPowerAck
	if raw, ok := prior[stepDispatch]; ok {
		_ = json.Unmarshal(raw, &ack)
	}
	return ack
}

// priorObserved is the observe_boot step's result; zero — an unknown boot —
// when it is missing, which can only weaken the claim the job makes.
func priorObserved(prior map[string]json.RawMessage) ObservedBoot {
	var obs ObservedBoot
	if raw, ok := prior[stepObserveBoot]; ok {
		_ = json.Unmarshal(raw, &obs)
	}
	return obs
}

// priorOutcome is the verify step's result.
func priorOutcome(prior map[string]json.RawMessage) (Outcome, bool) {
	var out Outcome
	raw, ok := prior[stepVerify]
	if !ok || json.Unmarshal(raw, &out) != nil {
		return Outcome{}, false
	}
	return out, true
}

// recordOutcome persists what happened against the node and publishes it.
func recordOutcome(ctx context.Context, svc *Service, spec *Spec, state proto.BMCPowerState, result string) {
	now := time.Now().UTC()
	if err := svc.store.Upsert(ctx, &NodeState{
		TargetNodeID:  spec.TargetNodeID,
		PowerState:    state,
		LastCmd:       string(spec.Verb),
		LastCmdAt:     &now,
		LastCmdResult: result,
		UpdatedAt:     now,
	}); err != nil {
		log.Printf("bmc: persist state: %v", err)
	}
	publishChange(svc, proto.BMCChangeEvt{
		TargetNodeID: spec.TargetNodeID,
		Change:       verbToChange(spec.Verb),
		State:        state,
		Detail:       result,
		Ts:           now,
	})
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
			proto.BMCPowerSubject(svc.Host(sc.Ctx), proto.BMCPowerQuery), cmd)
		state := proto.BMCStateUnknown
		detail := ""
		if err == nil {
			var ack proto.BMCPowerAck
			if json.Unmarshal(msg.Data, &ack) == nil {
				state = ack.State
				detail = ack.Detail
			}
		}
		// What is recorded against the node says what the outcome rests on,
		// ahead of the BMC's own detail.
		outcome, haveOutcome := priorOutcome(sc.PriorResults)
		result := detail
		if haveOutcome && outcome.Statement != "" {
			result = outcome.Statement
			if detail != "" {
				result += " (" + detail + ")"
			}
		}
		recordOutcome(sc.Ctx, svc, spec, state, result)
		sc.Log("info", fmt.Sprintf("recorded state=%s", state))
		final := map[string]any{
			"targetNodeId": spec.TargetNodeID,
			"verb":         spec.Verb,
			"state":        state,
		}
		if haveOutcome {
			final["evidence"] = outcome.Evidence
			final["restartVerified"] = outcome.RestartVerified
			final["statement"] = outcome.Statement
		}
		return json.Marshal(final)
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
		// Query is a read-only observation, not a command.
		return proto.BMCStatusChecked
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
