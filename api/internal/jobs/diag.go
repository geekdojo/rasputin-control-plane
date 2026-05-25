package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// PingSpec is the spec body the api accepts for a diag.ping job.
type PingSpec struct {
	NodeID string `json:"nodeId"`
}

// PingWorkflow is the one-step workflow that exercises the bus+agent loop.
// It publishes a command to the target node's diag.ping subject and waits
// for the reply via NATS request-reply.
func PingWorkflow() Workflow {
	return Workflow{
		Kind: "diag.ping",
		Steps: []WorkflowStep{
			{
				Name:    "ping",
				Timeout: 5 * time.Second,
				Retries: 1,
				Do:      pingStep,
			},
		},
	}
}

func pingStep(sc *StepCtx) (json.RawMessage, error) {
	var spec PingSpec
	if err := json.Unmarshal(sc.Spec, &spec); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	if spec.NodeID == "" {
		return nil, errors.New("nodeId is required")
	}
	sc.Log("info", fmt.Sprintf("sending ping to %s", spec.NodeID))

	cmd, err := json.Marshal(proto.DiagPingCmd{JobID: sc.JobID})
	if err != nil {
		return nil, err
	}
	subject := proto.NodeCmdSubject(spec.NodeID, "diag.ping")
	msg, err := sc.NATS.RequestWithContext(sc.Ctx, subject, cmd)
	if err != nil {
		return nil, fmt.Errorf("ping %s: %w", spec.NodeID, err)
	}
	sc.Log("info", fmt.Sprintf("received pong (%d bytes)", len(msg.Data)))
	return msg.Data, nil
}
