package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// SelfBuildCommitted answers "is the build this controlplane runs committed,
// such that nothing automatic can roll it back?" It is the fact bus TLS waits
// for before it starts handing out pins (geekdojo/geekdojo-brain#448): a pin
// cannot be taken back, and an api rolled back to a pre-TLS build would strand
// every pinned node.
//
// Two halves, both required:
//
//  1. The job ledger: no update saga that could still mark this node's slot bad
//     — a queued or running node.update for selfNodeID, or any system.update
//     (its fan-out can reach the controlplane). On the n100 the OS marks the
//     booted slot good at every boot, so only the saga's health-gated mark-bad
//     can still roll a new build back; this half is what sees that.
//  2. The controlplane's own agent, asked over update.precheck: its backend
//     reports the booted slot is the bootloader's primary, is good, and no
//     tryboot trial is pending (agent/internal/updater/commit.go).
//
// A controlplane with no node of its own (selfNodeID empty: a dev api with no
// RASPUTIN_SELF_NODE_ID) has no A/B slot that could roll it back, and is
// committed by definition. Anything that cannot be established — no answer, an
// agent too old to report the field — is NOT committed, with the reason.
func SelfBuildCommitted(ctx context.Context, jobStore *jobs.Store, nc *nats.Conn, selfNodeID string, timeout time.Duration) (bool, string, error) {
	if selfNodeID == "" {
		return true, "this api has no controlplane node of its own (RASPUTIN_SELF_NODE_ID is unset), so there is no A/B slot to roll it back", nil
	}
	inFlight, err := jobStore.ListJobsByStatus(ctx, []jobs.Status{jobs.StatusQueued, jobs.StatusRunning})
	if err != nil {
		return false, "", fmt.Errorf("list in-flight jobs: %w", err)
	}
	for _, j := range inFlight {
		switch j.Kind {
		case "system.update":
			return false, fmt.Sprintf("a fleet update (%s) is in flight and may still update or roll back the controlplane", j.ID), nil
		case "node.update":
			var spec UpdateSpec
			if json.Unmarshal(j.Spec, &spec) == nil && spec.NodeID == selfNodeID {
				return false, fmt.Sprintf("a self-update (%s) is in flight and has not committed or rolled back yet", j.ID), nil
			}
		}
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	msg, err := nc.RequestWithContext(rctx, proto.UpdatePrecheckSubject(selfNodeID), []byte("{}"))
	if err != nil {
		if errors.Is(err, nats.ErrNoResponders) {
			return false, fmt.Sprintf("the controlplane's agent (%s) did not answer update.precheck: it is not on the bus, or has no update backend", selfNodeID), nil
		}
		return false, fmt.Sprintf("could not ask the controlplane's agent (%s) whether its build is committed: %v", selfNodeID, err), nil
	}
	var ack proto.UpdatePrecheckAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return false, fmt.Sprintf("the controlplane's agent answered update.precheck with something unreadable: %v", err), nil
	}
	if ack.BootCommitted == nil {
		return false, fmt.Sprintf("the controlplane's agent does not report whether its build is committed (it predates the field, first in agent %s): update it", proto.BootCommittedMinAgentVersion), nil
	}
	return *ack.BootCommitted, ack.BootCommittedDetail, nil
}
