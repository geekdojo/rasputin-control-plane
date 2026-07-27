package bmc

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// StartStatusSeed subscribes to node registration events and, when a
// node registers advertising bmc-targets, sweeps a read-only status
// query across every advertised target and records the result. Without
// it, bmc_state only fills in as operators run verbs, so the node panel
// shows no power state for 23 of 24 nodes ("— —", bench 2026-07-26).
//
// Host registration is the right trigger: it fires on agent boot,
// reconnect, and backend (re)configure — exactly the moments state is
// missing or stale. Event-driven only, like the config reconciler; no
// ticker. The sweep runs as direct RPCs in one background goroutine
// (sequential — the host serializes the bus anyway) rather than as
// jobs, so 24 read-only queries don't flood the Tasks surface.
//
// A console opened mid-sweep is tolerated: each verb briefly suspends
// and resumes the bridge at a command boundary (design doc §3), and a
// fresh host registration implies no live console anyway — sessions
// die with the agent.
func StartStatusSeed(nc *nats.Conn, svc *Service) (unsubscribe func(), err error) {
	s := &statusSeeder{nc: nc, svc: svc}
	sub, err := nc.Subscribe("rasputin.node.*.evt.registered", func(m *nats.Msg) { s.onRegistered(m.Data) })
	if err != nil {
		return nil, err
	}
	return func() { _ = sub.Unsubscribe() }, nil
}

// seedDebounce suppresses re-sweeps from registration bursts (an agent
// reconnect storm re-registers the same host repeatedly).
const seedDebounce = 30 * time.Second

// seedQueryTimeout bounds one target's status RPC: the serial command
// itself is budgeted at 2s reply collection plus pipe close; leave
// slack for an interrupted console suspend/resume around it.
const seedQueryTimeout = 8 * time.Second

type statusSeeder struct {
	nc  *nats.Conn
	svc *Service

	mu       sync.Mutex
	sweeping bool
	lastDone time.Time
}

func (s *statusSeeder) onRegistered(data []byte) {
	var ev proto.NodeRegisteredEvt
	if err := json.Unmarshal(data, &ev); err != nil {
		return
	}
	targets := proto.NodeBMCTargets(&proto.Node{Metadata: ev.Metadata})
	if len(targets) == 0 {
		return // not a BMC host (or an empty advertisement)
	}

	s.mu.Lock()
	if s.sweeping || time.Since(s.lastDone) < seedDebounce {
		s.mu.Unlock()
		return
	}
	s.sweeping = true
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.sweeping = false
			s.lastDone = time.Now()
			s.mu.Unlock()
		}()
		s.sweep(ev.NodeID, targets)
	}()
}

// sweep queries each target through the advertising host and upserts
// what the hardware reports. Per-target failures are logged and skipped
// — a stale row beats a wedged sweep, and the next registration retries.
func (s *statusSeeder) sweep(hostID string, targets []string) {
	ok := 0
	for _, target := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), seedQueryTimeout)
		cmd, _ := json.Marshal(proto.BMCPowerCmd{TargetNodeID: target})
		msg, err := s.nc.RequestWithContext(ctx,
			proto.BMCPowerSubject(hostID, proto.BMCPowerQuery), cmd)
		cancel()
		if err != nil {
			log.Printf("bmc seed: status %s via %s: %v", target, hostID, err)
			continue
		}
		var ack proto.BMCPowerAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil || !ack.OK {
			log.Printf("bmc seed: status %s via %s: ok=%v detail=%s err=%v",
				target, hostID, ack.OK, ack.Detail, err)
			continue
		}
		now := time.Now().UTC()
		if err := s.svc.store.Upsert(context.Background(), &NodeState{
			TargetNodeID:  target,
			PowerState:    ack.State,
			LastCmd:       string(proto.BMCPowerQuery),
			LastCmdAt:     &now,
			LastCmdResult: ack.Detail,
			UpdatedAt:     now,
		}); err != nil {
			log.Printf("bmc seed: persist %s: %v", target, err)
			continue
		}
		publishChange(s.svc, proto.BMCChangeEvt{
			TargetNodeID: target,
			Change:       proto.BMCStatusChecked,
			State:        ack.State,
			Detail:       ack.Detail,
			Ts:           now,
		})
		ok++
	}
	log.Printf("bmc seed: swept %d/%d targets via %s", ok, len(targets), hostID)
}
