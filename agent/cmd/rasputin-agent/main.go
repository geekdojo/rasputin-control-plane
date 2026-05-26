package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/host"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// rasputin-agent: runs on every Rasputin node (control plane, firewall, compute).
// Dials the control-plane NATS broker outbound; never listens.
//
// Architecture: projects/rasputin/design/control-plane/architecture.md
//   in the geekdojo-wiki.

const AgentVersion = "0.0.1-dev"

const heartbeatInterval = 10 * time.Second

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	nodeID := envOr("RASPUTIN_NODE_ID", "node-dev")
	natsURL := envOr("RASPUTIN_NATS_URL", nats.DefaultURL)
	roleStr := envOr("RASPUTIN_NODE_ROLE", string(proto.RoleCompute))
	role := proto.NodeRole(roleStr)
	if !proto.ValidRole(role) {
		log.Fatalf("rasputin-agent: invalid RASPUTIN_NODE_ROLE %q; expected one of %v",
			roleStr, proto.AllRoles)
	}

	nc, err := bus.Connect(natsURL, nodeID, func(c *nats.Conn) {
		publishRegistered(c, nodeID, role)
	})
	if err != nil {
		log.Fatalf("rasputin-agent: %v", err)
	}
	defer func() { _ = nc.Drain() }()

	pingSubj := proto.NodeCmdSubject(nodeID, "diag.ping")
	sub, err := nc.Subscribe(pingSubj, func(m *nats.Msg) {
		handlePing(nodeID, m)
	})
	if err != nil {
		log.Fatalf("rasputin-agent: subscribe %s: %v", pingSubj, err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	log.Printf("rasputin-agent: subscribed to %s", pingSubj)

	go runHeartbeats(ctx, nc, nodeID)

	<-ctx.Done()
	log.Println("rasputin-agent: shutting down")
}

func publishRegistered(nc *nats.Conn, nodeID string, role proto.NodeRole) {
	ev := proto.NodeRegisteredEvt{
		NodeID:       nodeID,
		Role:         role,
		Hostname:     host.Hostname(),
		AgentVersion: AgentVersion,
		Ts:           time.Now().UTC(),
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		log.Printf("rasputin-agent: marshal registered: %v", err)
		return
	}
	if err := nc.Publish(proto.NodeRegisteredSubject(nodeID), payload); err != nil {
		log.Printf("rasputin-agent: publish registered: %v", err)
		return
	}
	log.Printf("rasputin-agent: registered as %s (role=%s)", nodeID, role)
}

func runHeartbeats(ctx context.Context, nc *nats.Conn, nodeID string) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	subj := proto.NodeHeartbeatSubject(nodeID)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			hb := proto.HeartbeatEvt{
				NodeID:       nodeID,
				Uptime:       host.Uptime().String(),
				AgentVersion: AgentVersion,
				Ts:           time.Now().UTC(),
			}
			payload, err := json.Marshal(hb)
			if err != nil {
				log.Printf("rasputin-agent: marshal heartbeat: %v", err)
				continue
			}
			if err := nc.Publish(subj, payload); err != nil {
				log.Printf("rasputin-agent: publish heartbeat: %v", err)
			}
		}
	}
}

func handlePing(nodeID string, m *nats.Msg) {
	var cmd proto.DiagPingCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		log.Printf("rasputin-agent: ping: bad cmd: %v", err)
		return
	}
	pong := proto.DiagPongEvt{
		JobID:    cmd.JobID,
		NodeID:   nodeID,
		Hostname: host.Hostname(),
		Uptime:   host.Uptime().String(),
		Ts:       time.Now().UTC(),
	}
	payload, err := json.Marshal(pong)
	if err != nil {
		log.Printf("rasputin-agent: ping: marshal pong: %v", err)
		return
	}
	if err := m.Respond(payload); err != nil {
		log.Printf("rasputin-agent: ping: respond: %v", err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
