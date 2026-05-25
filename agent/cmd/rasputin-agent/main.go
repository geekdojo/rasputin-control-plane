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
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// rasputin-agent: runs on every Rasputin node (control plane, firewall, compute).
// Dials the control-plane NATS broker outbound; never listens.
//
// Architecture: projects/rasputin/design/control-plane/architecture.md
//   in the geekdojo-wiki.

var startedAt = time.Now()

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	nodeID := envOr("RASPUTIN_NODE_ID", "node-dev")
	natsURL := envOr("RASPUTIN_NATS_URL", nats.DefaultURL)

	nc, err := bus.Connect(natsURL, nodeID)
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

	<-ctx.Done()
	log.Println("rasputin-agent: shutting down")
}

func handlePing(nodeID string, m *nats.Msg) {
	var cmd proto.DiagPingCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		log.Printf("rasputin-agent: ping: bad cmd: %v", err)
		return
	}
	hostname, _ := os.Hostname()
	pong := proto.DiagPongEvt{
		JobID:    cmd.JobID,
		NodeID:   nodeID,
		Hostname: hostname,
		Uptime:   time.Since(startedAt).Round(time.Second).String(),
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
