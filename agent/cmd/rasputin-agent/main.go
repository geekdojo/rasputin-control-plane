package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// rasputin-agent: runs on every Rasputin node (control plane, firewall, compute).
// Dials the control-plane NATS broker outbound; never listens.
//
// Subsystems (see internal/):
//   - bus       NATS client + subject dispatch
//   - host      facts, RAUC slot control, system control
//   - docker    compose ops (compute nodes)
//   - openwrt   ubus / UCI client (firewall node)
//   - ipmi      BMC client for adjacent slots
//
// Architecture: projects/rasputin/design/control-plane/architecture.md
//   in the geekdojo-wiki.

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Println("rasputin-agent: scaffold — not yet wired")

	<-ctx.Done()
	log.Println("rasputin-agent: shutting down")
}
