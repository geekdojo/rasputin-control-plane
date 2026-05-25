package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// rasputin-api: the Rasputin control-plane backend.
//
// Subsystems (see internal/) will be wired in as they land:
//   - bus       embedded NATS + JetStream server
//   - jobs      SQLite-backed Job ledger + Saga runner
//   - inventory, bmc, updater, apps, firewall, obs, auth
//   - api       HTTP + WebSocket handlers
//
// Architecture: projects/rasputin/design/control-plane/architecture.md
//   in the geekdojo-wiki.

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Println("rasputin-api: scaffold — not yet wired")

	<-ctx.Done()
	log.Println("rasputin-api: shutting down")
}
