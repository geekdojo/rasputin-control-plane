package bmc

import (
	"log"

	"github.com/nats-io/nats.go"
)

// Config carries the runtime knobs the bmc subsystem reads from main.
type Config struct {
	// HostNodeID is the id of the Rasputin node whose agent owns the BMC
	// bus. Commands target other nodes but are *delivered* to this one.
	// Defaults to RASPUTIN_SELF_NODE_ID; can be overridden via
	// RASPUTIN_BMC_HOST_NODE_ID for split-brain layouts (none expected v0).
	HostNodeID string
}

// Service ties together the store + config. The SOL session manager and
// the workflow constructors take a *Service as a dependency so they share
// the same view of which agent to talk to.
type Service struct {
	cfg   Config
	store *Store
	nc    *nats.Conn
}

func NewService(cfg Config, store *Store, nc *nats.Conn) *Service {
	if cfg.HostNodeID == "" {
		log.Printf("bmc: WARNING — no host node id configured; bmc operations will fail until RASPUTIN_BMC_HOST_NODE_ID or RASPUTIN_SELF_NODE_ID is set")
	}
	return &Service{cfg: cfg, store: store, nc: nc}
}

func (s *Service) HostNodeID() string { return s.cfg.HostNodeID }
func (s *Service) Store() *Store      { return s.store }
func (s *Service) NATS() *nats.Conn   { return s.nc }
