package bmc

import (
	"context"
	"fmt"
	"log"
	"slices"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
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

// TargetReachable enforces per-node BMC gating (design/control-plane/
// bmc.md §2a): when the configured BMC-host node advertises the
// bmc-targets capability, target must appear in its advertised list —
// power verbs and SoL against anything else are refused, so the UI can
// never drive a console that has no serial path. Hosts that don't
// advertise — older agents, or a mock backend with no configured
// targets — keep the interim presence-only behavior, so mixed-version
// clusters and dev setups don't regress.
func (s *Service) TargetReachable(ctx context.Context, inv *inventory.Store, target string) error {
	host, err := inv.Get(ctx, s.cfg.HostNodeID)
	if err != nil {
		return fmt.Errorf("bmc host lookup: %w", err)
	}
	if host == nil || !slices.Contains(host.Capabilities, proto.CapabilityBMCTargets) {
		return nil
	}
	if !slices.Contains(proto.NodeBMCTargets(host), target) {
		return fmt.Errorf("target %q is not reachable by BMC host %q (not in its advertised bmc-targets)",
			target, s.cfg.HostNodeID)
	}
	return nil
}
func (s *Service) NATS() *nats.Conn { return s.nc }
