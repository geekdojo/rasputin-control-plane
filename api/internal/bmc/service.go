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
	// HostFn resolves the id of the node whose agent owns the BMC bus —
	// live from the settings store (bmc.host_node_id, bmc-settings.md
	// S-5), so changing the host in Settings redirects routing without
	// an api restart. Commands target other nodes but are *delivered*
	// to this one. Empty result = no host configured.
	HostFn func(ctx context.Context) string

	// HostNodeID is a static fallback used when HostFn is nil — tests
	// and single-purpose tools; production wires HostFn.
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
	if cfg.HostFn == nil && cfg.HostNodeID == "" {
		log.Printf("bmc: WARNING — no host resolution configured; bmc operations will fail until the BMC host is set")
	}
	return &Service{cfg: cfg, store: store, nc: nc}
}

// Host resolves the current BMC-host node id ("" = none configured).
func (s *Service) Host(ctx context.Context) string {
	if s.cfg.HostFn != nil {
		return s.cfg.HostFn(ctx)
	}
	return s.cfg.HostNodeID
}

func (s *Service) Store() *Store { return s.store }

// TargetReachable enforces per-node BMC gating (design/control-plane/
// bmc.md §2a) — HARD on/off, decided 2026-07-21: the configured BMC-host
// node must be registered, must advertise the bmc-targets capability,
// and target must appear in its advertised list. There is no permissive
// fallback — a cluster whose host advertises nothing has BMC off, and
// every verb and SoL open is refused, so nothing can ever "succeed"
// against hardware that isn't there.
func (s *Service) TargetReachable(ctx context.Context, inv *inventory.Store, target string) error {
	hostID := s.Host(ctx)
	if hostID == "" {
		return fmt.Errorf("no BMC host configured")
	}
	host, err := inv.Get(ctx, hostID)
	if err != nil {
		return fmt.Errorf("bmc host lookup: %w", err)
	}
	if host == nil {
		return fmt.Errorf("BMC host %q is not registered", hostID)
	}
	if !slices.Contains(host.Capabilities, proto.CapabilityBMCTargets) {
		return fmt.Errorf("no BMC configured: host %q advertises no bmc-targets", hostID)
	}
	if !slices.Contains(proto.NodeBMCTargets(host), target) {
		return fmt.Errorf("target %q is not reachable by BMC host %q (not in its advertised bmc-targets)",
			target, hostID)
	}
	return nil
}
func (s *Service) NATS() *nats.Conn { return s.nc }
