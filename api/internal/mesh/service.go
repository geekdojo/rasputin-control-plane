package mesh

import (
	"context"
	"fmt"
	"log"
	"time"
)

// Config is what the package needs from main beyond what its constructor
// args carry.
type Config struct {
	// LoginServer is the URL agents pass to `tailscale up --login-server`.
	// In v0 mock mode this is mostly cosmetic; in production it's the
	// controlplane's tailnet-reachable Headscale URL.
	LoginServer string
	// DefaultUser is the Headscale user name new pre-auth keys default to.
	// Per the locked decision (#9), v0 maps everything to one user;
	// per-IAM-user mapping is post-v0 schema-ready.
	DefaultUser string
	// HeadplaneURL is the base URL of a Headplane instance the operator
	// runs alongside Headscale. When set, the UI surfaces a sibling-tab
	// link from the Mesh page; "" hides it. Per locked decision #6 in
	// mesh.md we do not iframe Headplane — the cross-origin auth pain
	// isn't worth it — so this is just a link target.
	HeadplaneURL string
	// ReconcileInterval — how often to drift-check against Headscale.
	// Default 5 min if zero.
	ReconcileInterval time.Duration
}

// Service ties together the store + the Headscale client + the supervisor.
// It owns the periodic reconcile loop. Workflows (apply/reconcile/enroll)
// take the Service as a dependency so they share the same client/cfg.
type Service struct {
	cfg    Config
	store  *Store
	client Client
	sup    Supervisor
}

func NewService(cfg Config, store *Store, client Client, sup Supervisor) *Service {
	if cfg.ReconcileInterval == 0 {
		cfg.ReconcileInterval = 5 * time.Minute
	}
	if cfg.DefaultUser == "" {
		cfg.DefaultUser = "rasputin-operator"
	}
	return &Service{cfg: cfg, store: store, client: client, sup: sup}
}

func (s *Service) Config() Config { return s.cfg }
func (s *Service) Client() Client { return s.client }
func (s *Service) Store() *Store  { return s.store }

// Start runs supervisor.Start + ensures the default user exists. Called
// from main after the store opens.
func (s *Service) Start(ctx context.Context) error {
	if err := s.sup.Start(ctx); err != nil {
		return fmt.Errorf("mesh supervisor start: %w", err)
	}
	if err := s.client.EnsureUser(ctx, s.cfg.DefaultUser); err != nil {
		return fmt.Errorf("ensure user %s: %w", s.cfg.DefaultUser, err)
	}
	log.Printf("mesh: ready (backend=%s, user=%s)", s.client.Backend(), s.cfg.DefaultUser)
	return nil
}

func (s *Service) Stop() {
	_ = s.sup.Stop(context.Background())
}
