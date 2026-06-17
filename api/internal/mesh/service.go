package mesh

import (
	"context"
	"log"
	"sync"
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
	// MeshCAPEM is the per-installation Mesh CA root (PEM). Shipped to nodes
	// in the enroll command so they can trust the self-hosted Headscale's
	// HTTPS leaf before `tailscale up`. Empty when Headscale is plain HTTP
	// or externally managed with a publicly trusted cert (no extra trust
	// needed node-side). See proto.MeshEnrollCmd.MeshCAPEM.
	MeshCAPEM []byte
}

// Service ties together the store + the Headscale client + the supervisor.
// It owns the periodic reconcile loop. Workflows (apply/reconcile/enroll)
// take the Service as a dependency so they share the same client/cfg.
//
// The client is read through a mutex because self-hosted mesh swaps it: it
// starts as a notReadyClient and is replaced by the real Headscale client
// once the background bring-up (container up → admin key minted) completes.
type Service struct {
	cfg   Config
	store *Store
	sup   Supervisor

	mu        sync.RWMutex
	client    Client
	bootstrap func(context.Context) (Client, error) // self-hosted: builds the real client; nil for eager modes
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

// SetBootstrap installs a deferred client builder, used by self-hosted mesh
// where the real client can't be constructed until the supervised Headscale
// container is up and an admin key is minted. The Service starts serving with
// the placeholder client passed to NewService and swaps in the result of
// bootstrap once Start's background bring-up succeeds.
func (s *Service) SetBootstrap(fn func(context.Context) (Client, error)) { s.bootstrap = fn }

func (s *Service) Config() Config { return s.cfg }
func (s *Service) Store() *Store  { return s.store }

func (s *Service) Client() Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.client
}

func (s *Service) setClient(c Client) {
	s.mu.Lock()
	s.client = c
	s.mu.Unlock()
}

// Start brings the mesh up in the BACKGROUND and returns immediately. This is
// deliberate: bringing up self-hosted Headscale pulls + runs a container and
// mints a key — slow, network-dependent, and failable. It must never block
// the api's HTTP server from answering /healthz, nor take the whole control
// plane down if Headscale can't start (a degraded mesh is recoverable; a dead
// api is not). The bring-up retries with backoff until it succeeds or the
// context is cancelled; until then Client() returns the placeholder, whose
// ops report ErrMeshNotReady.
func (s *Service) Start(ctx context.Context) error {
	go s.bringUp(ctx)
	return nil
}

func (s *Service) bringUp(ctx context.Context) {
	if s.bootstrap != nil {
		// Self-hosted: the bootstrap closure starts the supervisor, mints the
		// admin key, and builds the real client. Swap it in on success.
		if !s.retry(ctx, "headscale bring-up", func() error {
			c, err := s.bootstrap(ctx)
			if err != nil {
				return err
			}
			s.setClient(c)
			return nil
		}) {
			return
		}
	} else if !s.retry(ctx, "supervisor start", func() error { return s.sup.Start(ctx) }) {
		return
	}
	if !s.retry(ctx, "ensure user", func() error { return s.Client().EnsureUser(ctx, s.cfg.DefaultUser) }) {
		return
	}
	log.Printf("mesh: ready (backend=%s, user=%s)", s.Client().Backend(), s.cfg.DefaultUser)
}

// retry runs fn until it succeeds (returns true) or ctx is cancelled (returns
// false), backing off 2s→30s. Each failure is logged — a node sitting in
// mock/degraded mesh shouldn't be silent.
func (s *Service) retry(ctx context.Context, what string, fn func() error) bool {
	backoff := 2 * time.Second
	for {
		if err := fn(); err == nil {
			return true
		} else {
			log.Printf("mesh: %s not ready yet: %v (retrying in %s)", what, err, backoff)
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			if backoff *= 2; backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func (s *Service) Stop() {
	_ = s.sup.Stop(context.Background())
}
