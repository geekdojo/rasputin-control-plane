package mesh

import (
	"context"
	"log"
)

// Supervisor manages the Headscale container's lifecycle on the
// controlplane node. v0 ships a NoopSupervisor — the api assumes Headscale
// is already running (or, in mock mode, that the MockClient is sufficient).
// v1 will add a DockerSupervisor that:
//
//  1. Writes /var/lib/rasputin/headscale/config.yaml from a template
//     parameterized on Config.Public URL, the internal-CA-signed leaf
//     cert path, and the chosen DERP map.
//  2. Pulls the pinned image (juanfont/headscale:0.28.x) if missing.
//  3. `docker run` with the right mount + port bindings.
//  4. Health-checks GET /health on startup.
//  5. Restarts on crash; surfaces failures as mesh change events.
//
// Keeping the interface here lets the rest of the package wire to the
// concrete impl when it lands without API churn.
type Supervisor interface {
	// Start brings Headscale up; idempotent if already running.
	Start(ctx context.Context) error
	// Stop tears it down for graceful shutdown.
	Stop(ctx context.Context) error
	// Healthy reports the current container state.
	Healthy(ctx context.Context) (bool, error)
}

// NoopSupervisor is the v0 default. Logs once at start and otherwise
// returns success. Use this when running against the mock client OR when
// an operator is managing Headscale themselves on the same host.
type NoopSupervisor struct {
	announced bool
}

func NewNoopSupervisor() *NoopSupervisor { return &NoopSupervisor{} }

func (s *NoopSupervisor) Start(_ context.Context) error {
	if !s.announced {
		log.Printf("mesh: supervisor is noop — assuming Headscale is managed externally (or mock client is in use)")
		s.announced = true
	}
	return nil
}

func (s *NoopSupervisor) Stop(_ context.Context) error { return nil }
func (s *NoopSupervisor) Healthy(_ context.Context) (bool, error) {
	return true, nil
}
