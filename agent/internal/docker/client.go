// Package docker is the agent's interface to the local container runtime.
//
// Two implementations:
//
//   - compose.go: shells out to `docker compose` for real container lifecycle.
//   - mock.go: file-backed simulation for dev environments without Docker.
//
// The handler in handler.go is backend-agnostic — same NATS surface in both.
package docker

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Backend is the contract the docker subsystem uses to talk to the local
// container runtime. Both the real Docker Compose driver and the mock
// driver implement this.
type Backend interface {
	// Deploy writes the compose yaml to the backend's working area and
	// brings the app up. Returns the post-deploy status.
	Deploy(ctx context.Context, appID, name, composeYAML string) (proto.AppStatus, string, error)

	// Stop brings the app's services down. Returns the post-stop status.
	Stop(ctx context.Context, appID string) (proto.AppStatus, string, error)

	// Status returns the current status of an app's services. Used by the
	// docker.status handler — not currently exercised in v0 workflows but
	// will feed periodic reconciliation later.
	Status(ctx context.Context, appID string) (proto.AppStatus, []proto.AppServiceStatus, error)

	// Name identifies the backend in logs ("docker" or "mock").
	Name() string
}
