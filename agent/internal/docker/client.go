// Package docker is the agent's interface to the local container runtime.
//
// Two implementations:
//
//   - compose.go: shells out to `docker compose` for real container lifecycle.
//   - mock.go: file-backed simulation for dev environments without Docker.
//     EXPLICIT-ONLY (RASPUTIN_DOCKER_BACKEND=mock) — never autodetected, since
//     it reports apps as Running that no runtime is running.
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

	// Pull fetches the images composeYAML names for appID's compose project
	// WITHOUT writing the app's compose file and without creating, stopping or
	// recreating any container (geekdojo/geekdojo-brain#411). A failed pull
	// therefore leaves the node exactly as it was. The returned string is the
	// failure detail ("" on success).
	Pull(ctx context.Context, appID, composeYAML string) (string, error)

	// CheckVolumes reports the volume keys composeYAML declares, as Compose
	// resolves them for appID's project, and every named volume appID has on
	// this node that it does not declare (geekdojo/geekdojo-brain#412) — the
	// volumes applying that compose would orphan. Read-only: nothing is
	// pulled, created or removed, and the live compose file is not written.
	CheckVolumes(ctx context.Context, appID, composeYAML string) (declared []string, dropped []proto.AppDroppedVolume, err error)

	// Stop brings the app's services down. Returns the post-stop status.
	//
	// deleteVolumes additionally removes every volume the app ever had —
	// `compose down -v`, then by exact name whatever that could not see: a
	// renamed-away or dropped service's volume still labelled for the
	// project, and the anonymous volumes the agent recorded the app's
	// containers mounting (geekdojo/geekdojo-brain#413). It is set only by
	// the app.delete saga when the operator deliberately chose it (#399).
	// Without it, Stop removes no volume of any class.
	Stop(ctx context.Context, appID string, deleteVolumes bool) (proto.AppStatus, string, error)

	// Status returns the current status of an app's services. Used by the
	// docker.status handler — not currently exercised in v0 workflows but
	// will feed periodic reconciliation later.
	Status(ctx context.Context, appID string) (proto.AppStatus, []proto.AppServiceStatus, error)

	// Name identifies the backend in logs ("docker" or "mock").
	Name() string
}

// VolumeReaper is the OPTIONAL surface for the two orphan-volume verbs
// (docker.volumes.list / docker.volumes.remove). A Backend that implements it
// gets those handlers registered beside deploy/stop/status; one that does not
// simply has no such verbs, and the api reports the node as unable to answer.
//
// Separate from Backend because these verbs are about volumes the docker
// daemon holds for projects that may no longer exist — not about any app's
// lifecycle — and because the mock backend, which runs no containers, has no
// honest answer to give.
type VolumeReaper interface {
	// ListProjectVolumes enumerates every volume on this node whose name is
	// rasp_<ulid>_<volume> and whose compose labels agree, and every anonymous
	// volume exactly one app's record names. Read-only.
	ListProjectVolumes(ctx context.Context, opts proto.AppVolumesListCmd) ([]proto.AppVolumeInfo, error)
	// RemoveProjectVolumes removes exactly the named volumes that pass every
	// refusal rule (see volumes.go) and reports the rest by name with a
	// reason. A refusal is not an error.
	RemoveProjectVolumes(ctx context.Context, cmd proto.AppVolumesRemoveCmd) proto.AppVolumesRemoveAck
	// DropAppVolumes removes, by exact name, named volumes of a still-installed
	// app that its compose on this node no longer declares — the deleteVolumes
	// of a compose change, after its `up` succeeded (#412). Every name that is
	// not the app's own, that the live compose still declares, or that a
	// container references is refused by name with a reason.
	DropAppVolumes(ctx context.Context, cmd proto.AppVolumesDropCmd) proto.AppVolumesRemoveAck
}
