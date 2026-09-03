package quiesce

import (
	"context"
	"errors"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/docker"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Runtime is what the drivers need from the container runtime, and nothing
// more. Both docker backends implement it — ComposeBackend against a real
// daemon, MockBackend against directories and a state file — and main.go hands
// whichever it built to New.
//
// Kept separate from docker.Backend on purpose: that interface is the app
// lifecycle (deploy / down / status) and these are the quiesce operations,
// which have different semantics on the same stack — StopApp keeps the
// containers that Backend.Stop removes.
type Runtime interface {
	// Name identifies the runtime in logs ("docker" or "mock").
	Name() string
	// ResolveVolume returns the HOST path of the app's compose volume, named
	// as the tile declares it. docker.ErrVolumeNotFound when there is none.
	ResolveVolume(ctx context.Context, appID, volume string) (string, error)
	// AppRunning reports whether the app has live containers.
	AppRunning(ctx context.Context, appID string) (bool, error)
	// StopApp stops every container in the app's project WITHOUT removing it,
	// giving each graceSeconds to exit cleanly.
	StopApp(ctx context.Context, appID string, graceSeconds int) error
	// StartApp starts the app's stopped containers.
	StartApp(ctx context.Context, appID string) error
	// SnapshotSQLite writes a consistent copy of the database at dbRel to
	// dstRel, both relative to the volume root, from inside a running
	// container that mounts the volume. Returns the tool that did it.
	SnapshotSQLite(ctx context.Context, appID, volume, dbRel, dstRel string) (tool string, err error)
}

// The refusals, as sentinel errors so the ack's refusal code is derived from
// the error rather than matched on its text. Same discipline as
// agent/internal/storage.
var (
	// ErrUnsupported is a strategy this build has no driver for — postgres or
	// mysql. Deliberate; see doc.go.
	ErrUnsupported = errors.New("quiesce: strategy declared but not implemented in this build")
	// ErrClassNotStaged is a class this verb never stages: cache is never
	// copied, bulk streams direct.
	ErrClassNotStaged = errors.New("quiesce: volumes of that class are not staged")
	// ErrVolumeNotFound wraps docker.ErrVolumeNotFound at this layer.
	ErrVolumeNotFound = errors.New("quiesce: the runtime has no such volume for that app")
	// ErrQuiesceFailed is a stop or a snapshot that did not happen, so no copy
	// was taken.
	ErrQuiesceFailed = errors.New("quiesce: could not make the volume safe to copy")
	// ErrStagingExists is a staging name already in use under the root.
	ErrStagingExists = errors.New("quiesce: a staged file already exists under that name")
	// ErrInsufficientSpace is §4.7's source-side guard refusing.
	ErrInsufficientSpace = errors.New("quiesce: not enough free space under the staging root for this volume")
	// ErrBadName is a staging name that is not a plain file name, or a command
	// missing something it cannot proceed without.
	ErrBadName = errors.New("quiesce: refused by shape")
	// ErrWatchdogFired means the deadline restarted the app before the copy
	// finished, so the copy is not what the strategy promised.
	ErrWatchdogFired = errors.New("quiesce: the watchdog restarted the app before the copy finished; the copy was discarded")
)

// refusalFor maps an error onto the wire code the api and UI branch on.
// Anything unrecognised is a backend error, never a softer code.
func refusalFor(err error) proto.StorageRefusal {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUnsupported):
		return proto.BackupRefusalQuiesceUnsupported
	case errors.Is(err, ErrClassNotStaged):
		return proto.BackupRefusalClassNotStaged
	case errors.Is(err, ErrVolumeNotFound), errors.Is(err, docker.ErrVolumeNotFound):
		return proto.BackupRefusalVolumeNotFound
	case errors.Is(err, ErrQuiesceFailed):
		return proto.BackupRefusalQuiesceFailed
	case errors.Is(err, ErrStagingExists):
		return proto.BackupRefusalStagingExists
	case errors.Is(err, ErrInsufficientSpace):
		return proto.BackupRefusalInsufficientSpace
	case errors.Is(err, ErrBadName):
		return proto.BackupRefusalStagingMissing
	default:
		return proto.StorageRefusalBackendError
	}
}
