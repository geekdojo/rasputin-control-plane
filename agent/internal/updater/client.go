package updater

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Backend is the interface the NATS handlers dispatch to. Two
// implementations: rauc.go (real) and mock.go (dev/CI).
type Backend interface {
	// Name returns "rauc" or "mock"; surfaced in precheck so the api knows
	// what it's talking to.
	Name() string

	// Precheck reports the current slot layout without mutating anything.
	Precheck(ctx context.Context) (*proto.UpdatePrecheckAck, error)

	// Download fetches bundleURL into the agent's local cache and verifies
	// it against expectedSHA. On success returns the local path and the
	// observed sha256. ProgressFn (if non-nil) is called with
	// (bytesCompleted, bytesTotal) at the backend's discretion.
	Download(ctx context.Context, bundleID, url, expectedSHA string, sizeBytes int64,
		progressFn func(bytesCompleted, bytesTotal int64)) (localPath string, observedSHA string, err error)

	// Install writes the bundle to the inactive slot. Returns the version
	// extracted from the bundle manifest. ProgressFn reports phase + percent.
	Install(ctx context.Context, bundleID, localPath string, targetSlot proto.UpdateSlot,
		progressFn func(phase string, percent int)) (newVersion string, err error)

	// Reboot is non-blocking — it acks then triggers the reboot in the
	// background, same as the system.reboot handler. Returns the delay it
	// will wait before mutating heartbeat / re-registering.
	Reboot(ctx context.Context, bundleID string, delaySeconds int) (delaySecondsApplied int, err error)

	// MarkGood commits the slot. Called after a successful post-reboot
	// health check. Idempotent — calling on an already-good slot is a no-op.
	MarkGood(ctx context.Context, bundleID string) error

	// MarkBad marks the slot bad and reboots back to the prior slot.
	// Best-effort: returns nil if mark-bad was issued, even if the
	// subsequent reboot fails (the bootloader watchdog will catch it).
	MarkBad(ctx context.Context, bundleID, reason string) error
}
