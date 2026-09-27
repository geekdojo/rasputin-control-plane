package updater

import (
	"context"
	"errors"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/system"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Rebooter is the agent's one reboot function, (*system.Rebooter).Reboot. No
// update backend restarts the node itself: each one says WHY and in which
// MODE and hands the request over, so an update's reboot is announced, muted
// and logged exactly like an operator's.
type Rebooter interface {
	Reboot(req system.RebootRequest) (delaySeconds int, err error)
}

// errNoRebooter is what a backend's reboot returns when nothing was wired. It
// is an error and never a silent no-op: a backend that cannot reboot must not
// ack a reboot.
var errNoRebooter = errors.New("update backend has no rebooter wired, so it cannot reboot this node")

// requestReboot hands req to rb, refusing when rb was never wired.
func requestReboot(rb Rebooter, req system.RebootRequest) (int, error) {
	if rb == nil {
		return 0, errNoRebooter
	}
	return rb.Reboot(req)
}

// rebootReason names an update-path reboot for the journal and the rebooting
// event: which verb asked, and for which bundle.
func rebootReason(verb, bundleID string) string {
	if bundleID == "" {
		return verb
	}
	return verb + " bundle=" + proto.ShortFingerprint(bundleID)
}

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
	//
	// sigURL points at the artifact's detached CMS signature (see
	// proto.UpdateDownloadCmd.SigURL). Backends whose install path verifies a
	// detached signature fetch it here and MUST refuse to proceed when it is
	// empty or unfetchable; backends whose artifact format carries its own
	// signature (RAUC) ignore it. It is a download-time argument rather than an
	// install-time one so a firewall pointed at an api too old to send it fails
	// before moving half a gigabyte, not after.
	Download(ctx context.Context, bundleID, url, sigURL, expectedSHA string, sizeBytes int64,
		progressFn func(bytesCompleted, bytesTotal int64)) (localPath string, observedSHA string, err error)

	// Install writes the bundle to the inactive slot. Returns the version
	// extracted from the bundle manifest. ProgressFn reports phase + percent.
	Install(ctx context.Context, bundleID, localPath string, targetSlot proto.UpdateSlot,
		progressFn func(phase string, percent int)) (newVersion string, err error)

	// Reboot is non-blocking — it asks the agent's one reboot function
	// (Rebooter) for the reboot this backend needs and returns the delay
	// that will be applied. A backend never execs a reboot itself. An error
	// means the reboot was refused and will not happen.
	Reboot(ctx context.Context, bundleID string, delaySeconds int) (delaySecondsApplied int, err error)

	// MarkGood commits the slot. Called after a successful post-reboot
	// health check. Idempotent — calling on an already-good slot is a no-op.
	MarkGood(ctx context.Context, bundleID string) error

	// MarkBad marks the slot bad and reboots back to the prior slot, through
	// the same Rebooter. Best-effort: returns nil if mark-bad was issued,
	// even if the reboot is refused (the Rebooter logs the refusal, and the
	// bootloader's boot counter catches it on the next power cycle).
	MarkBad(ctx context.Context, bundleID, reason string) error
}
