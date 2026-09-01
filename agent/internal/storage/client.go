package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Backend is the interface the NATS handlers dispatch to. Two
// implementations: blockdev.go (real) and mock.go (dev/CI).
type Backend interface {
	// Name returns "blockdev" or "mock"; surfaced in the enumerate ack so the
	// api knows what it is talking to.
	Name() string

	// Enumerate lists every candidate whole disk, PROTECTED ONES INCLUDED, and
	// mutates nothing. Each candidate carries its current partition table, its
	// backup-set status, its Protected flag with a reason, and a fingerprint
	// over stable identity plus that partition table.
	//
	// Protected disks are reported rather than filtered out: an operator who
	// plugged in one disk and is shown two needs to be told which one is the
	// boot medium and why. Filtering would also make the api's step-2
	// re-verification unable to distinguish "protected" from "gone".
	Enumerate(ctx context.Context) (*proto.StorageEnumerateAck, error)

	// Claim formats devicePath and claims it as a backup target. It is the only
	// destructive verb in this package.
	//
	// Before writing anything it MUST, in this order:
	//
	//   1. re-resolve the protected set from LIVE MOUNTS and refuse if
	//      devicePath (or any device beneath it) is in it, and
	//   2. re-compute the fingerprint and refuse on any difference from the
	//      one passed in.
	//
	// Both are hard errors — an implementation that logs and proceeds is a bug,
	// and an empty fingerprint is a refusal rather than a wildcard.
	//
	// The returned ack carries the partition UUID minted at format time, which
	// is the target's identifier everywhere downstream. The device path is not.
	Claim(ctx context.Context, devicePath, fingerprint, label string) (*proto.StorageClaimAck, error)

	// Mount mounts an already-claimed target addressed by the partition UUID
	// minted at claim time, and returns where it landed. Mounting an
	// already-mounted target is a no-op returning the existing path.
	//
	// This is the shared mount primitive #302's data-disk contract is meant to
	// consume; keep it target-agnostic.
	Mount(ctx context.Context, partUUID string) (mountPath string, err error)

	// Inspect reads a claimed target's marker file and free space, mounting it
	// first if needed. Read-only. A target that is not attached comes back with
	// Present false and no error — "the operator unplugged it" is an answer,
	// not a failure.
	Inspect(ctx context.Context, partUUID string) (*proto.StorageInspectAck, error)
}

// The refusals. Every one is a REFUSAL and never a warning: §4.8 has no path
// where the agent formats a disk with a caveat attached.
//
// They are sentinel errors so both backends and the handler agree on the wire
// refusal code without stringly-typed matching — refusalFor maps an error to
// its proto.StorageRefusal.
var (
	// ErrProtected is the one this package exists for: the target holds the
	// currently-mounted boot or persistent partitions.
	ErrProtected = errors.New("storage: refusing to touch the device holding the mounted boot/persistent partitions")

	// ErrFingerprintMismatch means the disk is not the one the operator
	// confirmed, or changed underneath us. Also what a Claim replayed after a
	// successful format gets, because the format rewrote the partition table
	// the fingerprint hashes.
	ErrFingerprintMismatch = errors.New("storage: device fingerprint no longer matches the one confirmed")

	// ErrDeviceAbsent means no such device — unplugged between the picker and
	// the confirmation.
	ErrDeviceAbsent = errors.New("storage: device not present")

	// ErrNotWholeDisk means the path names a partition or a virtual device.
	// Claim repartitions a whole disk and will not be pointed at anything else.
	ErrNotWholeDisk = errors.New("storage: not a whole disk")

	// ErrNotFound means no claimed target with that partition UUID is attached.
	ErrNotFound = errors.New("storage: no claimed target with that partition UUID")

	// ErrNoFingerprint means the command carried an empty fingerprint. Empty is
	// not "skip the check" — a caller that cannot name the disk it confirmed
	// has not confirmed a disk.
	ErrNoFingerprint = errors.New("storage: claim requires the fingerprint the operator confirmed")
)

// refusalFor maps a backend error onto the machine-readable code the api and UI
// branch on. Anything unrecognised is a backend error, never a softer code —
// an unknown failure must not be renderable as "just re-confirm".
func refusalFor(err error) proto.StorageRefusal {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrProtected):
		return proto.StorageRefusalProtected
	case errors.Is(err, ErrFingerprintMismatch), errors.Is(err, ErrNoFingerprint):
		return proto.StorageRefusalFingerprintMismatch
	case errors.Is(err, ErrDeviceAbsent):
		return proto.StorageRefusalDeviceAbsent
	case errors.Is(err, ErrNotWholeDisk):
		return proto.StorageRefusalNotWholeDisk
	case errors.Is(err, ErrNotFound):
		return proto.StorageRefusalNotFound
	default:
		return proto.StorageRefusalBackendError
	}
}

// protectedError wraps ErrProtected with the reason, so the refusal the
// operator reads names the mount that caused it rather than a generic sentence.
func protectedError(devicePath, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrProtected, devicePath, reason)
}
