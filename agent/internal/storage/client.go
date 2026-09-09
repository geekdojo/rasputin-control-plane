package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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

	// Claim formats devicePath and claims it for cmd's purpose — §4.8's backup
	// target or §6's data disk. It is the only destructive verb in this
	// package.
	//
	// Before writing anything it MUST, in this order:
	//
	//   1. re-resolve the protected set from LIVE MOUNTS and refuse if
	//      devicePath (or any device beneath it) is in it, and
	//   2. re-compute the fingerprint and refuse on any difference from the
	//      one passed in.
	//
	// Both are hard errors — an implementation that logs and proceeds is a bug,
	// and an empty fingerprint is a refusal rather than a wildcard. Neither is
	// conditioned on the purpose, and neither ever may be: (1) in particular is
	// protect.go's guarantee, which §6.5 restates as unconditional across every
	// purpose.
	//
	// The purpose itself is resolved by claimSpec, which decides the GPT name,
	// the filesystem label and the marker file, and which refuses an
	// unrecognised purpose outright rather than defaulting it to backup.
	//
	// The returned ack carries the partition UUID minted at format time, which
	// is the target's identifier everywhere downstream. The device path is not.
	//
	// It takes the whole command rather than the four strings it used to,
	// because the marker it writes is the disk's own record of itself and the
	// api is the only thing that knows what belongs in it: the cluster id, the
	// §4.6 key id, and the two WRAPPED key blobs. Those used to be stamped onto
	// the ACK after the fact, which decorated the reply and left the platter
	// carrying none of them — see markerFrom.
	Claim(ctx context.Context, cmd proto.StorageClaimCmd) (*proto.StorageClaimAck, error)

	// Mount mounts an already-claimed target addressed by the partition UUID
	// minted at claim time, and returns where it landed. Mounting an
	// already-mounted target is a no-op returning the existing path.
	//
	// This is the shared mount primitive #302's data-disk contract consumes.
	// It stays addressed by partition UUID alone: the mount ROOT and OPTIONS
	// come from the target's purpose (§6.5, proto's spec table), which the
	// implementation resolves from the filesystem label it observes rather
	// than from an argument no wire type carries.
	Mount(ctx context.Context, partUUID string) (mountPath string, err error)

	// MountClaimedData mounts every claimed §6 data disk attached to this
	// node. The agent calls it at STARTUP, because §6.5 makes the agent the
	// thing that mounts the data disk — the rootfs is read-only squashfs, so
	// no mount unit can be written, and a systemd generator would mean an OS
	// change this contract deliberately keeps out.
	//
	// It makes NO api round-trip: the marker on the disk is the record and the
	// DB row is a cache, so the disks are found by enumerating this node's own
	// hardware. A node whose controlplane is unreachable still mounts its own
	// disks.
	//
	// That enumeration is for the DATA purpose ONLY, and an implementation
	// must keep it that way. Reading a marker means mounting the partition,
	// so an unnarrowed sweep would mount §4's backup target at every boot —
	// a controlplane path that shipped without it.
	//
	// NOTHING it reports is fatal, and a caller must not make it so. §6.3: a
	// data disk that is absent, unreadable, unclaimed or protected is logged
	// and skipped — a missing data disk must never make a node unbootable.
	// The error return means only that enumeration itself failed, i.e. the
	// sweep could not look; per-disk outcomes ride in the DataMounts.
	MountClaimedData(ctx context.Context) ([]DataMount, error)

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

	// ErrBadPurpose means the claim named a purpose this build does not
	// implement, or carried fields that purpose may not carry. Both are the
	// same kind of thing — a command whose contents this agent will not act on
	// — and neither is a backend failure, which is why they do not fall through
	// to StorageRefusalBackendError.
	ErrBadPurpose = errors.New("storage: claim purpose refused")
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
	case errors.Is(err, ErrBadPurpose):
		return proto.StorageRefusalBadPurpose
	case errors.Is(err, ErrInsufficientSpace):
		return proto.BackupRefusalInsufficientSpace
	case errors.Is(err, ErrStagingMissing):
		return proto.BackupRefusalStagingMissing
	case errors.Is(err, ErrDigestMismatch):
		return proto.BackupRefusalDigestMismatch
	default:
		return proto.StorageRefusalBackendError
	}
}

// claimSpec resolves what a claim is FOR and refuses a command whose purpose
// and contents disagree. Both backends call it, and both call it before they
// touch a disk — a purpose refusal that arrives after mkfs is not a refusal.
//
// Two things are decided here:
//
//  1. WHICH PURPOSE. proto.StoragePurposeSpecFor fails closed, so a value this
//     build does not recognise is refused by name rather than falling back to
//     backup. The one value that is not refused is the empty string, resolved
//     by EffectivePurpose to backup before the table sees it — the
//     wire-compatibility default for an api that predates §6, documented on
//     proto.StorageClaimCmd.Purpose and nowhere generalised.
//
//  2. WHETHER THE §4.6 CUSTODY FIELDS MAY RIDE. KeyID, KeyAlg, PublicKey and
//     the two wrappings exist to make a BACKUP disk adoptable by a replacement
//     controlplane that has never seen it. A data disk holds no archive, so
//     they would mean nothing in its marker — and writing them there would put
//     §4.6 material on a disk no unlock path ever reads, which is the sort of
//     thing that is discovered years later by someone holding the disk. The api
//     should never send that combination; if it does, this is where it stops,
//     not the platter.
func claimSpec(cmd proto.StorageClaimCmd) (proto.StoragePurposeSpec, error) {
	spec, err := proto.StoragePurposeSpecFor(cmd.EffectivePurpose())
	if err != nil {
		return proto.StoragePurposeSpec{}, fmt.Errorf("%w: %v", ErrBadPurpose, err)
	}
	if spec.Purpose == proto.StoragePurposeBackup {
		return spec, nil
	}
	var carried []string
	for _, f := range []struct {
		name  string
		value string
	}{
		{"keyId", cmd.KeyID},
		{"keyAlg", cmd.KeyAlg},
		{"publicKey", cmd.PublicKey},
		{"wrappedByPassphrase", cmd.WrappedByPassphrase},
		{"wrappedByRecoveryCode", cmd.WrappedByRecoveryCode},
	} {
		if strings.TrimSpace(f.value) != "" {
			carried = append(carried, f.name)
		}
	}
	if len(carried) > 0 {
		return proto.StoragePurposeSpec{}, fmt.Errorf(
			"%w: a %q claim carries §4.6 backup-key custody (%s) — those belong to a backup target and nowhere else",
			ErrBadPurpose, spec.Purpose, strings.Join(carried, ", "))
	}
	return spec, nil
}

// markerFrom builds the StorageBackupSet a Claim writes onto the platter.
//
// One constructor, shared by both backends, because until 2026-09-01 there was
// none and the two halves disagreed: the backends wrote a marker holding
// MarkerVersion, PartUUID, Label and CreatedAt, and the NATS handler then set
// ClusterID and KeyID on the ACK — the reply, not the file. Every disk this
// product has ever claimed therefore carries a marker that does not say which
// cluster wrote it or which §4.6 key its generations need, which are the two
// things §4.8 and §4.6 respectively say the marker exists to carry.
//
// ⚠️ Everything here is an identifier, a PUBLIC key, or ciphertext. §4.6's
// private key has no field on StorageClaimCmd, none on StorageBackupSet, and no
// way to arrive. The public key is written in clear on purpose: it is what lets
// a replacement controlplane keep writing to this disk, and it opens nothing.
func markerFrom(cmd proto.StorageClaimCmd, partUUID string, now time.Time) *proto.StorageBackupSet {
	return &proto.StorageBackupSet{
		MarkerVersion:         proto.StorageMarkerVersion,
		ClusterID:             cmd.ClusterID,
		PartUUID:              partUUID,
		KeyID:                 cmd.KeyID,
		KeyAlg:                cmd.KeyAlg,
		PublicKey:             cmd.PublicKey,
		WrappedByPassphrase:   cmd.WrappedByPassphrase,
		WrappedByRecoveryCode: cmd.WrappedByRecoveryCode,
		Label:                 cmd.Label,
		CreatedAt:             now,
	}
}

// dataMarkerFrom builds the StorageDataSet a §6 data claim writes onto the
// platter. markerFrom's opposite number, and shared by both backends for the
// same reason: one constructor is what stops the mock and production from
// writing different files.
//
// It takes the same command and copies four fields out of it. Everything it
// leaves behind is §4.6 backup-key custody, which claimSpec has already refused
// on this path — so the omission here is belt to that brace, not the guard
// itself. A data disk that carried key blobs would be carrying them for nobody.
func dataMarkerFrom(cmd proto.StorageClaimCmd, partUUID string, now time.Time) *proto.StorageDataSet {
	return &proto.StorageDataSet{
		MarkerVersion: proto.StorageDataMarkerVersion,
		ClusterID:     cmd.ClusterID,
		PartUUID:      partUUID,
		Label:         cmd.Label,
		CreatedAt:     now,
	}
}

// protectedError wraps ErrProtected with the reason, so the refusal the
// operator reads names the mount that caused it rather than a generic sentence.
func protectedError(devicePath, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrProtected, devicePath, reason)
}
