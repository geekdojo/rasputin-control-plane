package storage

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// §6's data disk: verifying that a path really IS the mounted data disk, and
// mounting the claimed ones at agent startup.
//
// Both halves answer the same question from the same evidence — the marker
// file on the filesystem — because §6.3 makes that file the only thing standing
// between a failed mount and an app quietly refilling the boot medium.

// ErrDataMarkerMissing means the path carries no §6 data marker.
//
// It is a REFUSAL and never a prompt to create one. A missing marker has two
// readings and both end the same way: the filesystem did not mount (so this is
// an empty directory on the boot medium wearing the mount point's name), or it
// mounted and is not the disk we think it is. Writing the marker would convert
// the first case — the dangerous one — into a permanent lie, because every
// later check would then find the marker it just wrote sitting on the boot
// medium.
var ErrDataMarkerMissing = errors.New("storage: no Rasputin data-set marker at this path")

// ErrDataMarkerMismatch means a marker is there and describes a different
// disk: another partition UUID, or a version this build does not accept.
var ErrDataMarkerMismatch = errors.New("storage: the data-set marker describes a different disk")

// VerifyDataMarker is §6.3's check, and the whole of it.
//
// It reports the marker at mountPath when — and only when — that path carries
// a readable §6 data marker naming partUUID. Anything else is an error, and
// the caller's only correct response to an error is to refuse to place app
// data there.
//
// ⚠️ THE TEST IS THE MARKER, NEVER "the directory is non-empty".
//
// §6.3 says so in as many words, and the reason is the exact failure being
// caught: /var/lib/rasputin/data/<uuid> is a real directory on the persistent
// partition whether or not the disk mounted over it, and if a previous deploy
// already wrote app data into it while unmounted, it is NOT empty. A
// non-emptiness test passes hardest precisely when the boot medium is being
// refilled. The marker is written once, by Claim, onto the claimed filesystem —
// so it is present exactly when that filesystem is the thing at this path.
//
// partUUID may be empty, which asks only "is a Rasputin data disk mounted
// here?" — the startup sweep knows which UUID it mounted and passes it; a
// caller that has only a path does not.
func VerifyDataMarker(mountPath, partUUID string) (*proto.StorageDataSet, error) {
	set, err := readDataMarker(mountPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s carries no %s, so it is either an unmounted mount point on the boot medium or not the disk it claims to be — refusing to place data on it",
				ErrDataMarkerMissing, mountPath, proto.StorageDataMarkerFile)
		}
		// Present and unreadable is its own answer and is not softened into
		// "absent": a truncated or corrupt marker is a disk to look at, not
		// one to write to.
		return nil, fmt.Errorf("%s at %s could not be read: %w", proto.StorageDataMarkerFile, mountPath, err)
	}
	if set.MarkerVersion < 1 {
		// Version 0 is what an empty or half-written JSON object unmarshals
		// to. A HIGHER version is accepted deliberately: a newer agent may
		// add fields (§6.4's placement work will), the fields read here are
		// frozen, and refusing would wedge every app on the disk after a
		// downgrade — which is the failure §6.3 is trying to avoid, not cause.
		return nil, fmt.Errorf("%w: the marker at %s carries no version", ErrDataMarkerMismatch, mountPath)
	}
	if partUUID != "" && set.PartUUID != "" && set.PartUUID != partUUID {
		return nil, fmt.Errorf("%w: %s names partition %s, but %s was expected — a copied marker or a cloned disk",
			ErrDataMarkerMismatch, mountPath, set.PartUUID, partUUID)
	}
	return set, nil
}

// DataMount is one claimed data disk the startup sweep looked at.
//
// Err non-nil means it was SKIPPED and why. Nothing here is fatal by
// construction: §6.3's first bullet is that a missing data disk must never make
// a node unbootable, and under §6.5 the agent is what mounts the disk, so an
// agent that refused to start over one would be the whole hazard rebuilt by
// hand.
type DataMount struct {
	PartUUID   string
	DevicePath string
	// MountPath is where it landed, empty when it was skipped.
	MountPath string
	// AlreadyMounted is true when the disk was mounted before the sweep ran —
	// an agent restart, not a boot.
	AlreadyMounted bool
	Err            error
}

// LogDataMounts writes one line per disk the sweep looked at, and is what the
// caller uses instead of failing.
//
// Every skip is a WARNING with the reason in it: the operator's data disk not
// being mounted is a condition §6.3 wants loud in three places, and until the
// alert path carries it (it needs the api round-trip this sweep deliberately
// does not make) the node's log is the one place it can be said at all.
func LogDataMounts(mounts []DataMount) {
	for _, m := range mounts {
		switch {
		case m.Err != nil:
			log.Printf("rasputin-agent: storage: data disk %s SKIPPED — apps placed on it will not find their data: %v",
				firstNonEmpty(m.PartUUID, m.DevicePath), m.Err)
		case m.AlreadyMounted:
			log.Printf("rasputin-agent: storage: data disk %s already mounted at %s", m.PartUUID, m.MountPath)
		default:
			log.Printf("rasputin-agent: storage: mounted data disk %s (%s) at %s", m.PartUUID, m.DevicePath, m.MountPath)
		}
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "(unidentified disk)"
}

// dataOnlyScan is what the startup sweep asks an enumeration for, in BOTH
// backends: the data purpose and nothing else.
//
// Spelled once, here, next to the sweep that is its only caller. Enumeration's
// marker read is a read-only mount, so this value is the difference between an
// agent that touches the data disk at boot and one that touches every claimed
// disk on the machine.
var dataOnlyScan = markerScan{proto.StoragePurposeData}

// dataDiskCandidates picks the claimed data disks out of an enumerate ack —
// the ONE discovery path, shared by both backends.
//
// It reuses enumeration rather than scanning for itself, which is the point:
// enumeration already finds Rasputin's own partitions by filesystem label,
// already reads the marker off each one to confirm it, and already resolves
// the protected set from live mounts. A second scanner would be a second
// answer to "which disks are ours", and the two would drift.
//
// Everything it refuses to return, it returns as a skip with a reason, so the
// caller can log a disk that is present-but-unusable rather than silently
// omitting it.
func dataDiskCandidates(ack *proto.StorageEnumerateAck) (claimed []proto.StorageCandidate, skipped []DataMount) {
	if ack == nil {
		return nil, nil
	}
	for _, c := range ack.Candidates {
		if !c.HasDataSet || c.DataSet == nil {
			// No data marker. Usually that just means it is not a data disk —
			// a backup target, an OS disk, a stranger's — and there is
			// nothing to say about it.
			//
			// Unless it carries our LABEL. Enumeration recognises a data disk
			// by mounting it read-only and reading the marker, so a
			// RASPUTIN-DATA partition that yields none did not merely fail a
			// check: its filesystem would not mount, or mounted and was
			// empty. That is a disk the operator needs told about, and it is
			// invisible otherwise. The label is a hint and is used as one —
			// nothing is mounted or written on the strength of it.
			if part, labelled := dataLabelledPartition(c); labelled {
				skipped = append(skipped, DataMount{
					PartUUID:   part.PartUUID,
					DevicePath: c.DevicePath,
					Err: fmt.Errorf("%w: %s carries the %s label but no readable %s — the filesystem did not mount, or mounted with no marker on it",
						ErrDataMarkerMissing, part.DevicePath, proto.StorageDataLabel, proto.StorageDataMarkerFile),
				})
			}
			continue
		}
		if c.Protected {
			// Unreachable unless something is badly wrong, and refused here
			// anyway: protect.go's exclusion is unconditional across every
			// purpose (§6.5), and a "data disk" that resolves onto the boot
			// medium is the one case where mounting it does harm.
			skipped = append(skipped, DataMount{
				PartUUID:   c.DataSet.PartUUID,
				DevicePath: c.DevicePath,
				Err:        protectedError(c.DevicePath, c.ProtectedReason),
			})
			continue
		}
		if strings.TrimSpace(c.DataSet.PartUUID) == "" {
			skipped = append(skipped, DataMount{
				DevicePath: c.DevicePath,
				Err:        fmt.Errorf("%w: the marker on %s names no partition UUID, which is the only identifier a claimed disk has", ErrDataMarkerMismatch, c.DevicePath),
			})
			continue
		}
		if !dataPartitionPresent(c) {
			// The marker names a partition that is not on this disk. A
			// cloned disk, or a marker copied by hand. Mounting by the UUID
			// the marker asserts would then mount somebody else's partition.
			skipped = append(skipped, DataMount{
				PartUUID:   c.DataSet.PartUUID,
				DevicePath: c.DevicePath,
				Err: fmt.Errorf("%w: %s carries a marker for partition %s, which is not one of its partitions",
					ErrDataMarkerMismatch, c.DevicePath, c.DataSet.PartUUID),
			})
			continue
		}
		claimed = append(claimed, c)
	}
	return claimed, skipped
}

// dataLabelledPartition finds a partition carrying the data filesystem label,
// whatever its marker says. A hint used for diagnostics only — see the call
// site.
func dataLabelledPartition(c proto.StorageCandidate) (proto.StoragePartition, bool) {
	for _, p := range c.Partitions {
		purpose, ok := proto.StoragePurposeForFSLabel(strings.TrimSpace(p.Label))
		if ok && purpose == proto.StoragePurposeData {
			return p, true
		}
	}
	return proto.StoragePartition{}, false
}

// dataPartitionPresent reports whether the partition the marker names is
// actually one of this disk's partitions, and carries the data label.
func dataPartitionPresent(c proto.StorageCandidate) bool {
	for _, p := range c.Partitions {
		if strings.TrimSpace(p.PartUUID) != strings.TrimSpace(c.DataSet.PartUUID) {
			continue
		}
		purpose, ok := proto.StoragePurposeForFSLabel(strings.TrimSpace(p.Label))
		return ok && purpose == proto.StoragePurposeData
	}
	return false
}

// MountClaimedData mounts every claimed data disk attached to this node, and is
// what the agent calls at startup (§6.5: the agent mounts the data disk itself,
// because the rootfs is read-only squashfs and nothing can write a mount unit).
//
// NO api round-trip. The marker on the platter is the record and the DB row is
// a cache — this package's position since §4.8 — so the disks are found by
// enumerating, which recognises them by their filesystem label and confirms
// each by reading its marker. A node whose controlplane is unreachable still
// mounts its own data disks, which matters because the alternative is apps
// deploying onto an unmounted mount point the moment the network is slow.
//
// ⚠️ It enumerates for the DATA purpose ONLY, and that is a correctness
// requirement rather than a saving. Reading a marker means mounting the
// partition read-only and unmounting it, so an unnarrowed enumeration would
// make every Rasputin-labelled filesystem on the machine live for a moment —
// on a controlplane that is §4's backup target, usually a removable disk
// holding the only copy of the archives. Nothing mounted that disk at boot
// before §6 and nothing asked for it to start. The sweep needs data disks, so
// it asks for data disks.
//
// The error return is "could not even look" (enumeration failed). Both it and
// every per-disk Err are for LOGGING: §6.3's first bullet is that a missing
// data disk must never make a node unbootable, so no failure in here is fatal
// and the caller must not make it one.
func (b *BlockDevBackend) MountClaimedData(ctx context.Context) ([]DataMount, error) {
	ack, err := b.enumerate(ctx, dataOnlyScan)
	if err != nil {
		return nil, fmt.Errorf("enumerate disks to find claimed data disks: %w", err)
	}
	claimed, out := dataDiskCandidates(ack)
	for _, c := range claimed {
		out = append(out, b.mountClaimedDataDisk(ctx, c))
	}
	return out, nil
}

// mountClaimedDataDisk mounts one already-identified data disk and verifies
// what landed. Every failure is returned in the DataMount, never panicked or
// propagated as fatal.
func (b *BlockDevBackend) mountClaimedDataDisk(ctx context.Context, c proto.StorageCandidate) DataMount {
	m := DataMount{PartUUID: c.DataSet.PartUUID, DevicePath: c.DevicePath}
	for _, p := range c.Partitions {
		if strings.TrimSpace(p.PartUUID) == m.PartUUID && strings.TrimSpace(p.Mountpoint) != "" {
			m.MountPath, m.AlreadyMounted = strings.TrimSpace(p.Mountpoint), true
		}
	}
	if !m.AlreadyMounted {
		// Mount goes through the same primitive every other caller uses, so
		// the root and options are the purpose's and a protected disk is
		// refused inside findByPartUUID rather than here.
		path, err := b.Mount(ctx, m.PartUUID)
		if err != nil {
			m.Err = err
			return m
		}
		m.MountPath = path
	}
	// §6.3, applied to the sweep's own work: having mounted it, prove the
	// thing at that path is the disk. A mount(8) that reported success and
	// left the mount point empty is exactly the case a bare error check
	// cannot see.
	if _, err := VerifyDataMarker(m.MountPath, m.PartUUID); err != nil {
		m.Err = err
		return m
	}
	return m
}

// DataMountPath is where a claimed data disk with this partition UUID belongs,
// derived from the purpose spec rather than assembled by the caller. Callers
// that need to name the path without mounting anything (a deploy-path check,
// a log line) use this so there is one spelling of <root>/<partUUID>.
func DataMountPath(partUUID string) (string, error) {
	spec, err := proto.StoragePurposeSpecFor(proto.StoragePurposeData)
	if err != nil {
		return "", err
	}
	if err := checkPartUUID(partUUID); err != nil {
		return "", err
	}
	return filepath.Join(spec.MountRoot, partUUID), nil
}
