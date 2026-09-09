// Package storage implements the agent side of disk claiming — enumerate
// candidate disks, claim one, format it, mount it.
//
// A claim carries a PURPOSE (proto.StoragePurpose): §4.8's backup target or
// §6's Node X data disk. The purpose decides five constants, all of them in
// proto's spec table and nowhere else — the GPT partition name, the filesystem
// label, the marker file, and (§6.5) the mount root and mount options. It
// decides nothing beyond those: every refusal below runs identically whatever
// the purpose is, and §6.5 says protect.go's exclusion in particular must stay
// unconditional across all of them.
//
// The two mounts differ because the disks do. A backup target lands
// job-scoped on tmpfs with noexec — its contents are an archive. A data disk
// lands on the persistent partition WITHOUT noexec, because it hosts live app
// volumes that can legitimately hold executables and it has to survive a
// reboot.
//
// # The data disk is mounted by the agent, at startup
//
// §6.5: the rootfs is read-only squashfs, so nothing can write a mount unit,
// and a generator would mean an `os` change this contract keeps out. So
// MountClaimedData sweeps at startup — no api round-trip, because the marker
// on the platter is the record and the DB row is a cache — and NOTHING it
// finds is fatal. §6.3's first bullet is that a missing data disk must never
// make a node unbootable, and under §6.5 the agent is the thing that mounts
// it, so an agent that refused to start over one would be the hazard itself.
//
// VerifyDataMarker is the other half, and §6.3 makes it the whole of the
// enforcement: the test is the MARKER, never "the mount point is non-empty",
// because an unmounted mount point a previous deploy already filled is exactly
// the failure being caught and it is not empty. Marker absent means refuse,
// never create.
//
// Two backends:
//
//   - BlockDevBackend shells out to util-linux (lsblk / blkid / wipefs /
//     sfdisk / mkfs.ext4 / mount) for real enumeration and formatting. Only
//     available where those tools are on PATH.
//
//   - MockBackend simulates a machine's disks with file-backed state under
//     <stateDir>/storage/. Used in dev and CI, and it is where the safety
//     rules are actually tested — see the warning below.
//
// Backend is selected at startup via RASPUTIN_STORAGE_BACKEND (blockdev|mock).
// blockdev is autodetected from the tooling on PATH; MOCK IS NEVER
// AUTODETECTED. When a required tool is missing the subsystem is disabled and
// the tool named — on 2026-09-01 a `wipefs` missing from an OS image made a
// real controlplane offer three fixture disks for a destructive format, with
// ok:true and nothing marking the answer as fiction. Read the next section for
// why this mock in particular is too convincing to ever infer.
//
// # Why the mock carries the weight
//
// The failure this package exists to prevent is "pick the wrong disk and
// force-format it", and on a two-NVMe controlplane that means destroying the
// cluster the backup was for. It cannot be exercised on hardware, so the mock
// is not a stub that returns canned answers — it models disks, partitions and
// LIVE MOUNTS, and derives Protected from the mounts exactly as the real
// backend derives it from /proc/self/mountinfo. Enumeration order is a
// permutation the tests can flip, so "protection followed the mount and not the
// name" is a thing a test can prove rather than a thing a comment can claim.
//
// # The two guards
//
// Both live in Claim, both run immediately before anything is written, and both
// are hard errors:
//
//  1. The protected set is RE-RESOLVED from live mounts. Not read from the
//     enumerate the operator saw — that snapshot is as old as the operator's
//     hesitation.
//
//  2. The fingerprint is RE-COMPUTED and compared with the one the command
//     carries. It hashes stable identity (WWN/serial + size) together with the
//     current partition table, so it catches both "this path now names a
//     different disk" and "this disk changed underneath us".
//
// The fingerprint necessarily changes once the format succeeds, because the
// partition table it hashes is the thing that was just replaced. That is the
// design: a Claim replayed with the fingerprint the operator confirmed fails
// closed on its own, with no dedup state anywhere — which matters because
// api/internal/jobs publishes over core NATS and has neither dedup nor
// compensation.
//
// See projects/rasputin/design/storage.md §4.8 and §6 in the geekdojo-brain.
package storage
