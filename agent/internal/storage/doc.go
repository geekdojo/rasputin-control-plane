// Package storage implements the agent side of backup-target selection —
// enumerate candidate disks, claim one, format it, mount it.
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
// See projects/rasputin/design/storage.md §4.8 in the geekdojo-brain.
package storage
