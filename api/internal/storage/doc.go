// Package storage is the api half of backup-target selection — design/storage.md
// §4.8's "the operator picks a disk and Rasputin formats it".
//
// It owns three things:
//
//   - the backup_targets ledger, one row per claim attempt;
//   - the backup.target.claim saga, which is the ONLY path by which a disk is
//     formatted;
//   - the read-only candidate enumeration the picker calls before a job exists.
//
// # Why the step order is the design
//
// api/internal/jobs is a linear saga runner with NO COMPENSATION: a step's
// failure terminates the job and leaves every prior step exactly as it ran.
// There is no undo, and for a mkfs there could not be one. So the saga is
// ordered so that nothing ever needs undoing —
//
//	1 validate       (api)   spec sanity; an existing claimed target
//	2 enumerate      (agent) the disk is present, unprotected, and the one
//	                         the operator confirmed
//	3 check_existing (api)   adopt-or-wipe-or-refuse for a disk that already
//	                         carries a Rasputin backup set
//	4 claim          (agent) THE DESTRUCTIVE STEP. Irreversible, never retried,
//	                         and the last agent step
//	5 persist_target (api)   record partUUID, node, mount path
//
// Steps 1–3 are all refusals. By the time step 4 runs, every question that
// could be answered has been answered, and the only remaining failures are the
// ones the agent itself refuses on live hardware.
//
// # Adopt and wipe
//
// §4.8: "A disk that already carries a Rasputin backup set is adopted, not
// wiped — or wiped only on a second, separate choice." Both halves live at step
// 3. Adopt keeps the set and formats nothing; wipe destroys it and claims the
// disk fresh, and is reachable only by echoing back a token the api minted over
// the disk as the picker showed it (wipe.go). Neither is a default: a disk
// carrying a set with neither choice made is refused, untouched.
//
// Wipe adds NOTHING to the wire and nothing to the agent. It selects the same
// format the blank-disk path already runs — same proto.StorageClaimCmd, same
// subject, same Irreversible step — so the agent's boot-device exclusion and
// its fingerprint re-check apply to it unchanged and there is no flag by which
// either could be bypassed.
//
// # Identity
//
// Nothing here persists a device path as the way to find a disk again.
// `nvme0n1`/`nvme1n1` order is not stable across boots, so a device path is a
// handle for one moment. The identity of a claimed target is its PARTITION
// UUID, minted at format time; the identity of a candidate is its fingerprint
// (WWN/serial + size + a hash of the partition table). See proto/storage.go.
//
// # §4.6 key material
//
// The archive data key is minted when the target is configured, OUTSIDE this
// package, and reaches it already wrapped. The plaintext data key must never
// enter the job ledger, a step result, a log line, or an event payload —
// jobs.StepCtx.Log writes to the job_events table AND to the live NATS stream,
// so a log line is a broadcast. This package handles opaque wrapped blobs and
// a KeyID, which is an identifier and never key material.
package storage
