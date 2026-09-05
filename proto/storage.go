package proto

import "time"

// Backup-target selection — the wire contract for design/storage.md §4.8.
//
// The operator picks a local disk in the UI and Rasputin FORMATS it. That makes
// this the only agent verb in the system that can destroy the cluster it is
// running on, so the types below are shaped around one question: how does the
// api name a disk to the agent in a way that cannot silently mean a DIFFERENT
// disk by the time the format runs?
//
// Not by device path. `nvme0n1`/`nvme1n1` enumeration order is not stable across
// boots, and a two-NVMe controlplane (the Geekworm x1004 the BitScope
// controlplane sits in, the LattePanda) offers no transport, bus, or size
// difference to discriminate on. A device path is a handle for one moment, not
// an identity.
//
// So every destructive verb carries a StorageCandidate.Fingerprint — a hash over
// WWN/serial + size + the current partition table — and the agent recomputes it
// against live hardware immediately before it writes anything. That closes the
// TOCTOU window between the operator confirming and mkfs running, and it doubles
// as the repeat guard: the partition-table half of the hash changes as a SIDE
// EFFECT of the format, so a Claim replayed with the fingerprint the operator
// confirmed fails closed on its own without any dedup state anywhere.
//
// The second guard is Protected. The device holding the currently-mounted boot
// and persistent partitions is resolved by walking BACK from the live mounts to
// their parent block device, never by matching a name, and it is re-resolved
// inside Claim rather than trusted from the enumerate the operator saw.

// StorageTransport is how a candidate disk is attached. Reported for the
// operator's benefit — it is what makes "the 2 TB USB one" recognisable in a
// picker — and for nothing else. It is NOT a safety signal: §4.8's whole point
// is that an internal NVMe is as legitimate a backup target as a USB disk, and
// the boot medium can be either.
type StorageTransport string

const (
	StorageTransportUSB     StorageTransport = "usb"
	StorageTransportNVMe    StorageTransport = "nvme"
	StorageTransportSATA    StorageTransport = "sata"
	StorageTransportMMC     StorageTransport = "mmc"
	StorageTransportVirtual StorageTransport = "virtual"
	StorageTransportUnknown StorageTransport = "unknown"
)

// StorageBackupLabel is the filesystem label a claimed target carries. §4.8:
// it survives as a HUMAN-READABLE HINT, not as the identifier — two disks
// carrying the same label is merely ambiguous today and destructively ambiguous
// once Rasputin does the formatting. The identifier is the partition UUID.
const StorageBackupLabel = "RASPUTIN-BACKUP"

// StorageMarkerFile is the file at the root of a claimed target that makes the
// disk SELF-DESCRIBING. It is what lets a formatted-but-unrecorded disk be found
// and adopted after a failed persist, and what lets a first-run flow on a
// replacement controlplane tell "blank disk" from "the only copy of the archive
// being restored" (§4.8, #291). The DB row is a cache; this file is the record.
const StorageMarkerFile = ".rasputin-backup-set.json"

// StorageMarkerVersion is the schema version written into StorageBackupSet.
const StorageMarkerVersion = 1

// Agent-side work budgets for the storage verbs — how long the AGENT may spend
// before it answers. Same contract as the updater's pair in updates.go: the bus
// reply grant in busreply.go is DERIVED from these, so a budget added here must
// be added to AgentWorkBudgetMax or the agent silently loses the right to answer
// a call that ran long.
//
// Claim gets fifteen minutes because it is wipefs + sfdisk + mkfs + a udev
// settle on a disk that may be a spinning 8 TB archive drive, and because the
// alternative to waiting is an RPC timeout on a step that is HALFWAY THROUGH
// REPARTITIONING A DISK. Enumerate and Inspect are read-only and quick.
const (
	StorageEnumerateWork = 60 * time.Second
	StorageClaimWork     = 15 * time.Minute
	StorageMountWork     = 2 * time.Minute
	StorageInspectWork   = 60 * time.Second
)

// StorageRefusal is a machine-readable reason a storage verb declined. The api
// renders these; the UI branches on them (adopt-or-wipe is a different prompt
// than "that is the disk you are running on"). Detail carries the prose.
//
// Every value here is a REFUSAL, never a warning — §4.8 has no path where the
// agent proceeds with a caveat.
type StorageRefusal string

const (
	// StorageRefusalProtected — the target holds the currently-mounted boot or
	// persistent partitions. The one refusal the whole feature exists for.
	StorageRefusalProtected StorageRefusal = "protected"
	// StorageRefusalFingerprintMismatch — the disk under this path is not the
	// disk the operator confirmed, or its partition table changed underneath.
	// Also what a replayed Claim gets after a successful format.
	StorageRefusalFingerprintMismatch StorageRefusal = "fingerprint-mismatch"
	// StorageRefusalDeviceAbsent — no such device (unplugged between the
	// picker and the confirmation).
	StorageRefusalDeviceAbsent StorageRefusal = "device-absent"
	// StorageRefusalNotWholeDisk — the path names a partition or a virtual
	// device, not a whole disk. Claim partitions the whole disk.
	StorageRefusalNotWholeDisk StorageRefusal = "not-whole-disk"
	// StorageRefusalBackupSetPresent — the disk already carries a Rasputin
	// backup set. The api's check_existing step owns adopt-or-wipe; the agent
	// reports the set and never decides.
	StorageRefusalBackupSetPresent StorageRefusal = "backup-set-present"
	// StorageRefusalNotFound — no claimed target with that partition UUID is
	// attached (Mount / Inspect).
	StorageRefusalNotFound StorageRefusal = "not-found"
	// StorageRefusalBackendError — the backend or a shelled-out tool failed.
	StorageRefusalBackendError StorageRefusal = "backend-error"
)

// StorageBackupSet is the content of StorageMarkerFile: what a disk says about
// itself. Read during enumeration (the disk is mounted read-only to look) and
// written by Claim.
//
// ⚠️ Identifiers, a PUBLIC key, and ciphertext. §4.6's keypair is minted in this
// flow and the PRIVATE key's plaintext must never enter a marker file, a job
// ledger, or a log line. The public key is a different thing and travels in
// clear — see PublicKey below.
type StorageBackupSet struct {
	MarkerVersion int `json:"markerVersion"`
	// ClusterID is which cluster wrote this set. A disk carrying another
	// cluster's archive is exactly the disk a first-run flow must not wipe.
	ClusterID string `json:"clusterId,omitempty"`
	// PartUUID is the target's own key, written into the marker so a disk that
	// was formatted but never recorded can be re-adopted by its own account.
	PartUUID string `json:"partUuid,omitempty"`
	// KeyID identifies the §4.6 KEYPAIR the generations on this disk are
	// encrypted to — which changes on a re-format, not on a passphrase
	// change. It is what lets restore tell which key a generation needs
	// instead of guessing. Never key material.
	KeyID string `json:"keyId,omitempty"`
	// KeyAlg names the wrapping construction of the blobs below, so an
	// unwrap years from now reads what it is looking at instead of assuming
	// whatever the code does at that moment.
	KeyAlg string `json:"keyAlg,omitempty"`
	// PublicKey is §4.6's X25519 PUBLIC key, base64url of 32 raw bytes,
	// written onto the disk IN CLEAR.
	//
	// This is the 2026-09-02 amendment, and it is the field that lets the
	// controlplane store no secret at all. A weekly 3 a.m. backup.run (#290)
	// has nobody at a keyboard: under the old single symmetric key it would
	// have needed that key cached in the clear, which is the exact exposure
	// §4.6 exists to close. Sealing to a public key needs no secret and no
	// human. A stolen persistent partition now yields a public key; a stolen
	// backup disk yields nothing without a custody secret.
	//
	// Absent on every disk claimed before the amendment. That absence, next to
	// non-empty wrappings, is precisely how such a disk is recognised — see
	// api/internal/storage's adopt gate.
	PublicKey string `json:"publicKey,omitempty"`
	// WrappedByPassphrase and WrappedByRecoveryCode are §4.6's TWO SEALED
	// COPIES of the PRIVATE key, written onto the disk itself.
	//
	// ⚠️ Ciphertext, both of them, and the distinction from KeyID and PublicKey
	// above is not a nuance — it is the whole contract. Each blob is the
	// 32-byte X25519 private key under AES-256-GCM, its key-encryption key
	// derived in the operator's browser from a passphrase (Argon2id) or from
	// the recovery code (HKDF-SHA-256). Neither the passphrase, the recovery
	// code, nor the private key exists anywhere but that browser; what lands
	// here cannot be opened by this agent, by the api, or by anyone holding the
	// disk alone.
	//
	// # Why on the disk, and not only in the controlplane's database
	//
	// §4.6's constraint is that the key cannot live on the controlplane: a
	// backup exists to survive that machine's death, and anything under
	// /var/lib/rasputin is inside the archive it encrypts. §4.6 answers that by
	// putting both wrapped copies in the archive header — on the disk — and
	// these fields are that, at the level of the target as a whole rather than
	// per generation.
	//
	// The consequence is the one that matters: a REPLACEMENT controlplane with
	// an empty database can adopt this disk and be handed something the
	// operator can actually open, by typing the passphrase or the recovery
	// code. Without them, adoption records a target whose key is sealed and
	// whose custody nobody was ever asked for — which is a target that cannot
	// be written to, discovered on the day it was needed.
	//
	// This is the LUKS/BitLocker header model, deliberately: an attacker
	// holding the disk holds the ciphertext and the wrapped keys, and is left
	// with the Argon2id cost and 160 bits of recovery-code entropy. That is the
	// posture §4.6 chose, and it is what makes the disk self-sufficient.
	//
	// The marker version does NOT move with the 2026-09-02 amendment, and that
	// is deliberate. PublicKey is an additive field: a pre-amendment marker
	// still parses, and it has to, because parsing it is what lets the adopt
	// path say "this disk's key predates this build" instead of failing at
	// something lower down. What changed version is the KEY BLOB, which carries
	// its own — see ui/lib/archive-key.ts's BLOB_VERSION for why the refusal
	// has to live there and cannot be inferred from lengths.
	WrappedByPassphrase   string `json:"wrappedByPassphrase,omitempty"`
	WrappedByRecoveryCode string `json:"wrappedByRecoveryCode,omitempty"`
	// Label is the human-readable name the operator gave this target.
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	// Generations is how many retained archive generations the agent could see
	// (§4.4 keeps four). Advisory — it is what the adopt-or-wipe prompt shows
	// the operator so "wipe" is a decision and not a shrug.
	Generations int `json:"generations,omitempty"`
}

// StoragePartition is one partition found on a candidate disk. Reported so the
// destructive-confirmation dialog can show CURRENT CONTENTS — §4.8 requires the
// operator see model, size and contents before confirming, and "contents" is
// the difference between a blank disk and someone's photo archive.
type StoragePartition struct {
	DevicePath string `json:"devicePath"`
	PartUUID   string `json:"partUuid,omitempty"`
	FSType     string `json:"fsType,omitempty"`
	Label      string `json:"label,omitempty"`
	SizeBytes  uint64 `json:"sizeBytes"`
	// Mountpoint is non-empty when this partition is mounted RIGHT NOW. A
	// non-empty mountpoint on a candidate is a strong hint and is how Protected
	// is derived, but the derivation is the agent's, not the UI's.
	Mountpoint string `json:"mountpoint,omitempty"`
}

// StorageCandidate is one whole disk the operator could choose.
type StorageCandidate struct {
	// DevicePath is the kernel name AT THIS MOMENT (/dev/nvme1n1). It is a
	// handle for issuing the Claim, not an identity — see the package comment.
	// Nothing downstream may persist it as the way to find this disk again.
	DevicePath string `json:"devicePath"`

	Model     string           `json:"model,omitempty"`
	Serial    string           `json:"serial,omitempty"`
	WWN       string           `json:"wwn,omitempty"`
	SizeBytes uint64           `json:"sizeBytes"`
	Transport StorageTransport `json:"transport"`
	Removable bool             `json:"removable"`

	// Partitions is the disk's current partition table, in on-disk order.
	Partitions []StoragePartition `json:"partitions,omitempty"`

	// HasBackupSet is true when the disk already carries a Rasputin backup set
	// (§4.8's adopt-or-wipe gate). BackupSet carries the marker's contents when
	// it was readable.
	//
	// Restore-before-first-boot (#291) has the operator plug their archive disk
	// into a REPLACEMENT controlplane, so a flow that force-formats whatever it
	// is handed can destroy the only copy of the thing being restored. This
	// field is what makes that a decision rather than an accident.
	HasBackupSet bool              `json:"hasBackupSet"`
	BackupSet    *StorageBackupSet `json:"backupSet,omitempty"`

	// Protected marks the disk holding the currently-mounted boot and
	// persistent partitions. Resolved by walking back from the live mounts to
	// their parent block device — never by device name, and never by transport
	// or size (a two-NVMe controlplane has neither to discriminate on).
	//
	// A protected candidate is still ENUMERATED rather than hidden: the
	// operator who plugged in one disk and sees two should be told which one is
	// the boot medium and why, not shown a list with a silent hole in it.
	Protected bool `json:"protected"`
	// ProtectedReason names the mount that protects it, e.g.
	// "holds the mounted persistent partition (/var/lib/rasputin)". Operator-
	// facing prose; do not parse it.
	ProtectedReason string `json:"protectedReason,omitempty"`

	// Fingerprint is the hash the operator's confirmation is bound to: stable
	// identity (WWN/serial + size) plus a hash of the current partition table.
	// Passed back verbatim in StorageClaimCmd and re-derived by the agent
	// against live hardware before it writes.
	Fingerprint string `json:"fingerprint"`

	// IdentityWeak is true when the disk reported neither WWN nor serial, so
	// its fingerprint rests on model + size + partition table alone. Two
	// identical blank USB sticks from the same batch can then fingerprint the
	// same, which is precisely the collision the fingerprint exists to catch —
	// surfaced so the UI can say so rather than implying a guarantee the data
	// does not support. Cheap USB-SATA bridges are the usual cause.
	IdentityWeak bool `json:"identityWeak,omitempty"`
}

// StorageEnumerateCmd is sent on rasputin.node.<id>.cmd.storage.enumerate. It
// mutates nothing.
//
// Two callers, both wanted: the UI picker calls it read-only from an HTTP
// handler, and the claim saga calls it again as step 2 to re-verify what the
// operator confirmed.
type StorageEnumerateCmd struct{}

// StorageEnumerateAck lists every candidate disk, protected ones included.
type StorageEnumerateAck struct {
	OK         bool               `json:"ok"`
	Backend    string             `json:"backend"` // "blockdev" or "mock"
	Candidates []StorageCandidate `json:"candidates,omitempty"`
	// Ts is when the agent observed this. The fingerprints are only as fresh
	// as this timestamp — which is why Claim re-derives rather than trusting.
	Ts      time.Time      `json:"ts"`
	Refusal StorageRefusal `json:"refusal,omitempty"`
	Detail  string         `json:"detail,omitempty"`
}

// StorageClaimCmd formats a disk and claims it as the backup target. THIS IS
// THE DESTRUCTIVE VERB. Every refusal in §4.8 is answered before it is sent,
// and it is the last agent step in the saga precisely so nothing needs undoing
// (api/internal/jobs has no compensation).
type StorageClaimCmd struct {
	// DevicePath is the whole disk to format, as reported by the enumerate the
	// operator confirmed.
	DevicePath string `json:"devicePath"`
	// Fingerprint is that candidate's fingerprint. The agent recomputes it
	// against live hardware and REFUSES on any difference. Empty is not a
	// wildcard — it is a refusal.
	Fingerprint string `json:"fingerprint"`
	// Label is the operator's human-readable name for the target, written into
	// the marker file. The filesystem label is always StorageBackupLabel.
	Label string `json:"label,omitempty"`
	// ClusterID and KeyID are stamped into the marker so the disk can say which
	// cluster wrote it and which §4.6 keypair its generations need. KeyID is
	// an identifier; the private key never crosses this wire.
	ClusterID string `json:"clusterId,omitempty"`
	KeyID     string `json:"keyId,omitempty"`
	// KeyAlg, PublicKey, WrappedByPassphrase and WrappedByRecoveryCode are the
	// §4.6 key material to write into the marker — a public key and two
	// ciphertexts, exactly the strings the browser produced. See
	// StorageBackupSet for what they are and why they belong on the disk rather
	// than only in the api's database.
	//
	// There is no field here for the PRIVATE key, in this struct or any other
	// in this file, and adding one would put it in the one place §4.6 says it
	// must never be: on the appliance the backup exists to outlive.
	KeyAlg                string `json:"keyAlg,omitempty"`
	PublicKey             string `json:"publicKey,omitempty"`
	WrappedByPassphrase   string `json:"wrappedByPassphrase,omitempty"`
	WrappedByRecoveryCode string `json:"wrappedByRecoveryCode,omitempty"`
}

// StorageClaimAck reports the claim outcome.
type StorageClaimAck struct {
	OK         bool   `json:"ok"`
	DevicePath string `json:"devicePath,omitempty"`
	// PartUUID is minted at format time and is THE key for this target
	// everywhere downstream (§4.8). Persist this, never the device path.
	PartUUID  string `json:"partUuid,omitempty"`
	Label     string `json:"label,omitempty"`
	FSLabel   string `json:"fsLabel,omitempty"`
	FSType    string `json:"fsType,omitempty"`
	MountPath string `json:"mountPath,omitempty"`
	SizeBytes uint64 `json:"sizeBytes,omitempty"`
	// Fingerprint is the POST-format fingerprint, which necessarily differs
	// from the one in the command — the partition table it hashes is the thing
	// that was just replaced. That is deliberate, not drift: it is what makes a
	// replayed Claim fail closed. Recorded so a later verify has something to
	// compare against.
	Fingerprint string            `json:"fingerprint,omitempty"`
	BackupSet   *StorageBackupSet `json:"backupSet,omitempty"`
	Refusal     StorageRefusal    `json:"refusal,omitempty"`
	Detail      string            `json:"detail,omitempty"`
}

// StorageMountCmd mounts an already-claimed target, addressed by the partition
// UUID minted at claim time. Never by device path, and never by label — §4.8
// demoted the label to a hint for exactly this reason.
//
// This is the mount primitive §1's Node X data-disk contract is meant to share
// (#302); it is built to be consumable rather than backup-specific.
type StorageMountCmd struct {
	PartUUID string `json:"partUuid"`
}

// StorageMountAck reports where the target was mounted. Mounting an
// already-mounted target is a no-op that returns the existing path.
type StorageMountAck struct {
	OK        bool           `json:"ok"`
	PartUUID  string         `json:"partUuid,omitempty"`
	MountPath string         `json:"mountPath,omitempty"`
	Refusal   StorageRefusal `json:"refusal,omitempty"`
	Detail    string         `json:"detail,omitempty"`
}

// StorageInspectCmd reads a claimed target's marker and free space, mounting it
// if it is not already mounted. Read-only unless Probe is set.
type StorageInspectCmd struct {
	PartUUID string `json:"partUuid"`
	// Probe asks for a WRITE PROBE on top of the read-only inspect: create,
	// fsync, read back and delete a small file under StorageHealthProbeDir on
	// the mount. Opt-in, so the callers that exist for reading — adopt, the
	// restore surfaces — stay read-only, and only the health poll pays for it.
	//
	// It exists because presence is not health. The e3bench stick (2026-09-02)
	// answered enumeration for some time after it had begun failing writes: a
	// dying disk can be listed, mounted and statfs'd and still refuse the one
	// thing a backup target is for. An agent that predates this field ignores
	// it and answers without WriteProbe; the api reads that absence honestly
	// (StorageInspectProbeMinAgentVersion).
	Probe bool `json:"probe,omitempty"`
}

// StorageHealthProbeDir is the dot-directory at the root of a claimed target
// that the write probe works in. A dot-name because the archive walker
// (listGenerations, countGenerations) reads generations/ only and skips
// dot-entries everywhere, so nothing the probe leaves behind after a crash can
// ever be counted as, pruned as, or restored from as a generation.
const StorageHealthProbeDir = ".rasputin-health"

// StorageWriteProbe is what the write probe found. Present on a
// StorageInspectAck only when the command asked for one and the target was
// present and mounted; absent otherwise, and absent from any agent that
// predates the probe.
type StorageWriteProbe struct {
	// OK is true when a small file was created, fsynced, read back
	// byte-identical and deleted under StorageHealthProbeDir.
	OK bool `json:"ok"`
	// Detail names the failing operation and the error when OK is false, and
	// says what was done when it is true. Operator-facing prose.
	Detail string `json:"detail,omitempty"`
	// DurationMs is how long the probe took. Advisory: a probe that took
	// twenty seconds on a disk that used to take twenty milliseconds is a
	// disk on its way out, and this is the only number that would show it.
	DurationMs int64 `json:"durationMs"`
}

// StorageInspectAck describes a claimed target as it exists on the disk.
type StorageInspectAck struct {
	OK         bool              `json:"ok"`
	PartUUID   string            `json:"partUuid,omitempty"`
	DevicePath string            `json:"devicePath,omitempty"`
	MountPath  string            `json:"mountPath,omitempty"`
	FSType     string            `json:"fsType,omitempty"`
	FSLabel    string            `json:"fsLabel,omitempty"`
	TotalBytes uint64            `json:"totalBytes,omitempty"`
	FreeBytes  uint64            `json:"freeBytes,omitempty"`
	BackupSet  *StorageBackupSet `json:"backupSet,omitempty"`
	// Present is false when nothing with that partition UUID is attached — the
	// operator unplugged the target. Distinct from OK=false, which means the
	// agent could not answer. The two combine in one more way: OK=false with
	// Present=true is a disk that IS attached and could not be mounted, which
	// the health poll renders as UNMOUNTED rather than MISSING.
	Present bool           `json:"present"`
	Refusal StorageRefusal `json:"refusal,omitempty"`
	Detail  string         `json:"detail,omitempty"`
	// WriteProbe is the result of the write probe StorageInspectCmd.Probe asked
	// for. nil when none was asked for, when the target was not present or
	// mounted, or when the answering agent predates the probe.
	WriteProbe *StorageWriteProbe `json:"writeProbe,omitempty"`
}

// StorageEnumerateSubject is the read-only candidate enumeration.
func StorageEnumerateSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "storage.enumerate")
}

// StorageClaimSubject is the destructive format-and-claim verb.
func StorageClaimSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "storage.claim")
}

// StorageMountSubject mounts a claimed target by partition UUID.
func StorageMountSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "storage.mount")
}

// StorageInspectSubject reads a claimed target's marker and free space.
func StorageInspectSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "storage.inspect")
}
