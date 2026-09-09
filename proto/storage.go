package proto

import (
	"fmt"
	"time"
)

// Disk claiming — the wire contract for design/storage.md §4.8 (the backup
// target) and §6 (the Node X data disk). Which of the two a claim is for is
// StorageClaimCmd.Purpose; everything else below is common to both, because
// what makes this dangerous is common to both.
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

// StoragePurpose says what a claimed disk is FOR.
//
// It exists because until §6 there was only one answer. `agent/internal/storage`
// could only ever format a disk as THE BACKUP TARGET: the GPT partition name,
// the filesystem label and the marker filename were literals inside the format
// path, and StorageClaimCmd carried §4.6 key custody unconditionally. §6's own
// correction to §1 and §4.8 says so in as many words — the claim/format half was
// not half of a reusable contract, it was hardcoded. This type is what makes it
// one (#302).
//
// It is a CLOSED enum, and StoragePurposeSpecFor fails closed on anything that
// is not one of the constants below. The single exception lives on the wire and
// nowhere else: an ABSENT purpose means backup, so an api that predates this
// field keeps working. See StorageClaimCmd.Purpose.
type StoragePurpose string

const (
	// StoragePurposeBackup is §4.8's backup target — the disk archive
	// generations are written to, and the only purpose that carries §4.6's
	// backup-key custody.
	StoragePurposeBackup StoragePurpose = "backup"
	// StoragePurposeData is §6's Node X data disk — the disk app volumes are
	// placed on. It holds no archive, so it holds no key material of any kind.
	StoragePurposeData StoragePurpose = "data"
)

// The GPT partition NAMES a claim writes, one per purpose. A GPT name is not
// the filesystem label and is not the identifier either — the identifier is the
// PARTUUID the kernel mints at format time.
//
// §6.2 keeps them distinct from each other and from `persistent` so that
// `lsblk` reads sensibly to a human. That is the whole job: nothing in this
// system resolves a disk by GPT name, and the reason is #307 — every Rasputin
// OS disk is flashed with the same partition names and the amd64 fstab already
// finds its persistent partition by PARTLABEL, so by-name lookups resolve
// ACROSS drives the moment two Rasputin disks share a machine. A data disk is a
// second disk by definition.
const (
	StorageBackupPartName = "rasputin-backup"
	StorageDataPartName   = "rasputin-data"
)

// StorageBackupLabel is the filesystem label a claimed target carries. §4.8:
// it survives as a HUMAN-READABLE HINT, not as the identifier — two disks
// carrying the same label is merely ambiguous today and destructively ambiguous
// once Rasputin does the formatting. The identifier is the partition UUID.
const StorageBackupLabel = "RASPUTIN-BACKUP"

// StorageDataLabel is StorageBackupLabel's opposite number for §6's data disk.
// Same hint-not-identifier rule, and distinct from both StorageBackupLabel and
// `persistent` for the reason given on StorageDataPartName.
const StorageDataLabel = "RASPUTIN-DATA"

// StorageMarkerFile is the file at the root of a claimed target that makes the
// disk SELF-DESCRIBING. It is what lets a formatted-but-unrecorded disk be found
// and adopted after a failed persist, and what lets a first-run flow on a
// replacement controlplane tell "blank disk" from "the only copy of the archive
// being restored" (§4.8, #291). The DB row is a cache; this file is the record.
const StorageMarkerFile = ".rasputin-backup-set.json"

// StorageDataMarkerFile is the same idea for a §6 data disk, and §6.3 leans on
// it harder than §4.8 leans on its own: the agent verifies this file on the
// MOUNTED filesystem before deploying onto it, because a data mount point that
// is merely an empty directory sends every app write to the boot medium and the
// operator concludes their data is gone. Marker absent means "this is not the
// disk you think it is" — refuse, never create.
const StorageDataMarkerFile = ".rasputin-data-set.json"

// StorageMarkerVersion is the schema version written into StorageBackupSet.
const StorageMarkerVersion = 1

// StorageDataMarkerVersion is the schema version written into StorageDataSet.
//
// A separate line from StorageMarkerVersion on purpose. StorageBackupSet is
// frozen — disks carrying it are in the field and a replacement controlplane
// has to parse them at first-run restore — while StorageDataSet has claimed no
// disk yet and will grow as §6.4's placement work lands. One shared counter
// would make each type's version move for the other type's reasons.
const StorageDataMarkerVersion = 1

// The mount ROOTS a claimed target lands under, one per purpose. The mount
// point itself is <root>/<partUUID> for both — the identifier, never the
// label or the device path.
//
// §6.5 is the whole reason there are two. /run is tmpfs, so a backup mount is
// job-scoped in exactly the way §4.1's "mounted for the duration of the job"
// wants and vanishes on reboot, which is correct for a disk whose contents are
// an archive read by a controlplane that has never seen it. A DATA disk is the
// opposite case on both counts: it hosts live app volumes and it has to survive
// a reboot, so its root is on the persistent partition beside everything else
// Rasputin keeps.
const (
	StorageBackupMountRoot = "/run/rasputin/storage"
	StorageDataMountRoot   = "/var/lib/rasputin/data"
)

// The mount OPTIONS, one per purpose, and the difference between them is
// deliberate rather than an oversight.
//
// A backup target gets noexec on top of nosuid,nodev: its contents are an
// archive written by a previous installation of this software, and nothing
// there is ever meant to be executed.
//
// A data disk deliberately does NOT get noexec. It holds app volumes, which
// can legitimately contain executables — an app shipping a helper script or a
// plugin directory is ordinary — and /var/lib/rasputin, where those same
// volumes live today, is mounted `defaults`. So noexec here would break apps
// to buy a property the partition they migrate FROM does not have. nosuid and
// nodev stay: a removable disk must not be able to introduce a setuid binary
// or a device node, and neither is something an app volume has any use for.
const (
	StorageBackupMountOptions = "noexec,nosuid,nodev"
	StorageDataMountOptions   = "nosuid,nodev"
)

// AllStoragePurposes is every purpose, in a stable order — the same service
// AllRoles does for NodeRole. It exists so a caller that has to do something
// once per purpose (seed a mount root, assert the table has no holes) iterates
// a list rather than re-spelling the constants and missing the next one added.
var AllStoragePurposes = []StoragePurpose{StoragePurposeBackup, StoragePurposeData}

// StoragePurposeSpec is everything about a claim that varies BY PURPOSE: the
// GPT partition name it writes, the filesystem label mkfs applies, the marker
// file it drops at the root of the new filesystem, and where and how that
// filesystem is mounted.
//
// One struct, one table, one lookup, because these constants have to agree
// across two backends and an api that never sees the disk. They used to be
// literals inside BlockDevBackend.Claim and MockBackend.Claim — which is how
// the mock and the real backend came to be the same decision written twice, and
// a second purpose added to one and not the other would leave CI green against
// a backend that no longer resembles production. The mount root and options
// joined them for §6.5, which is the same argument one step further out: the
// mount was the last per-purpose decision still spelled as a literal in the
// agent, and the one whose two answers differ most.
type StoragePurposeSpec struct {
	// Purpose is the purpose this spec describes, echoed back so a caller that
	// resolved it from an empty wire value can see what it actually got.
	Purpose StoragePurpose
	// PartName is the GPT partition name written into the new table.
	PartName string
	// FSLabel is the filesystem label mkfs applies. A hint, never an
	// identifier — see StorageBackupLabel.
	FSLabel string
	// MarkerFile is the dot-file written at the root of the claimed filesystem
	// that makes the disk self-describing.
	MarkerFile string
	// MountRoot is the directory claimed targets of this purpose are mounted
	// under; the mount point is MountRoot/<partUUID>. See the constants.
	MountRoot string
	// MountOptions is the -o list the mount is made with. A string rather than
	// a slice because that is exactly what mount(8) takes, and splitting it
	// would only invite a caller to reassemble it in a different order.
	MountOptions string
}

// storagePurposeSpecs is the table. Keyed by the wire value, so adding a
// purpose means adding a row here and the format path picks it up — there is
// nowhere else a per-purpose constant is allowed to be spelled.
var storagePurposeSpecs = map[StoragePurpose]StoragePurposeSpec{
	StoragePurposeBackup: {
		Purpose:      StoragePurposeBackup,
		PartName:     StorageBackupPartName,
		FSLabel:      StorageBackupLabel,
		MarkerFile:   StorageMarkerFile,
		MountRoot:    StorageBackupMountRoot,
		MountOptions: StorageBackupMountOptions,
	},
	StoragePurposeData: {
		Purpose:      StoragePurposeData,
		PartName:     StorageDataPartName,
		FSLabel:      StorageDataLabel,
		MarkerFile:   StorageDataMarkerFile,
		MountRoot:    StorageDataMountRoot,
		MountOptions: StorageDataMountOptions,
	},
}

// StoragePurposeSpecFor returns the per-purpose constants for p.
//
// It FAILS CLOSED, and that is the entire point of it being a function rather
// than a map read at the call site. The caller on the other end is the one
// agent verb in this system that can destroy the cluster it runs on, so a
// purpose this build does not recognise is an error and never a quiet fall back
// to backup — "format it as a backup target because we did not understand the
// request" is the sentence §4.8 exists to make unsayable.
//
// The empty string is unrecognised here TOO, deliberately. Its
// wire-compatibility meaning is applied by StorageClaimCmd.EffectivePurpose
// before it ever reaches this table, so the default stays attached to the wire
// type that needs it and cannot leak into every other caller — a zero-valued
// StoragePurpose anywhere else in the codebase is a bug, and this returns an
// error rather than backup constants when it meets one.
func StoragePurposeSpecFor(p StoragePurpose) (StoragePurposeSpec, error) {
	spec, ok := storagePurposeSpecs[p]
	if !ok {
		return StoragePurposeSpec{}, fmt.Errorf("unrecognised storage purpose %q (want %q or %q)",
			p, StoragePurposeBackup, StoragePurposeData)
	}
	return spec, nil
}

// StoragePurposeForFSLabel reverses the table: it names the purpose a partition
// announces by its filesystem label, or reports that the label is none of ours.
//
// This is a HINT, and the same hint §4.8 demoted the label to. It is what lets
// enumeration decide which partitions are worth mounting read-only to peek at —
// mounting every partition of every attached disk would be an enumeration with
// side effects — and which of the two markers to look for once it does. It is
// not identity and nothing destructive may key off it.
func StoragePurposeForFSLabel(label string) (StoragePurpose, bool) {
	for purpose, spec := range storagePurposeSpecs {
		if spec.FSLabel == label {
			return purpose, true
		}
	}
	return "", false
}

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
	// StorageRefusalBadPurpose — the claim named a StoragePurpose this agent
	// does not implement, or carried fields that purpose may not carry (§4.6
	// backup-key custody on a §6 data claim).
	//
	// Deliberately not StorageRefusalBackendError: nothing broke. The agent
	// understood the command perfectly and will not perform it, which is a
	// different sentence to show an operator and a different one to page on.
	// An older agent that predates §6 cannot send this — it does not know the
	// purpose field exists — so the api must gate on agent version rather than
	// read the absence of this code as consent.
	StorageRefusalBadPurpose StorageRefusal = "bad-purpose"
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

// StorageDataSet is the content of StorageDataMarkerFile: what a §6 data disk
// says about itself. Read during enumeration (the disk is mounted read-only to
// look) and written by Claim.
//
// It is a SEPARATE type from StorageBackupSet rather than a widening of it, and
// that is the decision worth reading twice.
//
// StorageBackupSet is FROZEN. It is what makes a backup disk self-describing so
// that a replacement controlplane can adopt it at first-run restore (§4.8,
// #291); disks carrying it are already in the field; and its parse path is what
// tells a symmetric-era disk from a post-amendment one by which fields are
// absent. Adding a purpose discriminator or data-disk fields to it would put
// every one of those disks behind a struct that has changed meaning, for the
// convenience of not writing four field names twice.
//
// The other half is what is NOT here. Every field on StorageBackupSet that is
// not an identifier is §4.6 backup-key custody, and a data disk holds no
// archive to encrypt: sharing the struct would give this marker four
// key-shaped fields whose only possible value is empty, sitting on a disk
// nothing expects to find key material on. StorageClaimCmd's custody fields are
// refused outright on a data claim for the same reason.
type StorageDataSet struct {
	MarkerVersion int `json:"markerVersion"`
	// ClusterID is which cluster wrote this set. A data disk carrying another
	// cluster's app volumes is exactly the disk that must not be silently
	// adopted, and §6.1 does not extend §4.8's adopt-not-wipe rule to it: the
	// operator confirms a destructive format or nothing happens.
	ClusterID string `json:"clusterId,omitempty"`
	// PartUUID is the disk's own key, written into the marker so a disk that
	// was formatted but never recorded can be re-adopted by its own account.
	PartUUID string `json:"partUuid,omitempty"`
	// Label is the human-readable name the operator gave this disk.
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
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

	// HasDataSet and DataSet are the same pair for §6's data disk, reported
	// ALONGSIDE the backup pair rather than merged with it. A data disk is not
	// a backup set and must not reach §4.8's adopt-or-wipe prompt, which offers
	// the operator a choice about an archive this disk does not hold; §6.1
	// declines to generalise adopt-not-wipe at all. Between them the two pairs
	// say which purpose, if any, the disk announces — see ClaimedPurpose.
	HasDataSet bool            `json:"hasDataSet,omitempty"`
	DataSet    *StorageDataSet `json:"dataSet,omitempty"`

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

// ClaimedPurpose names which purpose this disk announces itself claimed for,
// and reports false when it announces none.
//
// DERIVED from the two set pairs rather than carried as a third field, so there
// is no way for a candidate to say "backup" while holding a data set. A disk
// carrying both markers — which nothing this code path can produce, since a
// claim writes one filesystem with one marker on it — is reported as neither,
// because "it is one of the two, pick one" is not an answer worth handing a
// destructive-confirmation dialog.
func (c StorageCandidate) ClaimedPurpose() (StoragePurpose, bool) {
	switch {
	case c.HasBackupSet && !c.HasDataSet:
		return StoragePurposeBackup, true
	case c.HasDataSet && !c.HasBackupSet:
		return StoragePurposeData, true
	default:
		return "", false
	}
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

// StorageClaimCmd formats a disk and claims it — for §4.8's backup target or
// for §6's data disk, per Purpose. THIS IS THE DESTRUCTIVE VERB. Every refusal
// in §4.8 is answered before it is sent, and it is the last agent step in the
// saga precisely so nothing needs undoing (api/internal/jobs has no
// compensation).
type StorageClaimCmd struct {
	// DevicePath is the whole disk to format, as reported by the enumerate the
	// operator confirmed.
	DevicePath string `json:"devicePath"`
	// Fingerprint is that candidate's fingerprint. The agent recomputes it
	// against live hardware and REFUSES on any difference. Empty is not a
	// wildcard — it is a refusal.
	Fingerprint string `json:"fingerprint"`
	// Purpose is what the disk is being claimed FOR: the GPT name, filesystem
	// label and marker file all follow from it via StoragePurposeSpecFor.
	//
	// ABSENT MEANS BACKUP, and that is a WIRE-COMPATIBILITY default rather than
	// a general-purpose one. Every claim sent before this field existed carries
	// no purpose and means the backup target, so an api that predates §6 has to
	// keep working against an agent that does not. The codebase has this exact
	// precedent and this exact shape: backupxfer.Grant.Use is empty for the
	// upload credential that was the only kind when it was minted, with
	// Grant.ForUpload() reading that absence — see backupxfer/token.go.
	//
	// It is emphatically NOT "we could not tell, so backup". An unrecognised
	// NON-EMPTY purpose is a refusal (StorageRefusalBadPurpose), because the
	// value came from a caller that meant something this build cannot do, and
	// formatting a disk as the wrong thing is exactly the outcome §4.8 exists
	// to prevent. StoragePurposeSpecFor never sees the empty string:
	// EffectivePurpose resolves it first, and the table itself fails closed.
	Purpose StoragePurpose `json:"purpose,omitempty"`
	// Label is the operator's human-readable name for the target, written into
	// the marker file. The filesystem label is not the operator's to choose —
	// it comes from the purpose's spec.
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
	// They belong to StoragePurposeBackup and to nothing else. A data disk
	// holds no archive to encrypt, so a data claim carrying any of them is
	// REFUSED rather than having them dropped quietly: writing key blobs onto a
	// data disk would mean nothing there and would scatter §4.6 material onto a
	// disk no unlock path ever looks at, and a command whose purpose and
	// contents disagree is a caller bug the platter is the wrong place to
	// discover.
	//
	// There is no field here for the PRIVATE key, in this struct or any other
	// in this file, and adding one would put it in the one place §4.6 says it
	// must never be: on the appliance the backup exists to outlive.
	KeyAlg                string `json:"keyAlg,omitempty"`
	PublicKey             string `json:"publicKey,omitempty"`
	WrappedByPassphrase   string `json:"wrappedByPassphrase,omitempty"`
	WrappedByRecoveryCode string `json:"wrappedByRecoveryCode,omitempty"`
}

// EffectivePurpose resolves the purpose this command is asking for, applying
// the empty-means-backup rule documented on Purpose and nothing else.
//
// An unrecognised non-empty value is returned UNCHANGED so that
// StoragePurposeSpecFor refuses it by name and the operator is told which value
// was rejected. This method is the only place the empty-string default is
// allowed to live: every other caller goes through the table, which fails
// closed.
func (c StorageClaimCmd) EffectivePurpose() StoragePurpose {
	if c.Purpose == "" {
		return StoragePurposeBackup
	}
	return c.Purpose
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
	Fingerprint string `json:"fingerprint,omitempty"`
	// Purpose echoes the purpose the agent actually claimed the disk for —
	// RESOLVED, so a command that sent none comes back saying "backup" rather
	// than saying nothing. That is what lets the api record what happened
	// instead of re-deriving it from a default it also has to remember.
	Purpose StoragePurpose `json:"purpose,omitempty"`
	// BackupSet and DataSet are the marker that was written, and exactly one of
	// them is set: a claim formats one filesystem and drops one marker on it.
	BackupSet *StorageBackupSet `json:"backupSet,omitempty"`
	DataSet   *StorageDataSet   `json:"dataSet,omitempty"`
	Refusal   StorageRefusal    `json:"refusal,omitempty"`
	Detail    string            `json:"detail,omitempty"`
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
	// DataSet is the §6 data-disk marker, when the target carries one. Reported
	// alongside BackupSet rather than instead of it for the reason given on
	// StorageCandidate.HasDataSet, and it is what §6.3's
	// verify-the-marker-before-deploying check reads.
	DataSet *StorageDataSet `json:"dataSet,omitempty"`
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
