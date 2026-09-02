package proto

import (
	"fmt"
	"strings"
	"time"
)

// Backup runs — the wire contract for design/storage.md §4.1's `backup.run`
// producer, the job that actually writes an archive to the target §4.8 claimed.
//
// The split of labour is §4.1's, unchanged: THE CONTROL PLANE OWNS POLICY,
// SCHEDULING, RETENTION AND PLACEMENT; the agent moves bytes and owns the
// mount. So the api decides what goes in an archive, snapshots it, seals it and
// names the generation; the three verbs below are the only things the agent is
// asked to do, and each is a filesystem operation on a disk the api cannot
// reach.
//
// # Why the payload is a staging file name and not bytes
//
// A sealed identity archive is tens to hundreds of megabytes. NATS's default
// max payload is one, and raising it to carry a database would make every other
// subject on the bus pay for it. §4.7 already decided the shape for the
// per-node case — stage locally, then transfer — and the controlplane-local
// case this contract serves is the degenerate form of it: the api stages the
// sealed archive under its own staging root, and the co-located agent, which is
// the process that owns the mount, moves it onto the target.
//
// BackupWriteCmd therefore carries a STAGING NAME, never a path. The agent
// joins it onto its own configured staging root and refuses anything that is
// not a plain file name — see BackupValidStagingName. That is deliberate: a
// verb that took a path would be a general "copy any file on this node onto a
// removable disk" primitive, and this package does not hand one out.
//
// # What never crosses this wire
//
// §4.6's PRIVATE key, in any form. The api seals to the target's PUBLIC key
// with a fresh ephemeral key per run, so there is no private key on the
// controlplane to leak into a command, a ledger row, or a log line. What the
// agent receives is ciphertext, a digest over that ciphertext, and a manifest
// of plain prose.

// Agent-side work budgets for the backup verbs. Same contract as the storage
// verbs above them: the bus reply grant in busreply.go is DERIVED from these,
// so a budget added here must be added to AgentWorkBudgetMax or the agent
// silently loses the right to answer a call that ran long.
//
// Write gets fifteen minutes because it is a copy-and-fsync of a
// possibly-large archive onto a target that may be a USB 2.0 stick, and because
// the alternative to waiting is an RPC timeout on a step that is HALFWAY
// THROUGH WRITING A GENERATION. Preflight and prune are cheap: a statfs and a
// directory listing, plus, for prune, some unlinks.
const (
	BackupPreflightWork = 60 * time.Second
	BackupWriteWork     = 15 * time.Minute
	BackupPruneWork     = 2 * time.Minute
)

// BackupGenerationsDir is the directory, relative to the target's mount point,
// that holds the retained generations. One directory rather than files strewn
// at the root, so prune has an unambiguous set to converge and so the marker
// file (StorageMarkerFile) is never a candidate for deletion.
const BackupGenerationsDir = "generations"

// BackupArchiveFile and BackupManifestFile are the two files a generation is,
// inside its own directory under BackupGenerationsDir.
//
// A DIRECTORY per generation rather than two files sharing a stem, because the
// generation is the unit §4.4 retains and prune converges: a directory is
// deleted atomically enough that a half-pruned generation is not a state the
// disk can be left in, and it is what the already-shipped adopt-or-wipe prompt
// counts (agent countGenerations) to tell an operator how much a wipe destroys.
//
// The archive is sealed (§4.6) and unreadable without a custody secret. The
// manifest is CLEAR TEXT and deliberately so: an operator holding this disk
// must be able to read what a generation contains — and, more to the point,
// what it does NOT contain — without decrypting anything. It carries file
// names, sizes, digests and prose, and no key material beyond the key-id and
// public key the disk's own marker already publishes in clear.
const (
	BackupArchiveFile  = "archive.rasputin-archive"
	BackupManifestFile = "manifest.json"
)

// BackupRetainGenerations is §4.4's retention: four full generations on the
// target, oldest pruned first. At the default weekly cadence that is roughly a
// month of history.
const BackupRetainGenerations = 4

// BackupTargetReserveBytes is the free space the target must retain BEYOND the
// incoming archive for a preflight to pass.
//
// A guard rather than a bare `free >= size` comparison: filesystems get slow
// and then hostile at genuine zero, and a target wedged at 100% cannot be
// pruned either, which would turn one oversized run into a permanently stuck
// backup. §4.4 asks for a pre-flight free-space check that REFUSES rather than
// starting, and refusing with a margin is the only version of that which leaves
// room to recover.
const BackupTargetReserveBytes uint64 = 256 << 20 // 256 MiB

// BackupScopeIdentityOnly is the scope of every archive this build writes, and
// it is stamped into the generation id, the manifest, the ledger and the UI.
//
// §4.5's contents list is the identity set PLUS every volume classed `critical`
// or `state` on any node. No volume anywhere carries a class yet — the
// tileschema fields (#292), the catalog classification (#293), the quiesce
// drivers (#294), the streaming path (#295) and the ingest endpoint (#296) are
// all unbuilt — so the per-node fan-out runs and captures nothing.
//
// That is a legitimate state to ship, and it is NOT a legitimate state to leave
// implicit. An archive missing every app's data is not the backup an operator
// assumes they have, and the only defence against that misunderstanding is to
// say so everywhere the archive is named. Hence a constant, in the wire
// contract, that ends up in the file name on the platter.
const BackupScopeIdentityOnly = "identity-only"

// BackupScopeFull is what a build that captures the §4.5 volume set will stamp
// instead. Defined now so the manifest's `scope` field is a closed set from the
// first generation ever written rather than a string that acquires meaning
// later, and so a restore reading a generation can branch on a value it knows
// instead of on the absence of one.
const BackupScopeFull = "full"

// BackupRefusalInsufficientSpace is the preflight refusal §4.4 asks for: the
// target has not got room for the incoming archive plus the reserve.
//
// A StorageRefusal because it travels in the same field as the storage verbs'
// refusals and the UI branches on the same union. It is a refusal and never a
// warning: there is no path where the agent writes a generation onto a disk it
// has just said is too full.
const BackupRefusalInsufficientSpace StorageRefusal = "insufficient-space"

// BackupRefusalStagingMissing means the staging file the api named is not under
// the agent's staging root — it was never written, it was cleaned up, or the
// name was not a plain file name. Distinct from a backend error because the
// operator-facing fix is different: this one is the api's side of the handoff.
const BackupRefusalStagingMissing StorageRefusal = "staging-missing"

// BackupRefusalDigestMismatch means the staged bytes do not hash to the digest
// the command carried. The generation is NOT written.
//
// §4.6 says integrity is verified from a digest and never by decrypting, and
// this is where that happens: the agent cannot open the archive, so re-hashing
// what it is about to copy is the only check available to it — and it is a real
// one, because the digest was computed by the api over the same bytes.
const BackupRefusalDigestMismatch StorageRefusal = "digest-mismatch"

// BackupValidStagingName reports whether s is a plain file name the agent may
// join onto its staging root.
//
// The allowed shape is deliberately narrow: no separators, no `.` or `..`, no
// leading dot, and nothing that is not an unreserved file-name character. The
// point is not to sanitise a hostile string into a safe one — it is to refuse
// anything that is not obviously a name the api just minted, so this verb can
// never be talked into reading a file somewhere else on the node.
func BackupValidStagingName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	if s == "." || s == ".." || strings.HasPrefix(s, ".") {
		return false
	}
	if strings.ContainsAny(s, `/\`) {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// BackupValidGenerationID reports whether s is a usable generation id: the same
// narrow shape as a staging name, because it becomes a file name on the target.
func BackupValidGenerationID(s string) bool { return BackupValidStagingName(s) }

// BackupGeneration is one retained archive as it exists on the target.
type BackupGeneration struct {
	// ID is the generation's identifier and the name of its directory. It
	// carries the scope (BackupScopeIdentityOnly) so an operator listing the
	// directory sees what each generation is without opening anything.
	ID string `json:"id"`
	// ArchivePath and ManifestPath are absolute paths on the agent's node.
	// Reported so a log line can name the file that was actually written.
	ArchivePath  string `json:"archivePath,omitempty"`
	ManifestPath string `json:"manifestPath,omitempty"`
	SizeBytes    uint64 `json:"sizeBytes,omitempty"`
	// Digest is the SHA-256 of the sealed archive, lower-case hex. The api
	// computed it while sealing; the agent re-computed it before copying.
	Digest string `json:"digest,omitempty"`
	// WrittenAt is the archive file's modification time, which is what prune
	// orders by. Deliberately not parsed out of the id: a generation restored
	// or copied onto the disk by hand still sorts sensibly.
	WrittenAt time.Time `json:"writtenAt"`
	// Scope is BackupScopeIdentityOnly or BackupScopeFull, read from the
	// clear-text manifest when it could be read. Empty means the manifest was
	// missing or unparseable — which prune treats as a generation like any
	// other, because deleting the newest four of anything is not prune's call
	// to second-guess.
	Scope string `json:"scope,omitempty"`
}

// BackupPreflightCmd asks whether the target can take an archive of about
// EstimateBytes. Read-only; it mounts the target if it is not mounted.
type BackupPreflightCmd struct {
	// PartUUID is the claimed target, addressed the only way §4.8 allows.
	PartUUID string `json:"partUuid"`
	// EstimateBytes is the api's estimate of the sealed archive's size, made
	// before anything has been snapshotted. Zero is legal and means "I do not
	// know yet" — the agent then reports space and leaves Sufficient to the
	// reserve alone.
	EstimateBytes uint64 `json:"estimateBytes,omitempty"`
}

// BackupPreflightAck is §4.4's pre-flight free-space check.
//
// The numbers are reported whether or not the check passed, because a refusal
// an operator cannot size up is a refusal they cannot act on: "there is not
// room" is useless next to "the target has 900 MB free and this needs 1.4 GB".
type BackupPreflightAck struct {
	OK bool `json:"ok"`
	// Present is false when nothing with that partition UUID is attached — the
	// operator unplugged the target. Distinct from OK=false, which means the
	// agent could not answer, and both are distinct from Sufficient=false.
	Present    bool   `json:"present"`
	PartUUID   string `json:"partUuid,omitempty"`
	DevicePath string `json:"devicePath,omitempty"`
	MountPath  string `json:"mountPath,omitempty"`
	FSType     string `json:"fsType,omitempty"`
	TotalBytes uint64 `json:"totalBytes,omitempty"`
	FreeBytes  uint64 `json:"freeBytes,omitempty"`
	// RequiredBytes is EstimateBytes plus BackupTargetReserveBytes — what the
	// agent actually compared FreeBytes against.
	RequiredBytes uint64 `json:"requiredBytes,omitempty"`
	// Sufficient is the verdict. False is always accompanied by OK=false and
	// BackupRefusalInsufficientSpace: §4.4 wants a refusal, not a caveat.
	Sufficient bool `json:"sufficient"`
	// Generations is what is already retained, so the api can log the retention
	// picture before it adds to it.
	Generations []BackupGeneration `json:"generations,omitempty"`
	Refusal     StorageRefusal     `json:"refusal,omitempty"`
	Detail      string             `json:"detail,omitempty"`
}

// BackupWriteCmd lands one sealed archive on the target as a new generation.
// THIS IS THE VERB THAT WRITES, and the api declares its saga step Irreversible
// around it.
type BackupWriteCmd struct {
	PartUUID string `json:"partUuid"`
	// GenerationID is the file-name stem for both files, minted by the api and
	// carrying the scope. Validated with BackupValidGenerationID.
	GenerationID string `json:"generationId"`
	// StagingName is the file's name under the AGENT's staging root — a plain
	// file name, never a path. See the package comment for why.
	StagingName string `json:"stagingName"`
	// Digest is the SHA-256 the api computed over the sealed bytes, lower-case
	// hex. The agent re-hashes the staged file and refuses on any difference.
	Digest string `json:"digest"`
	// SizeBytes is the sealed archive's length, checked against the staged
	// file before the copy so a truncated stage is caught by size as well as by
	// hash.
	SizeBytes uint64 `json:"sizeBytes"`
	// ManifestJSON is the CLEAR-TEXT manifest written beside the archive. Prose,
	// file names, sizes and digests — see BackupScopeIdentityOnly for why an
	// operator has to be able to read it without a custody secret.
	ManifestJSON string `json:"manifestJson"`
}

// BackupWriteAck reports the generation that landed.
type BackupWriteAck struct {
	OK         bool             `json:"ok"`
	PartUUID   string           `json:"partUuid,omitempty"`
	Generation BackupGeneration `json:"generation,omitempty"`
	// FreeBytes is what is left on the target afterwards. Reported so the job
	// feed can show the retention picture tightening without a second RPC.
	FreeBytes uint64         `json:"freeBytes,omitempty"`
	Refusal   StorageRefusal `json:"refusal,omitempty"`
	Detail    string         `json:"detail,omitempty"`
}

// BackupPruneCmd enforces §4.4's retention.
//
// It is declarative — "the target should end up holding Keep generations" —
// rather than imperative ("delete the oldest"). That distinction is the whole
// reason the api's prune step is retryable: running this twice converges on the
// same disk contents, because the second run finds Keep generations and deletes
// nothing. An imperative delete-the-oldest verb would take a bite each time it
// ran.
type BackupPruneCmd struct {
	PartUUID string `json:"partUuid"`
	// Keep is how many generations survive, newest first. Zero is invalid and
	// refused — a prune that empties the disk is not a retention policy, and
	// a zero-valued struct must never be able to express one.
	Keep int `json:"keep"`
	// ProtectGenerationID is the generation this run just wrote. The agent
	// refuses to delete it whatever the ordering says, so a clock skew or a
	// filesystem with coarse timestamps cannot make a run delete its own
	// output.
	ProtectGenerationID string `json:"protectGenerationId,omitempty"`
}

// BackupPruneAck reports what survived and what did not.
type BackupPruneAck struct {
	OK       bool   `json:"ok"`
	PartUUID string `json:"partUuid,omitempty"`
	// Kept and Pruned are the generation ids on each side of the retention
	// line. Both are reported: "kept 4, pruned 1" is the sentence the job feed
	// needs, and an empty Pruned on a converged target is a success, not a
	// no-op worth hiding.
	Kept      []string       `json:"kept,omitempty"`
	Pruned    []string       `json:"pruned,omitempty"`
	FreeBytes uint64         `json:"freeBytes,omitempty"`
	Refusal   StorageRefusal `json:"refusal,omitempty"`
	Detail    string         `json:"detail,omitempty"`
}

// BackupPreflightSubject is the read-only space + retention check.
func BackupPreflightSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "storage.backup_preflight")
}

// BackupWriteSubject lands a sealed archive as a new generation.
func BackupWriteSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "storage.backup_write")
}

// BackupPruneSubject converges the target on §4.4's retention.
func BackupPruneSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "storage.backup_prune")
}

// BackupGenerationID mints the id for a run: an ISO-8601 basic-format UTC
// timestamp, a short job discriminator, and the SCOPE.
//
// The scope is in the file name on purpose and is the single most important
// thing in this function. `generations/20260902T031500Z-01J8ZQ4K-identity-only/`
// tells an operator listing the directory on any machine, with no Rasputin
// installed and no manifest parsed, that this archive does not contain their
// apps' data. A name that said only `backup` would be a claim this build cannot
// support.
func BackupGenerationID(at time.Time, jobID, scope string) string {
	disc := jobID
	if len(disc) > 8 {
		// ULIDs sort by their prefix, so the tail is the random half — which is
		// what makes two runs in the same second distinguishable.
		disc = disc[len(disc)-8:]
	}
	disc = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, disc)
	if disc == "" {
		disc = "nojob"
	}
	if scope == "" {
		scope = BackupScopeIdentityOnly
	}
	return fmt.Sprintf("%s-%s-%s", at.UTC().Format("20060102T150405Z"), disc, scope)
}
