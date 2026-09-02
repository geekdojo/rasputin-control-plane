package storage

import (
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TargetStatus is the rollup an operator sees for one claim attempt. The
// per-step detail lives in the jobs ledger; this is what the Backup view lists.
//
// Every value except TargetPending is TERMINAL. A row that is still pending
// after its job has finished is the #53 bug — a failed run rendering as one
// still in progress — which is why the workflow carries an OnTerminal hook.
type TargetStatus string

const (
	// TargetPending — the claim saga is running. Written by step 1 so the UI
	// has something to show immediately.
	TargetPending TargetStatus = "pending"
	// TargetClaimed — the disk is formatted (or adopted) and recorded. This is
	// the cluster's backup target.
	TargetClaimed TargetStatus = "claimed"
	// TargetReplaced — a previously-claimed target that a later claim with
	// `replace` superseded. Kept rather than deleted: the disk may still be on
	// a shelf holding the only copy of an archive, and a row saying so is the
	// only place an operator can learn that.
	TargetReplaced TargetStatus = "replaced"
	// TargetFailed — the saga did not reach persist_target.
	TargetFailed TargetStatus = "failed"
)

// ArchiveKey is design/storage.md §4.6's archive KEYPAIR AS IT REACHES THE API:
// the public half in clear, the private half wrapped, always.
//
// The keypair is minted where the passphrase and the recovery code exist — the
// browser — and the api receives the public key, the two sealed copies of the
// private key, and an identifier. That is the whole reason this type has no
// field for the PRIVATE key: there is nowhere in this package one could be put
// that is not also the job ledger, a step result or a log line.
//
// # What the 2026-09-02 amendment changed, and what it did not
//
// It did not change custody. Two paths, either sufficient, Argon2id for the
// passphrase and HKDF-SHA-256 for the recovery code — all unchanged. What
// changed is WHAT THEY WRAP: an X25519 private key rather than a symmetric data
// key. The forcing question was backup.run (#290), which runs unattended at
// 3 a.m.: encrypting under a symmetric key means this api caches that key in
// the clear, which is the exposure §4.6 exists to close. Sealing to a public
// key needs no secret at rest at all — so the question of whether the
// controlplane holds a plaintext data key disappears rather than being decided.
//
// The cost, recorded so nobody rediscovers it: this controlplane can write
// archives and cannot read them back without a human. Restore is interactive by
// construction (§4.5 unpacks before the api's first start), so that is a
// property, not a gap.
type ArchiveKey struct {
	// KeyID identifies which keypair a disk's generations are encrypted to.
	// Stamped into the on-disk marker so a restore can tell which key it needs
	// instead of guessing. An identifier — never key material.
	KeyID string `json:"keyId"`
	// Alg names the construction, so a later rotation can tell what it is
	// reading rather than assuming the current one.
	Alg string `json:"alg,omitempty"`
	// PublicKey is the X25519 public key, base64url of 32 raw bytes.
	//
	// IN CLEAR, and that is the amendment: a public key at rest is harmless,
	// and it is everything an unattended backup.run needs in order to seal a
	// generation. It is validated rather than trusted (see validate) because it
	// is the one piece of §4.6 material this api both stores and hands onward
	// to something that will encrypt with it — a garbage public key here is an
	// archive nobody can ever read, discovered on restore day.
	PublicKey string `json:"publicKey"`
	// WrappedByPassphrase is the PRIVATE key sealed under the operator's
	// passphrase. Opaque to the api.
	WrappedByPassphrase string `json:"wrappedByPassphrase"`
	// WrappedByRecoveryCode is the SAME private key sealed under the recovery
	// code the UI displays exactly once.
	//
	// Both wrappings are required together. A target holding only the
	// passphrase wrapping is one forgotten passphrase away from an archive
	// nobody can read, and the operator would not find out until the day they
	// needed the backup — which is the worst possible day to discover it.
	WrappedByRecoveryCode string `json:"wrappedByRecoveryCode"`
}

// present reports whether the operator supplied any key material at all.
func (k *ArchiveKey) present() bool {
	if k == nil {
		return false
	}
	return k.KeyID != "" || k.PublicKey != "" ||
		k.WrappedByPassphrase != "" || k.WrappedByRecoveryCode != ""
}

// x25519PublicKeyBytes is the length of a raw X25519 public key (RFC 7748).
const x25519PublicKeyBytes = 32

// validate enforces all-or-nothing, and checks the one field it can check.
//
// A partially-supplied key is refused rather than stored, because a half-formed
// key looks configured in every listing while being unusable in the one case it
// exists for. The public key gets a second look on top of that: it is the only
// §4.6 field this api can meaningfully verify — the wrappings are opaque
// ciphertext by design, and the private key is not here at all — and it is the
// one that #290 will encrypt to. Something that is not an X25519 public key
// produces archives nobody can read, and the failure would surface on restore
// day rather than here.
func (k *ArchiveKey) validate() error {
	if !k.present() {
		return nil
	}
	var missing []string
	if strings.TrimSpace(k.KeyID) == "" {
		missing = append(missing, "keyId")
	}
	if strings.TrimSpace(k.PublicKey) == "" {
		missing = append(missing, "publicKey")
	}
	if strings.TrimSpace(k.WrappedByPassphrase) == "" {
		missing = append(missing, "wrappedByPassphrase")
	}
	if strings.TrimSpace(k.WrappedByRecoveryCode) == "" {
		missing = append(missing, "wrappedByRecoveryCode")
	}
	if len(missing) > 0 {
		return fmt.Errorf("archiveKey is incomplete (missing %s): a target missing the public key or either wrapping is one forgotten passphrase — or one unreadable archive — away from useless, so it is refused rather than half-stored", strings.Join(missing, ", "))
	}
	return validatePublicKey(k.PublicKey)
}

// validatePublicKey checks that an ArchiveKey's public key is a usable X25519
// public key: 32 raw bytes, base64url, and not all zeroes.
//
// The all-zero refusal is not pedantry. It is the one public key with a
// catastrophic property — every X25519 exchange against it yields zero, so
// every archive sealed to it would be encrypted under a key an attacker derives
// too — and it is exactly what a zeroed or truncated marker field decodes to.
// crypto/ecdh checks the length and nothing else, so this says the rest.
func validatePublicKey(encoded string) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return fmt.Errorf("archiveKey.publicKey is not unpadded base64url: %w", err)
	}
	if len(raw) != x25519PublicKeyBytes {
		return fmt.Errorf("archiveKey.publicKey is %d bytes; an X25519 public key is %d", len(raw), x25519PublicKeyBytes)
	}
	if _, err := ecdh.X25519().NewPublicKey(raw); err != nil {
		return fmt.Errorf("archiveKey.publicKey is not a valid X25519 public key: %w", err)
	}
	var zero [x25519PublicKeyBytes]byte
	if subtle.ConstantTimeCompare(raw, zero[:]) == 1 {
		return errors.New("archiveKey.publicKey is all zeroes, which is not a usable X25519 key: every archive sealed to it would be readable by anyone")
	}
	return nil
}

// WipeConfirmation is §4.8's "or wiped only on a second, separate choice": the
// explicit, destructive decision to claim a disk that ALREADY CARRIES a Rasputin
// backup set by destroying that set.
//
// A struct rather than a `Wipe bool` beside `Adopt bool`, deliberately. A
// boolean is one typo, one copied request body, one mis-bound checkbox from
// wiping the only copy of an archive, and a caller can set it without ever
// having looked at what it is destroying. Reaching this branch requires a token
// the api minted over the disk as the picker showed it — see wipe.go for what
// that token is and, just as importantly, what it is not.
type WipeConfirmation struct {
	// Token must equal the `wipeToken` GET /api/backup/candidates published for
	// THIS disk in THIS state. It is re-derived from the live disk at step 3, so
	// a token minted before the disk's marker or partition table changed no
	// longer matches and the wipe is refused rather than applied to something
	// the operator was never shown.
	//
	// Empty is a refusal, never a default to wipe.
	Token string `json:"token"`
}

// ClaimSpec is the spec body of a backup.target.claim job.
//
// It is built by the HTTP handler from a typed request rather than forwarded
// from the operator's raw body, so nothing the caller invented can ride along
// into the job ledger. §4.6's private key has no field here and no way to reach
// one.
type ClaimSpec struct {
	// NodeID is the node the disk is attached to.
	NodeID string `json:"nodeId"`
	// DevicePath is the candidate's path AT THE MOMENT THE OPERATOR CONFIRMED.
	// It is a starting hint for step 2, not the identity: if the disk has moved
	// to another path by the time the saga runs, step 2 re-resolves it from the
	// fingerprint and the claim goes to wherever the disk actually is.
	DevicePath string `json:"devicePath"`
	// Fingerprint is the confirmed candidate's fingerprint — the thing the
	// operator's consent is actually bound to. Empty is a REFUSAL, never a
	// wildcard (proto/storage.go says so for the wire; it is enforced here so
	// a blank never reaches the wire at all).
	Fingerprint string `json:"fingerprint"`
	// Label is the operator's human-readable name for the target.
	Label string `json:"label,omitempty"`
	// Replace acknowledges that this cluster already has a claimed target and
	// that this one supersedes it.
	Replace bool `json:"replace,omitempty"`
	// Adopt acknowledges that the chosen disk ALREADY CARRIES a Rasputin backup
	// set and takes it over AS IT STANDS — no format, nothing destroyed.
	//
	// This is §4.8's restore guard and the recovery path for an orphaned claim
	// in one flag. Without it a disk carrying a backup set is refused at step 3,
	// which is what stops a replacement controlplane from wiping the only copy
	// of the archive it was plugged in to restore from.
	Adopt bool `json:"adopt,omitempty"`
	// Wipe is the OTHER answer to the same question, and §4.8's second, separate
	// choice: destroy the backup set the disk carries and claim it fresh.
	//
	// Mutually exclusive with Adopt — they are opposite answers, and a request
	// setting both is refused rather than resolved in either direction. Absent
	// (nil) means neither was chosen, which is what makes a disk carrying a
	// backup set a REFUSAL by default.
	//
	// This is also the only exit from the unreadable-marker dead end: a disk
	// that announces a set whose marker cannot be parsed can be neither adopted
	// (there is no partition UUID to adopt it by) nor claimed as blank (the
	// backup-set refusal stands in the way). It can be wiped.
	Wipe *WipeConfirmation `json:"wipe,omitempty"`
	// ArchiveKey carries the §4.6 keypair: the public half in clear, the
	// private half already wrapped under both custody paths. Optional: a target
	// may be claimed before encryption is configured. The private key is never
	// plaintext, and has no field here to be plaintext in.
	ArchiveKey *ArchiveKey `json:"archiveKey,omitempty"`
}

// ParseClaimSpec decodes and validates a job spec. Every failure here is a
// step-1 refusal, which is the cheapest kind: nothing has been touched.
func ParseClaimSpec(raw json.RawMessage) (*ClaimSpec, error) {
	var spec ClaimSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	if strings.TrimSpace(spec.NodeID) == "" {
		return nil, errors.New("nodeId is required")
	}
	if strings.TrimSpace(spec.DevicePath) == "" {
		return nil, errors.New("devicePath is required")
	}
	if strings.TrimSpace(spec.Fingerprint) == "" {
		// proto/storage.go: "Empty is not a wildcard — it is a refusal."
		return nil, errors.New("fingerprint is required: a claim with no fingerprint names no particular disk, and the whole point of the fingerprint is that the operator's confirmation binds to one")
	}
	if spec.Adopt && spec.Wipe != nil {
		// Opposite answers to one question. Picking either for the caller would
		// be guessing, and one of the two guesses destroys an archive.
		return nil, errors.New("`adopt` and `wipe` are opposite choices: adopt takes the existing backup set over as it stands, wipe destroys it. Choose exactly one")
	}
	if spec.Wipe != nil && strings.TrimSpace(spec.Wipe.Token) == "" {
		return nil, errors.New("wipe.token is required: a wipe must echo the `wipeToken` GET /api/backup/candidates published for the disk being destroyed, which is how a wipe proves it saw what it is destroying. An absent token is a refusal, never a default to wipe")
	}
	if err := spec.ArchiveKey.validate(); err != nil {
		return nil, err
	}
	return &spec, nil
}

// BackupTarget is one row of the backup_targets ledger: an attempt to claim a
// disk, and — once it succeeded — the record of the target itself.
//
// The wrapped key blobs are deliberately absent from the JSON. They are not
// plaintext, but nothing in the UI needs them to render a target, and the
// narrowest surface that works is the right one for anything key-shaped. A
// later unlock flow (#295) that genuinely needs them reads them from the store.
// PublicKey is the deliberate exception — see its comment.
type BackupTarget struct {
	JobID  string `json:"jobId"`
	NodeID string `json:"nodeId"`
	Label  string `json:"label,omitempty"`
	// PartUUID is THE identifier for a claimed target, minted at format time.
	// Empty until step 5.
	PartUUID string `json:"partUuid,omitempty"`
	// DevicePath is recorded for the operator's benefit ONLY — "the disk that
	// was /dev/sda that evening". Nothing resolves a target through it.
	DevicePath string `json:"devicePath,omitempty"`
	MountPath  string `json:"mountPath,omitempty"`
	FSType     string `json:"fsType,omitempty"`
	SizeBytes  uint64 `json:"sizeBytes,omitempty"`
	// Fingerprint is the POST-claim fingerprint the agent returned. It
	// necessarily differs from the one the operator confirmed, because the
	// partition table it hashes is the thing that was just replaced — that is
	// the design, not drift.
	Fingerprint string `json:"fingerprint,omitempty"`
	// KeyID names the §4.6 keypair this target's generations use.
	KeyID string `json:"keyId,omitempty"`
	// KeyAlg names the construction of the stored blobs.
	KeyAlg string `json:"keyAlg,omitempty"`
	// PublicKey is the X25519 public key this target's archives are sealed to,
	// base64url of 32 raw bytes.
	//
	// Marshalled, unlike the wrappings below, and the difference is the point:
	// this is not a secret, and #290's backup.run needs exactly this — and
	// nothing else — to write a generation. The narrowest surface that works is
	// still the rule; for a public key, the surface that works includes the
	// response body.
	PublicKey string `json:"publicKey,omitempty"`
	// HasWrappedKeys reports whether both wrappings of the PRIVATE key are on
	// file, without exposing either. It is what lets the UI say "encryption
	// configured" truthfully.
	HasWrappedKeys bool `json:"hasWrappedKeys"`
	// wrappedByPassphrase / wrappedByRecoveryCode are unexported so they cannot
	// be marshalled into a response by accident. Read them with
	// Store.GetWrappedKeys.
	wrappedByPassphrase   string
	wrappedByRecoveryCode string
	// Adopted is true when this target was taken over as it stood rather than
	// formatted — an existing backup set the operator chose to keep.
	Adopted bool `json:"adopted,omitempty"`
	// Wiped is Adopted's exact counterpart: this disk carried a Rasputin backup
	// set and the operator made §4.8's second, separate choice to destroy it.
	//
	// Recorded because it is the most consequential thing this product does, and
	// because the row otherwise reads identically to a fresh format of a blank
	// disk. Rows are never deleted, so this is a durable answer to "what
	// happened to the archive that used to be on that disk".
	Wiped     bool         `json:"wiped,omitempty"`
	Status    TargetStatus `json:"status"`
	CreatedAt time.Time    `json:"createdAt"`
	// ClaimedAt is when the row reached a terminal status, whatever that status
	// is. Its absence is what a list renders as still-running.
	ClaimedAt *time.Time `json:"claimedAt,omitempty"`
	Error     string     `json:"error,omitempty"`
}
