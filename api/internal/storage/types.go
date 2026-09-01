package storage

import (
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

// ArchiveKey is design/storage.md §4.6's data key AS IT REACHES THE API:
// wrapped, always, and never in the clear.
//
// The key is minted where the passphrase and the recovery code exist — the
// browser — and the api receives only the two sealed copies plus an
// identifier. That is the whole reason this type has no field for the key
// itself: there is nowhere in this package a plaintext data key could be put
// that is not also the job ledger, a step result or a log line.
type ArchiveKey struct {
	// KeyID identifies which data key a disk's generations are encrypted
	// under. Stamped into the on-disk marker so a restore can tell which key
	// it needs instead of guessing. An identifier — never key material.
	KeyID string `json:"keyId"`
	// Alg names the wrapping construction, so a later rotation can tell what
	// it is reading rather than assuming the current one.
	Alg string `json:"alg,omitempty"`
	// WrappedByPassphrase is the data key sealed under the operator's
	// passphrase. Opaque to the api.
	WrappedByPassphrase string `json:"wrappedByPassphrase"`
	// WrappedByRecoveryCode is the SAME data key sealed under the recovery
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
	return k.KeyID != "" || k.WrappedByPassphrase != "" || k.WrappedByRecoveryCode != ""
}

// validate enforces all-or-nothing. A partially-supplied key is refused rather
// than stored, because a half-wrapped key looks configured in every listing
// while being unusable in the one case it exists for.
func (k *ArchiveKey) validate() error {
	if !k.present() {
		return nil
	}
	var missing []string
	if strings.TrimSpace(k.KeyID) == "" {
		missing = append(missing, "keyId")
	}
	if strings.TrimSpace(k.WrappedByPassphrase) == "" {
		missing = append(missing, "wrappedByPassphrase")
	}
	if strings.TrimSpace(k.WrappedByRecoveryCode) == "" {
		missing = append(missing, "wrappedByRecoveryCode")
	}
	if len(missing) > 0 {
		return fmt.Errorf("archiveKey is incomplete (missing %s): a target with only one wrapping is one forgotten passphrase from an unreadable archive, so it is refused rather than half-stored", strings.Join(missing, ", "))
	}
	return nil
}

// ClaimSpec is the spec body of a backup.target.claim job.
//
// It is built by the HTTP handler from a typed request rather than forwarded
// from the operator's raw body, so nothing the caller invented can ride along
// into the job ledger. §4.6's plaintext data key has no field here and no way
// to reach one.
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
	// ArchiveKey carries the already-wrapped §4.6 data key. Optional: a target
	// may be claimed before encryption is configured. Never plaintext.
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
	// KeyID names the §4.6 data key this target's generations use.
	KeyID string `json:"keyId,omitempty"`
	// KeyAlg names the wrapping construction of the stored blobs.
	KeyAlg string `json:"keyAlg,omitempty"`
	// HasWrappedKeys reports whether both wrappings are on file, without
	// exposing either. It is what lets the UI say "encryption configured"
	// truthfully.
	HasWrappedKeys bool `json:"hasWrappedKeys"`
	// wrappedByPassphrase / wrappedByRecoveryCode are unexported so they cannot
	// be marshalled into a response by accident. Read them with
	// Store.GetWrappedKeys.
	wrappedByPassphrase   string
	wrappedByRecoveryCode string
	// Adopted is true when this target was taken over as it stood rather than
	// formatted — an existing backup set the operator chose to keep.
	Adopted   bool         `json:"adopted,omitempty"`
	Status    TargetStatus `json:"status"`
	CreatedAt time.Time    `json:"createdAt"`
	// ClaimedAt is when the row reached a terminal status, whatever that status
	// is. Its absence is what a list renders as still-running.
	ClaimedAt *time.Time `json:"claimedAt,omitempty"`
	Error     string     `json:"error,omitempty"`
}
