package storage

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The WIPE half of design/storage.md §4.8.
//
// §4.8 reads, in full: "A disk that already carries a Rasputin backup set is
// adopted, not wiped — OR WIPED ONLY ON A SECOND, SEPARATE CHOICE." `adopt` is
// the first half. This file is the second.
//
// # Why a token rather than a second boolean
//
// A `wipe bool` sitting beside `adopt bool` is one typo, one copied curl, one
// mis-bound checkbox away from destroying the only copy of an archive — and the
// caller never has to have LOOKED at what it is destroying. So the wipe choice
// is a nested object carrying a token that the api itself minted, over the disk
// AS THE PICKER SHOWED IT, and re-derives from the live disk at step 3.
//
// What the token IS:
//
//   - a capability the api mints ONLY for a candidate that is genuinely
//     eligible to be wiped — never for a protected disk, never for one carrying
//     no backup set. A UI cannot offer a wipe button for a disk the api refused
//     to mint a token for, because there is nothing to put in the field;
//   - a commitment to ONE disk in ONE state. It binds the fingerprint, the
//     stable identity (WWN/serial/size) and the marker's own contents. If any
//     of that changed between the picker and the saga, the token no longer
//     matches and the wipe is refused rather than applied to a disk the
//     operator was never shown;
//   - the only way to reach the destructive branch on a disk carrying a set.
//     Absent or wrong is a refusal, never a default.
//
// What the token is NOT: a secret. The derivation below is public code and
// anyone holding an enumerate result can compute it. That is fine and it is
// deliberate — the threat this guards against is an ACCIDENT (a stale
// confirmation, a boolean flipped by the wrong branch of a dialog, a replayed
// request), not an authenticated caller who has decided to destroy a disk. The
// endpoint's authentication is what answers "may this caller act at all".
//
// # What the wipe path does NOT change
//
// Nothing on the wire, and nothing in the agent. A wipe sends the SAME
// proto.StorageClaimCmd, on the same subject, from the same Irreversible /
// Retries:0 step as an ordinary format of a blank disk. There is no wipe flag
// on StorageClaimCmd, no force bit, and no agent-side branch — so the boot-
// device exclusion and the fingerprint re-check the agent performs immediately
// before it writes apply to a wipe exactly as they apply to every other claim,
// and there is nothing here that could bypass them. The wipe verb changes which
// disks are ELIGIBLE, never which safety checks run.

const (
	// wipeTokenPrefix makes a token recognisable in an error or a log line, so
	// nobody has to guess what the opaque string in a refusal was.
	wipeTokenPrefix = "wipe-"
	// wipeTokenDomain separates this hash's inputs from every other hash in the
	// system, so a digest minted for some other purpose can never be replayed
	// here as a wipe confirmation.
	wipeTokenDomain = "rasputin.backup.target.wipe.v1"
	// wipeTokenHexLen is how much of the digest a token carries. 24 hex
	// characters is 96 bits — far past any accidental collision, and short
	// enough that an operator can eyeball two tokens as different.
	wipeTokenHexLen = 24
)

// wipeTokenInput is the exact, ordered set of facts a token commits to.
//
// A struct marshalled to JSON rather than fields concatenated into a buffer:
// concatenation makes ("ab","c") and ("a","bc") hash the same, and the one
// place that must never quietly agree about two different disks is this one.
//
// Deliberately EXCLUDED: the device path (a handle for one moment, not an
// identity — §4.8), the transport, and the partition list's mountpoints. All
// three can change without the disk changing, and a token that goes stale for
// no reason trains operators to re-confirm without looking. The partition TABLE
// is already covered: the fingerprint hashes it.
type wipeTokenInput struct {
	Domain      string                  `json:"domain"`
	Fingerprint string                  `json:"fingerprint"`
	WWN         string                  `json:"wwn,omitempty"`
	Serial      string                  `json:"serial,omitempty"`
	SizeBytes   uint64                  `json:"sizeBytes"`
	BackupSet   *proto.StorageBackupSet `json:"backupSet"`
}

// WipeToken mints the confirmation token for one disk in one state.
//
// set is the marker's contents, or nil when the disk announces a backup set
// whose marker could not be read. THE NIL CASE IS THE POINT: an unreadable
// marker is precisely the disk an operator most needs to reclaim, and before
// this it could be neither adopted (nothing to adopt it by) nor formatted (the
// backup-set refusal stood in the way). A token is minted for it like any
// other, so the dead end has an exit.
//
// Returns "" when there is no fingerprint to bind to — a token that committed
// to nothing would confirm nothing, and "" never matches (see wipeTokenMatches).
func WipeToken(fingerprint, wwn, serial string, sizeBytes uint64, set *proto.StorageBackupSet) string {
	if fingerprint == "" {
		return ""
	}
	blob, err := json.Marshal(wipeTokenInput{
		Domain:      wipeTokenDomain,
		Fingerprint: fingerprint,
		WWN:         wwn,
		Serial:      serial,
		SizeBytes:   sizeBytes,
		BackupSet:   set,
	})
	if err != nil {
		// Unreachable for these field types, and it fails CLOSED anyway: no
		// token means no wipe.
		return ""
	}
	sum := sha256.Sum256(blob)
	return wipeTokenPrefix + hex.EncodeToString(sum[:])[:wipeTokenHexLen]
}

// CandidateWipeToken mints the token the picker publishes for a candidate — and
// mints NOTHING for a disk that must not be wiped.
//
// The two exclusions are the fail-closed half of the design and are not
// redundant with the saga's own refusals:
//
//   - Protected: the disk holding the currently-mounted boot and persistent
//     partitions. Step 2 refuses it regardless, but a UI that is handed no
//     token cannot render a wipe control for the cluster's own boot medium in
//     the first place.
//   - no backup set: an ordinary claim already formats a blank disk. Publishing
//     a wipe token for one would invent a second, destructive-sounding path to
//     something that needs no second choice at all.
func CandidateWipeToken(c *proto.StorageCandidate) string {
	if c == nil || !c.HasBackupSet || c.Protected {
		return ""
	}
	return WipeToken(c.Fingerprint, c.WWN, c.Serial, c.SizeBytes, c.BackupSet)
}

// wipeTokenMatches compares a supplied confirmation against the one derived
// from the LIVE disk. Empty on either side is a refusal, never a wildcard —
// the same rule proto/storage.go states for an empty fingerprint.
//
// Constant-time because the comparison is free to make constant-time and it
// removes the question. The token is not a secret (see the file comment), so
// this is not load-bearing; it is cheaper than explaining that in a review.
func wipeTokenMatches(supplied, expected string) bool {
	if supplied == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(expected)) == 1
}
