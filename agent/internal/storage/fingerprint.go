package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// fingerprintVersion prefixes the hashed material. Bump it if the recipe
// changes: a fingerprint from an older agent would then compare unequal rather
// than accidentally equal, and an unequal fingerprint is a refusal, which is the
// safe direction to fail.
const fingerprintVersion = "rasputin-storage-fingerprint/v1"

// Fingerprint hashes a candidate's STABLE IDENTITY together with its CURRENT
// PARTITION TABLE. It is the value the operator's confirmation is bound to and
// the value Claim re-derives against live hardware before it writes.
//
// Two halves, doing two different jobs:
//
//   - Identity (WWN, serial, model, size) answers "is this the same physical
//     disk?" across a reboot that renumbered nvme0n1 and nvme1n1. Device path
//     is deliberately NOT hashed — it is the very thing that cannot be trusted,
//     and hashing it would make the fingerprint agree with itself for the wrong
//     reason.
//
//   - The partition table answers "did this disk change underneath us?" and, as
//     a side effect, makes the fingerprint SINGLE-USE for a destructive claim:
//     the format replaces the table, so the same command replayed no longer
//     matches. That is the repeat guard, and it needs no state to work.
//
// Mountpoints and the Protected flag are excluded on purpose. A disk that got
// mounted since the picker rendered is the same disk; conflating "somebody
// mounted it" with "this is a different disk" would fail the operator's claim
// for a reason the operator cannot act on, and protection is enforced by its own
// re-resolution rather than smuggled into a hash.
func Fingerprint(c *proto.StorageCandidate) string {
	if c == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(fingerprintVersion)
	b.WriteByte('\n')
	// Identity. Normalised so a backend that reports "  ATA_FOO " and one that
	// reports "ATA_FOO" agree; case is preserved because serials are
	// case-significant on some vendors.
	fmt.Fprintf(&b, "wwn=%s\n", strings.TrimSpace(c.WWN))
	fmt.Fprintf(&b, "serial=%s\n", strings.TrimSpace(c.Serial))
	fmt.Fprintf(&b, "model=%s\n", strings.TrimSpace(c.Model))
	fmt.Fprintf(&b, "size=%d\n", c.SizeBytes)
	// Partition table, in on-disk order. Index is written explicitly so that
	// reordering two otherwise-identical partitions changes the hash.
	fmt.Fprintf(&b, "parts=%d\n", len(c.Partitions))
	for i, p := range c.Partitions {
		fmt.Fprintf(&b, "p%d uuid=%s fs=%s label=%s size=%d\n",
			i,
			strings.TrimSpace(p.PartUUID),
			strings.TrimSpace(p.FSType),
			strings.TrimSpace(p.Label),
			p.SizeBytes,
		)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// identityWeak reports whether a candidate offered neither WWN nor serial, so
// its fingerprint rests on model + size + partition table alone.
//
// Surfaced rather than silently tolerated: two identical blank USB sticks from
// the same batch then fingerprint the same, which is exactly the collision the
// fingerprint exists to catch. Cheap USB-SATA bridges that report nothing are
// the usual cause. The claim is still allowed — refusing would make a large
// class of perfectly good USB disks unusable as backup targets — but the UI is
// told so it can say "we cannot tell this disk apart from an identical one"
// instead of implying a guarantee the data does not support.
func identityWeak(c *proto.StorageCandidate) bool {
	return strings.TrimSpace(c.WWN) == "" && strings.TrimSpace(c.Serial) == ""
}

// stampFingerprint fills in Fingerprint and IdentityWeak. Called by both
// backends at the end of building a candidate so neither can forget, and so the
// two provably agree — fingerprint_test.go asserts a mock-built and a
// blockdev-built candidate with the same facts hash identically.
func stampFingerprint(c *proto.StorageCandidate) {
	c.IdentityWeak = identityWeak(c)
	c.Fingerprint = Fingerprint(c)
}
