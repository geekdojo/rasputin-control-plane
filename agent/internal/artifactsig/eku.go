package artifactsig

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// Rasputin's private OID arc, and the code-signing purposes issued under it.
//
// WHY THESE EXIST. Until #192 the OTA gate authorized on chain-to-root alone:
// Verify recorded the leaf's common name and never checked it, so ANY leaf that
// chained to the baked root and carried the generic codeSigning EKU could sign
// ANY artifact. That made ADR-0006 Decision 3's "same trust root, separate
// blast radius" untrue — an app-catalog signing leaf would have been
// cryptographically equivalent to the release leaf, and a compromise of catalog
// CI would have yielded a signature the firewall accepts for a rootfs it then
// flashes.
//
// The purpose is carried in the certificate's extended key usage, which is
// signed by the intermediate. That is what makes this authorization rather than
// a naming convention: a holder of the catalog leaf's private key cannot grant
// themselves the release purpose without the intermediate key, which is offline.
//
// THE ARC IS PROVISIONAL AND MUST BE REPLACED BEFORE ANY LEAF IS MINTED.
//
// The first attempt used 2.25, the ITU-T UUID arc — any UUID may be used as an
// OID under it with no registration and no chance of collision. That is the
// textbook answer and it is unusable here: Go models an OID as []int, and a
// UUID rendered as a decimal arc is ~2.1e38, which does not fit. encoding/asn1
// cannot represent it, so the idea fails at compile time rather than in review.
//
// The correct arc is 1.3.6.1.4.1.<PEN> under a Geekdojo IANA Private Enterprise
// Number. Registration is free but is a human action nobody has taken, so the
// placeholder below sits under PEN 0, which IANA has RESERVED and will never
// assign. That is deliberate: an unregistered placeholder that can never
// collide with a real organisation, and that is obviously wrong to anyone who
// looks it up. Inventing a plausible-looking PEN would be squatting and would
// eventually collide with whoever holds it.
//
// Nothing in the field carries these OIDs yet — the transitional rule below
// accepts the legacy leaf on its generic codeSigning EKU — so changing the arc
// today costs one line. Changing it after a leaf is minted costs a re-mint and
// a re-sign of everything that leaf signed. Hence: before minting, not after.
// Tracked on geekdojo/geekdojo-brain#192.
var (
	// OIDGeekdojo is the root of everything Geekdojo issues.
	// PROVISIONAL: PEN 0 is IANA-reserved. Replace with the real PEN — see above.
	OIDGeekdojo = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 0}

	// ArcIsProvisional reports that OIDGeekdojo is still the placeholder. Read
	// by the test that refuses to let a provisional arc reach a minted leaf.
	ArcIsProvisional = OIDGeekdojo.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 0})

	// OIDCodeSigningRelease marks a leaf permitted to sign OS and firmware
	// artifacts — the RAUC bundles and the firewall rootfs the agent flashes.
	OIDCodeSigningRelease = extend(OIDGeekdojo, 1, 1, 1)

	// OIDCodeSigningCatalog marks a leaf permitted to sign app-catalog bundles
	// and NOTHING ELSE. A leaf carrying only this must never satisfy the OTA
	// path; that refusal is the entire point of the split.
	OIDCodeSigningCatalog = extend(OIDGeekdojo, 1, 1, 2)
)

func extend(base asn1.ObjectIdentifier, more ...int) asn1.ObjectIdentifier {
	out := make(asn1.ObjectIdentifier, 0, len(base)+len(more))
	out = append(out, base...)
	return append(out, more...)
}

// ErrWrongPurpose is returned when a leaf verified against the trust root but
// is not authorized for the artifact class being installed.
type ErrWrongPurpose struct {
	Signer string
	Want   asn1.ObjectIdentifier
}

func (e *ErrWrongPurpose) Error() string {
	return fmt.Sprintf("leaf %q chains to the trust root but is not authorized for purpose %s", e.Signer, e.Want)
}

// authorizePurpose reports whether a verified leaf may sign the given class of
// artifact.
//
// TRANSITIONAL, AND THE TRANSITION IS THE DANGEROUS PART. Every leaf minted
// before 2026-08-19 — including leaf-001, which signed every artifact currently
// in the field — carries only the generic codeSigning EKU and none of the OIDs
// above. A verifier that simply demanded OIDCodeSigningRelease would reject
// every release already published and brick OTA for the whole fleet, which is a
// worse outcome than the hole it closes.
//
// So a bare generic codeSigning leaf is accepted for the RELEASE purpose only.
// It is NOT accepted for the catalog purpose: no catalog leaf exists yet, so
// nothing legitimate needs that allowance, and granting it would let the legacy
// leaf sign catalog bundles for no reason.
//
// This loosening must die when leaf-001 rotates. It is written into ADR-0006's
// revisit criteria rather than left as a comment nobody re-reads, because a
// transitional allowance with no expiry is just the permanent rule with an
// apology attached.
func authorizePurpose(leaf *x509.Certificate, want asn1.ObjectIdentifier) error {
	for _, oid := range leaf.UnknownExtKeyUsage {
		if oid.Equal(want) {
			return nil
		}
	}

	if want.Equal(OIDCodeSigningRelease) && hasGenericCodeSigning(leaf) && !hasAnyRasputinPurpose(leaf) {
		// Legacy leaf: generic codeSigning and no explicit purpose at all.
		return nil
	}

	return &ErrWrongPurpose{Signer: leaf.Subject.CommonName, Want: want}
}

func hasGenericCodeSigning(leaf *x509.Certificate) bool {
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	return false
}

// hasAnyRasputinPurpose distinguishes a LEGACY leaf (generic codeSigning, no
// explicit purpose) from a MODERN one that was deliberately issued for a
// different purpose. Without this, a catalog leaf that also carried generic
// codeSigning would slip through the legacy allowance and defeat the split.
func hasAnyRasputinPurpose(leaf *x509.Certificate) bool {
	for _, oid := range leaf.UnknownExtKeyUsage {
		if len(oid) > len(OIDGeekdojo) && oid[:len(OIDGeekdojo)].Equal(OIDGeekdojo) {
			return true
		}
	}
	return false
}
