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
// themselves the release purpose without the intermediate key.
//
// Key custody, per docs/pki.md: the root CA private key is kept offline on a
// YubiKey. The intermediate private key is not offline; it lives on the release
// machine or in a sealed CI secret. Whether to move to hardware-rooted signing
// is a separate open question, tracked in geekdojo/geekdojo-brain#256.
//
// THE ARC: 1.3.6.1.4.1.66587, Geekdojo's IANA Private Enterprise Number.
// Assigned 2026-08-20. https://www.iana.org/assignments/enterprise-numbers/
//
// Two dead ends are recorded because both look correct until you try them.
//
// 2.25, the ITU-T UUID arc, is the textbook answer — any UUID may be used as an
// OID beneath it with no registration and no chance of collision. It is
// unusable here: Go models an OID as []int, and a UUID rendered as a decimal
// arc is ~2.1e38. encoding/asn1 cannot represent it, so the idea fails at
// compile time rather than in review.
//
// Inventing a plausible-looking PEN while waiting for the real one is squatting
// on whoever holds it, and any leaf that escaped would assert another
// organisation's identifier. The placeholder used until this assignment landed
// was PEN 0, which IANA has reserved and will never assign — chosen precisely
// because it cannot collide and is obviously wrong to anyone who looks it up.
//
// No leaf was ever minted under the placeholder. Confirmed before the swap:
// pki-init.sh had no catalog-leaf mode, no catalog signing secret existed at
// org or repository level, and nothing outside this file referenced the OID.
// Closes geekdojo/geekdojo-brain#192.
var (
	// OIDGeekdojo is the root of everything Geekdojo issues.
	OIDGeekdojo = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66587}

	// OIDCodeSigningRelease marks a leaf permitted to sign OS and firmware
	// artifacts — the RAUC bundles and the firewall rootfs the agent flashes.
	OIDCodeSigningRelease = extend(OIDGeekdojo, 1, 1, 1)

	// OIDCodeSigningCatalog marks a leaf permitted to sign app-catalog bundles
	// and NOTHING ELSE. A leaf carrying only this must never satisfy the OTA
	// path; that refusal is the entire point of the split.
	OIDCodeSigningCatalog = extend(OIDGeekdojo, 1, 1, 2)
)

func extend(base asn1.ObjectIdentifier, more ...int) asn1.ObjectIdentifier {
	// Copy base rather than appending onto it: append could otherwise write
	// into a shared backing array and quietly rewrite one purpose OID into
	// another. No capacity arithmetic here on purpose — the only mutation that
	// survived the gate was on a capacity hint that cannot change behaviour.
	out := append(asn1.ObjectIdentifier{}, base...)
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
// artifact. The ONLY way to be authorized is to carry the purpose OID.
//
// THE TRANSITIONAL ALLOWANCE IS GONE. Until this change a leaf carrying the
// generic codeSigning EKU and no Rasputin purpose OID at all was accepted for
// the RELEASE purpose, because #192 landed while leaf-001 — which had signed
// every artifact then in the field — was still the signing leaf, and demanding
// the OID would have made every published release uninstallable.
//
// ADR-0006's revisit criterion for that allowance was "leaf-001 rotates". It
// has: `Rasputin Bundle Signing leaf-003` (notBefore 2026-08-21) signs every
// release from 2026.08.4 onward, and it carries
// `1.3.6.1.4.1.66587.1.1.1` — OIDCodeSigningRelease — explicitly, alongside
// codeSigning and emailProtection (scripts/pki-init.sh EKU_RELEASE mints
// exactly that, so a dev box's own leaf qualifies too).
//
// Deleting the allowance therefore changes the verdict on nothing that was
// ever published. `Rasputin Release Leaf 001` carries NO extendedKeyUsage
// extension whatsoever — not even generic codeSigning — so hasGenericCodeSigning
// was already false for it and artifacts it signed were already refused here.
// The allowance was a door that nothing walked through, which is the only kind
// worth deleting quietly.
func authorizePurpose(leaf *x509.Certificate, want asn1.ObjectIdentifier) error {
	for _, oid := range leaf.UnknownExtKeyUsage {
		if oid.Equal(want) {
			return nil
		}
	}
	return &ErrWrongPurpose{Signer: leaf.Subject.CommonName, Want: want}
}
