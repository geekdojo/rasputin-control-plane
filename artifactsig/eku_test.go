package artifactsig

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
)

func leafWith(eku []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier) *x509.Certificate {
	return &x509.Certificate{
		Subject:            pkix.Name{CommonName: "Test Leaf"},
		ExtKeyUsage:        eku,
		UnknownExtKeyUsage: unknown,
	}
}

// The whole point of #192: a leaf issued for the catalog must not be able to
// sign something the OTA path installs, even though it chains to the same root.
func TestAuthorize_CatalogLeafCannotSignReleases(t *testing.T) {
	catalog := leafWith(nil, []asn1.ObjectIdentifier{OIDCodeSigningCatalog})
	if err := authorizePurpose(catalog, OIDCodeSigningRelease); err == nil {
		t.Fatal("a catalog leaf was accepted for the release purpose — this is the bug #192 closes")
	}
	var wrong *ErrWrongPurpose
	if err := authorizePurpose(catalog, OIDCodeSigningRelease); !errors.As(err, &wrong) {
		t.Errorf("want ErrWrongPurpose, got %T: %v", err, err)
	}
	if err := authorizePurpose(catalog, OIDCodeSigningCatalog); err != nil {
		t.Errorf("a catalog leaf must still sign catalog bundles: %v", err)
	}
}

// The reverse direction matters too — a release leaf signing catalog bundles
// would let the image pipeline publish app content, which is the same boundary
// viewed from the other side.
func TestAuthorize_ReleaseLeafCannotSignCatalog(t *testing.T) {
	release := leafWith(nil, []asn1.ObjectIdentifier{OIDCodeSigningRelease})
	if err := authorizePurpose(release, OIDCodeSigningCatalog); err == nil {
		t.Fatal("a release leaf was accepted for the catalog purpose")
	}
	if err := authorizePurpose(release, OIDCodeSigningRelease); err != nil {
		t.Errorf("a release leaf must sign releases: %v", err)
	}
}

// THE ALLOWANCE IS DELETED. A leaf carrying generic codeSigning and no
// Rasputin purpose OID used to be accepted for the release purpose while
// leaf-001 was still signing. leaf-001 has rotated — leaf-003 carries
// OIDCodeSigningRelease explicitly on every release from 2026.08.4 onward —
// so the purpose OID is now the only way in, for either purpose.
func TestAuthorize_GenericCodeSigningIsNotEnough(t *testing.T) {
	for _, want := range []asn1.ObjectIdentifier{OIDCodeSigningRelease, OIDCodeSigningCatalog} {
		generic := leafWith([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, nil)
		err := authorizePurpose(generic, want)
		if err == nil {
			t.Fatalf("generic codeSigning was accepted for %s — the legacy allowance is back", want)
		}
		var wrong *ErrWrongPurpose
		if !errors.As(err, &wrong) {
			t.Errorf("want ErrWrongPurpose for %s, got %T: %v", want, err, err)
		}
	}
}

// The real shape of the leaf that signs today: codeSigning + emailProtection
// for openssl/RAUC purpose checks, plus the release OID for this one. The
// non-OID usages are noise here; the OID is what authorizes.
func TestAuthorize_DeployedReleaseLeafShapeIsAccepted(t *testing.T) {
	deployed := leafWith(
		[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection},
		[]asn1.ObjectIdentifier{OIDCodeSigningRelease})
	if err := authorizePurpose(deployed, OIDCodeSigningRelease); err != nil {
		t.Fatalf("the leaf shape scripts/pki-init.sh mints must verify: %v", err)
	}
	if err := authorizePurpose(deployed, OIDCodeSigningCatalog); err == nil {
		t.Error("the release leaf must still be refused for the catalog purpose")
	}
}

// A leaf with no EKU at all is not a shape this PKI issues. Conventionally it
// means "any purpose", which is exactly what we are refusing to grant. This is
// also the exact shape of `Rasputin Release Leaf 001`, which carries no
// extendedKeyUsage extension whatsoever — it was refused before the allowance
// was deleted and is refused after.
func TestAuthorize_NoEKULeafIsRefused(t *testing.T) {
	bare := leafWith(nil, nil)
	if err := authorizePurpose(bare, OIDCodeSigningRelease); err == nil {
		t.Fatal("a leaf with no EKU must not be treated as authorized for everything")
	}
}

// A leaf carrying the bare Rasputin arc with no purpose suffix is malformed.
// A prefix match would make it satisfy every purpose under the arc at once.
func TestAuthorize_BareArcLeafIsRefused(t *testing.T) {
	bareArc := leafWith([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		[]asn1.ObjectIdentifier{OIDGeekdojo})
	for _, want := range []asn1.ObjectIdentifier{OIDCodeSigningRelease, OIDCodeSigningCatalog} {
		if err := authorizePurpose(bareArc, want); err == nil {
			t.Fatalf("a leaf carrying the bare Rasputin arc was accepted for %s", want)
		}
	}
}

// extend must not alias its base. If it appended onto OIDGeekdojo's backing
// array, deriving the second purpose could overwrite the first — turning the
// release OID into the catalog OID at init time, which would invert every
// check in this file.
func TestExtend_DoesNotAliasTheBaseArc(t *testing.T) {
	if OIDCodeSigningRelease.Equal(OIDCodeSigningCatalog) {
		t.Fatal("the two purposes collapsed to the same OID — extend aliased its base")
	}
	last := OIDCodeSigningRelease[len(OIDCodeSigningRelease)-1]
	if last != 1 {
		t.Errorf("release purpose ends in %d, want 1 — base was mutated", last)
	}
	if got := OIDCodeSigningCatalog[len(OIDCodeSigningCatalog)-1]; got != 2 {
		t.Errorf("catalog purpose ends in %d, want 2", got)
	}
	if len(OIDGeekdojo) != 7 {
		t.Errorf("OIDGeekdojo grew to %d components — extend wrote into its base", len(OIDGeekdojo))
	}
}

// The arc is a PERMANENT contract as of 2026-08-20: leaves are minted under it
// and certificates outlive the code that made them. Changing any of these
// values silently invalidates every leaf already issued, and the failure shows
// up as a fleet that refuses its own updates rather than as a build error.
// Pinned as literal dotted strings so a mistake is visible in the diff.
func TestOIDArc_IsPinned(t *testing.T) {
	for _, c := range []struct {
		name string
		got  asn1.ObjectIdentifier
		want string
	}{
		{"geekdojo root", OIDGeekdojo, "1.3.6.1.4.1.66587"},
		{"code signing / release", OIDCodeSigningRelease, "1.3.6.1.4.1.66587.1.1.1"},
		{"code signing / catalog", OIDCodeSigningCatalog, "1.3.6.1.4.1.66587.1.1.2"},
	} {
		if got := c.got.String(); got != c.want {
			t.Errorf("%s = %s, want %s", c.name, got, c.want)
		}
	}
}

// Release and catalog must never be the same OID, and neither may be a prefix
// of the other — the whole authorization model is that holding one does not
// imply the other.
func TestOIDArc_PurposesAreDistinct(t *testing.T) {
	if OIDCodeSigningRelease.Equal(OIDCodeSigningCatalog) {
		t.Fatal("release and catalog purposes must be distinct OIDs")
	}
	for _, pair := range [][2]asn1.ObjectIdentifier{
		{OIDCodeSigningRelease, OIDCodeSigningCatalog},
		{OIDCodeSigningCatalog, OIDCodeSigningRelease},
	} {
		a, b := pair[0].String(), pair[1].String()
		if strings.HasPrefix(a+".", b+".") {
			t.Errorf("%s is a prefix of %s — a prefix match would let one purpose satisfy the other", b, a)
		}
	}
}
