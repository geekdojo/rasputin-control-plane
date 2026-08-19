package artifactsig

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
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

// leaf-001 signed everything currently in the field and carries only generic
// codeSigning. Rejecting it would brick OTA for the whole fleet, which is worse
// than the hole being closed.
func TestAuthorize_LegacyLeafStillSignsReleases(t *testing.T) {
	legacy := leafWith([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, nil)
	if err := authorizePurpose(legacy, OIDCodeSigningRelease); err != nil {
		t.Fatalf("the deployed legacy leaf must keep working: %v", err)
	}
}

// ...but the legacy allowance is scoped to releases only. Nothing legitimate
// needs a bare codeSigning leaf to sign catalog bundles, and granting it would
// hand the widest-reaching existing key a second job for free.
func TestAuthorize_LegacyLeafCannotSignCatalog(t *testing.T) {
	legacy := leafWith([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, nil)
	if err := authorizePurpose(legacy, OIDCodeSigningCatalog); err == nil {
		t.Fatal("the legacy allowance must not extend to the catalog purpose")
	}
}

// The escape hatch the legacy allowance could become: a catalog leaf that ALSO
// carries generic codeSigning would otherwise look legacy and be waved through.
func TestAuthorize_CatalogLeafWithGenericCodeSigningIsStillRefused(t *testing.T) {
	sneaky := leafWith([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		[]asn1.ObjectIdentifier{OIDCodeSigningCatalog})
	if err := authorizePurpose(sneaky, OIDCodeSigningRelease); err == nil {
		t.Fatal("a leaf carrying an explicit Rasputin purpose must not fall back to the legacy allowance")
	}
}

// A leaf with no EKU at all is not a shape this PKI issues. Conventionally it
// means "any purpose", which is exactly what we are refusing to grant.
func TestAuthorize_NoEKULeafIsRefused(t *testing.T) {
	bare := leafWith(nil, nil)
	if err := authorizePurpose(bare, OIDCodeSigningRelease); err == nil {
		t.Fatal("a leaf with no EKU must not be treated as authorized for everything")
	}
}

// Guards the swap that has to happen before any leaf is minted. It asserts the
// arc is STILL provisional so the reminder is impossible to lose; when the real
// PEN lands, this test is what tells you to delete it.
func TestOIDArc_IsStillProvisional(t *testing.T) {
	if !ArcIsProvisional {
		t.Fatal("OIDGeekdojo is no longer the PEN-0 placeholder — good. " +
			"Delete this test, and confirm no leaf was minted under the old arc " +
			"(geekdojo/geekdojo-brain#192).")
	}
	t.Log("arc is provisional (PEN 0, IANA-reserved); a real PEN is required before minting any leaf")
}
