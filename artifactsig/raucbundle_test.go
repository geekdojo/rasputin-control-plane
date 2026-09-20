package artifactsig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

// fakeBundle assembles a file with a RAUC "verity" trailer:
//
//	[ payload ][ CMS DER ][ big-endian uint64 len(CMS DER) ]
//
// The payload is arbitrary. Nothing under test reads it — the point of reading
// only the trailer is that a real bundle's payload is a whole rootfs image, and
// a test that needed one could not exist.
func fakeBundle(t *testing.T, dir, name string, payload, sig []byte) string {
	t.Helper()
	var trailer [8]byte
	binary.BigEndian.PutUint64(trailer[:], uint64(len(sig)))
	return writeBundleRaw(t, dir, name, payload, sig, trailer[:])
}

// writeBundleRaw is fakeBundle with the trailer supplied by the caller, so a
// test can lie about the signature length.
func writeBundleRaw(t *testing.T, dir, name string, payload, sig, trailer []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	var b []byte
	b = append(b, payload...)
	b = append(b, sig...)
	b = append(b, trailer...)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// signInline produces the kind of CMS object RAUC embeds: an ATTACHED
// SignedData, content included, leaf and intermediate carried.
func signInline(t *testing.T, content []byte, key *rsa.PrivateKey, chain []*x509.Certificate) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSignerChain(chain[0], key, chain[1:2], pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// purposeChain mints root -> intermediate -> leaf where the leaf carries
// exactly the Rasputin purposes named. The generic EKUs are the ones
// pki-init.sh issues for that class, so a leaf here has the shape of a leaf the
// pipeline would actually hand to CI.
func purposeChain(t *testing.T, purposes ...asn1.ObjectIdentifier) (*rsa.PrivateKey, []*x509.Certificate) {
	t.Helper()
	far := time.Now().Add(-time.Hour)
	rootKey, root := selfSigned(t, "Test Root", far, far.Add(10*365*24*time.Hour))
	interKey, inter := issued(t, "Test Intermediate", far, far.Add(10*365*24*time.Hour), root, rootKey, true)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test Bundle Signing Leaf"},
		NotBefore:             far,
		NotAfter:              far.Add(2 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection},
		UnknownExtKeyUsage:    purposes,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leafKey, []*x509.Certificate{leaf, inter, root}
}

func writeRoot(t *testing.T, dir string, chain []*x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, "root-ca.pem")
	writePEM(t, path, chain[2].Raw)
	return path
}

func TestVerifyRAUCBundleSigner_ReleaseLeafAccepted(t *testing.T) {
	dir := t.TempDir()
	key, chain := purposeChain(t, OIDCodeSigningRelease)
	root := writeRoot(t, dir, chain)
	sig := signInline(t, []byte("rauc manifest"), key, chain)
	// 8 KiB of "payload" stands in for a rootfs image. Its only job is to prove
	// the offset arithmetic lands on the signature and not on the payload.
	bundle := fakeBundle(t, dir, "ok.raucb", make([]byte, 8192), sig)

	res, err := VerifyRAUCBundleSignerForPurpose(bundle, root, OIDCodeSigningRelease)
	if err != nil {
		t.Fatalf("a release leaf must be accepted: %v", err)
	}
	if res.Signer != "Test Bundle Signing Leaf" {
		t.Errorf("Signer = %q, want the leaf's CN", res.Signer)
	}
	if res.Issuer != "Test Intermediate" {
		t.Errorf("Issuer = %q, want the intermediate's CN", res.Issuer)
	}
	// Nothing hashed the payload, so claiming a digest would report a check
	// that was never made.
	if res.DigestHex != "" || res.DigestAlg != "" {
		t.Errorf("Result reports a digest (%q/%q) for a check that hashes nothing", res.DigestAlg, res.DigestHex)
	}
}

// The whole reason this check exists. RAUC's check-purpose=codesign asks only
// for the generic codeSigning EKU, which this leaf has; it cannot tell a
// release leaf from any other code-signing leaf under the same intermediate.
// If this test ever passes, an OS image signed by a leaf issued for something
// else installs on every node.
func TestVerifyRAUCBundleSigner_NonReleaseLeafRefused(t *testing.T) {
	dir := t.TempDir()
	key, chain := purposeChain(t, OIDCodeSigningCatalog)
	root := writeRoot(t, dir, chain)
	sig := signInline(t, []byte("rauc manifest"), key, chain)
	bundle := fakeBundle(t, dir, "catalog-signed.raucb", make([]byte, 4096), sig)

	_, err := VerifyRAUCBundleSignerForPurpose(bundle, root, OIDCodeSigningRelease)
	if err == nil {
		t.Fatal("a leaf issued for the catalog purpose signed an OS bundle and it was accepted")
	}
	var wrong *ErrWrongPurpose
	if !errors.As(err, &wrong) {
		t.Fatalf("want ErrWrongPurpose, got %T: %v", err, err)
	}
}

// A leaf with no Rasputin purpose at all -- the shape every leaf had before
// #192, and the shape a leaf minted with generic codeSigning and nothing else
// still has.
func TestVerifyRAUCBundleSigner_NoPurposeRefused(t *testing.T) {
	dir := t.TempDir()
	key, chain := purposeChain(t)
	root := writeRoot(t, dir, chain)
	sig := signInline(t, []byte("rauc manifest"), key, chain)
	bundle := fakeBundle(t, dir, "nopurpose.raucb", make([]byte, 4096), sig)

	if _, err := VerifyRAUCBundleSignerForPurpose(bundle, root, OIDCodeSigningRelease); err == nil {
		t.Fatal("a leaf with no Rasputin purpose signed an OS bundle and it was accepted")
	}
}

func TestVerifyRAUCBundleSigner_ForeignRootRefused(t *testing.T) {
	dir := t.TempDir()
	key, chain := purposeChain(t, OIDCodeSigningRelease)
	sig := signInline(t, []byte("rauc manifest"), key, chain)
	bundle := fakeBundle(t, dir, "foreign.raucb", make([]byte, 4096), sig)

	// A wholly separate PKI, correct in every way except that this node does
	// not trust it.
	_, otherChain := purposeChain(t, OIDCodeSigningRelease)
	otherRoot := writeRoot(t, dir, otherChain)

	if _, err := VerifyRAUCBundleSignerForPurpose(bundle, otherRoot, OIDCodeSigningRelease); err == nil {
		t.Fatal("a bundle signed under a foreign root was accepted")
	}
}

func TestVerifyRAUCBundleSigner_ExpiredLeafRefused(t *testing.T) {
	dir := t.TempDir()
	past := time.Now().Add(-10 * 365 * 24 * time.Hour)
	rootKey, root := selfSigned(t, "Test Root", past, past.Add(20*365*24*time.Hour))
	interKey, inter := issued(t, "Test Intermediate", past, past.Add(20*365*24*time.Hour), root, rootKey, true)
	leafKey, leaf := issued(t, "Expired Leaf", past, past.Add(24*time.Hour), inter, interKey, false)
	chain := []*x509.Certificate{leaf, inter, root}

	rootPath := writeRoot(t, dir, chain)
	sig := signInline(t, []byte("rauc manifest"), leafKey, chain)
	bundle := fakeBundle(t, dir, "expired.raucb", make([]byte, 4096), sig)

	if _, err := VerifyRAUCBundleSignerForPurpose(bundle, rootPath, OIDCodeSigningRelease); err == nil {
		t.Fatal("a bundle signed by an expired leaf was accepted")
	}
}

// The certificate bag is attacker-influenced. Parking an authorized release
// leaf next to the leaf that really signed must not change the verdict: the
// signer is resolved by the SignerInfo's issuer and serial, not by position.
func TestVerifyRAUCBundleSigner_ExtraAuthorizedCertDoesNotLaunder(t *testing.T) {
	dir := t.TempDir()
	// One PKI, two leaves under the same intermediate: one authorized for
	// releases, one only for the catalog. The catalog leaf signs.
	far := time.Now().Add(-time.Hour)
	rootKey, root := selfSigned(t, "Test Root", far, far.Add(10*365*24*time.Hour))
	interKey, inter := issued(t, "Test Intermediate", far, far.Add(10*365*24*time.Hour), root, rootKey, true)
	releaseLeaf := leafWithPurpose(t, "Release Leaf", inter, interKey, OIDCodeSigningRelease)
	catalogKey, catalogLeaf := leafKeyWithPurpose(t, "Catalog Leaf", inter, interKey, OIDCodeSigningCatalog)

	sd, err := pkcs7.NewSignedData([]byte("rauc manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSignerChain(catalogLeaf, catalogKey, []*x509.Certificate{inter}, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	sd.AddCertificate(releaseLeaf)
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}

	rootPath := writeRoot(t, dir, []*x509.Certificate{catalogLeaf, inter, root})
	bundle := fakeBundle(t, dir, "laundered.raucb", make([]byte, 4096), der)

	_, err = VerifyRAUCBundleSignerForPurpose(bundle, rootPath, OIDCodeSigningRelease)
	if err == nil {
		t.Fatal("an authorized certificate parked in the bag laundered an unauthorized signer")
	}
	var wrong *ErrWrongPurpose
	if !errors.As(err, &wrong) {
		t.Fatalf("want ErrWrongPurpose naming the real signer, got %T: %v", err, err)
	}
	if wrong.Signer != "Catalog Leaf" {
		t.Errorf("attributed to %q; the signer is the Catalog Leaf", wrong.Signer)
	}
}

func TestVerifyRAUCBundleSigner_TrailerProblems(t *testing.T) {
	dir := t.TempDir()
	key, chain := purposeChain(t, OIDCodeSigningRelease)
	root := writeRoot(t, dir, chain)
	sig := signInline(t, []byte("rauc manifest"), key, chain)

	lenTrailer := func(n uint64) []byte {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], n)
		return b[:]
	}

	cases := []struct {
		name    string
		path    string
		wantErr error
		wantMsg string
	}{
		{
			name:    "too small to hold a trailer",
			path:    writeBundleRaw(t, dir, "tiny.raucb", nil, nil, []byte{0, 0, 0}),
			wantErr: ErrNotRAUCBundle,
		},
		{
			name:    "zero-length signature",
			path:    writeBundleRaw(t, dir, "zero.raucb", make([]byte, 64), nil, lenTrailer(0)),
			wantErr: ErrNotRAUCBundle,
		},
		{
			// RAUC refuses this before reading anything; so does this, rather
			// than seeking to a negative offset.
			name:    "signature longer than the bundle",
			path:    writeBundleRaw(t, dir, "huge.raucb", make([]byte, 64), sig, lenTrailer(1<<40)),
			wantErr: ErrNotRAUCBundle,
		},
		{
			// RAUC's own 64 KiB cap. A file claiming more is one no installer
			// would open, so buffering it would be work done for nothing.
			name:    "signature over RAUC's 64KiB cap",
			path:    writeBundleRaw(t, dir, "overcap.raucb", make([]byte, 1<<18), sig, lenTrailer(maxRAUCSigBytes+1)),
			wantErr: ErrNotRAUCBundle,
		},
		{
			name:    "trailer points at payload bytes, not a signature",
			path:    writeBundleRaw(t, dir, "garbage.raucb", make([]byte, 4096), nil, lenTrailer(2048)),
			wantMsg: "parse bundle signature",
		},
		{
			name:    "missing file",
			path:    filepath.Join(dir, "absent.raucb"),
			wantErr: ErrNoSignature,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyRAUCBundleSignerForPurpose(tc.path, root, OIDCodeSigningRelease)
			if err == nil {
				t.Fatal("accepted a bundle whose signature could not be located")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got: %v", tc.wantErr, err)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("want an error mentioning %q, got: %v", tc.wantMsg, err)
			}
		})
	}
}

func TestVerifyRAUCBundleSigner_MissingTrustRoot(t *testing.T) {
	dir := t.TempDir()
	key, chain := purposeChain(t, OIDCodeSigningRelease)
	sig := signInline(t, []byte("rauc manifest"), key, chain)
	bundle := fakeBundle(t, dir, "ok.raucb", make([]byte, 4096), sig)

	_, err := VerifyRAUCBundleSignerForPurpose(bundle, filepath.Join(dir, "nope.pem"), OIDCodeSigningRelease)
	if !errors.Is(err, ErrNoTrustRoot) {
		t.Fatalf("an unreadable trust root must be a hard failure, got: %v", err)
	}
}

// The trust root is read BEFORE the bundle, so a node with no baked root
// refuses every bundle rather than reporting a parse error about the file it
// never had a way to judge.
func TestVerifyRAUCBundleSigner_TrustRootCheckedFirst(t *testing.T) {
	dir := t.TempDir()
	bundle := writeBundleRaw(t, dir, "garbage.raucb", []byte("not a bundle at all"), nil, nil)
	_, err := VerifyRAUCBundleSignerForPurpose(bundle, filepath.Join(dir, "nope.pem"), OIDCodeSigningRelease)
	if !errors.Is(err, ErrNoTrustRoot) {
		t.Fatalf("want the trust root failure to come first, got: %v", err)
	}
}

func leafWithPurpose(t *testing.T, cn string, parent *x509.Certificate, parentKey *rsa.PrivateKey,
	purpose asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	_, cert := leafKeyWithPurpose(t, cn, parent, parentKey, purpose)
	return cert
}

func leafKeyWithPurpose(t *testing.T, cn string, parent *x509.Certificate, parentKey *rsa.PrivateKey,
	purpose asn1.ObjectIdentifier) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	far := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             far,
		NotAfter:              far.Add(2 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{purpose},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}
