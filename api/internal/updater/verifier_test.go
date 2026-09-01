package updater

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// pkiFixture builds an in-memory root CA + leaf cert + signing helpers and
// writes the CA PEM into a trust dir. Tests use it to mint mock bundles
// the Verifier can chain-validate.
type pkiFixture struct {
	rootKey  *rsa.PrivateKey
	rootCert *x509.Certificate
	rootPEM  []byte // bytes you'd write to root-ca.pem
	leafKey  *rsa.PrivateKey
	leafCert *x509.Certificate
	leafPEM  []byte // PEM-encoded leaf cert (what goes in the bundle envelope)
	trustDir string
}

func newPKI(t *testing.T) *pkiFixture {
	t.Helper()
	dir := t.TempDir()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Rasputin Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Rasputin Build Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	// Write the root CA to trust dir as root-ca.pem.
	if err := os.WriteFile(filepath.Join(dir, "root-ca.pem"), rootPEM, 0o600); err != nil {
		t.Fatalf("write root pem: %v", err)
	}
	return &pkiFixture{
		rootKey: rootKey, rootCert: rootCert, rootPEM: rootPEM,
		leafKey: leafKey, leafCert: leafCert, leafPEM: leafPEM,
		trustDir: dir,
	}
}

// buildMockBundle constructs a mock envelope: signs sha256(payload) with the
// leaf key (PKCS1v15+SHA256), encodes everything as the JSON envelope the
// verifier expects.
func (p *pkiFixture) buildMockBundle(t *testing.T, manifest proto.BundleManifest, payload []byte) []byte {
	t.Helper()
	hashed := sha256.Sum256(payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.leafKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}
	env := raspbundleEnvelope{
		Manifest:  manifest,
		Payload:   hex.EncodeToString(payload),
		Signature: hex.EncodeToString(sig),
		CertPEM:   string(p.leafPEM),
	}
	buf, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return buf
}

// ============================================================================
// NewVerifier
// ============================================================================

func TestNewVerifier_LoadsRootCA(t *testing.T) {
	pki := newPKI(t)
	v := NewVerifier(pki.trustDir)
	if !v.TrustConfigured() {
		t.Error("TrustConfigured: want true")
	}
	if !v.Available() || v.Mode() != TrustEnforced {
		t.Errorf("Mode() = %q, want %q", v.Mode(), TrustEnforced)
	}
}

// REPLACES TestNewVerifier_MissingRootIsDevPermissive, which asserted the
// defect: a missing root-ca.pem used to hand back a verifier that skipped every
// signature check and flagged the bundle "<unverified>". A missing trust root
// is now a refusal, and permissiveness has to be asked for by name.
func TestNewVerifier_MissingRootIsUnavailableNotPermissive(t *testing.T) {
	dir := t.TempDir() // no root-ca.pem
	v := NewVerifier(dir)
	if v.TrustConfigured() {
		t.Error("TrustConfigured: want false (no root pem)")
	}
	if v.Available() {
		t.Fatal("a missing trust root must NOT yield a usable verifier")
	}
	if v.Mode() != TrustUnavailable {
		t.Errorf("Mode() = %q, want %q", v.Mode(), TrustUnavailable)
	}
	if r := v.UnavailableReason(); !strings.Contains(r, "root-ca.pem") {
		t.Errorf("the reason must name the missing file; got %q", r)
	}
}

// An unparseable root CA used to be a hard error that the api turned into
// log.Fatalf. On an appliance (Restart=always, read-only rootfs) a process that
// will not start is unreachable and unfixable — #89. So it degrades to the same
// unavailable posture as a missing file: nothing verifies, the api still boots.
func TestNewVerifier_BadPEMIsUnavailableNotFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "root-ca.pem"), []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	v := NewVerifier(dir)
	if v.Available() {
		t.Fatal("an unparseable root CA must not yield a usable verifier")
	}
	if r := v.UnavailableReason(); !strings.Contains(r, "root-ca.pem") {
		t.Errorf("the reason must name the file; got %q", r)
	}
}

// The zero value is the last line of defence: a Verifier nobody constructed
// through a constructor must still refuse.
func TestZeroValueVerifierRefuses(t *testing.T) {
	var v Verifier
	if v.Available() {
		t.Fatal("the zero-value Verifier must not be available")
	}
	if _, _, err := v.Verify(strings.NewReader("{}"), FormatRaspbundle); !errors.Is(err, ErrTrustUnavailable) {
		t.Errorf("want ErrTrustUnavailable, got %v", err)
	}
}

// ============================================================================
// Verify: mock format with trust configured
// ============================================================================

func TestVerify_MockBundle_Valid(t *testing.T) {
	pki := newPKI(t)
	v := NewVerifier(pki.trustDir)
	manifest := proto.BundleManifest{
		Version:      "2026.05.30",
		Compatible:   "rasputin-rpi-arm64",
		Architecture: "arm64",
	}
	payload := []byte("hello world bundle")
	buf := pki.buildMockBundle(t, manifest, payload)

	got, shaHex, err := v.Verify(strings.NewReader(string(buf)), FormatRaspbundle)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Version != manifest.Version {
		t.Errorf("Version: got %q", got.Version)
	}
	if got.SignedBy != "Rasputin Build Signer" {
		t.Errorf("SignedBy: got %q", got.SignedBy)
	}
	// sha256 should be over the whole envelope buf.
	sum := sha256.Sum256(buf)
	if shaHex != hex.EncodeToString(sum[:]) {
		t.Errorf("sha mismatch")
	}
	if got.SizeBytes != int64(len(buf)) {
		t.Errorf("SizeBytes: got %d want %d", got.SizeBytes, len(buf))
	}
}

func TestVerify_MockBundle_TamperedPayload(t *testing.T) {
	pki := newPKI(t)
	v := NewVerifier(pki.trustDir)
	manifest := proto.BundleManifest{Version: "1", Compatible: "rasputin-rpi-arm64", Architecture: "arm64"}
	buf := pki.buildMockBundle(t, manifest, []byte("original"))

	// Decode → flip payload → re-encode, leaving signature intact.
	var env raspbundleEnvelope
	if err := json.Unmarshal(buf, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.Payload = hex.EncodeToString([]byte("TAMPERED"))
	tampered, _ := json.Marshal(env)

	if _, _, err := v.Verify(strings.NewReader(string(tampered)), FormatRaspbundle); err == nil {
		t.Error("want error for tampered payload, got nil")
	}
}

func TestVerify_MockBundle_BadCertChain(t *testing.T) {
	// PKI A signs; verifier trusts PKI B's root → chain verify should fail.
	pkiA := newPKI(t)
	pkiB := newPKI(t)
	manifest := proto.BundleManifest{Version: "1", Compatible: "x", Architecture: "arm64"}
	buf := pkiA.buildMockBundle(t, manifest, []byte("payload"))
	v := NewVerifier(pkiB.trustDir)

	if _, _, err := v.Verify(strings.NewReader(string(buf)), FormatRaspbundle); err == nil {
		t.Error("want chain-verify error")
	}
}

func TestVerify_MockBundle_MissingManifestVersion(t *testing.T) {
	pki := newPKI(t)
	v := NewVerifier(pki.trustDir)
	buf := pki.buildMockBundle(t, proto.BundleManifest{}, []byte("x"))
	if _, _, err := v.Verify(strings.NewReader(string(buf)), FormatRaspbundle); err == nil {
		t.Error("want error: manifest.version required")
	}
}

func TestVerify_MockBundle_NoCert(t *testing.T) {
	pki := newPKI(t)
	v := NewVerifier(pki.trustDir)
	buf := pki.buildMockBundle(t, proto.BundleManifest{Version: "1", Architecture: "arm64", Compatible: "x"}, []byte("x"))
	// Strip the cert PEM.
	var env raspbundleEnvelope
	_ = json.Unmarshal(buf, &env)
	env.CertPEM = ""
	stripped, _ := json.Marshal(env)
	if _, _, err := v.Verify(strings.NewReader(string(stripped)), FormatRaspbundle); err == nil {
		t.Error("want error for missing cert")
	}
}

// ============================================================================
// Verify: no trust root (fail closed) and the explicit dev opt-in
// ============================================================================

// REPLACES TestVerify_NoTrustReturnsUnverified, which asserted the fail-open:
// a well-formed bundle with no trust root came back with a manifest and a
// nil error, ready to be stored and installed.
func TestVerify_NoTrustRootRefusesEveryBundle(t *testing.T) {
	dir := t.TempDir() // no root pem
	v := NewVerifier(dir)
	pki := newPKI(t) // a perfectly valid bundle — signed, chain intact
	manifest := proto.BundleManifest{Version: "1", Compatible: "x", Architecture: "arm64"}
	buf := pki.buildMockBundle(t, manifest, []byte("any"))

	man, _, err := v.Verify(strings.NewReader(string(buf)), FormatRaspbundle)
	if err == nil {
		t.Fatal("a bundle must not verify with no trust root")
	}
	if !errors.Is(err, ErrTrustUnavailable) {
		t.Errorf("want ErrTrustUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "root-ca.pem") {
		t.Errorf("the error must name the missing trust root; got %v", err)
	}
	if man != nil {
		t.Error("no manifest may be returned when nothing could be verified")
	}
	// VerifyFile is the path the api actually calls; it must refuse too.
	path := filepath.Join(t.TempDir(), "bundle.raspbundle")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := v.VerifyFile(path, FormatRaspbundle); !errors.Is(err, ErrTrustUnavailable) {
		t.Errorf("VerifyFile: want ErrTrustUnavailable, got %v", err)
	}
}

// The dev workflow the old fail-open existed to serve is still reachable — by
// name. RASPUTIN_UPDATE_TRUST=dev-permissive is what the api wires to this.
func TestNewDevPermissiveVerifier_OptInStillSkipsTheCheck(t *testing.T) {
	dir := t.TempDir() // no root pem
	v := NewDevPermissiveVerifier(dir)
	if !v.Available() || v.Mode() != TrustDevPermissive {
		t.Fatalf("Mode() = %q, want %q", v.Mode(), TrustDevPermissive)
	}
	pki := newPKI(t)
	manifest := proto.BundleManifest{Version: "1", Compatible: "x", Architecture: "arm64"}
	buf := pki.buildMockBundle(t, manifest, []byte("any"))

	got, _, err := v.Verify(strings.NewReader(string(buf)), FormatRaspbundle)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.SignedBy != "<unverified>" {
		t.Errorf("SignedBy: want <unverified>, got %q", got.SignedBy)
	}
}

// The opt-in is a floor, not a ceiling: where a root CA exists it is loaded and
// enforced, so setting the dev var on a provisioned box does not weaken it.
func TestNewDevPermissiveVerifier_StillEnforcesAnExistingRoot(t *testing.T) {
	pkiA := newPKI(t)
	pkiB := newPKI(t)
	v := NewDevPermissiveVerifier(pkiB.trustDir)
	if v.Mode() != TrustEnforced {
		t.Fatalf("Mode() = %q, want %q with a root CA present", v.Mode(), TrustEnforced)
	}
	buf := pkiA.buildMockBundle(t, proto.BundleManifest{Version: "1", Compatible: "x", Architecture: "arm64"}, []byte("p"))
	if _, _, err := v.Verify(strings.NewReader(string(buf)), FormatRaspbundle); err == nil {
		t.Error("a bundle from the wrong PKI must still fail the chain check")
	}
}

// ============================================================================
// Verify: real RAUC path is rejected without rauc CLI
// ============================================================================

func TestVerify_RealRAUCBundleRejected(t *testing.T) {
	pki := newPKI(t)
	v := NewVerifier(pki.trustDir)
	// Non-JSON binary content (squashfs-ish prefix), no .raspbundle hint.
	binBuf := []byte{0x68, 0x73, 0x71, 0x73, 0x00, 0x01, 0x02, 0x03}
	if _, _, err := v.Verify(strings.NewReader(string(binBuf)), FormatRAUC); err == nil {
		t.Error("want error for real .raucb without rauc CLI, got nil")
	}
}

// ============================================================================
// VerifyFile
// ============================================================================

func TestVerifyFile(t *testing.T) {
	pki := newPKI(t)
	v := NewVerifier(pki.trustDir)
	manifest := proto.BundleManifest{Version: "9", Compatible: "x", Architecture: "amd64"}
	buf := pki.buildMockBundle(t, manifest, []byte("file payload"))
	path := filepath.Join(t.TempDir(), "bundle.raspbundle")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, _, err := v.VerifyFile(path, FormatRaspbundle)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if got.Version != "9" {
		t.Errorf("Version: got %q", got.Version)
	}
}

func TestVerifyFile_NotFound(t *testing.T) {
	pki := newPKI(t)
	v := NewVerifier(pki.trustDir)
	if _, _, err := v.VerifyFile(filepath.Join(t.TempDir(), "missing"), FormatRaspbundle); err == nil {
		t.Error("want error for missing file")
	}
}

// ============================================================================
// VerifyEnvelopeBytes
// ============================================================================

func TestVerifyEnvelopeBytes(t *testing.T) {
	pki := newPKI(t)
	manifest := proto.BundleManifest{Version: "1", Compatible: "x", Architecture: "amd64"}
	buf := pki.buildMockBundle(t, manifest, []byte("payload"))
	got, err := VerifyEnvelopeBytes(buf)
	if err != nil {
		t.Fatalf("VerifyEnvelopeBytes: %v", err)
	}
	if got.Version != "1" {
		t.Errorf("Version: got %q", got.Version)
	}
}

func TestVerifyEnvelopeBytes_NotJSON(t *testing.T) {
	if _, err := VerifyEnvelopeBytes([]byte("plain text")); err == nil {
		t.Error("want error for non-JSON bytes")
	}
}

// ============================================================================
// Format is declared, never sniffed
// ============================================================================

// The format used to be chosen by looking at the bundle's first non-space byte
// for '{', so a JSON blob selected the raspbundle verifier no matter what the
// operator or the signed release manifest said the artifact was. Content that
// picks its own checker is the defect; these cases pin that it cannot.
func TestVerify_FormatIsNeverInferredFromContent(t *testing.T) {
	pki := newPKI(t)
	v := NewVerifier(pki.trustDir)
	manifest := proto.BundleManifest{Version: "1", Compatible: "x", Architecture: "arm64"}
	jsonBundle := pki.buildMockBundle(t, manifest, []byte("payload"))

	// A cryptographically VALID raspbundle, declared as a RAUC artifact: the
	// bytes do not get to re-route themselves to the path that would accept
	// them. (Under the old sniff this returned a manifest and a nil error.)
	man, _, err := v.Verify(strings.NewReader(string(jsonBundle)), FormatRAUC)
	if err == nil {
		t.Fatal("JSON content must not select the raspbundle path when .raucb was declared")
	}
	if man != nil {
		t.Error("no manifest may come back from a format the caller did not ask for")
	}
	if !strings.Contains(err.Error(), "rauc") {
		t.Errorf("want the .raucb refusal, got %v", err)
	}

	// An undeclared format is refused rather than guessed — including the zero
	// value, which is what a caller that forgets the argument would pass.
	for _, f := range []Format{"", "raspbundle", ".rootfs", ".img.gz"} {
		if _, _, err := v.Verify(strings.NewReader(string(jsonBundle)), f); err == nil {
			t.Errorf("format %q must be refused, not guessed", f)
		}
	}
}

// ============================================================================
// checkRSA fallback
// ============================================================================

func TestCheckRSA_NonRSAKey(t *testing.T) {
	// Build a self-signed ECDSA-like leaf would be heavyweight; just feed a
	// cert whose PublicKey we synthesize to non-RSA via reflection-of-intent:
	// easier — pass a cert pointer with a manually replaced PublicKey field.
	pki := newPKI(t)
	leaf := *pki.leafCert
	leaf.PublicKey = "not an rsa pubkey"
	if err := checkRSA(&leaf, []byte("hash"), []byte("sig")); err == nil {
		t.Error("want error for non-RSA public key")
	}
}

func TestCheckRSA_ValidSignaturePasses(t *testing.T) {
	pki := newPKI(t)
	payload := []byte("payload-bytes")
	hashed := sha256.Sum256(payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, pki.leafKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := checkRSA(pki.leafCert, hashed[:], sig); err != nil {
		t.Errorf("checkRSA: want pass, got %v", err)
	}
}
