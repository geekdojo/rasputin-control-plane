package artifactsig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

// The fixtures under testdata/ are produced by gen-fixtures.sh, which runs the
// release pipeline's own `openssl cms -sign` invocation against a
// production-shaped chain. That is the point of them: these tests assert the
// verifier accepts what CI actually emits, not what a Go signer happens to
// produce. The hermetic Go-built cases further down cover the shapes openssl
// will not conveniently make (expired signer, stripped attributes).

func fixture(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("testdata", name)
}

func TestVerify_PipelineSignature(t *testing.T) {
	res, err := Verify(fixture(t, "payload.bin"), fixture(t, "payload.bin.sig"), fixture(t, "root-ca.pem"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Signer != "Rasputin Test Release Leaf" {
		t.Errorf("Signer = %q, want the leaf CN", res.Signer)
	}
	if res.Issuer != "Rasputin Test Intermediate CA" {
		t.Errorf("Issuer = %q, want the intermediate CN", res.Issuer)
	}
	// The chain only builds if the intermediate travelled inside the CMS — the
	// trust root pool holds the ROOT alone. The pipeline passes it via
	// -certfile, and the OS side learned this the hard way (release-pipeline.md
	// records rauc's --intermediate= being mandatory for the same reason), so
	// assert it rather than trusting the fixture.
	if res.Issuer == res.Signer {
		t.Errorf("leaf appears self-issued; the intermediate did not travel in the CMS")
	}

	want, err := os.ReadFile(fixture(t, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(want)
	if res.DigestHex != hex.EncodeToString(sum[:]) {
		t.Errorf("DigestHex = %s, want %s", res.DigestHex, hex.EncodeToString(sum[:]))
	}
	if res.DigestAlg != "sha256" {
		t.Errorf("DigestAlg = %q, want sha256", res.DigestAlg)
	}
}

// A well-formed signature under someone else's root. This is the case the whole
// issue is about: the sha256 gate would happily pass these bytes, because the
// bytes are exactly what the (hostile) publisher intended to ship.
func TestVerify_ForeignRootRejected(t *testing.T) {
	_, err := Verify(fixture(t, "payload.bin"), fixture(t, "payload.bin.other.sig"), fixture(t, "root-ca.pem"))
	if err == nil {
		t.Fatal("Verify accepted a signature chaining to a foreign root")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error should name the chain failure, got: %v", err)
	}

	// ...and the same signature verifies fine against ITS own root, which
	// proves the rejection above is the pinning working rather than the fixture
	// being malformed.
	if _, err := Verify(fixture(t, "payload.bin"), fixture(t, "payload.bin.other.sig"),
		fixture(t, "other-root-ca.pem")); err != nil {
		t.Fatalf("foreign signature should verify under its own root: %v", err)
	}
}

func TestVerify_TamperedArtifactRejected(t *testing.T) {
	orig, err := os.ReadFile(fixture(t, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"flipped bit in the middle", func(b []byte) []byte {
			c := append([]byte(nil), b...)
			c[len(c)/2] ^= 0x01
			return c
		}},
		{"truncated by one byte", func(b []byte) []byte { return append([]byte(nil), b[:len(b)-1]...) }},
		{"one byte appended", func(b []byte) []byte { return append(append([]byte(nil), b...), 0x00) }},
		{"emptied", func(b []byte) []byte { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "payload.bin")
			if err := os.WriteFile(path, tc.mutate(orig), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(path, fixture(t, "payload.bin.sig"), fixture(t, "root-ca.pem")); err == nil {
				t.Fatal("Verify accepted a tampered artifact")
			}
		})
	}
}

func TestVerify_SignatureProblems(t *testing.T) {
	good, err := os.ReadFile(fixture(t, "payload.bin.sig"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		sig     []byte
		absent  bool
		wantErr error
	}{
		{name: "absent", absent: true, wantErr: ErrNoSignature},
		{name: "empty file", sig: []byte{}, wantErr: ErrNoSignature},
		{name: "truncated DER", sig: good[:len(good)/2]},
		{name: "not DER at all", sig: []byte("-----BEGIN PKCS7-----\nnope\n")},
		{name: "flipped byte in the signature", sig: func() []byte {
			c := append([]byte(nil), good...)
			c[len(c)-8] ^= 0xff
			return c
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sigPath := filepath.Join(t.TempDir(), "payload.bin.sig")
			if !tc.absent {
				if err := os.WriteFile(sigPath, tc.sig, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			_, err := Verify(fixture(t, "payload.bin"), sigPath, fixture(t, "root-ca.pem"))
			if err == nil {
				t.Fatal("Verify accepted a broken signature")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// The size cap is a boundary and boundaries are where caps fail. A signature of
// exactly maxSigBytes is legal and must be rejected on its CONTENTS, not on its
// length; one byte more must be rejected on length alone and never read. Both
// halves matter: a cap that is off by one either truncates a legitimate object
// (turning a valid signature into "tampered") or admits an unbounded read.
func TestVerify_SignatureSizeCapBoundary(t *testing.T) {
	for _, tc := range []struct {
		name       string
		size       int
		wantTooBig bool
	}{
		{name: "exactly at the cap", size: maxSigBytes, wantTooBig: false},
		{name: "one byte over the cap", size: maxSigBytes + 1, wantTooBig: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sigPath := filepath.Join(t.TempDir(), "payload.bin.sig")
			if err := os.WriteFile(sigPath, make([]byte, tc.size), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := Verify(fixture(t, "payload.bin"), sigPath, fixture(t, "root-ca.pem"))
			if err == nil {
				t.Fatal("Verify accepted a signature of zero bytes padded to the cap")
			}
			tooBig := strings.Contains(err.Error(), "exceeds")
			if tooBig != tc.wantTooBig {
				t.Errorf("error = %v; rejected-for-size = %v, want %v", err, tooBig, tc.wantTooBig)
			}
		})
	}
}

// A trust root that cannot be read is indistinguishable from one an attacker
// removed, so it must fail rather than fall through to an empty pool (which
// x509 treats as "use the system roots" on some platforms — a bypass).
func TestVerify_TrustRootProblems(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "absent.pem"), garbage} {
		_, err := Verify(fixture(t, "payload.bin"), fixture(t, "payload.bin.sig"), path)
		if !errors.Is(err, ErrNoTrustRoot) {
			t.Errorf("trust root %s: error = %v, want ErrNoTrustRoot", filepath.Base(path), err)
		}
	}
}

// The artifact is never read into memory — see the package doc, choice 2. This
// asserts it structurally: a regression to os.ReadFile would allocate the whole
// artifact and blow the budget immediately.
func TestVerify_StreamsTheArtifact(t *testing.T) {
	const size = 32 << 20
	dir := t.TempDir()
	big := filepath.Join(dir, "big.bin")
	blob := make([]byte, size)
	if _, err := rand.Read(blob[:1<<20]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	blob = nil

	key, chain := testChain(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	sig := signDetached(t, big, key, chain)
	sigPath := filepath.Join(dir, "big.bin.sig")
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(dir, "root.pem")
	writePEM(t, rootPath, chain[len(chain)-1].Raw)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := Verify(big, sigPath, rootPath); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	runtime.ReadMemStats(&after)

	// Generous: the honest cost is one 32 KiB io.Copy buffer plus the parsed
	// CMS. 4 MiB still fails loudly if 32 MiB of artifact ever lands on the heap.
	const budget = 4 << 20
	if grew := after.TotalAlloc - before.TotalAlloc; grew > budget {
		t.Errorf("Verify allocated %d bytes verifying a %d-byte artifact; it must stream, not buffer", grew, size)
	}
}

// The chain is checked at time.Now(), matching RAUC on Rasputin OS, which pins
// the same root with no allow-expired escape. These two cases are what that
// decision MEANS in practice, and they are here so that changing the posture
// has to be a deliberate edit to a named expectation.
func TestVerify_SignerValidityIsCheckedAtVerifyTime(t *testing.T) {
	for _, tc := range []struct {
		name                string
		notBefore, notAfter time.Time
	}{
		{"expired signer", time.Now().Add(-72 * time.Hour), time.Now().Add(-time.Hour)},
		{"not yet valid signer", time.Now().Add(time.Hour), time.Now().Add(72 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "payload.bin")
			if err := os.WriteFile(artifact, []byte("hello"), 0o644); err != nil {
				t.Fatal(err)
			}
			key, chain := testChain(t, tc.notBefore, tc.notAfter)
			sigPath := filepath.Join(dir, "payload.bin.sig")
			if err := os.WriteFile(sigPath, signDetached(t, artifact, key, chain), 0o644); err != nil {
				t.Fatal(err)
			}
			rootPath := filepath.Join(dir, "root.pem")
			writePEM(t, rootPath, chain[len(chain)-1].Raw)

			if _, err := Verify(artifact, sigPath, rootPath); err == nil {
				t.Fatal("Verify accepted a signature whose signer is not valid now")
			}
		})
	}
}

// The sharp edge guarded in Verify: pkcs7 checks the signature against
// p7.Content when a signer has no authenticated attributes, and this package
// deliberately keeps Content empty so the artifact can stream. Without the
// guard, a signature over NOTHING would verify — the artifact would never be
// looked at, and the digest binding would silently vanish.
func TestVerify_SignerWithoutAuthenticatedAttributesRejected(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(artifact, []byte("the real artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	key, chain := testChain(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	content, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.SignWithoutAttr(chain[0], key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	sd.AddCertificate(chain[1])
	sd.Detach()
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "payload.bin.sig")
	if err := os.WriteFile(sigPath, der, 0o644); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(dir, "root.pem")
	writePEM(t, rootPath, chain[len(chain)-1].Raw)

	_, err = Verify(artifact, sigPath, rootPath)
	if !errors.Is(err, ErrNoSignedAttrs) {
		t.Fatalf("error = %v, want ErrNoSignedAttrs", err)
	}
}

// An opaque (attached) CMS carries its own content. Honouring one would verify
// a signature over the bytes inside the .sig and never look at the artifact on
// disk — so the artifact could be anything at all.
func TestVerify_AttachedSignatureRejected(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(artifact, []byte("the real artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	key, chain := testChain(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	sd, err := pkcs7.NewSignedData([]byte("something else entirely"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSignerChain(chain[0], key, chain[1:2], pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	der, err := sd.Finish() // no Detach() — content stays inside
	if err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "payload.bin.sig")
	if err := os.WriteFile(sigPath, der, 0o644); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(dir, "root.pem")
	writePEM(t, rootPath, chain[len(chain)-1].Raw)

	if _, err := Verify(artifact, sigPath, rootPath); !errors.Is(err, ErrNotDetached) {
		t.Fatalf("error = %v, want ErrNotDetached", err)
	}
}

func TestSigPathFor(t *testing.T) {
	if got := SigPathFor("/var/lib/rasputin/bundles/abc.rootfs"); got != "/var/lib/rasputin/bundles/abc.rootfs.sig" {
		t.Errorf("SigPathFor = %q", got)
	}
}

func TestTrustRootPath(t *testing.T) {
	t.Setenv(TrustRootEnv, "")
	if got := TrustRootPath(); got != DefaultTrustRoot {
		t.Errorf("unset %s: got %q, want the baked default %q", TrustRootEnv, got, DefaultTrustRoot)
	}
	t.Setenv(TrustRootEnv, "/somewhere/else.pem")
	if got := TrustRootPath(); got != "/somewhere/else.pem" {
		t.Errorf("set %s: got %q", TrustRootEnv, got)
	}
}

// --- hermetic chain + signing helpers --------------------------------------
// Used only for the shapes openssl will not conveniently produce. Returns the
// leaf key and a chain ordered leaf → intermediate → root.

func testChain(t *testing.T, leafNotBefore, leafNotAfter time.Time) (*rsa.PrivateKey, []*x509.Certificate) {
	t.Helper()
	far := time.Now().Add(-time.Hour)
	rootKey, root := selfSigned(t, "Test Root", far, far.Add(10*365*24*time.Hour))
	interKey, inter := issued(t, "Test Intermediate", far, far.Add(10*365*24*time.Hour), root, rootKey, true)
	leafKey, leaf := issued(t, "Test Leaf", leafNotBefore, leafNotAfter, inter, interKey, false)
	return leafKey, []*x509.Certificate{leaf, inter, root}
}

func selfSigned(t *testing.T, cn string, notBefore, notAfter time.Time) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func issued(t *testing.T, cn string, notBefore, notAfter time.Time,
	parent *x509.Certificate, parentKey *rsa.PrivateKey, isCA bool) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
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

func signDetached(t *testing.T, artifactPath string, key *rsa.PrivateKey, chain []*x509.Certificate) []byte {
	t.Helper()
	content, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSignerChain(chain[0], key, chain[1:2], pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	sd.Detach()
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func writePEM(t *testing.T, path string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}
