package updater

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/artifactsig"
)

// The CMS fixtures live in artifactsig's testdata and are reached across
// modules, exactly as catalogsync's verifier tests reach them. Hand-rolling a
// second set here would mean this verifier was proven against signatures we
// made up rather than against the ones the release pipeline's own `openssl cms
// -sign` command emits — which is the only property worth testing.
func fixture(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "artifactsig", "testdata", name)
}

// trustDirWith writes the named fixture root CA into a fresh trust dir and
// returns the dir, so NewVerifier can be exercised the way main wires it.
func trustDirWith(t *testing.T, rootFixture string) string {
	t.Helper()
	dir := t.TempDir()
	raw, err := os.ReadFile(fixture(t, rootFixture))
	if err != nil {
		t.Fatalf("read %s: %v", rootFixture, err)
	}
	if err := os.WriteFile(filepath.Join(dir, RootCAName), raw, 0o600); err != nil {
		t.Fatalf("write trust root: %v", err)
	}
	return dir
}

func TestNewVerifier_LoadsRootCA(t *testing.T) {
	v := NewVerifier(trustDirWith(t, "root-ca.pem"))
	if !v.TrustConfigured() {
		t.Fatal("TrustConfigured = false with a real root CA present")
	}
	if !v.Available() {
		t.Error("Available = false with a real root CA present")
	}
	if got := v.Mode(); got != TrustEnforced {
		t.Errorf("Mode = %q, want %q", got, TrustEnforced)
	}
	if got := v.UnavailableReason(); got != "" {
		t.Errorf("UnavailableReason = %q, want empty", got)
	}
}

// A missing root CA is a REFUSAL, not a downgrade. This is the fail-open the
// verifier's type doc exists to describe: deleting one file used to turn every
// signature check off.
func TestNewVerifier_MissingRootIsUnavailableNotPermissive(t *testing.T) {
	v := NewVerifier(t.TempDir())
	if v.TrustConfigured() {
		t.Fatal("TrustConfigured = true with no root CA")
	}
	if v.Available() {
		t.Fatal("Available = true with no root CA — the verifier degraded instead of refusing")
	}
	if got := v.Mode(); got != TrustUnavailable {
		t.Errorf("Mode = %q, want %q", got, TrustUnavailable)
	}
	reason := v.UnavailableReason()
	if !strings.Contains(reason, "no update trust root") {
		t.Errorf("the reason must name what is missing, got %q", reason)
	}
	if !strings.Contains(reason, "pki-init.sh") {
		t.Errorf("the reason must name the fix, got %q", reason)
	}
}

// An unparseable root is a configuration fault reported once at startup, not a
// per-upload verification failure that reads like a bad artifact.
func TestNewVerifier_BadPEMIsUnavailableNotFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, RootCAName), []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(dir)
	if v.Available() {
		t.Fatal("a garbage root CA produced an available verifier")
	}
	if !strings.Contains(v.UnavailableReason(), "no certificates parsed") {
		t.Errorf("reason = %q", v.UnavailableReason())
	}
}

// The zero value is what a struct literal or a forgotten constructor produces.
// It must refuse like any other unavailable verifier rather than sail through.
func TestZeroValueVerifierRefuses(t *testing.T) {
	var v Verifier
	if v.Available() {
		t.Fatal("the zero-value Verifier is available")
	}
	_, err := v.VerifyArtifact(fixture(t, "payload.bin"), fixture(t, "payload.bin.sig"))
	if !errors.Is(err, ErrTrustUnavailable) {
		t.Fatalf("want ErrTrustUnavailable, got %v", err)
	}
	if got := v.UnavailableReason(); got == "" {
		t.Error("an unavailable verifier must say why")
	}
}

// The happy path, against the artifact and detached signature the release
// pipeline's own signing command produces.
func TestVerifyArtifact_PipelineSignature(t *testing.T) {
	v := NewVerifier(trustDirWith(t, "root-ca.pem"))
	res, err := v.VerifyArtifact(fixture(t, "payload.bin"), fixture(t, "payload.bin.sig"))
	if err != nil {
		t.Fatalf("VerifyArtifact: %v", err)
	}
	if res.Signer == "" {
		t.Error("a verified result must attribute the signature to a leaf")
	}
	if res.DigestAlg != "sha256" {
		t.Errorf("DigestAlg = %q, want sha256", res.DigestAlg)
	}
}

// THE PURPOSE SPLIT, on the api's side of it. A catalog bundle is a real,
// well-formed signature chaining to the same root — the only thing wrong with
// it is that its signer was never issued to sign an OS artifact. An api that
// accepted it would let a compromise of catalog CI produce something the
// update path installs.
func TestVerifyArtifact_CatalogLeafIsRefused(t *testing.T) {
	v := NewVerifier(trustDirWith(t, "root-ca.pem"))
	_, err := v.VerifyArtifact(fixture(t, "payload.bin"), fixture(t, "payload.bin.catalog.sig"))
	if err == nil {
		t.Fatal("a catalog-purpose signature was accepted for an OS update artifact")
	}
	var wrong *artifactsig.ErrWrongPurpose
	if !errors.As(err, &wrong) {
		t.Errorf("want ErrWrongPurpose so the fault is distinguishable from a broken signature; got %T: %v", err, err)
	}
}

// The retired envelope's chain check passed x509.ExtKeyUsageAny, so a leaf
// with no stated purpose satisfied it. The detached path requires the release
// OID and nothing else does.
func TestVerifyArtifact_GenericCodeSigningLeafIsRefused(t *testing.T) {
	v := NewVerifier(trustDirWith(t, "root-ca.pem"))
	if _, err := v.VerifyArtifact(fixture(t, "payload.bin"), fixture(t, "payload.bin.generic.sig")); err == nil {
		t.Fatal("a leaf carrying only generic codeSigning was accepted for an OS update artifact")
	}
}

// A properly signed artifact under someone else's root. Without this, a
// verifier that parses the CMS and forgets to pin the root passes everything
// else in this file.
func TestVerifyArtifact_ForeignRootIsRefused(t *testing.T) {
	v := NewVerifier(trustDirWith(t, "root-ca.pem"))
	if _, err := v.VerifyArtifact(fixture(t, "payload.bin"), fixture(t, "payload.bin.other.sig")); err == nil {
		t.Fatal("a signature under a foreign root was accepted")
	}
}

func TestVerifyArtifact_TamperedArtifactIsRefused(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile(fixture(t, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xFF
	tampered := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(tampered, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(trustDirWith(t, "root-ca.pem"))
	if _, err := v.VerifyArtifact(tampered, fixture(t, "payload.bin.sig")); err == nil {
		t.Fatal("a flipped byte in the artifact still verified")
	}
}

// A missing `.sig` is a hard failure, never a fallback to some weaker check.
func TestVerifyArtifact_MissingSignatureIsRefused(t *testing.T) {
	v := NewVerifier(trustDirWith(t, "root-ca.pem"))
	_, err := v.VerifyArtifact(fixture(t, "payload.bin"), filepath.Join(t.TempDir(), "absent.sig"))
	if !errors.Is(err, artifactsig.ErrNoSignature) {
		t.Fatalf("want ErrNoSignature, got %v", err)
	}
}

// An unavailable verifier refuses before either file is opened, so an api with
// no PKI answers "this installation cannot verify" rather than "your artifact
// is bad" — two different problems with two different fixes.
func TestVerifyArtifact_NoTrustRootRefusesEverything(t *testing.T) {
	v := NewVerifier(t.TempDir())
	_, err := v.VerifyArtifact(fixture(t, "payload.bin"), fixture(t, "payload.bin.sig"))
	if !errors.Is(err, ErrTrustUnavailable) {
		t.Fatalf("want ErrTrustUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "no update trust root") {
		t.Errorf("the refusal must carry the reason, got %v", err)
	}
}

// There is no mode that skips the check. This is the assertion that would fail
// if a permissive verifier were reintroduced: nothing in the package's surface
// can turn a refusal into a pass.
func TestVerifier_HasNoPermissivePosture(t *testing.T) {
	for _, v := range []*Verifier{NewVerifier(t.TempDir()), NewVerifier(trustDirWith(t, "root-ca.pem"))} {
		if got := v.Mode(); got != TrustEnforced && got != TrustUnavailable {
			t.Errorf("Mode returned %q — a third posture is back", got)
		}
		if v.Available() != v.TrustConfigured() {
			t.Error("a verifier is available exactly when a trust root is configured; " +
				"a gap between the two is where a permissive mode lives")
		}
	}
}
