package nodekeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Generated once, then loaded: a second Ensure must return the SAME keys.
// A node that re-minted its identity on every agent restart would raise the
// control plane's key-change alert on every restart, which would make the
// alert worthless.
func TestEnsure_GeneratesOnceAndLoadsAfter(t *testing.T) {
	dir := t.TempDir()
	first, generated, err := Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := proto.NodeKeyPurposes()
	if !reflect.DeepEqual(generated, want) {
		t.Fatalf("generated = %v, want %v", generated, want)
	}
	for _, p := range want {
		if first.Signer(p) == nil {
			t.Fatalf("no signer for %s", p)
		}
		if first.Hashes()[p] == "" {
			t.Fatalf("no hash for %s", p)
		}
	}
	if first.Hashes()[proto.NodeKeyAgent] == first.Hashes()[proto.NodeKeyCollector] {
		t.Fatal("the agent and collector share one key")
	}

	second, generated, err := Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated) != 0 {
		t.Errorf("a second Ensure generated %v", generated)
	}
	if !first.Hashes().Equal(second.Hashes()) {
		t.Errorf("hashes changed across Ensure: %v then %v", first.Hashes(), second.Hashes())
	}
}

// The hash reported is the hash of the key on disk. Anything else and the
// control plane records an identity the node cannot present.
func TestEnsure_HashMatchesTheKeyOnDisk(t *testing.T) {
	dir := t.TempDir()
	keys, _, err := Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range proto.NodeKeyPurposes() {
		blob, err := os.ReadFile(KeyPath(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		signer, err := parse(blob)
		if err != nil {
			t.Fatal(err)
		}
		want, err := proto.NodeKeySPKIHash(signer.Public())
		if err != nil {
			t.Fatal(err)
		}
		if got := keys.Hashes()[p]; got != want {
			t.Errorf("%s: reported %q, key on disk hashes to %q", p, got, want)
		}
	}
}

// 0600 in a 0700 directory, and a wider mode left by a restore or a copy is
// tightened rather than accepted.
func TestEnsure_Modes(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("key dir mode %o, want 700", got)
	}
	for _, p := range proto.NodeKeyPurposes() {
		fi, err := os.Stat(KeyPath(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("%s key mode %o, want 600", p, got)
		}
	}

	loose := KeyPath(dir, proto.NodeKeyAgent)
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(loose)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("a 0644 key was left at %o, want tightened to 600", got)
	}
	di, err = os.Stat(Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("a 0755 key dir was left at %o, want tightened to 700", got)
	}
}

// A key file that does not parse is an ERROR, never a reason to generate a
// new one: replacing a key the control plane recorded would take the node off
// HTTPS, and minting a new identity silently is exactly what the key-change
// alert exists to stop happening unnoticed.
func TestEnsure_RefusesAnUnreadableKeyRatherThanReplacingIt(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	path := KeyPath(dir, proto.NodeKeyCollector)
	before, err := os.ReadFile(KeyPath(dir, proto.NodeKeyAgent))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Ensure(dir); err == nil {
		t.Fatal("Ensure accepted an unusable key file")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "not a key\n" {
		t.Errorf("the unusable file was rewritten: %q, %v", got, err)
	}
	after, err := os.ReadFile(KeyPath(dir, proto.NodeKeyAgent))
	if err != nil || string(after) != string(before) {
		t.Errorf("the other key was disturbed by the failure")
	}
}

func TestEnsure_RequiresAStateDir(t *testing.T) {
	if _, _, err := Ensure(""); err == nil {
		t.Fatal("Ensure accepted an empty state dir")
	}
}

// A nil key set reports nothing rather than panicking, so a caller that never
// got keys does not have to guard every use.
func TestNilKeysReportNothing(t *testing.T) {
	var k *Keys
	if k.Hashes() != nil || k.Signer(proto.NodeKeyAgent) != nil || k.Path(proto.NodeKeyAgent) != "" {
		t.Error("a nil key set answered something")
	}
}

func TestPathsAreUnderTheStateDir(t *testing.T) {
	dir := t.TempDir()
	keys, _, err := Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "keys", "collector.key")
	if got := keys.Path(proto.NodeKeyCollector); got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}

// A key an operator made with openssl comes out as an "EC PRIVATE KEY" block
// rather than PKCS#8. It is accepted, and the key it yields is the one in the
// file — a node whose key was produced that way must not read as unusable,
// which Ensure treats as a hard error rather than a reason to generate.
func TestParse_AcceptsAnOpenSSLECKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := parse(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatalf("an EC PRIVATE KEY block was refused: %v", err)
	}
	got, err := proto.NodeKeySPKIHash(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	want, err := proto.NodeKeySPKIHash(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("parsed key hashes to %s, the file holds %s", got, want)
	}

	// And a block that is neither is refused rather than half-read.
	if _, err := parse(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("nonsense")})); err == nil {
		t.Error("a malformed EC PRIVATE KEY block was accepted")
	}
	if _, err := parse([]byte("no pem here")); err == nil {
		t.Error("a non-PEM blob was accepted")
	}
}

// The self-signed wrapper: clientAuth EKU, 1970-9999, carrying the key beside
// it, and owner-only like the key.
func TestEnsure_WritesASelfSignedCertificatePerKey(t *testing.T) {
	dir := t.TempDir()
	keys, _, err := Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range proto.NodeKeyPurposes() {
		path := CertPath(dir, p)
		blob, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(blob)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("%s is not a PEM certificate", path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		// Self-signed: issuer is subject and the signature verifies under its
		// own key. Not CheckSignatureFrom, which additionally demands the
		// signer be a CA — this certificate deliberately is not one, because
		// nothing chains to it.
		if cert.Issuer.String() != cert.Subject.String() {
			t.Errorf("%s issuer %q != subject %q", p, cert.Issuer, cert.Subject)
		}
		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			t.Errorf("%s signature does not verify under its own key: %v", p, err)
		}
		if cert.IsCA {
			t.Errorf("%s is marked as a CA", p)
		}
		if !reflect.DeepEqual(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
			t.Errorf("%s EKU = %v, want clientAuth only", p, cert.ExtKeyUsage)
		}
		if !cert.NotBefore.Equal(certNotBefore) || !cert.NotAfter.Equal(certNotAfter) {
			t.Errorf("%s dates = %s..%s, want 1970..9999", p, cert.NotBefore, cert.NotAfter)
		}
		// It wraps THIS key: the api admits by SPKI, so a certificate around
		// another key would be an identity the node cannot present.
		hash := proto.NodeKeySPKIHashForDER(cert.RawSubjectPublicKeyInfo)
		if hash != keys.Hashes()[p] {
			t.Errorf("%s certificate wraps %s, the key hashes to %s", p, hash, keys.Hashes()[p])
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		// Owner-only like everything else in the agent's state tree: it
		// carries public bytes, but the only reader is the collector
		// container, which runs as uid 0.
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("%s certificate mode %o, want 600", p, got)
		}
	}
}

// The certificate is stable across restarts — a new one every start would
// churn the collector — but a certificate that wraps the WRONG key is
// rewritten rather than served.
func TestEnsure_CertificateIsStableAndSelfHealing(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	path := CertPath(dir, proto.NodeKeyCollector)
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(path)
	if err != nil || string(again) != string(first) {
		t.Fatalf("the certificate was rewritten on a second Ensure")
	}

	// A certificate for the OTHER key — what a restore from another node, or
	// a half-written file, looks like.
	other, err := os.ReadFile(CertPath(dir, proto.NodeKeyAgent))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, other, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	healed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(healed) == string(other) {
		t.Error("a certificate wrapping the wrong key was left in place")
	}
	block, _ := pem.Decode(healed)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keys, _, err := Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := proto.NodeKeySPKIHashForDER(cert.RawSubjectPublicKeyInfo); got != keys.Hashes()[proto.NodeKeyCollector] {
		t.Errorf("the healed certificate wraps %s, want %s", got, keys.Hashes()[proto.NodeKeyCollector])
	}
}

// The api renders a node's collector compose from proto's fixed convention,
// without being able to ask that node where its files are. The agent derives
// the same paths from its own state dir. Pinned here so the two cannot drift
// apart and leave a collector bind-mounting nothing.
func TestPathsAgreeWithTheProtoConvention(t *testing.T) {
	for _, p := range proto.NodeKeyPurposes() {
		if got, want := KeyPath(proto.NodeStateDir, p), proto.NodeKeyPath(p); got != want {
			t.Errorf("%s key: agent says %q, proto says %q", p, got, want)
		}
		if got, want := CertPath(proto.NodeStateDir, p), proto.NodeCertPath(p); got != want {
			t.Errorf("%s cert: agent says %q, proto says %q", p, got, want)
		}
	}
}
