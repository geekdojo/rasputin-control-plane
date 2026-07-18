package mesh

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// EnsureMeshCA
// ============================================================================

func TestEnsureMeshCA_CreatesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureMeshCA(dir, "casa-rasputin")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	if ca.Cert == nil || ca.Key == nil || len(ca.CertPEM) == 0 {
		t.Fatal("EnsureMeshCA returned a non-populated CA")
	}
	// Subject embeds the install name so the operator can identify it
	// in their device's trust store.
	if !strings.Contains(ca.Cert.Subject.CommonName, "casa-rasputin") {
		t.Errorf("CN should embed install name; got %q", ca.Cert.Subject.CommonName)
	}
	if !ca.Cert.IsCA {
		t.Error("cert is not flagged as CA")
	}
	// Lifetime should be roughly 10 years.
	want := 10 * 365 * 24 * time.Hour
	got := ca.Cert.NotAfter.Sub(ca.Cert.NotBefore)
	if got < want-2*time.Hour || got > want+2*time.Hour {
		t.Errorf("CA lifetime: got %v, want ~%v", got, want)
	}
	// Files written with expected perms.
	mustHavePerm(t, filepath.Join(dir, MeshCAFileName), 0o644)
	mustHavePerm(t, filepath.Join(dir, MeshCAKeyFileName), 0o600)
}

func TestEnsureMeshCA_IsIdempotent(t *testing.T) {
	dir := t.TempDir()
	a, err := EnsureMeshCA(dir, "x")
	if err != nil {
		t.Fatalf("first EnsureMeshCA: %v", err)
	}
	b, err := EnsureMeshCA(dir, "x")
	if err != nil {
		t.Fatalf("second EnsureMeshCA: %v", err)
	}
	if !a.Cert.NotAfter.Equal(b.Cert.NotAfter) {
		t.Error("second call should return the same CA (NotAfter mismatch)")
	}
	if string(a.CertPEM) != string(b.CertPEM) {
		t.Error("second call should return the same CertPEM bytes")
	}
}

// Per certificates.md C-3: a half-written CA (cert but no key, or vice
// versa) must fail loudly rather than silently regenerate. Silent
// regeneration would invalidate every operator device's trust without
// their knowledge.
func TestEnsureMeshCA_FailsOnPartialState(t *testing.T) {
	dir := t.TempDir()
	// Seed only the cert, not the key.
	if err := os.WriteFile(filepath.Join(dir, MeshCAFileName), []byte("dummy"), 0o644); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	_, err := EnsureMeshCA(dir, "x")
	if err == nil {
		t.Fatal("expected error on partial state, got nil")
	}
	if !strings.Contains(err.Error(), "partial") {
		t.Errorf("error should mention partial state; got %v", err)
	}
}

func TestEnsureMeshCA_RejectsEmptyTrustDir(t *testing.T) {
	if _, err := EnsureMeshCA("", "x"); err == nil {
		t.Error("empty trustDir should fail")
	}
}

func TestEnsureMeshCA_DefaultsInstallName(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureMeshCA(dir, "")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	if !strings.Contains(strings.ToLower(ca.Cert.Subject.CommonName), "rasputin") {
		t.Errorf("CN should default to something Rasputin-shaped; got %q", ca.Cert.Subject.CommonName)
	}
}

// ============================================================================
// MintLeaf
// ============================================================================

func TestMintLeaf_HappyPath(t *testing.T) {
	ca := newCAForTest(t)
	certPEM, keyPEM, err := MintLeaf(ca, LeafSpec{
		CommonName:  "headscale.rasputin.local",
		DNSNames:    []string{"headscale.rasputin.local", "rasputin.local"},
		IPAddresses: []net.IP{net.IPv4(192, 168, 50, 10), net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	if !strings.HasPrefix(string(certPEM), "-----BEGIN CERTIFICATE-----") {
		t.Error("cert PEM not well-formed")
	}
	if !strings.HasPrefix(string(keyPEM), "-----BEGIN EC PRIVATE KEY-----") {
		t.Error("key PEM not well-formed")
	}
	cert := mustParseCert(t, certPEM)
	// Chain must verify against the CA.
	if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("leaf not signed by CA: %v", err)
	}
	// SANs round-trip both DNS + IP forms.
	if got := cert.DNSNames; len(got) != 2 || got[0] != "headscale.rasputin.local" {
		t.Errorf("DNSNames: %v", got)
	}
	if got := cert.IPAddresses; len(got) != 2 {
		t.Errorf("IPAddresses: %v", got)
	}
	// ExtKeyUsage = ServerAuth — required for TLS handshakes to accept it.
	var hasServerAuth bool
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("leaf missing ExtKeyUsageServerAuth")
	}
}

func TestMintLeaf_ValidationErrors(t *testing.T) {
	ca := newCAForTest(t)
	if _, _, err := MintLeaf(nil, LeafSpec{CommonName: "x", DNSNames: []string{"x"}}); err == nil {
		t.Error("nil CA should fail")
	}
	if _, _, err := MintLeaf(ca, LeafSpec{DNSNames: []string{"x"}}); err == nil {
		t.Error("missing CN should fail")
	}
	if _, _, err := MintLeaf(ca, LeafSpec{CommonName: "x"}); err == nil {
		t.Error("missing all SANs should fail")
	}
}

func TestMintLeaf_HonorsExplicitLifetime(t *testing.T) {
	ca := newCAForTest(t)
	certPEM, _, err := MintLeaf(ca, LeafSpec{
		CommonName: "x",
		DNSNames:   []string{"x"},
		Lifetime:   30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	cert := mustParseCert(t, certPEM)
	got := cert.NotAfter.Sub(cert.NotBefore)
	want := 30 * 24 * time.Hour
	// NotBefore is shifted -1h for skew, so total span is lifetime + 1h.
	if got < want+time.Hour-time.Minute || got > want+time.Hour+time.Minute {
		t.Errorf("lifetime: got %v, want ~%v", got, want+time.Hour)
	}
}

// ============================================================================
// MintLeafToDisk — the idempotent operational path
// ============================================================================

func TestMintLeafToDisk_CreatesWhenMissing(t *testing.T) {
	ca := newCAForTest(t)
	outDir := t.TempDir()
	paths, err := MintLeafToDisk(ca, outDir, LeafSpec{
		CommonName: "headscale.local",
		DNSNames:   []string{"headscale.local"},
	})
	if err != nil {
		t.Fatalf("MintLeafToDisk: %v", err)
	}
	if _, err := os.Stat(paths.CertPath); err != nil {
		t.Errorf("cert not written: %v", err)
	}
	if _, err := os.Stat(paths.KeyPath); err != nil {
		t.Errorf("key not written: %v", err)
	}
	mustHavePerm(t, paths.KeyPath, 0o600)
}

func TestMintLeafToDisk_IdempotentOnFreshLeaf(t *testing.T) {
	ca := newCAForTest(t)
	outDir := t.TempDir()
	spec := LeafSpec{CommonName: "x", DNSNames: []string{"x"}}
	first, err := MintLeafToDisk(ca, outDir, spec)
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	beforeMtime := mustMtime(t, first.CertPath)
	// Second call must NOT rewrite — operator devices that already
	// pinned the public key (rare but possible) would otherwise break.
	time.Sleep(20 * time.Millisecond)
	if _, err := MintLeafToDisk(ca, outDir, spec); err != nil {
		t.Fatalf("second mint: %v", err)
	}
	afterMtime := mustMtime(t, first.CertPath)
	if !beforeMtime.Equal(afterMtime) {
		t.Errorf("cert was rewritten on idempotent re-mint (mtime changed %v → %v)",
			beforeMtime, afterMtime)
	}
}

// SAN drift: operator adds a new hostname / IP to the spec. The leaf
// must be re-minted to cover it; the old SAN-set is silently replaced.
func TestMintLeafToDisk_ReMintsOnSANDrift(t *testing.T) {
	ca := newCAForTest(t)
	outDir := t.TempDir()
	if _, err := MintLeafToDisk(ca, outDir, LeafSpec{
		CommonName: "x", DNSNames: []string{"old.local"},
	}); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	time.Sleep(20 * time.Millisecond) // ensure mtime resolution catches the rewrite
	if _, err := MintLeafToDisk(ca, outDir, LeafSpec{
		CommonName: "x", DNSNames: []string{"old.local", "new.local"},
	}); err != nil {
		t.Fatalf("second mint: %v", err)
	}
	cert := mustParseCertFile(t, filepath.Join(outDir, "leaf.pem"))
	have := make(map[string]bool)
	for _, n := range cert.DNSNames {
		have[n] = true
	}
	if !have["new.local"] {
		t.Errorf("re-mint did not include new SAN; have=%v", cert.DNSNames)
	}
}

func TestMintLeafToDisk_ReMintsOnIssuerChange(t *testing.T) {
	// First CA signs a leaf; then the CA is regenerated (a fresh one
	// with the same install name) and MintLeafToDisk must reject the
	// old leaf as stale because CheckSignatureFrom fails.
	dir := t.TempDir()
	caA, err := EnsureMeshCA(dir, "x")
	if err != nil {
		t.Fatalf("first CA: %v", err)
	}
	outDir := t.TempDir()
	spec := LeafSpec{CommonName: "x", DNSNames: []string{"x"}}
	if _, err := MintLeafToDisk(caA, outDir, spec); err != nil {
		t.Fatalf("mint under caA: %v", err)
	}
	leafA := mustParseCertFile(t, filepath.Join(outDir, "leaf.pem"))

	// Build a brand-new CA in a fresh dir (different keypair).
	caB, err := EnsureMeshCA(t.TempDir(), "x")
	if err != nil {
		t.Fatalf("second CA: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := MintLeafToDisk(caB, outDir, spec); err != nil {
		t.Fatalf("mint under caB: %v", err)
	}
	leafB := mustParseCertFile(t, filepath.Join(outDir, "leaf.pem"))

	if leafA.SerialNumber.Cmp(leafB.SerialNumber) == 0 {
		t.Error("leaf was not re-minted under the new CA (same serial)")
	}
	if err := leafB.CheckSignatureFrom(caB.Cert); err != nil {
		t.Errorf("re-minted leaf is not signed by caB: %v", err)
	}
}

// ============================================================================
// helpers
// ============================================================================

// ensureLeaf must mint a cert valid for the ServerURL host (the name clients
// actually dial), not just the resolved ListenAddr. Pinning server_url to
// rasputin.local previously left the leaf valid only for localhost/IP, and the
// api's own client rejected it: "x509: certificate is valid for localhost, not
// rasputin.local" (bench 2026-06-18).
func TestEnsureLeaf_CoversServerURLHost(t *testing.T) {
	ca := newCAForTest(t)
	stateDir := t.TempDir()
	sup, err := NewDockerSupervisor(DockerSupervisorConfig{
		StateDir:   stateDir,
		ListenAddr: "127.0.0.1:18080", // deterministic — avoids the dial-trick
		ServerURL:  "https://rasputin.local:18080",
		MeshCA:     ca,
	})
	if err != nil {
		t.Fatalf("NewDockerSupervisor: %v", err)
	}
	if err := sup.ensureLeaf(); err != nil {
		t.Fatalf("ensureLeaf: %v", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(stateDir, "certs", "leaf.pem"))
	if err != nil {
		t.Fatalf("read leaf: %v", err)
	}
	cert := mustParseCert(t, certPEM)
	if err := cert.VerifyHostname("rasputin.local"); err != nil {
		t.Errorf("leaf not valid for rasputin.local: %v (DNS=%v IP=%v)", err, cert.DNSNames, cert.IPAddresses)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("leaf not valid for loopback: %v", err)
	}
}

func newCAForTest(t *testing.T) *MeshCA {
	t.Helper()
	ca, err := EnsureMeshCA(t.TempDir(), "test-install")
	if err != nil {
		t.Fatalf("newCAForTest: %v", err)
	}
	return ca
}

func mustParseCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("PEM block did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func mustParseCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return mustParseCert(t, b)
}

func mustHavePerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return // file mode bits don't map cleanly
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	got := info.Mode().Perm()
	if got != want {
		t.Errorf("%s perm: got %#o, want %#o", path, got, want)
	}
}

func mustMtime(t *testing.T, path string) time.Time {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.ModTime()
}

// A client-auth leaf carries ExtKeyUsageClientAuth (and NOT ServerAuth) —
// least-privilege for the obs per-node collectors, which are TLS clients to
// the api's mTLS ingress and never servers.
func TestMintLeaf_ClientAuth(t *testing.T) {
	ca := newCAForTest(t)
	certPEM, _, err := MintLeaf(ca, LeafSpec{
		CommonName:  "c02",
		DNSNames:    []string{"c02"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ClientAuth:  true,
	})
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	cert := mustParseCert(t, certPEM)
	var hasClient, hasServer bool
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageClientAuth:
			hasClient = true
		case x509.ExtKeyUsageServerAuth:
			hasServer = true
		}
	}
	if !hasClient {
		t.Error("client leaf missing ExtKeyUsageClientAuth")
	}
	if hasServer {
		t.Error("client leaf should NOT carry ServerAuth (least privilege)")
	}
}

// A leaf on disk with the wrong EKU must be re-minted, not reused — otherwise
// a collector could pick up a stale server leaf and fail the mTLS handshake.
func TestMintLeafToDisk_ReMintsOnEKUDrift(t *testing.T) {
	ca := newCAForTest(t)
	dir := t.TempDir()
	spec := LeafSpec{CommonName: "c02", DNSNames: []string{"c02"}}

	// First mint a SERVER leaf.
	if _, err := MintLeafToDisk(ca, dir, spec); err != nil {
		t.Fatalf("mint server leaf: %v", err)
	}
	serverCert := mustParseCertFile(t, filepath.Join(dir, "leaf.pem"))

	// Now ask for a CLIENT leaf at the same path — must re-mint, not reuse.
	clientSpec := spec
	clientSpec.ClientAuth = true
	if _, err := MintLeafToDisk(ca, dir, clientSpec); err != nil {
		t.Fatalf("mint client leaf: %v", err)
	}
	clientCert := mustParseCertFile(t, filepath.Join(dir, "leaf.pem"))

	if clientCert.SerialNumber.Cmp(serverCert.SerialNumber) == 0 {
		t.Fatal("EKU drift did not force a re-mint — the server leaf was reused for a client spec")
	}
	hasClient := false
	for _, eku := range clientCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClient = true
		}
	}
	if !hasClient {
		t.Error("re-minted leaf is not client-auth")
	}
}
