package mesh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Mesh TLS PKI ("TLS-A" per design/control-plane/certificates.md).
//
// Two-CA model: a per-installation Mesh TLS CA lives on the controlplane
// and signs TLS leaves for any HTTPS service the controlplane runs —
// Headscale today, future Headplane / observability / api-HTTPS later.
// Operator devices install the CA once (via the .mobileconfig endpoint
// for iOS, curl-to-keystore for laptops) and from that moment on every
// controlplane HTTPS service is "real TLS" to that device.
//
// Deliberately separated from the bundle-signing CA: the bundle root
// belongs to Rasputin-Inc and never needs to leave Geekdojo's offline
// custody. Mixing it with a TLS CA would either leak the cross-fleet
// intermediate onto every customer's box, or make operators trust
// Rasputin-Inc keys to verify their own Rasputin — both wrong.

const (
	// MeshCAFileName is the public cert delivered via .mobileconfig and
	// served to operator devices for trust-root install.
	MeshCAFileName = "mesh-ca.pem"
	// MeshCAKeyFileName is the matching private key. 0600 perms; never
	// leaves the controlplane.
	MeshCAKeyFileName = "mesh-ca.key"

	// meshCALifetime is intentionally long — the operator installs the
	// CA on their phone exactly once and shouldn't have to re-trust for
	// the lifetime of their hardware.
	meshCALifetime = 10 * 365 * 24 * time.Hour
	// defaultLeafLifetime — short enough that compromise has a bounded
	// blast radius; long enough that auto-rotation doesn't generate
	// noise. Per certificates.md §4.
	defaultLeafLifetime = 365 * 24 * time.Hour
	// renewWindow — when a leaf has less than this much life left at
	// startup, MintLeaf re-mints it instead of returning the existing one.
	renewWindow = 60 * 24 * time.Hour
)

// MeshCA is a loaded TLS CA — public cert + private key + PEM-encoded
// public cert (cached so callers can serve it directly without re-encoding).
type MeshCA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

// EnsureMeshCA loads the Mesh TLS CA from trustDir, generating a fresh
// per-installation CA if none exists. The CA's Subject embeds installName
// so an operator browsing their device's trust store can tell which
// Rasputin issued it.
//
// Idempotent: subsequent calls return the same CA. Re-generation only
// happens when neither file exists — a partial state (cert without key
// or vice versa) is treated as corrupted and returns an error rather
// than silently regenerating (per certificates.md C-3, leaning toward
// fail-loudly).
//
// Permissions: cert is 0644 (it's public), key is 0600.
func EnsureMeshCA(trustDir, installName string) (*MeshCA, error) {
	if trustDir == "" {
		return nil, errors.New("mesh: EnsureMeshCA: trustDir required")
	}
	if installName == "" {
		installName = "rasputin"
	}
	if err := os.MkdirAll(trustDir, 0o755); err != nil {
		return nil, fmt.Errorf("mesh: mkdir trust dir: %w", err)
	}
	certPath := filepath.Join(trustDir, MeshCAFileName)
	keyPath := filepath.Join(trustDir, MeshCAKeyFileName)

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)
	if certExists != keyExists {
		// Per C-3: corrupted half-state. Refuse to silently re-issue
		// because that would invalidate every operator device's trust
		// without their knowledge.
		return nil, fmt.Errorf("mesh: partial CA state at %s — found %s=%v key=%v; aborting to avoid silent re-trust",
			trustDir, MeshCAFileName, certExists, keyExists)
	}
	if certExists {
		return loadMeshCA(certPath, keyPath)
	}
	return createMeshCA(certPath, keyPath, installName)
}

func createMeshCA(certPath, keyPath, installName string) (*MeshCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mesh: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("Rasputin Mesh CA (%s)", installName),
			Organization: []string{"Rasputin"},
		},
		NotBefore:             now.Add(-time.Hour), // skew tolerance
		NotAfter:              now.Add(meshCALifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("mesh: self-sign CA: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("mesh: marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writeAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mesh: round-trip parse CA: %w", err)
	}
	return &MeshCA{Cert: cert, Key: key, CertPEM: certPEM}, nil
}

func loadMeshCA(certPath, keyPath string) (*MeshCA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("mesh: read mesh-ca.pem: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("mesh: %s is not a PEM-encoded CERTIFICATE", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mesh: parse mesh-ca.pem: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("mesh: read mesh-ca.key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("mesh: %s is not PEM-encoded", keyPath)
	}
	key, err := parseECKey(keyBlock)
	if err != nil {
		return nil, fmt.Errorf("mesh: parse mesh-ca.key: %w", err)
	}
	return &MeshCA{Cert: cert, Key: key, CertPEM: certPEM}, nil
}

func parseECKey(block *pem.Block) (*ecdsa.PrivateKey, error) {
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		// PKCS8-wrapped EC key (for forward-compat / round-trip with
		// other tools that prefer PKCS8 over the legacy SEC1 form).
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS8 key is not ECDSA")
		}
		return ec, nil
	default:
		return nil, fmt.Errorf("unsupported key PEM type: %s", block.Type)
	}
}

// LeafSpec describes a TLS server-auth leaf to mint under the Mesh CA.
type LeafSpec struct {
	// CommonName goes on the cert's Subject. Mostly cosmetic for modern
	// clients — SANs are what get validated — but useful in operator
	// debugging output.
	CommonName string
	// DNSNames is the set of hostnames the leaf should validate for.
	// Empty when the operator only reaches the service by IP.
	DNSNames []string
	// IPAddresses is the set of IPs the leaf should validate for.
	// Should include 127.0.0.1 (for same-host health checks) plus
	// every LAN IP the operator might use to reach the service.
	IPAddresses []net.IP
	// Lifetime — defaults to 365d if zero. The auto-rotation path only
	// kicks in when an existing leaf has less than `renewWindow` left.
	Lifetime time.Duration
}

// LeafPaths is a small bundle of where a leaf's PEM files live on disk.
// Returned from MintLeafToDisk so callers (the supervisor) can mount
// them into containers without re-deriving paths.
type LeafPaths struct {
	CertPath string
	KeyPath  string
}

// MintLeafToDisk is the operational entry point used by the supervisor.
// It checks whether a usable leaf already exists at the given paths and
// either returns it untouched or mints a fresh one.
//
// "Usable" means: parseable, signed by ca.Cert, has all the SAN entries
// in spec, and expires more than renewWindow from now. Any mismatch
// triggers a fresh mint — SAN drift (controlplane moved subnets, new
// hostname) silently replaces the leaf so the operator never sees a
// "wrong cert for this address" error.
func MintLeafToDisk(ca *MeshCA, outDir string, spec LeafSpec) (LeafPaths, error) {
	if ca == nil {
		return LeafPaths{}, errors.New("mesh: MintLeafToDisk: nil CA")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return LeafPaths{}, fmt.Errorf("mesh: mkdir leaf dir: %w", err)
	}
	paths := LeafPaths{
		CertPath: filepath.Join(outDir, "leaf.pem"),
		KeyPath:  filepath.Join(outDir, "leaf.key"),
	}
	if existing := loadLeafIfUsable(paths, ca, spec); existing != nil {
		return paths, nil
	}
	certPEM, keyPEM, err := MintLeaf(ca, spec)
	if err != nil {
		return LeafPaths{}, err
	}
	if err := writeAtomic(paths.CertPath, certPEM, 0o644); err != nil {
		return LeafPaths{}, err
	}
	if err := writeAtomic(paths.KeyPath, keyPEM, 0o600); err != nil {
		return LeafPaths{}, err
	}
	return paths, nil
}

// MintLeaf creates a fresh leaf cert + key under ca, returning them as
// PEM bytes. Pure function: no disk I/O. Use MintLeafToDisk for the
// idempotent-with-on-disk-state path.
func MintLeaf(ca *MeshCA, spec LeafSpec) (certPEM, keyPEM []byte, err error) {
	if ca == nil {
		return nil, nil, errors.New("mesh: MintLeaf: nil CA")
	}
	if spec.CommonName == "" {
		return nil, nil, errors.New("mesh: MintLeaf: CommonName required")
	}
	if len(spec.DNSNames) == 0 && len(spec.IPAddresses) == 0 {
		return nil, nil, errors.New("mesh: MintLeaf: at least one DNS or IP SAN required")
	}
	lifetime := spec.Lifetime
	if lifetime <= 0 {
		lifetime = defaultLeafLifetime
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("mesh: generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   spec.CommonName,
			Organization: []string{"Rasputin"},
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(lifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    append([]string(nil), spec.DNSNames...),
		IPAddresses: append([]net.IP(nil), spec.IPAddresses...),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &leafKey.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("mesh: sign leaf: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, nil, fmt.Errorf("mesh: marshal leaf key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// loadLeafIfUsable returns a non-nil cert when the on-disk leaf matches
// the spec well enough to skip re-issuing. Returns nil on any of:
// missing files, parse error, wrong issuer, missing SAN, near-expiry,
// or unreadable key. Caller treats nil as "mint a fresh one."
func loadLeafIfUsable(paths LeafPaths, ca *MeshCA, spec LeafSpec) *x509.Certificate {
	certPEM, err := os.ReadFile(paths.CertPath)
	if err != nil {
		return nil
	}
	if _, err := os.ReadFile(paths.KeyPath); err != nil {
		return nil
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	// Issuer match — protects against trying to use an old leaf after
	// the CA itself was regenerated.
	if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
		return nil
	}
	// Near-expiry → re-mint.
	if time.Until(cert.NotAfter) < renewWindow {
		return nil
	}
	// SAN drift — every requested name/IP must be present on the leaf,
	// otherwise mint a fresh one with the updated set. We DON'T require
	// exact equality (older SAN entries are fine to keep) since the
	// operator may add a new hostname mid-lifetime.
	have := make(map[string]bool, len(cert.DNSNames))
	for _, n := range cert.DNSNames {
		have[n] = true
	}
	for _, want := range spec.DNSNames {
		if !have[want] {
			return nil
		}
	}
	haveIP := make(map[string]bool, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		haveIP[ip.String()] = true
	}
	for _, want := range spec.IPAddresses {
		if !haveIP[want.String()] {
			return nil
		}
	}
	return cert
}

// ----- file helpers -------------------------------------------------------

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// writeAtomic writes to a temp file in the same dir and renames into
// place — atomic on POSIX, so a crashed write never leaves a partial
// cert/key on disk that EnsureMeshCA would later mis-interpret.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pki-*.tmp")
	if err != nil {
		return fmt.Errorf("mesh: open temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op on success (rename moved it)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("mesh: write %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("mesh: chmod %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("mesh: close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("mesh: rename %s → %s: %w", tmpPath, path, err)
	}
	return nil
}

// randomSerial generates a 128-bit positive integer for cert serials.
// 128 bits is RFC 5280's recommendation; small enough for ASN.1 INTEGER
// encoding, large enough to be effectively unique without coordination.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("mesh: random serial: %w", err)
	}
	return n, nil
}
