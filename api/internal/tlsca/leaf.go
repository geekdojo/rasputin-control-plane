package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	// defaultLeafLifetime — short enough that compromise has a bounded
	// blast radius; long enough that auto-rotation doesn't generate
	// noise. Per certificates.md §4.
	defaultLeafLifetime = 365 * 24 * time.Hour
	// renewWindow — when a leaf has less than this much life left, the
	// usable-leaf check reads it as due and it is re-minted.
	renewWindow = 60 * 24 * time.Hour
)

// Usage is what a leaf is for. Every leaf carries exactly one, stamped as its
// only ExtKeyUsage: Go's verifier reads an absent EKU as "any", so a leaf
// minted without one would verify for a purpose nobody chose.
type Usage int

const (
	// UsageServer is a TLS server leaf (ExtKeyUsageServerAuth).
	UsageServer Usage = iota + 1
	// UsageClient is a TLS client leaf (ExtKeyUsageClientAuth).
	UsageClient
)

// extKeyUsage maps u to the EKU it stamps. ok is false for the zero Usage and
// any value not declared above.
func (u Usage) extKeyUsage() (x509.ExtKeyUsage, bool) {
	switch u {
	case UsageServer:
		return x509.ExtKeyUsageServerAuth, true
	case UsageClient:
		return x509.ExtKeyUsageClientAuth, true
	}
	return 0, false
}

func (u Usage) String() string {
	switch u {
	case UsageServer:
		return "server"
	case UsageClient:
		return "client"
	}
	return fmt.Sprintf("Usage(%d)", int(u))
}

// LeafSpec describes a leaf to mint under a CA.
type LeafSpec struct {
	// Usage is what the leaf is for. Required: there is no default, so a
	// spec says which EKU its leaf carries.
	Usage Usage
	// CommonName goes on the cert's Subject. Required. A client leaf is
	// identified by it; for a server leaf it is mostly cosmetic (SANs are
	// what get validated) but useful in operator debugging output.
	CommonName string
	// DNSNames is the set of hostnames the leaf should validate for.
	DNSNames []string
	// IPAddresses is the set of IPs the leaf should validate for. A server
	// leaf needs at least one DNS or IP SAN; a client leaf may carry none.
	IPAddresses []net.IP
	// Lifetime — defaults to 365d if zero. The auto-rotation path only
	// kicks in when an existing leaf has less than `renewWindow` left.
	Lifetime time.Duration
	// ExactDNSNames requires the on-disk leaf's SAN set to EQUAL DNSNames
	// rather than merely contain it, so a name being REMOVED forces a
	// re-mint the same way adding one does.
	//
	// Off by default because the tolerant check below is right for a leaf
	// whose names only ever grow. Turn it on wherever a name can be
	// WITHDRAWN and the leaf must not outlive it — a rename, or a change of
	// cluster id. App leaves set it for exactly that reason (see
	// mesh.appLeafSpec); note they no longer withdraw a name on an exposure
	// change, because exposure is enforced by the route, not the SAN set.
	ExactDNSNames bool
}

// LeafPaths is a small bundle of where a leaf's PEM files live on disk.
// Returned from MintLeafToDisk so callers (the supervisor) can mount
// them into containers without re-deriving paths.
type LeafPaths struct {
	CertPath string
	KeyPath  string
}

// MintLeafToDisk is the operational entry point used by the supervisor.
// It checks whether a usable leaf already exists in outDir and either leaves
// it untouched or mints a fresh one.
//
// "Usable" is LeafUsable: parseable, signed by this CA, the spec's EKU and
// nothing else, all the SAN entries in spec, and more than renewWindow left.
// Any mismatch triggers a fresh mint — SAN drift (controlplane moved subnets,
// new hostname) silently replaces the leaf so the operator never sees a
// "wrong cert for this address" error.
func (ca *CA) MintLeafToDisk(outDir string, spec LeafSpec) (LeafPaths, error) {
	if ca == nil {
		return LeafPaths{}, errors.New("tlsca: MintLeafToDisk: nil CA")
	}
	// The leaf dir holds the leaf's private key: owner-only, existing
	// installs included.
	if err := atrest.EnsureSecretDir(outDir); err != nil {
		return LeafPaths{}, fmt.Errorf("tlsca %s: leaf dir: %w", ca.cfg.Name, err)
	}
	paths := LeafPathsIn(outDir)
	if ca.LeafUsable(paths, spec) {
		return paths, nil
	}
	certPEM, key, err := ca.MintLeaf(spec)
	if err != nil {
		return LeafPaths{}, err
	}
	defer key.Destroy()
	if err := WriteLeafFiles(paths, certPEM, key); err != nil {
		return LeafPaths{}, err
	}
	return paths, nil
}

// MintLeaf creates a fresh leaf cert + key under ca: the certificate as PEM
// bytes, and the private key's PEM as a secret.Value the caller owns and
// destroys (ADR-0009). Pure function: no disk I/O. Use MintLeafToDisk for the
// idempotent-with-on-disk-state path. A failure returns the zero Value.
//
// It refuses a zero or unknown Usage, a Usage this instance does not issue,
// an empty CommonName, and a server leaf with no SAN.
func (ca *CA) MintLeaf(spec LeafSpec) (certPEM []byte, key secret.Value, err error) {
	if ca == nil {
		return nil, secret.Value{}, errors.New("tlsca: MintLeaf: nil CA")
	}
	eku, err := ca.checkSpec(spec)
	if err != nil {
		return nil, secret.Value{}, err
	}
	lifetime := spec.Lifetime
	if lifetime <= 0 {
		lifetime = defaultLeafLifetime
	}
	// Don't date a certificate against a clock nobody has checked. The gate
	// blocks until the clock is trustworthy, within its own budget; when that
	// budget runs out it says so and the mint proceeds, because a node with no
	// reachable NTP still has to serve TLS. The gate owns the warning — this
	// path mints once per leaf per renewal, and a line per mint would either
	// be silence or a flood depending on the fleet.
	if ca.deps.LeafClock != nil {
		ca.deps.LeafClock()
	}
	// GenerateKey ignores its reader since Go 1.26; see create.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), ca.deps.Rand)
	if err != nil {
		return nil, secret.Value{}, fmt.Errorf("tlsca %s: generate leaf key: %w", ca.cfg.Name, err)
	}
	serial, err := randomSerial(ca.deps.Rand)
	if err != nil {
		return nil, secret.Value{}, fmt.Errorf("tlsca %s: %w", ca.cfg.Name, err)
	}
	now := ca.deps.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   spec.CommonName,
			Organization: []string{"Rasputin"},
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(lifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{eku},
		DNSNames:    append([]string(nil), spec.DNSNames...),
		IPAddresses: append([]net.IP(nil), spec.IPAddresses...),
	}
	der, err := x509.CreateCertificate(ca.deps.Rand, tmpl, ca.Cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, secret.Value{}, fmt.Errorf("tlsca %s: sign leaf: %w", ca.cfg.Name, err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, secret.Value{}, fmt.Errorf("tlsca %s: marshal leaf key: %w", ca.cfg.Name, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	key = secret.New(keyPEM)
	clear(keyPEM)
	clear(keyDER)
	return certPEM, key, nil
}

// checkSpec is MintLeaf's refusals, and the EKU the leaf will carry.
func (ca *CA) checkSpec(spec LeafSpec) (x509.ExtKeyUsage, error) {
	eku, ok := spec.Usage.extKeyUsage()
	if !ok {
		return 0, fmt.Errorf("tlsca %s: MintLeaf: leaf usage is unset or unknown (%s)", ca.cfg.Name, spec.Usage)
	}
	if !slices.Contains(ca.cfg.Usages, spec.Usage) {
		return 0, fmt.Errorf("tlsca %s: MintLeaf: this CA does not issue %s leaves", ca.cfg.Name, spec.Usage)
	}
	if spec.CommonName == "" {
		return 0, fmt.Errorf("tlsca %s: MintLeaf: CommonName required", ca.cfg.Name)
	}
	if spec.Usage == UsageServer && len(spec.DNSNames) == 0 && len(spec.IPAddresses) == 0 {
		return 0, fmt.Errorf("tlsca %s: MintLeaf: a server leaf needs at least one DNS or IP SAN", ca.cfg.Name)
	}
	return eku, nil
}

// LeafUsable reports whether the leaf at paths matches spec well enough to
// skip re-issuing. False on any of: missing files, parse error, wrong issuer,
// an EKU set other than exactly the spec's, a missing SAN, near-expiry under
// the CA's clock, an unreadable key, or a spec MintLeaf would refuse. The
// caller treats false as "mint a fresh one".
func (ca *CA) LeafUsable(paths LeafPaths, spec LeafSpec) bool {
	if ca == nil {
		return false
	}
	eku, err := ca.checkSpec(spec)
	if err != nil {
		return false
	}
	certPEM, err := os.ReadFile(paths.CertPath)
	if err != nil {
		return false
	}
	if _, err := os.ReadFile(paths.KeyPath); err != nil {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	// Issuer match — protects against trying to use an old leaf after
	// the CA itself was regenerated.
	if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
		return false
	}
	// Near-expiry → re-mint.
	if cert.NotAfter.Sub(ca.deps.Now()) < renewWindow {
		return false
	}
	// EKU drift — a leaf on disk minted for another purpose (a client leaf
	// where a server leaf is wanted, or the reverse, or one carrying more
	// than the spec's single EKU) is not reused.
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != eku {
		return false
	}
	// SAN drift — every requested name/IP must be present on the leaf,
	// otherwise mint a fresh one with the updated set. By default we DON'T
	// require exact equality (older SAN entries are fine to keep) since the
	// operator may add a new hostname mid-lifetime.
	//
	// That tolerance is one-directional, and a spec that WITHDRAWS a name
	// must say so with ExactDNSNames. Found on #197 by the automated review:
	// revoking an app's LAN exposure shrinks the wanted set to a subset of
	// what the leaf already carries, so the leaf read as still-usable,
	// nothing was re-minted, nothing was shipped, and the node kept both a
	// valid .lan certificate and its Caddy LAN route until the leaf's own
	// renew window — 365d lifetime minus 60d window, so roughly ten months
	// after the operator was told the app had left the LAN.
	have := make(map[string]bool, len(cert.DNSNames))
	for _, n := range cert.DNSNames {
		have[n] = true
	}
	for _, want := range spec.DNSNames {
		if !have[want] {
			return false
		}
	}
	if spec.ExactDNSNames && len(cert.DNSNames) != len(spec.DNSNames) {
		return false
	}
	haveIP := make(map[string]bool, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		haveIP[ip.String()] = true
	}
	for _, want := range spec.IPAddresses {
		if !haveIP[want.String()] {
			return false
		}
	}
	return true
}
