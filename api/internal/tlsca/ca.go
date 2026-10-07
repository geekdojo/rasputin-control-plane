package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The file names each instance keeps in the trust dir. The controlplane CA's
// names are compatibility names (see the package comment): they predate this
// package and are never migrated.
const (
	// ControlplaneCertFile is the controlplane CA's public cert, served to
	// operator devices and shipped to every node.
	ControlplaneCertFile = "mesh-ca.pem"
	// ControlplaneKeyFile is its private key. 0600; never leaves the
	// controlplane.
	ControlplaneKeyFile = "mesh-ca.key"
	// StoreCertFile is the store CA's public cert. It never enters a node,
	// browser or collector trust bundle.
	StoreCertFile = "store-ca.pem"
	// StoreKeyFile is the store CA's private key. 0600.
	StoreKeyFile = "store-ca.key"

	// controlplaneCALifetime is intentionally long: the operator installs the
	// CA on their devices exactly once and should not have to re-trust it for
	// the lifetime of their hardware.
	controlplaneCALifetime = 10 * 365 * 24 * time.Hour
	// storeCALifetime matches it. The store CA's only verifier is the
	// secret store's listener, which re-reads the CA file it is configured
	// with; there is no device to re-trust, and no fact to rotate on yet.
	storeCALifetime = 10 * 365 * 24 * time.Hour
)

// Config is one CA instance. Every instance goes through the same code; the
// differences between them are exactly these fields.
type Config struct {
	// Name identifies the instance in logs and errors ("controlplane",
	// "store").
	Name string
	// CertFile and KeyFile are the file names inside the trust dir.
	CertFile, KeyFile string
	// SubjectFormat is the CA certificate's CommonName, with one %s for the
	// install name.
	SubjectFormat string
	// Lifetime is the CA certificate's validity.
	Lifetime time.Duration
	// Usages are the leaf kinds this CA issues. MintLeaf refuses any other.
	Usages []Usage
}

// ControlplaneConfig is the CA that signs every HTTPS leaf the controlplane
// serves (the api, Headscale, the per-app leaves). Its subject is unchanged
// from the release that created it, so installed devices keep the name they
// show.
func ControlplaneConfig() Config {
	return Config{
		Name:          "controlplane",
		CertFile:      ControlplaneCertFile,
		KeyFile:       ControlplaneKeyFile,
		SubjectFormat: "Rasputin Mesh CA (%s)",
		Lifetime:      controlplaneCALifetime,
		Usages:        []Usage{UsageServer},
	}
}

// StoreConfig is the CA the secret store's listener trusts, alone. It issues
// client leaves (the api's login to the store) and server leaves (the
// listener's own).
func StoreConfig() Config {
	return Config{
		Name:          "store",
		CertFile:      StoreCertFile,
		KeyFile:       StoreKeyFile,
		SubjectFormat: "Rasputin Store CA (%s)",
		Lifetime:      storeCALifetime,
		Usages:        []Usage{UsageClient, UsageServer},
	}
}

// ClockGate answers whether the wall clock can be trusted to stamp a
// certificate's validity window, blocking — bounded by the caller's own
// budget — until it can be, and reporting false when that budget runs out.
//
// It exists because a node with no RTC (a Pi 5, say) boots to a bogus pre-NTP
// time, and a certificate minted then anchors its NotBefore/NotAfter in that
// bogus window. Once the clock corrects, every verifier reads the certificate
// as expired or not yet valid — and nothing about the certificate says why.
//
// The gate is a fact check, not a timer: it asks whether the clock has
// synchronized, and the bound on its wait only decides how long a mint is
// willing to be delayed before proceeding anyway, loudly.
//
// Scope, deliberately: it gates LEAF mints. Creating the CA itself is not
// gated, because Ensure runs synchronously in the api's startup and the api
// unit is Type=notify with systemd's default start timeout — a wait there
// could delay or lose the :80 bootstrap surface on a first boot with no
// reachable NTP.
type ClockGate func() bool

// Deps are a CA's collaborators, passed in by the composition root.
type Deps struct {
	// Now is the clock that dates the CA and every leaf, and that the
	// near-expiry check reads. Required.
	Now func() time.Time
	// Rand feeds certificate serials, signatures and key generation.
	// Required; production passes crypto/rand.Reader.
	Rand io.Reader
	// LeafClock, when set, is consulted before a leaf's validity window is
	// stamped. Optional.
	LeafClock ClockGate
	// Log receives the load and create records. Required.
	Log *slog.Logger
}

// CA is a loaded TLS CA: its certificate, the PEM it was read from (so
// callers can serve it without re-encoding), and its private key, which
// nothing outside this package reads.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte

	key  *ecdsa.PrivateKey
	cfg  Config
	deps Deps
}

// Name is the instance's Config.Name.
func (ca *CA) Name() string { return ca.cfg.Name }

// Ensure loads the cfg instance from dir, creating it when neither of its
// files exists. The CA's subject embeds installName so a person reading a
// device's trust store can tell which Rasputin issued it.
//
// A partial state (a cert without its key, or the reverse) is refused, never
// re-issued: a fresh CA would silently invalidate everything that trusts the
// old one (certificates.md C-3). No failure writes a file.
//
// Permissions: the dir is 0700, the cert 0644 (it is public), the key 0600.
func Ensure(cfg Config, dir, installName string, d Deps) (*CA, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := d.validate(cfg.Name); err != nil {
		return nil, err
	}
	if dir == "" {
		return nil, fmt.Errorf("tlsca %s: trust dir required", cfg.Name)
	}
	if installName == "" {
		installName = "rasputin"
	}
	// The trust dir holds CA keys: owner-only, existing installs included.
	if err := atrest.EnsureSecretDir(dir); err != nil {
		return nil, fmt.Errorf("tlsca %s: trust dir: %w", cfg.Name, err)
	}
	certPath := filepath.Join(dir, cfg.CertFile)
	keyPath := filepath.Join(dir, cfg.KeyFile)
	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)
	if certExists != keyExists {
		return nil, fmt.Errorf("tlsca %s: partial CA state in %s — found %s=%v %s=%v; refusing to re-issue a CA everything already trusts",
			cfg.Name, dir, cfg.CertFile, certExists, cfg.KeyFile, keyExists)
	}
	var (
		ca  *CA
		err error
		msg = "tls ca loaded"
	)
	if certExists {
		ca, err = load(cfg, certPath, keyPath)
	} else {
		ca, err = create(cfg, d, certPath, keyPath, installName)
		msg = "tls ca created"
	}
	if err != nil {
		return nil, err
	}
	ca.deps = d
	sum := sha256.Sum256(ca.Cert.Raw)
	d.Log.Info(msg, "ca", cfg.Name, "subject", ca.Cert.Subject.CommonName,
		"not_after", ca.Cert.NotAfter.UTC().Format(time.RFC3339), "sha256", hex.EncodeToString(sum[:]))
	return ca, nil
}

func (c Config) validate() error {
	if c.Name == "" || c.CertFile == "" || c.KeyFile == "" || c.SubjectFormat == "" || c.Lifetime <= 0 || len(c.Usages) == 0 {
		return fmt.Errorf("tlsca %q: incomplete config", c.Name)
	}
	for _, u := range c.Usages {
		if _, ok := u.extKeyUsage(); !ok {
			return fmt.Errorf("tlsca %s: config names unknown usage %d", c.Name, u)
		}
	}
	return nil
}

func (d Deps) validate(name string) error {
	if d.Now == nil || d.Rand == nil || d.Log == nil {
		return fmt.Errorf("tlsca %s: Deps needs Now, Rand and Log", name)
	}
	return nil
}

func create(cfg Config, d Deps, certPath, keyPath, installName string) (*CA, error) {
	// Since Go 1.26 GenerateKey ignores its reader and always draws from the
	// system's secure source (go doc crypto/ecdsa.GenerateKey); Rand is passed
	// anyway so every randomness consumer here takes the injected one.
	key, err := ecdsa.GenerateKey(elliptic.P256(), d.Rand)
	if err != nil {
		return nil, fmt.Errorf("tlsca %s: generate CA key: %w", cfg.Name, err)
	}
	serial, err := randomSerial(d.Rand)
	if err != nil {
		return nil, fmt.Errorf("tlsca %s: %w", cfg.Name, err)
	}
	now := d.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf(cfg.SubjectFormat, installName),
			Organization: []string{"Rasputin"},
		},
		NotBefore:             now.Add(-time.Hour), // skew tolerance
		NotAfter:              now.Add(cfg.Lifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(d.Rand, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("tlsca %s: self-sign CA: %w", cfg.Name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tlsca %s: round-trip parse CA: %w", cfg.Name, err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("tlsca %s: marshal CA key: %w", cfg.Name, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	caKey := secret.New(keyPEM)
	clear(keyPEM)
	clear(keyDER)
	defer caKey.Destroy()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	// Key first, then cert, and the key is taken back if the cert cannot be
	// written: a failure leaves neither file, so the next start does not
	// read a half state it must refuse.
	if err := writeKey(keyPath, caKey); err != nil {
		return nil, fmt.Errorf("tlsca %s: %w", cfg.Name, err)
	}
	if err := writeCert(certPath, certPEM); err != nil {
		_ = os.Remove(keyPath)
		return nil, fmt.Errorf("tlsca %s: %w", cfg.Name, err)
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key, cfg: cfg}, nil
}

func load(cfg Config, certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("tlsca %s: read %s: %w", cfg.Name, cfg.CertFile, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("tlsca %s: %s is not a PEM-encoded CERTIFICATE", cfg.Name, cfg.CertFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsca %s: parse %s: %w", cfg.Name, cfg.CertFile, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("tlsca %s: read %s: %w", cfg.Name, cfg.KeyFile, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	clear(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("tlsca %s: %s is not PEM-encoded", cfg.Name, cfg.KeyFile)
	}
	key, err := parseECKey(keyBlock)
	clear(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsca %s: parse %s: %w", cfg.Name, cfg.KeyFile, err)
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key, cfg: cfg}, nil
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

// ----- file helpers -------------------------------------------------------

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// writeCert and writeKey persist a certificate and its private key through
// the at-rest helper: atomic (a crashed write never leaves a partial cert or
// key that Ensure would later mis-interpret), with the mode set explicitly. A
// certificate is public by construction and is 0644; a private key is 0600.
func writeCert(path string, certPEM []byte) error {
	if err := atrest.WritePublicFile(path, certPEM); err != nil {
		return fmt.Errorf("tlsca: %w", err)
	}
	return nil
}

// writeKey is the one place a key file's bytes leave their secret.Value: into
// the owner-only file they are read back from. The caller owns key.
func writeKey(path string, key secret.Value) error {
	if err := atrest.WriteSecretFile(path, key.Reveal()); err != nil {
		return fmt.Errorf("tlsca: %w", err)
	}
	return nil
}

// WriteLeafFiles persists a leaf's certificate (0644) and key (0600) at paths,
// each atomically. For a caller that mints in memory and commits only once the
// leaf has been accepted (mesh.CommitAppLeaf). The caller still owns key.
func WriteLeafFiles(paths LeafPaths, certPEM []byte, key secret.Value) error {
	if err := writeCert(paths.CertPath, certPEM); err != nil {
		return err
	}
	return writeKey(paths.KeyPath, key)
}

// randomSerial generates a 128-bit positive integer for cert serials from r.
// 128 bits is RFC 5280's recommendation; small enough for ASN.1 INTEGER
// encoding, large enough to be effectively unique without coordination.
func randomSerial(r io.Reader) (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := cryptorand.Int(r, limit)
	if err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}
	return n, nil
}
