// Package bustls is the controlplane's half of TLS on the cluster bus
// (geekdojo/geekdojo-brain#448): the dedicated bus key, the self-signed
// certificate the embedded NATS server wraps it in, the pin nodes trust it by,
// the migration mode that decides whether plaintext is still accepted, and the
// delivery of the pin to nodes that were enrolled before it existed.
//
// The seed and file contract the OS and firewall images consume is
// docs/bus-tls-contract.md; keep the two in step.
package bustls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// KeyFileName is the bus key under the api's bus directory
// (<dataDir>/bus/bus.key, /var/lib/rasputin/bus/bus.key on an appliance) —
// beside issuer.nk and the token preseed.
//
// Format: ONE line, the standard base64 of the PKCS#8 DER private key, then a
// newline. It is the same string a controlplane seed carries as
// RASPUTIN_BUS_KEY, so the OS firstboot's whole job is to write the seed value
// into this file verbatim — no decoding in shell. A PEM "PRIVATE KEY" (or "EC
// PRIVATE KEY") block is accepted too, for an operator who made one with
// openssl; the api only ever writes the one-line form.
const KeyFileName = "bus.key"

// Key is the dedicated, long-lived bus key.
type Key struct {
	signer crypto.Signer
	pin    string

	// The node listener's certificate, minted once — see ListenerCertificate.
	certOnce sync.Once
	cert     *tls.Certificate
	certErr  error
}

// Pin is the value nodes carry as RASPUTIN_BUS_PIN.
func (k *Key) Pin() string { return k.pin }

// Signer is the private key.
func (k *Key) Signer() crypto.Signer { return k.signer }

// EnsureKey loads dir/bus.key, generating and persisting a fresh ECDSA P-256
// key (0600) when there is none — the same idiom as busauth.EnsureIssuer and
// mesh.EnsureMeshCA. generated reports which happened, so the caller can say
// so: a generated key on a cluster whose nodes already carry a pin is a
// stranded fleet, and the log line is where that is first visible.
//
// A file that exists and does not parse is an error, never a reason to
// generate: replacing a key the nodes pin would strand every one of them.
func EnsureKey(dir string) (key *Key, generated bool, err error) {
	if strings.TrimSpace(dir) == "" {
		return nil, false, errors.New("bustls: EnsureKey: dir required")
	}
	if err := atrest.EnsureSecretDir(dir); err != nil {
		return nil, false, fmt.Errorf("bustls: %w", err)
	}
	path := filepath.Join(dir, KeyFileName)
	data, err := os.ReadFile(path)
	if err == nil {
		signer, perr := ParseKey(data)
		if perr != nil {
			return nil, false, fmt.Errorf("bustls: %s exists but is not a usable bus key (refusing to replace it — every node pins this key): %w", path, perr)
		}
		// A seed consumer that forgot the mode leaves the private key world-
		// readable; tighten it rather than refuse the key the nodes pin.
		if cerr := atrest.TightenIfExists(path); cerr != nil {
			return nil, false, fmt.Errorf("bustls: %s could not be made 0600: %w", path, cerr)
		}
		k, kerr := keyFrom(signer)
		return k, false, kerr
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("bustls: read %s: %w", path, err)
	}

	signer, err := GenerateKey()
	if err != nil {
		return nil, false, err
	}
	line, err := EncodeKey(signer)
	if err != nil {
		return nil, false, err
	}
	// Exclusive: two api processes racing a first start must not each write
	// a different key and leave the loser's pin handed out. Staged and linked
	// into place, so a crash never leaves a partial key that the next start
	// would refuse as unparseable.
	if err := atrest.CreateSecretFile(path, []byte(line+"\n")); err != nil {
		return nil, false, fmt.Errorf("bustls: create %s: %w", path, err)
	}
	k, err := keyFrom(signer)
	return k, true, err
}

// GenerateKey makes a fresh bus key: ECDSA P-256. Chosen over Ed25519 for
// reach, not speed — every Go TLS stack and every openssl an operator will
// debug with speaks it — and over RSA for size and handshake cost on a Pi 4
// with no crypto extensions.
func GenerateKey() (crypto.Signer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("bustls: generate key: %w", err)
	}
	return k, nil
}

// EncodeKey renders a key in the one-line seed/file form: standard base64 of
// PKCS#8 DER. No PEM armour, no line breaks, nothing a sourced sh file or a
// UCI value would mangle (the alphabet is A-Z a-z 0-9 + / =).
func EncodeKey(signer crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return "", fmt.Errorf("bustls: marshal key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// ParseKey reads either form EnsureKey accepts: the one-line base64 PKCS#8
// DER, or a PEM block. Surrounding whitespace is ignored.
func ParseKey(data []byte) (crypto.Signer, error) {
	s := strings.TrimSpace(string(data))
	if s == "" {
		return nil, errors.New("empty")
	}
	var der []byte
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, errors.New("PEM armour with no decodable block")
		}
		if block.Type == "EC PRIVATE KEY" {
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse EC private key: %w", err)
			}
			return k, nil
		}
		der = block.Bytes
	} else {
		b, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("not standard base64 of a PKCS#8 key: %w", err)
		}
		der = b
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	switch v := k.(type) {
	case *ecdsa.PrivateKey:
		return v, nil
	case ed25519.PrivateKey:
		return v, nil
	case *rsa.PrivateKey:
		return v, nil
	}
	return nil, fmt.Errorf("unsupported key type %T", k)
}

func keyFrom(signer crypto.Signer) (*Key, error) {
	pin, err := proto.BusPinForPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("bustls: %w", err)
	}
	return &Key{signer: signer, pin: pin}, nil
}

// certNotBefore / certNotAfter bracket every certificate the api wraps the
// key in. The dates mean nothing to a Rasputin node, which checks the key's
// hash and nothing else; they are wide so a client that DOES look at them — an
// operator's `nats` CLI with --tlsca, say — is not tripped by a node clock or
// by the passage of time. 9999-12-31 is RFC 5280's "no well-defined expiration".
var (
	certNotBefore = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	certNotAfter  = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

// BusDNSName is the one name a certificate wrapping the bus key carries, and
// it is FIXED: the same value on every cluster.
//
// Nothing resolves it. A node reaches the bus, and the api, by address and
// verifies the server by the pin — the hash of the key — checking no chain, no
// name and no dates. The SAN exists for clients that cannot be told to do
// that, and for one thing more: it is what lets the node listener tell a
// client that pins the BUS key from one that trusts the mesh CA. Both dial the
// same address, so SNI is the only thing that separates them, and it can only
// separate them if the two certificates answer to different names.
//
// ⚠️ geekdojo/geekdojo-brain#508 (PR #360) owns this constant and declares it
// in bustls/cert.go, with this same name and this same value, alongside the
// certificate it persists. This declaration is the seam that lets the listener
// land first; merging #508 deletes it and nothing else changes.
const BusDNSName = "rasputin-bus"

// SelfSignedCert wraps signer in a self-signed certificate valid from
// notBefore to notAfter, carrying BusDNSName. Exported so a test can build a
// certificate that is not yet valid, or long expired, around the same key and
// prove the pin check ignores both.
func SelfSignedCert(signer crypto.Signer, notBefore, notAfter time.Time) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("bustls: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "rasputin-bus"},
		DNSNames:              []string{BusDNSName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("bustls: self-sign: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("bustls: parse self-signed: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signer, Leaf: leaf}, nil
}

// ServerTLSConfig is what the embedded NATS server serves: the key in a
// freshly self-signed certificate, TLS 1.3 only (every client is a Go agent),
// no client certificates (mTLS is out of scope, #448 decided design step 6).
func (k *Key) ServerTLSConfig() (*tls.Config, error) {
	cert, err := SelfSignedCert(k.signer, certNotBefore, certNotAfter)
	if err != nil {
		return nil, err
	}
	return ServerTLSConfigFor(cert), nil
}

// ListenerCertificate is the certificate the api's node listener serves: the
// bus key, wrapped once for the life of the process and dated 1970-9999 like
// the one the NATS server re-mints on every call.
//
// Minted once rather than per handshake because a client that cannot pin a
// key — Grafana Alloy, which takes a CA as PEM bytes — has to be handed the
// exact bytes it will be shown. A per-handshake mint would hand it a
// different serial every time.
//
// It is held in memory only. geekdojo/geekdojo-brain#508 persists it and adds
// it to the identity backup, at which point a restart stops changing the
// bytes; until then a restart re-mints, and the fact-driven collector
// reconcile redeploys the collectors that pinned the previous one.
func (k *Key) ListenerCertificate() (*tls.Certificate, error) {
	k.certOnce.Do(func() {
		cert, err := SelfSignedCert(k.signer, certNotBefore, certNotAfter)
		if err != nil {
			k.certErr = err
			return
		}
		k.cert = &cert
	})
	return k.cert, k.certErr
}

// ServerTLSConfigFor is ServerTLSConfig around an existing certificate.
func ServerTLSConfigFor(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
}
