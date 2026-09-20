// Package nodekeys holds the node's own long-lived TLS keys: one the agent
// presents to the control plane, one it hands to the per-node observability
// collector (geekdojo/geekdojo-brain#514).
//
// The keys are generated ONCE, on the node, and never leave it. What leaves is
// the SHA-256 of each key's public half, reported in registration metadata
// (proto.MetadataNodeKeys) and only over a pinned TLS bus connection. The
// control plane records those hashes and admits an HTTPS connection by
// comparing the peer's key against them — no CA issues anything here.
//
// The files live under the agent's state directory, which is persistent on
// both images: /var/lib/rasputin/agent-state on Rasputin OS, and
// /etc/rasputin/agent-state on the firewall, which keep.d already preserves
// across a sysupgrade (fw/files/lib/upgrade/keep.d/rasputin). So a reboot or an
// image update keeps a node's keys, and only a reflash changes them — which is
// what makes the control plane's "node key changed" alert a rare event worth
// looking at rather than noise.
//
// An existing file that does not parse is an error, never a reason to
// generate: replacing a key the control plane has recorded would take the node
// off HTTPS until an operator noticed, and silently minting a new identity is
// exactly what the key-change alert exists to make visible.
package nodekeys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Dir is the directory holding the node's keys under a state dir.
func Dir(stateDir string) string { return filepath.Join(stateDir, "keys") }

// KeyPath is where one purpose's private key lives. PEM, PKCS#8, 0600 —
// PEM rather than the bus key's one-line base64 because this file is only ever
// read by Go and, for the collector, handed to Alloy, which wants PEM.
func KeyPath(stateDir string, p proto.NodeKeyPurpose) string {
	return filepath.Join(Dir(stateDir), string(p)+".key")
}

// CertPath is where the key's SELF-SIGNED certificate lives, 0600 like the
// key beside it.
//
// The certificate is a wrapper, not a credential: the api admits the key by
// its SPKI and reads nothing else, so nothing about the certificate is
// checked — not its chain, not its name, not its dates. It exists because TLS
// has no way to present a bare key, and because Grafana Alloy takes a
// cert_file.
//
// It carries only public bytes, but it is written owner-only like everything
// else in the agent's state tree: the one thing that reads it is the collector
// container, which runs as uid 0 and bind-mounts it read-only.
func CertPath(stateDir string, p proto.NodeKeyPurpose) string {
	return filepath.Join(Dir(stateDir), string(p)+".crt")
}

// certNotBefore / certNotAfter bracket every certificate written here. The
// dates mean nothing to the api, which checks the key and ignores the wrapper,
// and they are wide on purpose: a node boots before NTP with no battery-backed
// clock, so a certificate minted at a bogus time — or checked at one — must
// not decide whether the node can reach its control plane. 9999-12-31 is
// RFC 5280's "no well-defined expiration". Same bracket as the bus
// certificate (api/internal/bustls).
var (
	certNotBefore = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	certNotAfter  = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

// Keys is the node's loaded key set.
type Keys struct {
	stateDir string
	signers  map[proto.NodeKeyPurpose]crypto.Signer
	hashes   proto.NodeKeys
}

// Ensure loads the node's keys from stateDir, generating and persisting any
// that are missing. generated names the purposes that were created in this
// call, so the caller can log a first generation — the one moment the node's
// HTTPS identity comes into being.
//
// Every key is written 0600 inside a 0700 directory, staged and renamed so a
// power cut leaves the old file or the new one and never half of one.
func Ensure(stateDir string) (keys *Keys, generated []proto.NodeKeyPurpose, err error) {
	if stateDir == "" {
		return nil, nil, errors.New("nodekeys: state dir required")
	}
	dir := Dir(stateDir)
	// The agent's one at-rest rule: 0700, and an existing directory from an
	// earlier release — or one a restore put back wider — is tightened
	// rather than left open.
	if err := atrest.EnsureSecretDir(dir); err != nil {
		return nil, nil, fmt.Errorf("nodekeys: %w", err)
	}
	k := &Keys{
		stateDir: stateDir,
		signers:  map[proto.NodeKeyPurpose]crypto.Signer{},
		hashes:   proto.NodeKeys{},
	}
	for _, p := range proto.NodeKeyPurposes() {
		path := KeyPath(stateDir, p)
		signer, made, err := ensureOne(path)
		if err != nil {
			return nil, nil, err
		}
		if made {
			generated = append(generated, p)
		}
		hash, err := proto.NodeKeySPKIHash(signer.Public())
		if err != nil {
			return nil, nil, fmt.Errorf("nodekeys: %s: %w", path, err)
		}
		// The self-signed wrapper the key is presented in. Rewritten whenever
		// it is missing or does not wrap THIS key, so a half-written file or a
		// restored certificate from another node heals itself rather than
		// leaving a node that presents a key it cannot prove it holds.
		if err := ensureCert(CertPath(stateDir, p), signer, string(p)); err != nil {
			return nil, nil, err
		}
		k.signers[p] = signer
		k.hashes[p] = hash
	}
	return k, generated, nil
}

// ensureCert writes a self-signed certificate for signer at path when the one
// there does not wrap signer's public key. clientAuth EKU, because that is
// what a TLS client certificate is for and what Go's own verification of a
// chain would demand; the api checks neither.
func ensureCert(path string, signer crypto.Signer, cn string) error {
	if blob, err := os.ReadFile(path); err == nil && certWraps(blob, signer) {
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("nodekeys: read %s: %w", path, err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return fmt.Errorf("nodekeys: serial for %s: %w", path, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             certNotBefore,
		NotAfter:              certNotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return fmt.Errorf("nodekeys: self-sign %s: %w", path, err)
	}
	// Through the same at-rest helper as the key: the agent's state tree is
	// owner-only (geekdojo/geekdojo-brain#353), and nothing needs this file
	// wider. It carries only public bytes, but the one thing that reads it is
	// the collector container, which bind-mounts it read-only and runs as
	// uid 0.
	return atrest.WriteSecretFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// certWraps reports whether the PEM certificate in blob carries signer's
// public key. A certificate that wraps a different key is not this node's.
func certWraps(blob []byte, signer crypto.Signer) bool {
	block, _ := pem.Decode(blob)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	want, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return false
	}
	return bytes.Equal(cert.RawSubjectPublicKeyInfo, want)
}

// ensureOne loads path, or generates and persists a key when there is none.
func ensureOne(path string) (signer crypto.Signer, generated bool, err error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		s, perr := parse(data)
		if perr != nil {
			return nil, false, fmt.Errorf("nodekeys: %s exists but is not a usable key (refusing to replace it — the control plane has recorded this key): %w", path, perr)
		}
		// A key restored or copied with a wider mode is tightened rather
		// than refused: it is still the key the control plane recorded.
		if cerr := atrest.TightenIfExists(path); cerr != nil {
			return nil, false, fmt.Errorf("nodekeys: %s could not be made 0600: %w", path, cerr)
		}
		return s, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("nodekeys: read %s: %w", path, err)
	}

	// ECDSA P-256 for the same reasons the bus key uses it (bustls.GenerateKey):
	// every Go TLS stack and every openssl an operator debugs with speaks it,
	// and the handshake is cheap on a Pi 4 with no crypto extensions.
	fresh, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("nodekeys: generate %s: %w", path, err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(fresh)
	if err != nil {
		return nil, false, fmt.Errorf("nodekeys: marshal %s: %w", path, err)
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := atrest.WriteSecretFile(path, blob); err != nil {
		return nil, false, fmt.Errorf("nodekeys: %w", err)
	}
	return fresh, true, nil
}

// parse reads the PEM PKCS#8 form Ensure writes. An EC PRIVATE KEY block is
// accepted too, for a key an operator made with openssl.
func parse(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no decodable PEM block")
	}
	if block.Type == "EC PRIVATE KEY" {
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T", k)
	}
	return s, nil
}

// Signer returns the private key for a purpose, or nil when there is none.
func (k *Keys) Signer(p proto.NodeKeyPurpose) crypto.Signer {
	if k == nil {
		return nil
	}
	return k.signers[p]
}

// Hashes returns the SPKI hashes to report, as an independent copy. nil
// receiver returns nil, so a caller with no keys reports nothing rather than
// having to guard.
func (k *Keys) Hashes() proto.NodeKeys {
	if k == nil {
		return nil
	}
	return k.hashes.Clone()
}

// Path is where a purpose's key file is, for a caller that must hand the path
// to something other than Go.
func (k *Keys) Path(p proto.NodeKeyPurpose) string {
	if k == nil {
		return ""
	}
	return KeyPath(k.stateDir, p)
}

// CertPath is where a purpose's certificate file is.
func (k *Keys) CertPath(p proto.NodeKeyPurpose) string {
	if k == nil {
		return ""
	}
	return CertPath(k.stateDir, p)
}
