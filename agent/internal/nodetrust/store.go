package nodetrust

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Store is the node's trust bundle file. Every read is fresh: Install replaces
// the file atomically, so what Fingerprint and ClientTLSConfig answer is
// always the bundle tailscaled and the agent's HTTPS clients actually use.
type Store struct {
	path string
}

// NewStore is the bundle at path. The composition root passes BundlePath()
// (or, for the mock tailscale backend, a file in the agent's own state dir).
func NewStore(path string) *Store { return &Store{path: path} }

// Path is where the bundle lives.
func (s *Store) Path() string { return s.path }

// Validate refuses anything that is not a bundle of CA certificates: no PEM
// at all, a block that is not a CERTIFICATE (a private key, say — this file is
// written 0644), a CERTIFICATE that does not parse, or non-whitespace bytes
// outside the blocks.
func Validate(bundle []byte) error {
	rest := bundle
	n := 0
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return errors.New("trust bundle carries bytes outside a PEM block")
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return errors.New("trust bundle carries a malformed PEM block")
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("trust bundle carries a %q block; only certificates belong in it", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("trust bundle carries a certificate that does not parse: %w", err)
		}
		n++
	}
	if n == 0 {
		return errors.New("trust bundle carries no certificate")
	}
	return nil
}

// Install validates bundle and writes it, atomically, reporting whether the
// on-disk content changed. Idempotent: an identical bundle is a no-op
// (changed=false), so the caller skips the tailscaled reload. A refused
// bundle or a failed write leaves the file as it was.
func (s *Store) Install(bundle []byte) (changed bool, err error) {
	if err := Validate(bundle); err != nil {
		return false, err
	}
	want := append(bytes.TrimSpace(bundle), '\n')
	if existing, e := os.ReadFile(s.path); e == nil && bytes.Equal(existing, want) {
		return false, nil
	}
	// 0700, tightening an existing install's 0755 (geekdojo/geekdojo-brain#144).
	// On a controlplane this is the same /var/lib/rasputin/mesh the api keeps
	// its mesh state in — pre-auth keys among it. Everything that reads what
	// is in here (tailscaled via SSL_CERT_FILE, the agent's own HTTPS
	// clients, the api) runs as root.
	if err := atrest.EnsureSecretDir(filepath.Dir(s.path)); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(s.path), err)
	}
	// 0644, set explicitly: a CA certificate is public by construction, and
	// the mode is stated here rather than left to the umask.
	if err := atrest.WritePublicFile(s.path, want); err != nil {
		return false, fmt.Errorf("write %s: %w", s.path, err)
	}
	return true, nil
}

// Fingerprint reports proto.TrustFingerprint of the bundle, or
// proto.TrustFingerprintNone when there is none (or it is empty, or
// unreadable — every one of which means "this node trusts nothing", which is
// what the api needs to know).
func (s *Store) Fingerprint() string {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return proto.TrustFingerprintNone
	}
	if fp := proto.TrustFingerprint(b); fp != "" {
		return fp
	}
	return proto.TrustFingerprintNone
}

// ClientTLSConfig is the TLS client config the agent's own HTTPS clients
// verify the api with: the bundle and nothing else (geekdojo/geekdojo-brain
// #590). Every one of those clients connects to the api at
// https://<cluster>.local, whose leaf the controlplane CA signs. A system root
// can never legitimately verify that name, so adding the system pool could
// only widen who can impersonate the api; no pin is added either (the leaf is
// re-minted on SAN drift and near expiry).
//
// Read from disk on this call, so a re-delivered bundle is trusted by the next
// request without an agent restart. A missing, unreadable, empty or
// certificate-less bundle is refused, with the path named — never a config
// that falls back to the system roots.
func (s *Store) ClientTLSConfig() (*tls.Config, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("trust bundle %s: %w: this node trusts no controlplane CA; "+
			"trust.install installs it and trust.converge re-delivers it", s.path, err)
	}
	return proto.CATLSConfig(b, "trust bundle "+s.path)
}
