package nodetrust

import (
	"bytes"
	"crypto/tls"
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

// Differs validates bundle and reports whether installing it would change
// the on-disk content, writing nothing. The trust.install handler asks before
// it installs, so the reload-pending marker is on disk before the bundle
// changes.
func (s *Store) Differs(bundle []byte) (bool, error) {
	if err := proto.ValidateTrustBundle(bundle); err != nil {
		return false, err
	}
	existing, err := os.ReadFile(s.path)
	return err != nil || !bytes.Equal(existing, normalize(bundle)), nil
}

// normalize is the bundle as the file holds it: trimmed, then exactly one
// trailing newline.
func normalize(bundle []byte) []byte { return append(bytes.TrimSpace(bundle), '\n') }

// Install validates bundle and writes it, atomically, reporting whether the
// on-disk content changed. Idempotent: an identical bundle is a no-op
// (changed=false), so the caller skips the tailscaled reload. A refused
// bundle or a failed write leaves the file as it was.
func (s *Store) Install(bundle []byte) (changed bool, err error) {
	if changed, err := s.Differs(bundle); err != nil || !changed {
		return false, err
	}
	want := normalize(bundle)
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
