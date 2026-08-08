// Package proxy is the agent side of the node-local reverse proxy (ADR-0004
// §1/§6). This slice is leaf delivery: it receives per-app TLS leaves from the
// control plane and stores them on the node where the node-local Caddy will
// terminate TLS with them. The Caddy runtime + route config land in a later
// slice.
package proxy

import (
	"fmt"
	"os"
	"path/filepath"
)

// LeafStore holds per-app TLS leaves under <dir>/certs/<appID>/ — dir is
// typically <agent-state>/proxy. Keyed by the stable AppID so a rename can't
// orphan or misdirect a leaf.
type LeafStore struct {
	dir string
}

// NewLeafStore roots the store at dir (its certs/ subtree is created on write).
func NewLeafStore(dir string) *LeafStore { return &LeafStore{dir: dir} }

func (s *LeafStore) appDir(appID string) string { return filepath.Join(s.dir, "certs", appID) }

// CertPath / KeyPath are where appID's leaf lives — the paths the Caddy config
// will reference.
func (s *LeafStore) CertPath(appID string) string { return filepath.Join(s.appDir(appID), "leaf.pem") }
func (s *LeafStore) KeyPath(appID string) string  { return filepath.Join(s.appDir(appID), "leaf.key") }

// Write stores appID's leaf, cert 0644 and key 0600, each written atomically
// (temp + rename). Caddy reads the pair on config (re)load, not via a
// filewatcher, so an atomic rename is safe here (unlike the Headscale
// extra_records file).
func (s *LeafStore) Write(appID string, certPEM, keyPEM []byte) error {
	if appID == "" {
		return fmt.Errorf("proxy: leaf write: empty appID")
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return fmt.Errorf("proxy: leaf write %s: empty cert or key", appID)
	}
	if err := os.MkdirAll(s.appDir(appID), 0o755); err != nil {
		return fmt.Errorf("proxy: leaf dir: %w", err)
	}
	if err := writeFileAtomic(s.CertPath(appID), certPEM, 0o644); err != nil {
		return err
	}
	return writeFileAtomic(s.KeyPath(appID), keyPEM, 0o600)
}

// Remove deletes appID's cert directory (teardown on delete / re-target).
// Idempotent: a missing directory is not an error.
func (s *LeafStore) Remove(appID string) error {
	if appID == "" {
		return fmt.Errorf("proxy: leaf remove: empty appID")
	}
	return os.RemoveAll(s.appDir(appID))
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("proxy: write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("proxy: rename %s: %w", path, err)
	}
	return nil
}
