// Package proxy is the agent side of the node-local reverse proxy (ADR-0004
// §1/§6). This slice is leaf delivery: it receives per-app TLS leaves from the
// control plane and stores them on the node where the node-local Caddy will
// terminate TLS with them. The Caddy runtime + route config land in a later
// slice.
package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RouteMeta is the per-app routing info the control plane delivers with the leaf
// (proto.AppLeafCmd) — the Host names and the loopback upstream port. Persisted
// next to the cert so the agent can rebuild the full Caddy config after a
// restart without the control plane re-sending.
type RouteMeta struct {
	TailnetFQDN  string `json:"tailnetFqdn"`
	LANFQDN      string `json:"lanFqdn,omitempty"`
	UpstreamPort int    `json:"upstreamPort"`
	// UpstreamTLS: the app serves HTTPS on UpstreamPort (#387). Persisted with
	// the rest of the route because the whole Caddy config is rebuilt from this
	// file after a restart — losing it would silently downgrade the upstream
	// leg to cleartext against a TLS listener, which fails as a 502 with no
	// obvious cause.
	UpstreamTLS bool `json:"upstreamTls,omitempty"`
}

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
func (s *LeafStore) metaPath(appID string) string { return filepath.Join(s.appDir(appID), "meta.json") }

// Write stores appID's leaf (cert 0644, key 0600) and route metadata, each
// written atomically (temp + rename). Caddy reads the pair on config (re)load,
// not via a filewatcher, so an atomic rename is safe here (unlike the Headscale
// extra_records file).
func (s *LeafStore) Write(appID string, certPEM, keyPEM []byte, meta RouteMeta) error {
	if appID == "" {
		return fmt.Errorf("proxy: leaf write: empty appID")
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return fmt.Errorf("proxy: leaf write %s: empty cert or key", appID)
	}
	if meta.TailnetFQDN == "" || meta.UpstreamPort == 0 {
		return fmt.Errorf("proxy: leaf write %s: tailnet FQDN and upstream port required", appID)
	}
	if err := os.MkdirAll(s.appDir(appID), 0o755); err != nil {
		return fmt.Errorf("proxy: leaf dir: %w", err)
	}
	if err := writeFileAtomic(s.CertPath(appID), certPEM, 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(s.KeyPath(appID), keyPEM, 0o600); err != nil {
		return err
	}
	metaJSON, _ := json.Marshal(meta)
	return writeFileAtomic(s.metaPath(appID), metaJSON, 0o644)
}

// Routes assembles an AppRoute for every app with a stored leaf + metadata,
// ready for RenderCaddyConfig. A directory missing its meta or unreadable is
// skipped (best-effort — a half-written app must not sink the whole config).
func (s *LeafStore) Routes() ([]AppRoute, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "certs"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // nothing delivered yet
		}
		return nil, err
	}
	var out []AppRoute
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		appID := e.Name()
		metaJSON, err := os.ReadFile(s.metaPath(appID))
		if err != nil {
			continue
		}
		var m RouteMeta
		if json.Unmarshal(metaJSON, &m) != nil || m.TailnetFQDN == "" || m.UpstreamPort == 0 {
			continue
		}
		out = append(out, AppRoute{
			AppID:        appID,
			TailnetFQDN:  m.TailnetFQDN,
			LANFQDN:      m.LANFQDN,
			UpstreamTLS:  m.UpstreamTLS,
			UpstreamPort: m.UpstreamPort,
			CertPath:     s.CertPath(appID),
			KeyPath:      s.KeyPath(appID),
		})
	}
	return out, nil
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
