package openwrt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// MockClient is a file-backed UCIClient. State lives at
// <stateDir>/firewall.json. Hashes are SHA-256 over the canonicalized JSON.
//
// Behavior:
//   - On Apply, the new state is written atomically (tmp + rename).
//   - On Get, the file is read each time so an operator can hand-edit the
//     JSON between calls to simulate drift.
//   - Missing file is treated as empty firewall state (no redirects, etc.)
//     with a known empty-state hash, so a fresh install reads cleanly.
//
// The mock is intentionally tolerant of human editing — the api's reconcile
// flow depends on observing user-introduced drift, and the easiest way to
// reproduce that in dev is to open the JSON in a text editor.
type MockClient struct {
	mu        sync.Mutex
	dir       string
	statePath string
}

// NewMockClient creates a MockClient rooted at dir. dir is created if it
// doesn't exist.
func NewMockClient(dir string) (*MockClient, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("openwrt-mock: mkdir %s: %w", dir, err)
	}
	return &MockClient{
		dir:       dir,
		statePath: filepath.Join(dir, "firewall.json"),
	}, nil
}

// Apply writes state to disk and returns its hash.
func (c *MockClient) Apply(ctx context.Context, state map[string]any) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if state == nil {
		state = emptyState()
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return "", fmt.Errorf("openwrt-mock: marshal: %w", err)
	}
	// Atomic write — temp file + rename so a partial write can't be observed.
	tmp := c.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return "", fmt.Errorf("openwrt-mock: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, c.statePath); err != nil {
		return "", fmt.Errorf("openwrt-mock: rename: %w", err)
	}
	return hashState(state)
}

// SetActive records the requested active state to <dir>/active so a test (or
// an operator inspecting a dev box) can observe it. The mock has no real
// dnsmasq/snort to toggle; persisting the flag keeps the file-backed contract
// honest and idempotent.
func (c *MockClient) SetActive(ctx context.Context, active bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := []byte("0")
	if active {
		v = []byte("1")
	}
	if err := os.WriteFile(filepath.Join(c.dir, "active"), v, 0o644); err != nil {
		return fmt.Errorf("openwrt-mock: write active: %w", err)
	}
	return nil
}

// Get reads the on-disk state and returns it with its hash.
func (c *MockClient) Get(ctx context.Context) (map[string]any, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := os.ReadFile(c.statePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s := emptyState()
			h, err := hashState(s)
			return s, h, err
		}
		return nil, "", fmt.Errorf("openwrt-mock: read: %w", err)
	}
	var state map[string]any
	if err := json.Unmarshal(b, &state); err != nil {
		return nil, "", fmt.Errorf("openwrt-mock: parse %s: %w", c.statePath, err)
	}
	h, err := hashState(state)
	return state, h, err
}

// emptyState matches what firewall.Compile produces with no enabled intents,
// so a fresh agent's hash matches the api's expectation when both have zero
// intents on file. Both kind slices are always present (possibly empty) so
// adding a new intent kind doesn't churn the empty-state hash.
func emptyState() map[string]any {
	return map[string]any{
		"firewall": map[string]any{
			"redirect": []map[string]any{},
			"rule":     []map[string]any{},
		},
	}
}

// hashState canonicalizes the state and SHA-256s it. Map keys are sorted by
// encoding/json; the api's firewall.Hash uses the same function, so hashes
// match across the boundary.
func hashState(state map[string]any) (string, error) {
	b, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
