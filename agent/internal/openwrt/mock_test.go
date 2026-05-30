package openwrt

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func newOpenwrtMock(t *testing.T) *MockClient {
	t.Helper()
	c, err := NewMockClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockClient: %v", err)
	}
	return c
}

func TestMockClient_GetOnFreshInstallReturnsEmptyState(t *testing.T) {
	// No firewall.json on disk → empty state with the known empty hash.
	c := newOpenwrtMock(t)
	state, hash, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if state == nil {
		t.Fatal("state should not be nil")
	}
	if hash == "" {
		t.Error("empty state should still have a hash")
	}
	// Empty state is {"firewall": {"redirect": []}}.
	fw, ok := state["firewall"].(map[string]any)
	if !ok {
		t.Fatalf("state.firewall not map: %T", state["firewall"])
	}
	if _, ok := fw["redirect"]; !ok {
		t.Errorf("empty state missing firewall.redirect key: %v", fw)
	}
}

func TestMockClient_ApplyThenGetReturnsSameHash(t *testing.T) {
	c := newOpenwrtMock(t)
	ctx := context.Background()
	state := map[string]any{
		"firewall": map[string]any{
			"redirect": []map[string]any{{
				"name":      "ssh",
				"src":       "wan",
				"src_dport": "2222",
				"dest":      "lan",
				"dest_ip":   "10.0.0.5",
				"dest_port": "22",
				"target":    "DNAT",
				"proto":     "tcp",
			}},
		},
	}
	hashApplied, err := c.Apply(ctx, state)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if hashApplied == "" {
		t.Error("Apply returned empty hash")
	}

	// Get should report the same state with the same hash.
	gotState, hashGot, err := c.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if hashGot != hashApplied {
		t.Errorf("hash drift: apply=%s get=%s", hashApplied, hashGot)
	}
	if gotState["firewall"] == nil {
		t.Errorf("firewall key lost after round trip")
	}
}

func TestMockClient_HashStable_AcrossInstances(t *testing.T) {
	// Regression: hashes must be deterministic for the same input. The api
	// uses identical bytes to compute its intent hash; if these drift the
	// drift detector will lie.
	c1 := newOpenwrtMock(t)
	c2 := newOpenwrtMock(t)
	state := map[string]any{"firewall": map[string]any{"redirect": []map[string]any{}}}
	h1, err := c1.Apply(context.Background(), state)
	if err != nil {
		t.Fatalf("Apply c1: %v", err)
	}
	h2, err := c2.Apply(context.Background(), state)
	if err != nil {
		t.Fatalf("Apply c2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("two independent instances produced different hashes for same state: %s vs %s", h1, h2)
	}
}

func TestMockClient_ApplyNilStateSubstitutesEmpty(t *testing.T) {
	c := newOpenwrtMock(t)
	hash, err := c.Apply(context.Background(), nil)
	if err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	// Should equal the hash for the canonical empty state.
	emptyHash, err := hashState(emptyState())
	if err != nil {
		t.Fatalf("hashState: %v", err)
	}
	if hash != emptyHash {
		t.Errorf("nil state hash %s does not match empty-state hash %s", hash, emptyHash)
	}
}

func TestMockClient_ApplyWritesAtomically(t *testing.T) {
	// We can't directly observe the rename atomicity, but we can confirm
	// the temp file no longer exists after a successful apply.
	dir := t.TempDir()
	c, err := NewMockClient(dir)
	if err != nil {
		t.Fatalf("NewMockClient: %v", err)
	}
	if _, err := c.Apply(context.Background(), map[string]any{"x": 1}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "firewall.json.tmp")); !os.IsNotExist(err) {
		t.Errorf("temp file should have been renamed, got stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "firewall.json")); err != nil {
		t.Errorf("final file should exist: %v", err)
	}
}

func TestMockClient_GetReadsCorruptedStateAsError(t *testing.T) {
	dir := t.TempDir()
	c, err := NewMockClient(dir)
	if err != nil {
		t.Fatalf("NewMockClient: %v", err)
	}
	// Hand-write garbage to mimic an operator who broke the JSON.
	if err := os.WriteFile(filepath.Join(dir, "firewall.json"), []byte("not-json"), 0o644); err != nil {
		t.Fatalf("seed bad file: %v", err)
	}
	if _, _, err := c.Get(context.Background()); err == nil {
		t.Errorf("expected error on corrupted firewall.json")
	}
}

func TestMockClient_HashStateProducesHex(t *testing.T) {
	h, err := hashState(map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("hashState: %v", err)
	}
	if len(h) != 64 {
		t.Errorf("hash length: got %d want 64 (sha256 hex)", len(h))
	}
	for _, ch := range h {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			t.Errorf("non-hex char in hash: %q", h)
			break
		}
	}
}

func TestMockClient_StateOnDiskIsValidJSON(t *testing.T) {
	dir := t.TempDir()
	c, err := NewMockClient(dir)
	if err != nil {
		t.Fatalf("NewMockClient: %v", err)
	}
	if _, err := c.Apply(context.Background(), map[string]any{"a": "b"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	buf, err := os.ReadFile(filepath.Join(dir, "firewall.json"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var v any
	if err := json.Unmarshal(buf, &v); err != nil {
		t.Errorf("on-disk state is not valid JSON: %v\n%s", err, string(buf))
	}
}
