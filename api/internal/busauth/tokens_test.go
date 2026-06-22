package busauth

import (
	"context"
	"path/filepath"
	"testing"
)

func newTokenStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(context.Background(), filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStore_MintValidateRevoke(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)

	plaintext, id, err := s.Mint(ctx, "firewall")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if plaintext == "" || id == "" {
		t.Fatal("Mint returned empty plaintext/id")
	}
	if plaintext == id {
		t.Fatal("id must be the hash, not the plaintext")
	}

	// An unbound token validates for any presented node id.
	ok, err := s.Validate(ctx, plaintext, "any-node")
	if err != nil || !ok {
		t.Fatalf("Validate(good) = %v, %v; want true, nil", ok, err)
	}
	if ok, _ := s.Validate(ctx, "not-a-real-token", "any-node"); ok {
		t.Error("Validate(garbage) must be false")
	}
	if ok, _ := s.Validate(ctx, "", "any-node"); ok {
		t.Error("Validate(empty) must be false")
	}

	if err := s.Revoke(ctx, id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, _ := s.Validate(ctx, plaintext, "any-node"); ok {
		t.Error("Validate after revoke must be false")
	}
	// Revoking again (no live row) reports ErrNoRows.
	if err := s.Revoke(ctx, id); err == nil {
		t.Error("second Revoke should error (no live token)")
	}
}

func TestStore_HashAtRest(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	plaintext, id, err := s.Mint(ctx, "")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// The stored id is sha256(plaintext) — a DB read never yields the secret.
	if id != HashToken(plaintext) {
		t.Fatalf("id %q is not sha256(plaintext)", id)
	}
	infos, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("List len = %d, want 1", len(infos))
	}
	if infos[0].ID == plaintext {
		t.Fatal("List must not expose the plaintext token")
	}
}

// A bound token authenticates only as the node it was provisioned for.
func TestStore_BoundToken(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)

	plaintext, _, err := s.MintBound(ctx, "fw", "fw-1")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	if ok, _ := s.Validate(ctx, plaintext, "fw-1"); !ok {
		t.Error("bound token must validate for its own node id")
	}
	if ok, _ := s.Validate(ctx, plaintext, "fw-2"); ok {
		t.Error("bound token must NOT validate for a different node id")
	}
	if ok, _ := s.Validate(ctx, plaintext, ""); ok {
		t.Error("bound token must NOT validate for an empty node id")
	}

	// List surfaces the binding.
	infos, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 1 || infos[0].NodeID == nil || *infos[0].NodeID != "fw-1" {
		t.Fatalf("List should report node binding fw-1, got %+v", infos)
	}
}

// PreloadHashes is the controlplane half of a matched set: hash + binding, no
// plaintext, idempotent.
func TestStore_PreloadHashes(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)

	// Simulate the offline CLI: generate tokens, keep only the hashes.
	pt1, h1, _ := GenerateToken()
	pt2, h2, _ := GenerateToken()
	preseed := []PreseedToken{
		{Hash: h1, NodeID: "node-a", Label: "compute"},
		{Hash: h2, NodeID: "node-b", Label: "compute"},
	}

	n, err := s.PreloadHashes(ctx, preseed)
	if err != nil {
		t.Fatalf("PreloadHashes: %v", err)
	}
	if n != 2 {
		t.Fatalf("PreloadHashes inserted %d, want 2", n)
	}

	// The preloaded (bound) tokens validate for their node and nobody else,
	// using only the plaintext the node holds.
	if ok, _ := s.Validate(ctx, pt1, "node-a"); !ok {
		t.Error("preloaded token must validate for its bound node")
	}
	if ok, _ := s.Validate(ctx, pt1, "node-b"); ok {
		t.Error("preloaded token must not validate for another node")
	}
	if ok, _ := s.Validate(ctx, pt2, "node-b"); !ok {
		t.Error("second preloaded token must validate for its bound node")
	}

	// Idempotent: re-running inserts nothing new and doesn't disturb state.
	n2, err := s.PreloadHashes(ctx, preseed)
	if err != nil {
		t.Fatalf("PreloadHashes (2nd): %v", err)
	}
	if n2 != 0 {
		t.Errorf("re-preload inserted %d, want 0 (idempotent)", n2)
	}
	if ok, _ := s.Validate(ctx, pt1, "node-a"); !ok {
		t.Error("token must still validate after idempotent re-preload")
	}
}

// GenerateToken/HashToken are the shared format contract with the offline CLI.
func TestGenerateToken_HashMatches(t *testing.T) {
	pt, h, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if pt == "" || h == "" || pt == h {
		t.Fatalf("bad token/hash pair: pt=%q h=%q", pt, h)
	}
	if HashToken(pt) != h {
		t.Fatal("HashToken(plaintext) must equal the returned hash")
	}
}

func TestStore_RevokeByNodeID(t *testing.T) {
	s := newTokenStore(t)
	ctx := context.Background()
	if _, _, err := s.MintBound(ctx, "compute", "bench-compute1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MintBound(ctx, "compute", "bench-compute1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MintBound(ctx, "compute", "bench-compute2"); err != nil {
		t.Fatal(err)
	}

	n, err := s.RevokeByNodeID(ctx, "bench-compute1")
	if err != nil {
		t.Fatalf("RevokeByNodeID: %v", err)
	}
	if n != 2 {
		t.Fatalf("revoked %d tokens, want 2", n)
	}
	// Idempotent: a second pass revokes nothing.
	if n2, _ := s.RevokeByNodeID(ctx, "bench-compute1"); n2 != 0 {
		t.Errorf("second call revoked %d, want 0", n2)
	}
	// bench-compute2's token is untouched.
	list, _ := s.List(ctx)
	for _, ti := range list {
		if ti.NodeID != nil && *ti.NodeID == "bench-compute2" && ti.RevokedAt != nil {
			t.Errorf("bench-compute2 token wrongly revoked")
		}
		if ti.NodeID != nil && *ti.NodeID == "bench-compute1" && ti.RevokedAt == nil {
			t.Errorf("bench-compute1 token %s not revoked", ti.ID)
		}
	}
}
