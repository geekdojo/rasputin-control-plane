package busauth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// newTokenStore opens a store with a node registry attached, which is what
// main does before the auth-callout responder starts. Without one the store
// admits nobody (livenodes.go), so every test that exercises admission needs
// it; newTokenStoreNoRegistry is the deliberate exception.
func newTokenStore(t *testing.T) *Store {
	t.Helper()
	s := newTokenStoreNoRegistry(t)
	if err := s.SetNodeRegistry(context.Background(), newRecordingRegistry()); err != nil {
		t.Fatalf("SetNodeRegistry: %v", err)
	}
	return s
}

func newTokenStoreNoRegistry(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(context.Background(), filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// insertLegacyUnbound writes an UNBOUND token row the way stores did before
// geekdojo-brain#423 (node_id NULL) — nothing in the store can create one any
// more, but a database from before that decision may still hold them. It
// returns the plaintext and id, as a mint did.
func insertLegacyUnbound(t *testing.T, s *Store, label string) (plaintext, id string) {
	t.Helper()
	plaintext, id, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, err := s.db.ExecContext(context.Background(),
		`INSERT INTO bus_tokens (token_hash, label, created_at, node_id) VALUES (?, ?, ?, NULL)`,
		id, label, ms(time.Now().UTC())); err != nil {
		t.Fatalf("insert legacy unbound token: %v", err)
	}
	return plaintext, id
}

func TestStore_MintValidateRevoke(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)

	plaintext, id, err := s.MintBound(ctx, "firewall", "fw-1", "compute")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	if plaintext == "" || id == "" {
		t.Fatal("MintBound returned empty plaintext/id")
	}
	if plaintext == id {
		t.Fatal("id must be the hash, not the plaintext")
	}

	ok, err := s.Validate(ctx, plaintext, "fw-1")
	if err != nil || !ok {
		t.Fatalf("Validate(good) = %v, %v; want true, nil", ok, err)
	}
	if ok, _ := s.Validate(ctx, "not-a-real-token", "fw-1"); ok {
		t.Error("Validate(garbage) must be false")
	}
	if ok, _ := s.Validate(ctx, "", "fw-1"); ok {
		t.Error("Validate(empty) must be false")
	}

	if _, err := s.Revoke(ctx, id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, _ := s.Validate(ctx, plaintext, "fw-1"); ok {
		t.Error("Validate after revoke must be false")
	}
	// Revoking again (no live row) reports ErrNoRows.
	if _, err := s.Revoke(ctx, id); err == nil {
		t.Error("second Revoke should error (no live token)")
	}
}

func TestStore_HashAtRest(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	plaintext, id, err := s.MintBound(ctx, "", "node-a", "compute")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
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

	plaintext, _, err := s.MintBound(ctx, "fw", "fw-1", "compute")
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

// There is no unbound mint (geekdojo-brain#423): MintBound with no node id is
// refused and stores nothing.
func TestStore_MintBoundRefusesUnbound(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	if pt, id, err := s.MintBound(ctx, "unbound", "", "compute"); !errors.Is(err, ErrUnboundToken) || pt != "" || id != "" {
		t.Fatalf("MintBound(no node id) = (%q, %q, %v); want (\"\", \"\", ErrUnboundToken)", pt, id, err)
	}
	infos, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 0 {
		t.Fatalf("a refused unbound mint stored %d rows; want 0", len(infos))
	}
}

// A legacy unbound token — a row from before geekdojo-brain#423 — validates
// for no node id at all, including the ids it used to accept, and
// CountActiveUnbound finds it until it is revoked.
func TestStore_LegacyUnboundTokenNeverValidates(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)

	if n, err := s.CountActiveUnbound(ctx); err != nil || n != 0 {
		t.Fatalf("CountActiveUnbound on an empty store = (%d, %v); want (0, nil)", n, err)
	}

	legacy, legacyID := insertLegacyUnbound(t, s, "legacy")
	// A row whose node_id is an empty string is just as unbound.
	emptyPT, emptyID, _ := GenerateToken()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO bus_tokens (token_hash, label, created_at, node_id) VALUES (?, 'empty', ?, '')`,
		emptyID, ms(time.Now().UTC())); err != nil {
		t.Fatalf("insert empty-node token: %v", err)
	}
	// Bound and revoked tokens are not counted.
	if _, _, err := s.MintBound(ctx, "bound", "node-a", "compute"); err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	_, revokedID := insertLegacyUnbound(t, s, "legacy-revoked")
	if _, err := s.Revoke(ctx, revokedID); err != nil {
		t.Fatalf("Revoke(legacy-revoked): %v", err)
	}

	for _, node := range []string{"node-a", "node-b", "fw-1", ""} {
		if ok, err := s.Validate(ctx, legacy, node); err != nil || ok {
			t.Errorf("Validate(legacy unbound, %q) = (%v, %v); want (false, nil)", node, ok, err)
		}
		if ok, err := s.Validate(ctx, emptyPT, node); err != nil || ok {
			t.Errorf("Validate(empty-node token, %q) = (%v, %v); want (false, nil)", node, ok, err)
		}
	}

	if n, err := s.CountActiveUnbound(ctx); err != nil || n != 2 {
		t.Fatalf("CountActiveUnbound = (%d, %v); want (2, nil)", n, err)
	}
	// The existing revoke clears them.
	for _, id := range []string{legacyID, emptyID} {
		if _, err := s.Revoke(ctx, id); err != nil {
			t.Fatalf("Revoke(%s): %v", id, err)
		}
	}
	if n, err := s.CountActiveUnbound(ctx); err != nil || n != 0 {
		t.Fatalf("CountActiveUnbound after revoking them = (%d, %v); want (0, nil)", n, err)
	}
}

// A preseed entry naming no node id fails the whole load: nothing is stored,
// not even the bound entry beside it.
func TestStore_PreloadHashesRefusesUnboundEntry(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	_, h1, _ := GenerateToken()
	_, h2, _ := GenerateToken()
	n, err := s.PreloadHashes(ctx, []PreseedToken{
		{Hash: h1, NodeID: "node-a", Label: "compute"},
		{Hash: h2, Label: "unbound"},
	})
	if !errors.Is(err, ErrUnboundToken) || n != 0 {
		t.Fatalf("PreloadHashes with an unbound entry = (%d, %v); want (0, ErrUnboundToken)", n, err)
	}
	infos, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 0 {
		t.Fatalf("a refused preseed stored %d rows; want 0", len(infos))
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
	if _, _, err := s.MintBound(ctx, "compute", "bench-compute1", "compute"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MintBound(ctx, "compute", "bench-compute1", "compute"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MintBound(ctx, "compute", "bench-compute2", "compute"); err != nil {
		t.Fatal(err)
	}

	n, _, err := s.RevokeByNodeID(ctx, "bench-compute1")
	if err != nil {
		t.Fatalf("RevokeByNodeID: %v", err)
	}
	if n != 2 {
		t.Fatalf("revoked %d tokens, want 2", n)
	}
	// Idempotent: a second pass revokes nothing.
	if n2, _, _ := s.RevokeByNodeID(ctx, "bench-compute1"); n2 != 0 {
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
