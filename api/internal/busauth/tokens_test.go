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

	ok, err := s.Validate(ctx, plaintext)
	if err != nil || !ok {
		t.Fatalf("Validate(good) = %v, %v; want true, nil", ok, err)
	}
	if ok, _ := s.Validate(ctx, "not-a-real-token"); ok {
		t.Error("Validate(garbage) must be false")
	}
	if ok, _ := s.Validate(ctx, ""); ok {
		t.Error("Validate(empty) must be false")
	}

	if err := s.Revoke(ctx, id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, _ := s.Validate(ctx, plaintext); ok {
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
	if id != hashToken(plaintext) {
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
