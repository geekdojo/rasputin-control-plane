package proxy

import (
	"os"
	"testing"
)

func TestLeafStore_WriteReadRemove(t *testing.T) {
	s := NewLeafStore(t.TempDir())

	if err := s.Write("app-1", []byte("CERT"), []byte("KEY")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if b, _ := os.ReadFile(s.CertPath("app-1")); string(b) != "CERT" {
		t.Errorf("cert = %q, want CERT", b)
	}
	if b, _ := os.ReadFile(s.KeyPath("app-1")); string(b) != "KEY" {
		t.Errorf("key = %q, want KEY", b)
	}
	// The key must be 0600 (private).
	if fi, err := os.Stat(s.KeyPath("app-1")); err != nil {
		t.Fatalf("stat key: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("key perm = %v, want 0600", fi.Mode().Perm())
	}

	// Rotation: a second write overwrites in place.
	if err := s.Write("app-1", []byte("CERT2"), []byte("KEY2")); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if b, _ := os.ReadFile(s.CertPath("app-1")); string(b) != "CERT2" {
		t.Errorf("cert after rotate = %q, want CERT2", b)
	}

	// Teardown removes the directory; a second remove is idempotent.
	if err := s.Remove("app-1"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(s.CertPath("app-1")); !os.IsNotExist(err) {
		t.Errorf("cert still present after Remove: %v", err)
	}
	if err := s.Remove("app-1"); err != nil {
		t.Errorf("Remove of absent app should be nil, got %v", err)
	}
}

func TestLeafStore_Rejects(t *testing.T) {
	s := NewLeafStore(t.TempDir())
	if err := s.Write("", []byte("c"), []byte("k")); err == nil {
		t.Error("empty appID should error")
	}
	if err := s.Write("a", nil, []byte("k")); err == nil {
		t.Error("empty cert should error")
	}
	if err := s.Write("a", []byte("c"), nil); err == nil {
		t.Error("empty key should error")
	}
}
