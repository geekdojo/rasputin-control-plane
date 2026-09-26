package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

func TestLeafStore_WriteReadRemove(t *testing.T) {
	s := NewLeafStore(t.TempDir())

	if err := s.Write("app-1", []byte("CERT"), []byte("KEY"), RouteMeta{TailnetFQDN: "a.home1.internal", UpstreamPort: 80}); err != nil {
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
	if err := s.Write("app-1", []byte("CERT2"), []byte("KEY2"), RouteMeta{TailnetFQDN: "a.home1.internal", UpstreamPort: 80}); err != nil {
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
	if err := s.Write("", []byte("c"), []byte("k"), RouteMeta{TailnetFQDN: "a", UpstreamPort: 80}); err == nil {
		t.Error("empty appID should error")
	}
	if err := s.Write("a", nil, []byte("k"), RouteMeta{TailnetFQDN: "a", UpstreamPort: 80}); err == nil {
		t.Error("empty cert should error")
	}
	if err := s.Write("a", []byte("c"), nil, RouteMeta{TailnetFQDN: "a", UpstreamPort: 80}); err == nil {
		t.Error("empty key should error")
	}
}

// Routes carries the certificate's digest (#611) and skips an app whose
// certificate cannot be read rather than rendering a path Caddy would reject.
func TestLeafStore_RoutesCertDigest(t *testing.T) {
	s := NewLeafStore(t.TempDir())
	meta := RouteMeta{TailnetFQDN: "a.home1.internal", UpstreamPort: 80}
	if err := s.Write("a1", []byte("CERT-1"), []byte("KEY-1"), meta); err != nil {
		t.Fatal(err)
	}
	if err := s.Write("gone", []byte("CERT-G"), []byte("KEY-G"), meta); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.CertPath("gone")); err != nil {
		t.Fatal(err)
	}

	routes, err := s.Routes()
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].AppID != "a1" {
		t.Fatalf("routes = %+v, want only a1 (gone has no certificate)", routes)
	}
	want := sha256.Sum256([]byte("CERT-1"))
	if routes[0].CertSHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("CertSHA256 = %q, want sha256(CERT-1) %x", routes[0].CertSHA256, want)
	}
	keySum := sha256.Sum256([]byte("KEY-1"))
	if routes[0].CertSHA256 == hex.EncodeToString(keySum[:]) {
		t.Error("CertSHA256 is the key's digest; only the certificate may be hashed into the config")
	}
}
