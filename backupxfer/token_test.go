package backupxfer

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// The credential's scope, TTL and blast radius, pinned.

func testGrant() Grant {
	return Grant{
		Generation: "20260903T120000Z-JOB12345-full",
		Member:     "volumes/vaultwarden/vaultwarden-data.rasputin-archive",
		NodeID:     "e3bench-compute1",
		JobID:      "01JOB",
		MaxBytes:   1 << 30,
	}
}

func TestCredentialRoundTrips(t *testing.T) {
	a, err := NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a.Mint(testGrant(), CredentialTTL)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(tok, "rbx1.") || strings.Count(tok, ".") != 2 {
		t.Errorf("token shape %q", tok)
	}
	g, err := a.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := testGrant()
	if g.Generation != want.Generation || g.Member != want.Member || g.NodeID != want.NodeID || g.JobID != want.JobID {
		t.Errorf("grant = %+v", g)
	}
	if g.Nonce == "" || g.IssuedAt == 0 || g.ExpiresAt-g.IssuedAt != int64(CredentialTTL.Seconds()) {
		t.Errorf("grant timing = iat %d exp %d nonce %q", g.IssuedAt, g.ExpiresAt, g.Nonce)
	}
	// A second mint for the same grant is a different credential.
	tok2, _ := a.Mint(testGrant(), CredentialTTL)
	if tok2 == tok {
		t.Error("two mints produced the same credential")
	}
}

func TestCredentialIsRefusedAfterItsTTL(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	clock := &now
	a, _ := NewAuthority()
	a.withClock(func() time.Time { return *clock })
	tok, err := a.Mint(testGrant(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Verify(tok); err != nil {
		t.Fatalf("fresh credential refused: %v", err)
	}
	*clock = now.Add(10*time.Minute - time.Second)
	if _, err := a.Verify(tok); err != nil {
		t.Errorf("credential refused one second before expiry: %v", err)
	}
	*clock = now.Add(10 * time.Minute)
	if _, err := a.Verify(tok); !errors.Is(err, ErrCredentialExpired) {
		t.Errorf("expired credential: err = %v, want ErrCredentialExpired", err)
	}
	// A TTL longer than the ceiling cannot be minted at all.
	if _, err := a.Mint(testGrant(), CredentialTTL+time.Second); err == nil {
		t.Error("a credential longer than CredentialTTL was minted")
	}
	if _, err := a.Mint(testGrant(), 0); err == nil {
		t.Error("a zero-TTL credential was minted")
	}
}

func TestCredentialFromAnotherKeyOrEditedIsRefused(t *testing.T) {
	a, _ := NewAuthority()
	b, _ := NewAuthority()
	tok, _ := a.Mint(testGrant(), CredentialTTL)
	if _, err := b.Verify(tok); !errors.Is(err, ErrCredentialSignature) {
		t.Errorf("another authority's key verified our credential: %v", err)
	}
	// Edit the grant to name a different member and keep the signature.
	parts := strings.Split(tok, ".")
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	edited := strings.Replace(string(body), "vaultwarden-data", "paperless-data", 1)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(edited)) + "." + parts[2]
	if _, err := a.Verify(forged); !errors.Is(err, ErrCredentialSignature) {
		t.Errorf("an edited grant verified: %v", err)
	}
	for _, bad := range []string{"", "rbx1", "rbx1..", "rbx0." + parts[1] + "." + parts[2], parts[1] + "." + parts[2], tok + ".x", "Bearer " + tok, strings.Repeat("a", 5000)} {
		if _, err := a.Verify(bad); err == nil {
			t.Errorf("%q verified", bad[:min(len(bad), 30)])
		}
	}
}

func TestGrantShapeIsEnforcedAtMint(t *testing.T) {
	a, _ := NewAuthority()
	for name, mutate := range map[string]func(*Grant){
		"traversal member":  func(g *Grant) { g.Member = "volumes/../../etc/shadow.rasputin-archive" },
		"absolute member":   func(g *Grant) { g.Member = "/volumes/a/b.rasputin-archive" },
		"identity archive":  func(g *Grant) { g.Member = "archive.rasputin-archive" },
		"manifest":          func(g *Grant) { g.Member = "manifest.json" },
		"generation with /": func(g *Grant) { g.Generation = "../other" },
		"no node":           func(g *Grant) { g.NodeID = " " },
		"no job":            func(g *Grant) { g.JobID = "" },
	} {
		g := testGrant()
		mutate(&g)
		if _, err := a.Mint(g, CredentialTTL); err == nil {
			t.Errorf("%s: minted", name)
		}
	}
}
