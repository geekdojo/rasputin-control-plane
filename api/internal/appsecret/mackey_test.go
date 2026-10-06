package appsecret

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// TC-827-06: MACKey is a pinned 32-byte vector for a fixed seed, the same on
// every call, and equal to no app secret derived from that seed. The vector
// was computed outside Go as HKDF-Expand-SHA256(seed, "rasputin/credmac/v1",
// 32), which for one block is HMAC-SHA256(seed, info || 0x01).
func TestSeed_MACKey(t *testing.T) {
	seedBytes := make([]byte, SeedLen)
	for i := range seedBytes {
		seedBytes[i] = byte(i)
	}
	seed, err := NewSeed(seedBytes, DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("0ab0a9ea113701863139299f519d7888dc8dc4afa1d0b8eb76f8a901cc4c513c")

	first, err := seed.MACKey()
	if err != nil {
		t.Fatalf("MACKey: %v", err)
	}
	second, err := seed.MACKey()
	if err != nil {
		t.Fatalf("MACKey (2): %v", err)
	}
	if !bytes.Equal(first.Reveal(), want) {
		t.Errorf("MACKey = %x, want %x", first.Reveal(), want)
	}
	if !bytes.Equal(second.Reveal(), first.Reveal()) {
		t.Error("two MACKey calls on one seed differ")
	}

	for _, tuple := range []struct{ app, name string }{
		{"01HZY0000000000000000000AA", "db-password"},
		{"01HZY0000000000000000000AA", "session-key"},
		{"01HZY0000000000000000000BB", "db-password"},
	} {
		v, err := seed.Derive(tuple.app, tuple.name, InitialVersion)
		if err != nil {
			t.Fatalf("Derive: %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(string(v.Reveal()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(raw, first.Reveal()) {
			t.Errorf("MACKey equals the app secret for %s/%s", tuple.app, tuple.name)
		}
	}

	var none *Seed
	if v, err := none.MACKey(); err == nil || v.Len() != 0 {
		t.Errorf("a nil seed: %d bytes, err %v; want an error and the zero Value", v.Len(), err)
	}
}
