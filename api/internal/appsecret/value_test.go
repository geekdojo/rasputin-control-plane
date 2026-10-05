package appsecret

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// str reads a Derive or Resolve result as the string the previous release
// returned, so the tests written against that API keep asserting the same
// bytes: str(seed.Derive(...)).
func str(v secret.Value, err error) (string, error) {
	return string(v.Reveal()), err
}

// TC-825-01: Derive and Resolve hand back a secret.Value whose bytes are the
// frozen vector and the previous release's resolved compose, byte for byte.
// The previous release spliced Derive's string into the compose, so its output
// for a vector's tuple is the compose with each token replaced by that
// vector's Want — pinned here as a literal, not recomputed through Resolve.
func TestDeriveAndResolveReturnTheVectorBytesAsAValue(t *testing.T) {
	c := loadVectors(t).Cases[0]
	seedBytes, err := hex.DecodeString(c.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := NewSeed(seedBytes, DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}

	v, err := seed.Derive(c.AppID, c.Name, c.Version)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if got := string(v.Reveal()); got != c.Want {
		t.Errorf("Derive(...).Reveal() = %q, want the vector %q", got, c.Want)
	}

	compose := "services:\n  db:\n    environment:\n      P: ${secret:" + c.Name + "}\n      Q: ${secret:" + c.Name + "}\n"
	want := "services:\n  db:\n    environment:\n      P: " + c.Want + "\n      Q: " + c.Want + "\n"
	r, err := Resolve(compose, c.AppID, seed, c.Version)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := string(r.Reveal()); got != want {
		t.Errorf("Resolve(...).Reveal() differs from the previous release's output:\n got %q\nwant %q", got, want)
	}

	plain := "services:\n  web:\n    image: x\n    environment:\n      A: ${OTHER}\n      B: $$LITERAL\n"
	for _, s := range []*Seed{seed, nil} {
		r, err := Resolve(plain, c.AppID, s, c.Version)
		if err != nil {
			t.Fatalf("Resolve of a compose with no token (seed=%v): %v", s != nil, err)
		}
		if got := string(r.Reveal()); got != plain {
			t.Errorf("a compose with no token came back changed (seed=%v):\n got %q\nwant %q", s != nil, got, plain)
		}
	}
}

// TC-825-02: every failure returns its error and the zero Value, so a caller
// that ignored the error would still have nothing to send.
func TestDeriveAndResolveFailuresReturnAZeroValue(t *testing.T) {
	seed := testSeed(t)
	tokenised := "environment:\n  P: ${secret:db-password}\n"

	for _, c := range []struct {
		why string
		run func() (secret.Value, error)
	}{
		{"a nil seed with a tokenised compose", func() (secret.Value, error) {
			return Resolve(tokenised, appID, nil, InitialVersion)
		}},
		{"a nil seed, derived directly", func() (secret.Value, error) {
			var none *Seed
			return none.Derive(appID, "db-password", InitialVersion)
		}},
		{"an empty appID", func() (secret.Value, error) {
			return Resolve(tokenised, "", seed, InitialVersion)
		}},
		{"an empty appID, derived directly", func() (secret.Value, error) {
			return seed.Derive("", "db-password", InitialVersion)
		}},
		{"an over-long appID", func() (secret.Value, error) {
			return Resolve(tokenised, strings.Repeat("a", maxAppIDLen+1), seed, InitialVersion)
		}},
		{"an over-long appID, derived directly", func() (secret.Value, error) {
			return seed.Derive(strings.Repeat("a", maxAppIDLen+1), "db-password", InitialVersion)
		}},
		{"an invalid secret name", func() (secret.Value, error) {
			return seed.Derive(appID, "DB", InitialVersion)
		}},
		{"a malformed token", func() (secret.Value, error) {
			return Resolve("environment:\n  P: ${secret:db-password\n", appID, seed, InitialVersion)
		}},
	} {
		v, err := c.run()
		if err == nil {
			t.Errorf("%s: no error", c.why)
		}
		if v.Len() != 0 {
			t.Errorf("%s: returned a Value holding %d bytes alongside its error, want the zero Value", c.why, v.Len())
		}
	}
}
