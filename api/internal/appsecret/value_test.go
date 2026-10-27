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

// resolved reads a Resolve or ResolveCompose result as the compose string and
// the values by variable name (geekdojo/geekdojo-brain#776). A nil map stays
// nil, so a test can tell "no map" from "an empty one".
func resolved(v secret.Value, env map[string]secret.Value, err error) (string, map[string]string, error) {
	var out map[string]string
	if env != nil {
		out = make(map[string]string, len(env))
		for k, e := range env {
			out[k] = string(e.Reveal())
		}
	}
	return string(v.Reveal()), out, err
}

// firstTwo drops a resolve result's map, for a test about the compose or the
// error only.
func firstTwo(v secret.Value, _ map[string]secret.Value, err error) (secret.Value, error) {
	return v, err
}

// TC-825-01: Derive and Resolve hand back secret.Values whose bytes are the
// frozen vector. Since geekdojo/geekdojo-brain#776 the vector is in Resolve's
// map under the token's variable, and the compose holds the reference —
// pinned here as literals, not recomputed through Resolve.
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

	key := "RASPUTIN_SECRET_" + strings.ToUpper(strings.ReplaceAll(c.Name, "-", "_"))
	compose := "services:\n  db:\n    environment:\n      P: ${secret:" + c.Name + "}\n      Q: ${secret:" + c.Name + "}\n"
	want := "services:\n  db:\n    environment:\n      P: ${" + key + "}\n      Q: ${" + key + "}\n"
	got, env, err := resolved(Resolve(compose, c.AppID, seed, c.Version))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != want {
		t.Errorf("Resolve(...) compose:\n got %q\nwant %q", got, want)
	}
	if len(env) != 1 || env[key] != c.Want {
		t.Errorf("Resolve(...) map = %d entries, %s=%q; want one, the vector %q", len(env), key, env[key], c.Want)
	}

	plain := "services:\n  web:\n    image: x\n    environment:\n      A: ${OTHER}\n      B: $$LITERAL\n"
	for _, s := range []*Seed{seed, nil} {
		got, env, err := resolved(Resolve(plain, c.AppID, s, c.Version))
		if err != nil {
			t.Fatalf("Resolve of a compose with no token (seed=%v): %v", s != nil, err)
		}
		if got != plain || env != nil {
			t.Errorf("a compose with no token came back changed (seed=%v):\n got %q, %v\nwant %q, nil map", s != nil, got, env, plain)
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
			return firstTwo(Resolve(tokenised, appID, nil, InitialVersion))
		}},
		{"a nil seed, derived directly", func() (secret.Value, error) {
			var none *Seed
			return none.Derive(appID, "db-password", InitialVersion)
		}},
		{"an empty appID", func() (secret.Value, error) {
			return firstTwo(Resolve(tokenised, "", seed, InitialVersion))
		}},
		{"an empty appID, derived directly", func() (secret.Value, error) {
			return seed.Derive("", "db-password", InitialVersion)
		}},
		{"an over-long appID", func() (secret.Value, error) {
			return firstTwo(Resolve(tokenised, strings.Repeat("a", maxAppIDLen+1), seed, InitialVersion))
		}},
		{"an over-long appID, derived directly", func() (secret.Value, error) {
			return seed.Derive(strings.Repeat("a", maxAppIDLen+1), "db-password", InitialVersion)
		}},
		{"an invalid secret name", func() (secret.Value, error) {
			return seed.Derive(appID, "DB", InitialVersion)
		}},
		{"a malformed token", func() (secret.Value, error) {
			return firstTwo(Resolve("environment:\n  P: ${secret:db-password\n", appID, seed, InitialVersion))
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
