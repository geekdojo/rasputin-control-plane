package appsecret

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

func testSeed(t *testing.T) *Seed {
	t.Helper()
	key := make([]byte, SeedLen)
	for i := range key {
		key[i] = byte(i)
	}
	seed, err := NewSeed(key, DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

const appID = "01K5R6P8Q9ZJ7V2XW4YB3D5EFG"

// TC-776-07: the one substitution site, HKDF path. Every token becomes its
// Compose interpolation reference, the compose holds no derived value, a name
// used twice gives one map entry, and the entry is the derived value.
func TestResolveReplacesEveryTokenWithItsReference(t *testing.T) {
	seed := testSeed(t)
	compose := "services:\n  db:\n    environment:\n" +
		"      POSTGRES_PASSWORD: ${secret:db-password}\n" +
		"      SESSION_KEY: ${secret:session-key}\n" +
		"      ALSO_DB: ${secret:db-password}\n"

	got, env, err := resolved(Resolve(compose, appID, seed, InitialVersion))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	dbValue, err := str(seed.Derive(appID, "db-password", InitialVersion))
	if err != nil {
		t.Fatal(err)
	}
	sessionValue, err := str(seed.Derive(appID, "session-key", InitialVersion))
	if err != nil {
		t.Fatal(err)
	}
	// Everything that is not a token is untouched, byte for byte.
	want := "services:\n  db:\n    environment:\n" +
		"      POSTGRES_PASSWORD: ${RASPUTIN_SECRET_DB_PASSWORD}\n" +
		"      SESSION_KEY: ${RASPUTIN_SECRET_SESSION_KEY}\n" +
		"      ALSO_DB: ${RASPUTIN_SECRET_DB_PASSWORD}\n"
	if got != want {
		t.Errorf("resolved compose:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(got, dbValue) || strings.Contains(got, sessionValue) {
		t.Errorf("the compose holds a derived value:\n%s", got)
	}
	// Two occurrences of ONE name resolve to ONE entry — the app has one
	// database password, not two.
	if len(env) != 2 {
		t.Errorf("the map has %d entries, want 2 (one per distinct name)", len(env))
	}
	if env["RASPUTIN_SECRET_DB_PASSWORD"] != dbValue {
		t.Error("the db password entry is not the derived value")
	}
	if env["RASPUTIN_SECRET_SESSION_KEY"] != sessionValue {
		t.Error("the session key entry is not the derived value")
	}
	if dbValue == sessionValue {
		t.Error("two different names derived the same value")
	}
}

// TC-776-07: HKDFSource.ResolveCompose returns the same compose and map.
func TestHKDFSourceResolvesToReferencesAndAMap(t *testing.T) {
	seed := testSeed(t)
	src, err := NewHKDFSource(seed)
	if err != nil {
		t.Fatal(err)
	}
	got, env, err := resolved(src.ResolveCompose(context.Background(), appID, "services:\n  db:\n    environment:\n      P: ${secret:db-password}\n"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := str(seed.Derive(appID, "db-password", InitialVersion))
	if err != nil {
		t.Fatal(err)
	}
	if got != "services:\n  db:\n    environment:\n      P: ${RASPUTIN_SECRET_DB_PASSWORD}\n" || strings.Contains(got, want) {
		t.Errorf("compose = %q, want the reference and no value", got)
	}
	if len(env) != 1 || env["RASPUTIN_SECRET_DB_PASSWORD"] != want {
		t.Errorf("map has %d entries; want the one derived value", len(env))
	}
}

// TC-776-10: every resolve failure returns the zero compose, a nil map and an
// error that quotes no value.
func TestResolveFailuresReturnZeroComposeAndNilMap(t *testing.T) {
	seed := testSeed(t)
	dbValue, err := str(seed.Derive(appID, "db-password", InitialVersion))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ why, compose string }{
		{"a malformed token", "environment:\n  P: ${secret:db-password}\n  Q: ${secret:Bad}\n"},
		{"an unterminated token after a good one", "environment:\n  P: ${secret:db-password}\n  Q: ${secret:x\n"},
	} {
		v, env, err := Resolve(c.compose, appID, seed, InitialVersion)
		if err == nil {
			t.Fatalf("%s: no error", c.why)
		}
		if v.Len() != 0 || env != nil {
			t.Errorf("%s: compose %d bytes, map %v; want the zero Value and a nil map", c.why, v.Len(), env != nil)
		}
		if strings.Contains(err.Error(), dbValue) {
			t.Errorf("%s: the error quotes a value", c.why)
		}
	}
	// A derivation that fails after an earlier one succeeded: splice destroys
	// what it gathered and returns nothing.
	var gathered secretValueList
	_, env, err := splice("P: ${secret:a}\nQ: ${secret:b}\n", mustScan(t, "P: ${secret:a}\nQ: ${secret:b}\n"), func(name string) (secret.Value, error) {
		if name == "b" {
			return secret.Value{}, errors.New("refused")
		}
		v := secret.New([]byte(dbValue))
		gathered = append(gathered, v)
		return v, nil
	})
	if err == nil || env != nil {
		t.Fatalf("splice = (map %v, %v), want a nil map and the error", env != nil, err)
	}
	for _, v := range gathered {
		if v.Len() != 0 {
			t.Error("a value gathered before the failure was not destroyed")
		}
	}
}

type secretValueList []secret.Value

func mustScan(t *testing.T, compose string) []tileschema.SecretToken {
	t.Helper()
	toks, err := tileschema.ScanSecretTokens(compose)
	if err != nil {
		t.Fatal(err)
	}
	return toks
}

// The install path's contract: what the database holds is what the node gets. A
// compose with no token is returned as the SAME string, not re-rendered, because
// every app in the field today has no tokens and the revert path matches on the
// compose hash.
func TestResolveLeavesAComposeWithNoTokensVerbatim(t *testing.T) {
	compose := "services:\n  web:\n    image: x@sha256:" + strings.Repeat("a", 64) + "\n    environment:\n      A: ${OTHER}\n      B: $$LITERAL\n"
	// TC-776-09: the same bytes and no map.
	got, env, err := resolved(Resolve(compose, appID, testSeed(t), InitialVersion))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != compose || len(env) != 0 {
		t.Errorf("a compose with no secret token was rewritten:\n got %q (map %d)\nwant %q", got, len(env), compose)
	}
	// And with no seed either: a cluster with no seed loaded must still be able
	// to deploy every app that does not ask for a secret.
	got, env, err = resolved(Resolve(compose, appID, nil, InitialVersion))
	if err != nil || got != compose || len(env) != 0 {
		t.Errorf("no-token, no-seed: got %q, %d entries, %v", got, len(env), err)
	}
}

// Refused, not passed through. A token sent on as a literal is deployed as a
// password — the exact failure this channel closes, and silently, with a
// container that came up and a job that succeeded.
func TestResolveRefusesATokenWithNoSeed(t *testing.T) {
	_, _, err := Resolve("environment:\n  P: ${secret:db-password}\n", appID, nil, InitialVersion)
	if err == nil {
		t.Fatal("resolved a token with no seed loaded")
	}
	if !strings.Contains(err.Error(), "seed") {
		t.Errorf("the error does not say the seed is missing: %v", err)
	}
}

func TestResolveRefusesAMalformedToken(t *testing.T) {
	seed := testSeed(t)
	for _, c := range []struct{ why, compose string }{
		{"no closing brace on the line", "environment:\n  P: ${secret:db-password\n  Q: 1\n"},
		{"an empty name", "environment:\n  P: ${secret:}\n"},
		{"an upper-case name", "environment:\n  P: ${secret:DB}\n"},
		{"a name with a separator, which is the impersonation attempt", "environment:\n  P: ${secret:x:" + appID + ":y}\n"},
		{"a name over 63 characters", "environment:\n  P: ${secret:" + strings.Repeat("a", 64) + "}\n"},
		{"already escaped — the form the control plane emits for the paths that must NOT resolve", "environment:\n  P: $${secret:db-password}\n"},
	} {
		if _, _, err := Resolve(c.compose, appID, seed, InitialVersion); err == nil {
			t.Errorf("resolved a compose with %s", c.why)
		}
	}
}

func TestResolveIsBoundToTheAppAndTheVersion(t *testing.T) {
	seed := testSeed(t)
	compose := "P: ${secret:db-password}\n"
	const key = "RASPUTIN_SECRET_DB_PASSWORD"
	_, one, err := resolved(Resolve(compose, appID, seed, InitialVersion))
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := resolved(Resolve(compose, "01OTHERAPP0000000000000000", seed, InitialVersion))
	if err != nil {
		t.Fatal(err)
	}
	_, rotated, err := resolved(Resolve(compose, appID, seed, InitialVersion+1))
	if err != nil {
		t.Fatal(err)
	}
	if one[key] == other[key] {
		t.Error("two apps with the same tile got the same secret")
	}
	if one[key] == rotated[key] {
		t.Error("the rotation version did not reach the derivation")
	}
}

func TestEscapeNeutralisesEveryToken(t *testing.T) {
	for _, c := range []struct{ why, in, want string }{
		{"one token", "P: ${secret:db}\n", "P: $${secret:db}\n"},
		{"two tokens on one line", "P: ${secret:a}${secret:b}\n", "P: $${secret:a}$${secret:b}\n"},
		{"a token at the very start of the file", "${secret:a}", "$${secret:a}"},
		{"no token at all — returned unchanged", "P: ${OTHER}\n", "P: ${OTHER}\n"},
		{"a malformed token is still neutralised: escaping needs no parse", "P: ${secret:DB", "P: $${secret:DB"},
		{"already escaped — idempotent, so a double escape cannot make Compose emit $${secret:a}", "P: $${secret:a}\n", "P: $${secret:a}\n"},
	} {
		if got := Escape(c.in); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.why, got, c.want)
		}
	}
}

func TestEscapeIsIdempotent(t *testing.T) {
	in := "P: ${secret:a}\nQ: ${secret:b}\n"
	once := Escape(in)
	if twice := Escape(once); twice != once {
		t.Errorf("escaping twice changed the result:\n once %q\ntwice %q", once, twice)
	}
}
