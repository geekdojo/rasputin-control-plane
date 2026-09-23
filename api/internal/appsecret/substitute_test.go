package appsecret

import (
	"strings"
	"testing"
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

func TestResolveReplacesEveryTokenWithItsDerivedValue(t *testing.T) {
	seed := testSeed(t)
	compose := "services:\n  db:\n    environment:\n" +
		"      POSTGRES_PASSWORD: ${secret:db-password}\n" +
		"      SESSION_KEY: ${secret:session-key}\n" +
		"      ALSO_DB: ${secret:db-password}\n"

	got, err := Resolve(compose, appID, seed, InitialVersion)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strings.Contains(got, "${secret:") {
		t.Fatalf("a token survived resolution:\n%s", got)
	}
	dbValue, err := seed.Derive(appID, "db-password", InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	sessionValue, err := seed.Derive(appID, "session-key", InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	// Two occurrences of ONE name resolve to the SAME value — the app has one
	// database password, not two, and a tile that names it twice (an app and its
	// sidecar) must get a working pair.
	if strings.Count(got, dbValue) != 2 {
		t.Errorf("the db password appears %d time(s), want 2:\n%s", strings.Count(got, dbValue), got)
	}
	if !strings.Contains(got, sessionValue) {
		t.Errorf("the session key is not in the resolved compose:\n%s", got)
	}
	if dbValue == sessionValue {
		t.Error("two different names derived the same value")
	}
	// Everything that is not a token is untouched, byte for byte.
	want := strings.ReplaceAll(strings.ReplaceAll(compose, "${secret:db-password}", dbValue), "${secret:session-key}", sessionValue)
	if got != want {
		t.Errorf("resolution changed bytes outside the tokens:\n got %q\nwant %q", got, want)
	}
}

// The install path's contract: what the database holds is what the node gets. A
// compose with no token is returned as the SAME string, not re-rendered, because
// every app in the field today has no tokens and the revert path matches on the
// compose hash.
func TestResolveLeavesAComposeWithNoTokensVerbatim(t *testing.T) {
	compose := "services:\n  web:\n    image: x@sha256:" + strings.Repeat("a", 64) + "\n    environment:\n      A: ${OTHER}\n      B: $$LITERAL\n"
	got, err := Resolve(compose, appID, testSeed(t), InitialVersion)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != compose {
		t.Errorf("a compose with no secret token was rewritten:\n got %q\nwant %q", got, compose)
	}
	// And with no seed either: a cluster with no seed loaded must still be able
	// to deploy every app that does not ask for a secret.
	got, err = Resolve(compose, appID, nil, InitialVersion)
	if err != nil || got != compose {
		t.Errorf("no-token, no-seed: got %q, %v", got, err)
	}
}

// Refused, not passed through. A token sent on as a literal is deployed as a
// password — the exact failure this channel closes, and silently, with a
// container that came up and a job that succeeded.
func TestResolveRefusesATokenWithNoSeed(t *testing.T) {
	_, err := Resolve("environment:\n  P: ${secret:db-password}\n", appID, nil, InitialVersion)
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
		if _, err := Resolve(c.compose, appID, seed, InitialVersion); err == nil {
			t.Errorf("resolved a compose with %s", c.why)
		}
	}
}

func TestResolveIsBoundToTheAppAndTheVersion(t *testing.T) {
	seed := testSeed(t)
	compose := "P: ${secret:db-password}\n"
	one, err := Resolve(compose, appID, seed, InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Resolve(compose, "01OTHERAPP0000000000000000", seed, InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := Resolve(compose, appID, seed, InitialVersion+1)
	if err != nil {
		t.Fatal(err)
	}
	if one == other {
		t.Error("two apps with the same tile got the same secret")
	}
	if one == rotated {
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
