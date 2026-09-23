package tileschema

import (
	"strings"
	"testing"
)

func TestScanSecretTokensFindsEveryTokenAndWhereItIs(t *testing.T) {
	compose := "services:\n  db:\n    environment:\n" +
		"      POSTGRES_PASSWORD: ${secret:db-password}\n" +
		"      SESSION_KEY: ${secret:session-key}\n" +
		"      AGAIN: ${secret:db-password}\n"
	tokens, err := ScanSecretTokens(compose)
	if err != nil {
		t.Fatalf("ScanSecretTokens: %v", err)
	}
	want := []string{"db-password", "session-key", "db-password"}
	if len(tokens) != len(want) {
		t.Fatalf("found %d token(s), want %d: %+v", len(tokens), len(want), tokens)
	}
	for i, tok := range tokens {
		if tok.Name != want[i] {
			t.Errorf("token %d name %q, want %q", i, tok.Name, want[i])
		}
		// The offsets are the contract: a caller rewrites compose[Start:End]
		// without re-finding the token, so an off-by-one here corrupts a compose
		// rather than failing a check.
		if got := compose[tok.Start:tok.End]; got != SecretTokenPrefix+tok.Name+"}" {
			t.Errorf("token %d spans %q, want %q", i, got, SecretTokenPrefix+tok.Name+"}")
		}
	}
}

func TestScanSecretTokensFindsNoneWhereThereAreNone(t *testing.T) {
	for _, compose := range []string{
		"",
		"services: {}\n",
		"environment:\n  A: ${OTHER}\n  B: ${OTHER:-default}\n",
		"environment:\n  A: secret:db\n  B: ${secrets:db}\n",
	} {
		tokens, err := ScanSecretTokens(compose)
		if err != nil {
			t.Errorf("%q: %v", compose, err)
		}
		if len(tokens) != 0 {
			t.Errorf("%q: found %+v", compose, tokens)
		}
	}
}

func TestScanSecretTokensRefusesMalformedOnes(t *testing.T) {
	for _, c := range []struct{ why, compose string }{
		{"unterminated, with a brace pages later", "A: ${secret:db\nB: 1\nC: }\n"},
		{"unterminated at end of file", "A: ${secret:db"},
		{"empty name", "A: ${secret:}\n"},
		{"upper case", "A: ${secret:DB}\n"},
		{"underscore", "A: ${secret:db_password}\n"},
		{"leading hyphen", "A: ${secret:-db}\n"},
		{"trailing hyphen", "A: ${secret:db-}\n"},
		{"a colon, which is the impersonation a separator-joined info string would allow", "A: ${secret:x:01OTHER:y}\n"},
		{"64 characters, one over a DNS label", "A: ${secret:" + strings.Repeat("a", 64) + "}\n"},
		{"a space in the name", "A: ${secret:db password}\n"},
		{"the escaped form, which only the control plane may emit", "A: $${secret:db}\n"},
	} {
		if _, err := ScanSecretTokens(c.compose); err == nil {
			t.Errorf("accepted a compose with %s", c.why)
		}
	}
}

// A valid token after a bad one is never reached, so the scan must not report
// success on a compose whose FIRST token is fine and whose second is not.
func TestScanSecretTokensRefusesALaterMalformedToken(t *testing.T) {
	if _, err := ScanSecretTokens("A: ${secret:ok}\nB: ${secret:NOT-OK}\n"); err == nil {
		t.Fatal("accepted a compose whose second token is malformed")
	}
}

func TestValidSecretNameIsTheSameGuardAsTheTileID(t *testing.T) {
	for _, s := range []string{"db", "db-password", "a", strings.Repeat("a", 63)} {
		if !ValidSecretName(s) {
			t.Errorf("refused %q", s)
		}
		if ValidSecretName(s) != ValidDNSLabel(s) {
			t.Errorf("%q: ValidSecretName and ValidDNSLabel disagree", s)
		}
	}
	for _, s := range []string{"", "DB", "db_x", "-db", "db-", "db.x", strings.Repeat("a", 64)} {
		if ValidSecretName(s) {
			t.Errorf("accepted %q", s)
		}
		if ValidSecretName(s) != ValidDNSLabel(s) {
			t.Errorf("%q: ValidSecretName and ValidDNSLabel disagree", s)
		}
	}
}

func TestTileSecretsIsAKnownCapability(t *testing.T) {
	if !KnownCapabilities[CapabilityTileSecrets] {
		t.Fatalf("%q is not in KnownCapabilities, so a tile declaring it is refused by this build", CapabilityTileSecrets)
	}
	// It is the THIRD entry, not the first — ADR-0006's own text is stale on
	// that point and this is where the count is checked rather than restated.
	if len(KnownCapabilities) != 3 {
		t.Errorf("KnownCapabilities holds %d entries; if that is deliberate, update this assertion and say why in the PR", len(KnownCapabilities))
	}
}

func TestValidateTileRequiresTheCapabilityWhenTheComposeUsesASecret(t *testing.T) {
	tile := okTile()
	tile.ComposeYAML = "services:\n  db:\n    environment:\n      P: ${secret:db-password}\n"

	err := ValidateTile(tile)
	if err == nil {
		t.Fatal("a tile whose compose uses ${secret:} was accepted without the capability: an older control plane would deploy the literal as a password")
	}
	if !strings.Contains(err.Error(), CapabilityTileSecrets) {
		t.Errorf("the refusal does not name the capability to add: %v", err)
	}

	tile.Requires = []string{CapabilityTileSecrets}
	if err := ValidateTile(tile); err != nil {
		t.Fatalf("a tile that declares the capability was refused: %v", err)
	}
}

// The other direction: declaring the capability without using a token is legal.
// A tile may carry it ahead of the compose that needs it, and refusing that
// would make the declaration a thing an author has to time.
func TestValidateTileAllowsTheCapabilityWithoutAToken(t *testing.T) {
	tile := okTile()
	tile.Requires = []string{CapabilityTileSecrets}
	if err := ValidateTile(tile); err != nil {
		t.Fatalf("declaring the capability with no token in the compose was refused: %v", err)
	}
}

// One validator, two callers (Decision 8): the name bound is enforced in
// ValidateTile, which the publisher runs before signing and the control plane
// runs at catalog load. A malformed token is a refused tile at BOTH ends rather
// than a broken install at deploy.
func TestValidateTileRefusesAMalformedTokenEvenWithTheCapability(t *testing.T) {
	tile := okTile()
	tile.Requires = []string{CapabilityTileSecrets}
	for _, c := range []struct{ why, compose string }{
		{"an upper-case name", "environment:\n  P: ${secret:DB}\n"},
		{"an unterminated token", "environment:\n  P: ${secret:db\n"},
		{"a name carrying a separator", "environment:\n  P: ${secret:x:other:y}\n"},
	} {
		tile.ComposeYAML = c.compose
		if err := ValidateTile(tile); err == nil {
			t.Errorf("accepted a tile with %s", c.why)
		}
	}
}

// A PREVIEW tile ships no compose, so it has no tokens and must still validate —
// the same reason the must-understand loop was moved out of ValidateTileSafety.
func TestValidateTileAcceptsAPreviewTileDeclaringTheCapability(t *testing.T) {
	tile := okTile()
	tile.Status = StatusPreview
	tile.ComposeYAML = ""
	tile.Requires = []string{CapabilityTileSecrets}
	if err := ValidateTile(tile); err != nil {
		t.Fatalf("a preview tile declaring tile.secrets was refused: %v", err)
	}
}
