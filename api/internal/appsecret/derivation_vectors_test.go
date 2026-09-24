package appsecret

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Hand-rolled spec code is checked against other implementations, never against
// itself — the rule api/internal/console/sha512crypt_test.go states, applied to
// the one derivation in this tree that can never change again.
//
// testdata/derivation-vectors.json was produced by
// scripts/gen-app-secret-vectors.sh from TWO implementations that share no code
// with this package: OpenSSL's libcrypto HKDF, and an RFC 5869 §2.3 reading in
// Python that the script validates against the RFC's own Appendix A vectors
// before it will write anything. The two agreed byte for byte. This test is the
// third implementation and the only one that is allowed to be wrong.
//
// What a failure here means. NOT "update the vectors". ADR-0006 Decision 11a
// freezes this derivation: a change to the algorithm, the info encoding, the
// output length or the output ENCODING hands every deployed app a credential it
// never received while its data volume still holds the old one — every cluster,
// at the same moment, on upgrade. If a change genuinely has to happen it happens
// as derivationVersion 2, which existing seeds never select. Re-blessing this
// file is the failure mode it exists to prevent.
type derivationVectors struct {
	DerivationVersion int    `json:"derivationVersion"`
	Algorithm         string `json:"algorithm"`
	Encoding          string `json:"encoding"`
	Cases             []struct {
		Why     string `json:"why"`
		SeedHex string `json:"seedHex"`
		AppID   string `json:"appId"`
		Name    string `json:"name"`
		Version uint32 `json:"version"`
		InfoHex string `json:"infoHex"`
		Want    string `json:"want"`
	} `json:"cases"`
}

const vectorsPath = "testdata/derivation-vectors.json"

func loadVectors(t *testing.T) derivationVectors {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", vectorsPath, err)
	}
	var v derivationVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse %s: %v", vectorsPath, err)
	}
	// A vectors file that has quietly emptied — a bad merge, a generator that
	// wrote a truncated document, a testdata directory lost in a move — would
	// make this suite pass while pinning nothing, which is the failure the whole
	// arrangement exists to prevent. Same guard as
	// api/internal/setup/operatorkeys_test.go.
	if len(v.Cases) < 9 {
		t.Fatalf("the committed vectors look truncated: %d cases, want at least 9 — regenerate with scripts/gen-app-secret-vectors.sh", len(v.Cases))
	}
	if v.DerivationVersion != DerivationVersion {
		t.Fatalf("the vectors pin derivation version %d and this build mints %d: a new version needs its own vectors, not the old ones re-read",
			v.DerivationVersion, DerivationVersion)
	}
	return v
}

func TestDerivationMatchesTheFrozenVectors(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Cases {
		seedBytes, err := hex.DecodeString(c.SeedHex)
		if err != nil {
			t.Fatalf("%s: seedHex: %v", c.Why, err)
		}
		seed, err := NewSeed(seedBytes, v.DerivationVersion)
		if err != nil {
			t.Fatalf("%s: NewSeed: %v", c.Why, err)
		}
		got, err := seed.Derive(c.AppID, c.Name, c.Version)
		if err != nil {
			t.Fatalf("%s: Derive: %v", c.Why, err)
		}
		if got != c.Want {
			t.Errorf("THE FROZEN DERIVATION MOVED (%s)\n appID=%q name=%q version=%d\n  got %q\n want %q\nThis is not a vector to re-bless: see this file's header.",
				c.Why, c.AppID, c.Name, c.Version, got, c.Want)
		}
	}
}

// The info string, pinned on its own. A vector set that only carried outputs
// could not tell a changed info ENCODING from a changed hash, and the encoding
// is the half an independent re-implementation gets wrong — a separator instead
// of length prefixes, little-endian lengths, the version left off the end.
func TestInfoEncodingMatchesTheFrozenVectors(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Cases {
		info, err := infoV1(c.AppID, c.Name, c.Version)
		if err != nil {
			t.Fatalf("infoV1(%q, %q, %d): %v", c.AppID, c.Name, c.Version, err)
		}
		got := hex.EncodeToString(info)
		if got != c.InfoHex {
			t.Errorf("info encoding moved (%s)\n appID=%q name=%q version=%d\n  got %s\n want %s",
				c.Why, c.AppID, c.Name, c.Version, got, c.InfoHex)
		}
	}
}

// The property the length prefixing exists for, asserted directly rather than
// left implicit in two vector values: appID "a" + name "bc" and appID "ab" +
// name "c" are the same bytes once a separator is removed. A concatenating
// implementation gives them the same secret, and an author who can name a secret
// can then reach another app's tuple.
func TestLengthPrefixingKeepsTheTupleInjective(t *testing.T) {
	seed, err := NewSeed(make([]byte, SeedLen), DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	one, err := seed.Derive("a", "bc", InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	two, err := seed.Derive("ab", "c", InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatalf("(a,bc) and (ab,c) derive the same secret %q: the info string is not injective, so a crafted secret name can impersonate another app's tuple", one)
	}
}

// Each component moving, moving the value. Cheap, and it is what would catch a
// derivation that quietly dropped one of its inputs — a bug the vectors above
// would still pass if the dropped input happened to be constant across them.
func TestEveryComponentOfTheTupleChangesTheValue(t *testing.T) {
	seedA, err := NewSeed(make([]byte, SeedLen), DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	other := make([]byte, SeedLen)
	other[31] = 1
	seedB, err := NewSeed(other, DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	base, err := seedA.Derive("app-one", "db-password", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		why  string
		seed *Seed
		app  string
		name string
		ver  uint32
	}{
		{"a different seed", seedB, "app-one", "db-password", 1},
		{"a different appID", seedA, "app-two", "db-password", 1},
		{"a different name", seedA, "app-one", "session-key", 1},
		{"a different rotation version", seedA, "app-one", "db-password", 2},
	} {
		got, derr := c.seed.Derive(c.app, c.name, c.ver)
		if derr != nil {
			t.Fatalf("%s: %v", c.why, derr)
		}
		if got == base {
			t.Errorf("%s produced the same secret — that input is not reaching the derivation", c.why)
		}
	}
}

// The value has to survive an unquoted YAML scalar, an env file and whatever
// shell an image's entrypoint hands it to, which is why the encoding is
// base64url without padding rather than standard base64.
func TestDerivedValueIsSafeUnquoted(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Cases {
		for _, r := range c.Want {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
			if !ok {
				t.Fatalf("%s: derived value %q contains %q, which is not in the base64url alphabet", c.Why, c.Want, r)
			}
		}
		// 32 bytes, unpadded base64url: ceil(32/3)*4 - 1 padding char = 43.
		if len(c.Want) != 43 {
			t.Fatalf("%s: derived value is %d chars, want 43 (32 bytes, base64url, no padding)", c.Why, len(c.Want))
		}
	}
}

func TestDeriveRefusesWhatCannotBeDerivedFrom(t *testing.T) {
	seed, err := NewSeed(make([]byte, SeedLen), DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	var nilSeed *Seed
	for _, c := range []struct {
		why  string
		seed *Seed
		app  string
		name string
	}{
		{"no seed at all — an empty string would be deployed as a password", nilSeed, "app-one", "db-password"},
		{"an empty appID — the appID is what separates one app's secrets from another's", seed, "", "db-password"},
		{"a whitespace appID", seed, "   ", "db-password"},
		{"an appID over the length the info prefix can encode without truncating", seed, string(make([]byte, maxAppIDLen+1)), "db-password"},
		{"an empty name", seed, "app-one", ""},
		{"an upper-case name — the bound is a DNS-1123 label", seed, "app-one", "DB"},
		{"a name with a separator in it, which is the impersonation this validator kills at the source", seed, "app-one", "x:other:y"},
		{"a name over 63 characters", seed, "app-one", string(make([]byte, 64))},
	} {
		if _, err := c.seed.Derive(c.app, c.name, InitialVersion); err == nil {
			t.Errorf("derived a secret for %s", c.why)
		}
	}
}

func TestNewSeedRefusesAWrongSizeSeedAndAnUnknownDerivation(t *testing.T) {
	if _, err := NewSeed(make([]byte, SeedLen-1), DerivationVersion); err == nil {
		t.Error("accepted a short seed")
	}
	if _, err := NewSeed(make([]byte, SeedLen+1), DerivationVersion); err == nil {
		t.Error("accepted a long seed")
	}
	// A newer release wrote this file. Deriving under a version the seed was not
	// minted with is worse than refusing to start.
	if _, err := NewSeed(make([]byte, SeedLen), DerivationVersion+1); err == nil {
		t.Error("accepted a derivation version this build cannot derive with")
	}
	if _, err := NewSeed(make([]byte, SeedLen), 0); err == nil {
		t.Error("accepted derivation version 0")
	}
}

// A Seed must not alias the caller's slice: the caller is EnsureSeed, whose
// buffer is a local, but a future caller's might not be, and a seed that changed
// under the derivation would produce credentials no app has ever seen.
func TestNewSeedCopiesItsKey(t *testing.T) {
	key := make([]byte, SeedLen)
	seed, err := NewSeed(key, DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	before, err := seed.Derive("app-one", "db-password", InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	for i := range key {
		key[i] = 0xaa
	}
	after, err := seed.Derive("app-one", "db-password", InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("mutating the caller's slice changed what the seed derives")
	}
}
