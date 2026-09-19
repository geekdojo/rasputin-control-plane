package mesh

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestParseAPIKey(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"prefixed key on trailing line", "An API key was created:\nhskey-abcdef0123456789abcdef\n", "hskey-abcdef0123456789abcdef"},
		{"bare token", "Y3J5cHRvLXRva2VuLXZhbHVlLTEyMzQ1Ng==", "Y3J5cHRvLXRva2VuLXZhbHVlLTEyMzQ1Ng=="},
		{"ignores short/words trailing lines", "longtokenvalue0123456789\nok\n", "longtokenvalue0123456789"},
		{"trailing blank lines", "tokentokentokentoken1234\n\n\n", "tokentokentokentoken1234"},
		{"prose only -> empty", "no key here today\n", ""},
		{"empty -> empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseAPIKey([]byte(tc.in)); got != tc.want {
				t.Fatalf("parseAPIKey(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestHeadscaleAPIKeyPrefix(t *testing.T) {
	secret := strings.Repeat("x", 64)
	cases := []struct {
		name, in, want string
		ok             bool
	}{
		{"current format", "hskey-api-abcdefABCDEF-" + secret, "abcdefABCDEF", true},
		{"prefix may hold url-safe punctuation", "hskey-api-ab-d_fABCDEF-" + secret, "ab-d_fABCDEF", true},
		{"surrounding whitespace", "  hskey-api-abcdefABCDEF-" + secret + "\n", "abcdefABCDEF", true},
		{"legacy prefix.secret", "abcdefg." + secret, "abcdefg", true},
		{"current format, prefix too short", "hskey-api-abc-" + secret, "", false},
		{"current format, no separator", "hskey-api-abcdefABCDEFG" + secret, "", false},
		{"current format, bad characters", "hskey-api-abc/efABCDEF-" + secret, "", false},
		{"legacy, wrong prefix length", "abcdef." + secret, "", false},
		{"not a key", "hello", "", false},
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := headscaleAPIKeyPrefix(tc.in)
			if tc.ok && (err != nil || got != tc.want) {
				t.Fatalf("headscaleAPIKeyPrefix(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
			}
			if !tc.ok && err == nil {
				t.Fatalf("headscaleAPIKeyPrefix(%q) = %q; want an error", tc.in, got)
			}
		})
	}
}

func startedSupervisor(t *testing.T) (*DockerSupervisor, *fakeDocker) {
	t.Helper()
	fd := newFakeDocker()
	fd.imagePresent = true
	sup := newTestSupervisor(t, fd)
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return sup, fd
}

func recordedPrefixes(t *testing.T, sup *DockerSupervisor) []string {
	t.Helper()
	p, err := sup.readAPIKeyPrefixes()
	if err != nil {
		t.Fatalf("readAPIKeyPrefixes: %v", err)
	}
	return p
}

// Each api start mints its own key, holds it only in memory, and expires the
// one the previous start minted.
func TestMintSessionAPIKey_EachStartExpiresThePrevious(t *testing.T) {
	ctx := context.Background()
	sup, fd := startedSupervisor(t)

	key1, err := sup.MintSessionAPIKey(ctx)
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	p1, _ := headscaleAPIKeyPrefix(key1)
	if got := recordedPrefixes(t, sup); !slices.Equal(got, []string{p1}) {
		t.Fatalf("recorded prefixes after first mint = %v, want [%s]", got, p1)
	}
	if _, err := os.Stat(sup.legacyAPIKeyPath()); !os.IsNotExist(err) {
		t.Fatalf("the key must not be persisted; stat err=%v", err)
	}
	b, err := os.ReadFile(sup.apiKeyPrefixesPath())
	if err != nil {
		t.Fatalf("read prefixes file: %v", err)
	}
	if strings.Contains(string(b), key1) || strings.Contains(string(b), strings.Repeat("s", 64)) {
		t.Fatal("the prefixes file holds the key's secret")
	}
	if info, err := os.Stat(sup.apiKeyPrefixesPath()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("prefixes file mode: %v %v", info, err)
	}

	// A new api process: a new supervisor over the same state dir.
	sup2 := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) { c.StateDir = sup.cfg.StateDir })
	key2, err := sup2.MintSessionAPIKey(ctx)
	if err != nil {
		t.Fatalf("second mint: %v", err)
	}
	if key2 == key1 {
		t.Fatal("a restart must mint a new key, not reuse the old one")
	}
	p2, _ := headscaleAPIKeyPrefix(key2)
	if !fd.apiKeys[p1] {
		t.Errorf("previous key %s was not expired on Headscale", p1)
	}
	if fd.apiKeys[p2] {
		t.Errorf("the new key %s must stay live", p2)
	}
	if got := recordedPrefixes(t, sup2); !slices.Equal(got, []string{p2}) {
		t.Fatalf("recorded prefixes after restart = %v, want [%s]", got, p2)
	}
	if fd.mintCount != 2 {
		t.Fatalf("mintCount = %d, want 2", fd.mintCount)
	}
}

// A prefix Headscale cannot expire stays recorded and is retried next time;
// a prefix Headscale no longer has counts as expired.
func TestMintSessionAPIKey_KeepsUnexpiredPrefixesForRetry(t *testing.T) {
	ctx := context.Background()
	sup, fd := startedSupervisor(t)
	key1, err := sup.MintSessionAPIKey(ctx)
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	p1, _ := headscaleAPIKeyPrefix(key1)

	fd.expireErr = errors.New("exit status 1")
	key2, err := sup.MintSessionAPIKey(ctx)
	if err != nil {
		t.Fatalf("a failed expire must not fail the mint: %v", err)
	}
	p2, _ := headscaleAPIKeyPrefix(key2)
	if got := recordedPrefixes(t, sup); !slices.Equal(got, []string{p2, p1}) {
		t.Fatalf("recorded = %v, want [%s %s]", got, p2, p1)
	}

	fd.expireErr = nil
	delete(fd.apiKeys, p1) // Headscale lost it (a restored DB, say)
	key3, err := sup.MintSessionAPIKey(ctx)
	if err != nil {
		t.Fatalf("third mint: %v", err)
	}
	p3, _ := headscaleAPIKeyPrefix(key3)
	if !fd.apiKeys[p2] {
		t.Errorf("%s should now be expired", p2)
	}
	if got := recordedPrefixes(t, sup); !slices.Equal(got, []string{p3}) {
		t.Fatalf("recorded = %v, want [%s]: a not-found prefix is done", got, p3)
	}
}

// The long-lived key an older api persisted is expired by its prefix, then
// its file is deleted.
func TestMintSessionAPIKey_RetiresLegacyKeyFile(t *testing.T) {
	ctx := context.Background()
	sup, fd := startedSupervisor(t)
	const legacyPrefix = "LegacyPrefx1"
	fd.apiKeys[legacyPrefix] = false
	legacy := "hskey-api-" + legacyPrefix + "-" + strings.Repeat("L", 64)
	if err := os.WriteFile(sup.legacyAPIKeyPath(), []byte(legacy+"\n"), 0o600); err != nil {
		t.Fatalf("seed legacy key: %v", err)
	}

	key, err := sup.MintSessionAPIKey(ctx)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if key == legacy {
		t.Fatal("the legacy key must not be reused")
	}
	if !fd.apiKeys[legacyPrefix] {
		t.Error("legacy key was not expired on Headscale")
	}
	if _, err := os.Stat(sup.legacyAPIKeyPath()); !os.IsNotExist(err) {
		t.Errorf("legacy key file should be deleted; stat err=%v", err)
	}
}

// The legacy file stays until its key is confirmed expired.
func TestMintSessionAPIKey_KeepsLegacyFileWhenExpireFails(t *testing.T) {
	ctx := context.Background()
	sup, fd := startedSupervisor(t)
	legacy := "hskey-api-LegacyPrefx1-" + strings.Repeat("L", 64)
	fd.apiKeys["LegacyPrefx1"] = false
	if err := os.WriteFile(sup.legacyAPIKeyPath(), []byte(legacy), 0o600); err != nil {
		t.Fatalf("seed legacy key: %v", err)
	}
	fd.expireErr = errors.New("exit status 1")
	if _, err := sup.MintSessionAPIKey(ctx); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := os.Stat(sup.legacyAPIKeyPath()); err != nil {
		t.Fatalf("legacy file must stay for a retry when the expire failed: %v", err)
	}

	fd.expireErr = nil
	if _, err := sup.MintSessionAPIKey(ctx); err != nil {
		t.Fatalf("second mint: %v", err)
	}
	if _, err := os.Stat(sup.legacyAPIKeyPath()); !os.IsNotExist(err) {
		t.Fatalf("legacy file should be gone once expired; stat err=%v", err)
	}
	if !fd.apiKeys["LegacyPrefx1"] {
		t.Error("legacy key was not expired")
	}
}

// An empty legacy file holds no key to expire and is simply deleted.
func TestMintSessionAPIKey_DeletesEmptyLegacyFile(t *testing.T) {
	sup, _ := startedSupervisor(t)
	if err := os.WriteFile(sup.legacyAPIKeyPath(), []byte("  \n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := sup.MintSessionAPIKey(context.Background()); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := os.Stat(sup.legacyAPIKeyPath()); !os.IsNotExist(err) {
		t.Fatalf("empty legacy file should be deleted; stat err=%v", err)
	}
}

func TestMintSessionAPIKey_PropagatesMintError(t *testing.T) {
	ctx := context.Background()
	fd := newFakeDocker()
	fd.imagePresent = true
	fd.errOnCmd["exec"] = errors.New("boom")
	sup := newTestSupervisor(t, fd)
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := sup.MintSessionAPIKey(ctx); err == nil {
		t.Fatal("expected error when docker exec fails, got nil")
	}
	if p := recordedPrefixes(t, sup); len(p) != 0 {
		t.Fatalf("nothing should be recorded on mint failure; got %v", p)
	}
}

// A mint whose output is not a key must not echo that output: it is where a
// key would be.
func TestMintAPIKey_ErrorDoesNotEchoOutput(t *testing.T) {
	fd := newFakeDocker()
	fd.imagePresent = true
	sup := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) {
		c.Runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "exec" {
				return []byte("sensitive-ish output no key\n"), nil
			}
			return fd.run(ctx, name, args...)
		}
	})
	_ = sup.Start(context.Background())
	_, err := sup.mintAPIKey(context.Background())
	if err == nil || strings.Contains(err.Error(), "sensitive-ish") {
		t.Fatalf("mintAPIKey error = %v; want an error that does not carry the CLI output", err)
	}
}
