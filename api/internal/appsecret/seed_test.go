package appsecret

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
)

func TestEnsureSeedCreatesOnceAndAdoptsWhatItFinds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "trust")

	first, err := EnsureSeed(dir)
	if err != nil {
		t.Fatalf("first EnsureSeed: %v", err)
	}
	if first.DerivationVersion() != DerivationVersion {
		t.Errorf("derivation version %d, want %d", first.DerivationVersion(), DerivationVersion)
	}
	one, err := first.Derive("app", "db-password", InitialVersion)
	if err != nil {
		t.Fatal(err)
	}

	// The second call must ADOPT, never re-mint. Re-minting is unrecoverable:
	// every app secret on the cluster is a function of the seed and the old
	// values survive inside the apps' data volumes.
	second, err := EnsureSeed(dir)
	if err != nil {
		t.Fatalf("second EnsureSeed: %v", err)
	}
	two, err := second.Derive("app", "db-password", InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Fatal("a second EnsureSeed derives a different value: the seed was replaced, and every app secret on the cluster with it")
	}
}

func TestEnsureSeedWritesAnOwnerOnlyFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "trust")
	if _, err := EnsureSeed(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(dir, SeedFileName))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != atrest.SecretFileMode {
		t.Errorf("seed file mode %#o, want %#o", got, atrest.SecretFileMode)
	}
	dinfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dinfo.Mode().Perm(); got != atrest.SecretDirMode {
		t.Errorf("trust dir mode %#o, want %#o", got, atrest.SecretDirMode)
	}
}

// Two api processes racing a first start — the case atrest.CreateSecretFile's
// hard link exists for. One seed wins and both callers must end up on it; a
// loser that kept its own would derive credentials no container was given.
func TestEnsureSeedSurvivesAConcurrentFirstStart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "trust")
	const racers = 8
	values := make([]string, racers)
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seed, err := EnsureSeed(dir)
			if err != nil {
				errs[i] = err
				return
			}
			values[i], errs[i] = seed.Derive("app", "db-password", InitialVersion)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("racer %d: %v", i, err)
		}
	}
	for i, v := range values {
		if v != values[0] {
			t.Fatalf("racer %d derived %q, racer 0 derived %q: the racers are on different seeds", i, v, values[0])
		}
	}
}

// The seed file carries the derivation version, so the pair cannot be separated.
func TestSeedFileRoundTripsTheDerivationVersion(t *testing.T) {
	key := make([]byte, SeedLen)
	for i := range key {
		key[i] = byte(i)
	}
	raw := formatSeedFile(key, DerivationVersion)
	if !strings.HasPrefix(string(raw), seedFileMagic) {
		t.Fatalf("the seed file does not identify itself: %q", raw)
	}
	seed, err := parseSeedFile(raw)
	if err != nil {
		t.Fatalf("parseSeedFile: %v", err)
	}
	if seed.DerivationVersion() != DerivationVersion {
		t.Errorf("derivation version %d, want %d", seed.DerivationVersion(), DerivationVersion)
	}
	fresh, err := NewSeed(key, DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	fromFile, err := seed.Derive("app", "db-password", InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := fresh.Derive("app", "db-password", InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	if fromFile != direct {
		t.Error("the seed did not survive the file round trip")
	}
}

func TestParseSeedFileRefusesWhatItCannotTrust(t *testing.T) {
	for _, c := range []struct{ why, raw string }{
		{"empty", ""},
		{"no magic", "1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"},
		{"magic but no seed after the version", seedFileMagic + "1\n"},
		{"a non-numeric derivation version", seedFileMagic + "x AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"},
		{"a derivation version this build cannot derive with", seedFileMagic + "99 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"},
		{"a padded base64 seed", seedFileMagic + "1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"},
		{"standard-alphabet base64", seedFileMagic + "1 //////////////////////////////////////////\n"},
		{"a short seed", seedFileMagic + "1 AAAA\n"},
		{"not base64 at all", seedFileMagic + "1 not-base-64!!!\n"},
	} {
		if _, err := parseSeedFile([]byte(c.raw)); err == nil {
			t.Errorf("accepted a seed file that is %s", c.why)
		}
	}
}

// A seed file this build cannot read is NOT repaired and NOT replaced: a fresh
// seed written over it destroys every app secret on the cluster with no way
// back, and refusing to start leaves the file there to be rolled back to.
func TestEnsureSeedRefusesRatherThanReplacingAnUnreadableSeed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "trust")
	if err := atrest.EnsureSecretDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, SeedFileName)
	junk := []byte("this is not a seed file\n")
	if err := atrest.WriteSecretFile(path, junk); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureSeed(dir); err == nil {
		t.Fatal("EnsureSeed accepted an unreadable seed file")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(junk) {
		t.Fatalf("EnsureSeed overwrote a seed file it could not read: %q", after)
	}
}
