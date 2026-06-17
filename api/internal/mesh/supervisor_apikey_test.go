package mesh

import (
	"context"
	"errors"
	"os"
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

func TestEnsureAPIKey_MintsPersistsAndReuses(t *testing.T) {
	ctx := context.Background()
	fd := newFakeDocker()
	fd.imagePresent = true
	sup := newTestSupervisor(t, fd)

	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	key1, err := sup.EnsureAPIKey(ctx)
	if err != nil {
		t.Fatalf("EnsureAPIKey (mint): %v", err)
	}
	if key1 == "" {
		t.Fatal("EnsureAPIKey returned empty key")
	}
	if fd.mintCount != 1 {
		t.Fatalf("expected exactly 1 mint, got %d", fd.mintCount)
	}
	// The key must be persisted at <state>/apikey with 0600.
	b, err := os.ReadFile(sup.apiKeyPath())
	if err != nil {
		t.Fatalf("read persisted key: %v", err)
	}
	if strings.TrimSpace(string(b)) != key1 {
		t.Fatalf("persisted key %q != returned key %q", strings.TrimSpace(string(b)), key1)
	}
	if info, err := os.Stat(sup.apiKeyPath()); err != nil {
		t.Fatalf("stat key file: %v", err)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file perm = %o, want 600", perm)
	}

	// Second call must reuse the persisted key — no new docker exec.
	key2, err := sup.EnsureAPIKey(ctx)
	if err != nil {
		t.Fatalf("EnsureAPIKey (reuse): %v", err)
	}
	if key2 != key1 {
		t.Fatalf("reuse returned different key: %q != %q", key2, key1)
	}
	if fd.mintCount != 1 {
		t.Fatalf("reuse should not re-mint; mintCount = %d", fd.mintCount)
	}
}

func TestEnsureAPIKey_RemintsWhenPersistedKeyEmpty(t *testing.T) {
	ctx := context.Background()
	fd := newFakeDocker()
	fd.imagePresent = true
	sup := newTestSupervisor(t, fd)
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Pre-seed an empty/whitespace key file — should be treated as absent.
	if err := os.WriteFile(sup.apiKeyPath(), []byte("  \n"), 0o600); err != nil {
		t.Fatalf("seed empty key: %v", err)
	}
	key, err := sup.EnsureAPIKey(ctx)
	if err != nil {
		t.Fatalf("EnsureAPIKey: %v", err)
	}
	if key == "" || fd.mintCount != 1 {
		t.Fatalf("expected a fresh mint; key=%q mintCount=%d", key, fd.mintCount)
	}
}

func TestEnsureAPIKey_PropagatesMintError(t *testing.T) {
	ctx := context.Background()
	fd := newFakeDocker()
	fd.imagePresent = true
	fd.errOnCmd["exec"] = errors.New("boom")
	sup := newTestSupervisor(t, fd)
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := sup.EnsureAPIKey(ctx); err == nil {
		t.Fatal("expected error when docker exec fails, got nil")
	}
	if _, err := os.Stat(sup.apiKeyPath()); !os.IsNotExist(err) {
		t.Fatalf("no key file should be written on mint failure; stat err=%v", err)
	}
}
