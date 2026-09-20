package setup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const (
	testKeyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2AcGjrl5kW bryce@laptop"
	testKeyB = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB other@host"
)

func newKeysService(t *testing.T) (*Service, *Store) {
	t.Helper()
	st := newStore(t)
	return NewService(st, Probes{}, "cp-1", "test1.local", "test1"), st
}

func mustKey(t *testing.T, s *Service) OperatorKey {
	t.Helper()
	k, err := s.OperatorSSHKey(context.Background())
	if err != nil {
		t.Fatalf("OperatorSSHKey: %v", err)
	}
	return k
}

func mustRaw(t *testing.T, st *Store) string {
	t.Helper()
	raw, err := st.Get(context.Background(), KeyOperatorSSHKeys)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return raw
}

func TestOperatorSSHKey_UnsetIsUncaptured(t *testing.T) {
	s, _ := newKeysService(t)
	if k := mustKey(t, s); k != (OperatorKey{}) {
		t.Errorf("want zero value (never captured), got %+v", k)
	}
}

func TestSetOperatorSSHKey_StoresExactlyOneTrimmedKey(t *testing.T) {
	s, st := newKeysService(t)
	got, err := s.SetOperatorSSHKey(context.Background(), "  "+testKeyA+"\n")
	if err != nil {
		t.Fatalf("SetOperatorSSHKey: %v", err)
	}
	if got != testKeyA {
		t.Errorf("want trimmed key back, got %q", got)
	}
	if want := `["` + testKeyA + `"]`; mustRaw(t, st) != want {
		t.Errorf("storage keeps the list encoding with one element: want %s, got %s", want, mustRaw(t, st))
	}
	if k := mustKey(t, s); k != (OperatorKey{Key: testKeyA, Captured: true}) {
		t.Errorf("round-trip: got %+v", k)
	}
}

func TestSetOperatorSSHKey_ReplaceNeverAccumulates(t *testing.T) {
	s, st := newKeysService(t)
	ctx := context.Background()
	for _, k := range []string{testKeyA, testKeyB} {
		if _, err := s.SetOperatorSSHKey(ctx, k); err != nil {
			t.Fatalf("SetOperatorSSHKey(%q): %v", k, err)
		}
	}
	if want := `["` + testKeyB + `"]`; mustRaw(t, st) != want {
		t.Errorf("want only B stored, got %s", mustRaw(t, st))
	}
}

func TestSetOperatorSSHKey_BlankClearsExplicitly(t *testing.T) {
	s, st := newKeysService(t)
	ctx := context.Background()
	if _, err := s.SetOperatorSSHKey(ctx, testKeyA); err != nil {
		t.Fatal(err)
	}
	for _, blank := range []string{"", "   "} {
		if _, err := s.SetOperatorSSHKey(ctx, blank); err != nil {
			t.Fatalf("SetOperatorSSHKey(%q): %v", blank, err)
		}
		if mustRaw(t, st) != "[]" {
			t.Errorf("clear stores an empty list, got %s", mustRaw(t, st))
		}
		if k := mustKey(t, s); k != (OperatorKey{Captured: true}) {
			t.Errorf("want captured with no key, got %+v", k)
		}
	}
}

func TestSetOperatorSSHKey_RejectsInvalid(t *testing.T) {
	s, st := newKeysService(t)
	ctx := context.Background()
	if _, err := s.SetOperatorSSHKey(ctx, testKeyA); err != nil {
		t.Fatal(err)
	}
	before := mustRaw(t, st)
	for _, bad := range []string{
		"not-a-key",
		"ssh-ed25519",                         // no key material
		testKeyA + "\n" + testKeyB,            // two lines is not one key
		`ssh-ed25519 AAAA comment"with-quote`, // breaks seed quoting
		"ssh-ed25519 AAAA comment$(pwned)",    // breaks seed quoting
		"ssh-ed25519 AAAA comment`bad`",       // breaks seed quoting
		"ssh-ed25519 AAAA comment\\backslash", // breaks seed quoting
	} {
		if _, err := s.SetOperatorSSHKey(ctx, bad); err == nil {
			t.Errorf("want error for %q, got nil", bad)
		}
	}
	if mustRaw(t, st) != before {
		t.Errorf("a rejected key changed the stored value: %s", mustRaw(t, st))
	}
}

// Legacy values from the list UI: the first key is the key (the wizard always
// prefilled keys[0]); the rest are counted, not dropped, until the next write.
func TestOperatorSSHKey_LegacyMultiKeyValue(t *testing.T) {
	ctx := context.Background()
	legacy := `["` + testKeyA + `","` + testKeyB + `"]`

	t.Run("first key wins, extras reported, read does not rewrite", func(t *testing.T) {
		s, st := newKeysService(t)
		if err := st.Set(ctx, KeyOperatorSSHKeys, legacy); err != nil {
			t.Fatal(err)
		}
		if k := mustKey(t, s); k != (OperatorKey{Key: testKeyA, Captured: true, IgnoredKeys: 1}) {
			t.Errorf("got %+v", k)
		}
		if mustRaw(t, st) != legacy {
			t.Errorf("read rewrote the stored value: %s", mustRaw(t, st))
		}
	})

	t.Run("next write drops the extras", func(t *testing.T) {
		s, st := newKeysService(t)
		if err := st.Set(ctx, KeyOperatorSSHKeys, legacy); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SetOperatorSSHKey(ctx, testKeyA); err != nil {
			t.Fatal(err)
		}
		if k := mustKey(t, s); k != (OperatorKey{Key: testKeyA, Captured: true}) {
			t.Errorf("got %+v", k)
		}
	})

	t.Run("explicit empty list is a clear", func(t *testing.T) {
		s, st := newKeysService(t)
		if err := st.Set(ctx, KeyOperatorSSHKeys, "[]"); err != nil {
			t.Fatal(err)
		}
		if k := mustKey(t, s); k != (OperatorKey{Captured: true}) {
			t.Errorf("got %+v", k)
		}
	})

	t.Run("corrupt value is an error, not a silent empty", func(t *testing.T) {
		s, st := newKeysService(t)
		if err := st.Set(ctx, KeyOperatorSSHKeys, `"ssh-ed25519 AAAA not-a-list"`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.OperatorSSHKey(ctx); err == nil {
			t.Error("want error for a non-list value")
		}
	})
}

func TestSeedOperatorSSHKeyFromFile(t *testing.T) {
	ctx := context.Background()

	writeAK := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "authorized_keys")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("captures the first valid line when unset", func(t *testing.T) {
		s, st := newKeysService(t)
		p := writeAK(t, "# managed by rasputin\n\nnot a key line\n"+testKeyA+"\n"+testKeyB+"\n")
		key, others, err := s.SeedOperatorSSHKeyFromFile(ctx, p)
		if err != nil {
			t.Fatalf("SeedOperatorSSHKeyFromFile: %v", err)
		}
		if key != testKeyA || others != 1 {
			t.Errorf("want (A, 1 other), got (%q, %d)", key, others)
		}
		if want := `["` + testKeyA + `"]`; mustRaw(t, st) != want {
			t.Errorf("want only the first key stored, got %s", mustRaw(t, st))
		}
	})

	t.Run("no-op when already captured", func(t *testing.T) {
		s, st := newKeysService(t)
		if _, err := s.SetOperatorSSHKey(ctx, ""); err != nil { // explicit clear
			t.Fatal(err)
		}
		key, others, err := s.SeedOperatorSSHKeyFromFile(ctx, writeAK(t, testKeyA+"\n"))
		if err != nil {
			t.Fatalf("SeedOperatorSSHKeyFromFile: %v", err)
		}
		if key != "" || others != 0 {
			t.Errorf("want no capture (explicit clear sticks), got (%q, %d)", key, others)
		}
		if mustRaw(t, st) != "[]" {
			t.Errorf("explicit clear was clobbered: %s", mustRaw(t, st))
		}
	})

	t.Run("missing file is a no-op", func(t *testing.T) {
		s, st := newKeysService(t)
		key, others, err := s.SeedOperatorSSHKeyFromFile(ctx, filepath.Join(t.TempDir(), "nope"))
		if err != nil || key != "" || others != 0 {
			t.Errorf("want (\"\", 0, nil) for missing file, got (%q, %d, %v)", key, others, err)
		}
		if mustRaw(t, st) != "" {
			t.Errorf("want still unset, got %s", mustRaw(t, st))
		}
	})

	t.Run("file with no usable lines stays unset", func(t *testing.T) {
		s, _ := newKeysService(t)
		if _, _, err := s.SeedOperatorSSHKeyFromFile(ctx, writeAK(t, "# nothing\n")); err != nil {
			t.Fatal(err)
		}
		if k := mustKey(t, s); k.Captured {
			t.Errorf("want still-unset, got %+v", k)
		}
	})
}

// The operator-SSH-key rule, executed against the vectors the TypeScript
// mirror is executed against.
//
// ValidOperatorSSHKey is THE rule (methodology §5.1,
// geekdojo/geekdojo-brain#545). rasputin-provision and the bus-token mint call
// it directly; ui/lib/enroll.ts carries a mirror, because a browser cannot
// call Go. Three copies of this rule existed before, each with a comment
// asking the next reader to keep them in sync, and they drifted — the UI
// accepted any algorithm beginning "ssh-", which this rule refuses.
//
// ui/lib/operator-ssh-key-vectors.json is the contract. Both suites run the
// same file, so a change on one side without the other fails a build.
func TestValidOperatorSSHKey_SharedVectors(t *testing.T) {
	const vectorsPath = "../../../ui/lib/operator-ssh-key-vectors.json"
	b, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read the shared vectors (%s): %v", vectorsPath, err)
	}
	var vectors struct {
		Valid []struct {
			Why string `json:"why"`
			Key string `json:"key"`
		} `json:"valid"`
		Invalid []struct {
			Why string `json:"why"`
			Key string `json:"key"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatalf("parse %s: %v", vectorsPath, err)
	}
	// A vectors file that has quietly emptied would make both suites pass
	// while testing nothing, which is the failure this whole arrangement is
	// meant to prevent.
	if len(vectors.Valid) < 5 || len(vectors.Invalid) < 10 {
		t.Fatalf("the shared vectors look truncated: %d valid, %d invalid", len(vectors.Valid), len(vectors.Invalid))
	}
	for _, v := range vectors.Valid {
		if !ValidOperatorSSHKey(v.Key) {
			t.Errorf("refused a valid key (%s): %q", v.Why, v.Key)
		}
	}
	for _, v := range vectors.Invalid {
		if ValidOperatorSSHKey(v.Key) {
			t.Errorf("accepted an invalid key (%s): %q", v.Why, v.Key)
		}
	}
}
