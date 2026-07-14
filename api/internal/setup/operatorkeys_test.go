package setup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const (
	testKeyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2AcGjrl5kW bryce@laptop"
	testKeyB = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB other@host"
)

func newKeysService(t *testing.T) *Service {
	t.Helper()
	return NewService(newStore(t), Probes{}, "cp-1")
}

func TestOperatorSSHKeys_UnsetReturnsNil(t *testing.T) {
	s := newKeysService(t)
	keys, err := s.OperatorSSHKeys(context.Background())
	if err != nil {
		t.Fatalf("OperatorSSHKeys: %v", err)
	}
	if keys != nil {
		t.Errorf("want nil (never captured), got %v", keys)
	}
}

func TestSetOperatorSSHKeys_RoundTripAndDedup(t *testing.T) {
	s := newKeysService(t)
	ctx := context.Background()
	got, err := s.SetOperatorSSHKeys(ctx, []string{" " + testKeyA + " ", testKeyA, testKeyB})
	if err != nil {
		t.Fatalf("SetOperatorSSHKeys: %v", err)
	}
	if len(got) != 2 || got[0] != testKeyA || got[1] != testKeyB {
		t.Errorf("want trimmed+deduped [A B], got %v", got)
	}
	keys, err := s.OperatorSSHKeys(ctx)
	if err != nil {
		t.Fatalf("OperatorSSHKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("round-trip: want 2 keys, got %v", keys)
	}
}

func TestSetOperatorSSHKeys_EmptyListIsExplicit(t *testing.T) {
	s := newKeysService(t)
	ctx := context.Background()
	if _, err := s.SetOperatorSSHKeys(ctx, []string{}); err != nil {
		t.Fatalf("SetOperatorSSHKeys(empty): %v", err)
	}
	keys, err := s.OperatorSSHKeys(ctx)
	if err != nil {
		t.Fatalf("OperatorSSHKeys: %v", err)
	}
	if keys == nil || len(keys) != 0 {
		t.Errorf("want non-nil empty list (explicit none), got %v", keys)
	}
}

func TestSetOperatorSSHKeys_RejectsInvalid(t *testing.T) {
	s := newKeysService(t)
	for _, bad := range []string{
		"not-a-key",
		"ssh-ed25519",                         // no key material
		`ssh-ed25519 AAAA comment"with-quote`, // breaks seed quoting
		"ssh-ed25519 AAAA comment$(pwned)",    // breaks seed quoting
		"ssh-ed25519 AAAA comment`bad`",       // breaks seed quoting
		"ssh-ed25519 AAAA comment\\backslash", // breaks seed quoting
	} {
		if _, err := s.SetOperatorSSHKeys(context.Background(), []string{bad}); err == nil {
			t.Errorf("want error for %q, got nil", bad)
		}
	}
}

func TestRememberOperatorSSHKey_AppendsOnceOnly(t *testing.T) {
	s := newKeysService(t)
	ctx := context.Background()
	if _, err := s.RememberOperatorSSHKey(ctx, testKeyA); err != nil {
		t.Fatalf("RememberOperatorSSHKey: %v", err)
	}
	keys, err := s.RememberOperatorSSHKey(ctx, testKeyA) // duplicate = no-op
	if err != nil {
		t.Fatalf("RememberOperatorSSHKey(dup): %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("want 1 key after duplicate remember, got %v", keys)
	}
	keys, err = s.RememberOperatorSSHKey(ctx, testKeyB)
	if err != nil {
		t.Fatalf("RememberOperatorSSHKey(B): %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("want 2 keys, got %v", keys)
	}
}

func TestSeedOperatorSSHKeysFromFile(t *testing.T) {
	ctx := context.Background()

	t.Run("seeds valid lines when unset", func(t *testing.T) {
		s := newKeysService(t)
		p := filepath.Join(t.TempDir(), "authorized_keys")
		content := "# managed by rasputin\n\n" + testKeyA + "\nnot a key line\n" + testKeyB + "\n"
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		keys, err := s.SeedOperatorSSHKeysFromFile(ctx, p)
		if err != nil {
			t.Fatalf("SeedOperatorSSHKeysFromFile: %v", err)
		}
		if len(keys) != 2 || keys[0] != testKeyA || keys[1] != testKeyB {
			t.Errorf("want [A B] skipping comments/garbage, got %v", keys)
		}
	})

	t.Run("no-op when already captured", func(t *testing.T) {
		s := newKeysService(t)
		if _, err := s.SetOperatorSSHKeys(ctx, []string{}); err != nil { // explicit empty
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "authorized_keys")
		if err := os.WriteFile(p, []byte(testKeyA+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		keys, err := s.SeedOperatorSSHKeysFromFile(ctx, p)
		if err != nil {
			t.Fatalf("SeedOperatorSSHKeysFromFile: %v", err)
		}
		if keys != nil {
			t.Errorf("want nil (explicit empty sticks), got %v", keys)
		}
		stored, _ := s.OperatorSSHKeys(ctx)
		if len(stored) != 0 {
			t.Errorf("explicit empty was clobbered: %v", stored)
		}
	})

	t.Run("missing file is a no-op", func(t *testing.T) {
		s := newKeysService(t)
		keys, err := s.SeedOperatorSSHKeysFromFile(ctx, filepath.Join(t.TempDir(), "nope"))
		if err != nil || keys != nil {
			t.Errorf("want (nil,nil) for missing file, got (%v,%v)", keys, err)
		}
	})

	t.Run("file with no usable lines stays unset", func(t *testing.T) {
		s := newKeysService(t)
		p := filepath.Join(t.TempDir(), "authorized_keys")
		if err := os.WriteFile(p, []byte("# nothing\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SeedOperatorSSHKeysFromFile(ctx, p); err != nil {
			t.Fatal(err)
		}
		keys, _ := s.OperatorSSHKeys(ctx)
		if keys != nil {
			t.Errorf("want still-unset (nil), got %v", keys)
		}
	})
}
