package sealrotate

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TC-765-15: CheckRestore allows a restore with the gate free and the tree
// Clean, and refuses with its own sentence while a rotation holds the gate,
// while the tree is not Clean, and while it cannot be read. A backup
// holding the gate does not refuse a restore.
func TestGate_CheckRestore(t *testing.T) {
	st := &fakeState{}
	st.set(Clean)
	g := newGate(t, st, nil)
	if err := g.CheckRestore(); err != nil {
		t.Fatalf("free and Clean: %v", err)
	}
	if err := g.Acquire(context.Background(), "backup-1"); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckRestore(); err != nil {
		t.Errorf("a backup holding the gate refused the restore: %v", err)
	}
	g.Release("backup-1")

	if err := g.TryAcquire("rot-1"); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	check := func(name string, want jobError) {
		t.Helper()
		err := g.CheckRestore()
		if !errors.Is(err, want) {
			t.Fatalf("%s: %v, want %q", name, err, want)
		}
		msg := err.Error()
		if seen[msg] || !strings.HasSuffix(msg, ".") || strings.Contains(msg, "/") || !strings.Contains(msg, "this restore did not start") {
			t.Errorf("%s: %q is not its own path-free sentence", name, msg)
		}
		seen[msg] = true
	}
	check("a rotation holds the gate", errRestoreRotation)
	g.Release("rot-1")

	st.set(Staged)
	check("the tree is not Clean", errRestoreRotationIncomplete)

	st.mu.Lock()
	st.err = errors.New("sealrotate: read the seal fragment: permission denied")
	st.mu.Unlock()
	check("the tree is unreadable", errRestoreSealUnreadable)
}

// CurrentKeyID reads the id from each shape's bytes, and refuses bytes the
// grammar does not admit.
func TestCurrentKeyID(t *testing.T) {
	p := Paths{SealDir: "/s", CredDir: "/c", RotationCred: func(id KeyID) string { return "/c/r_" + string(id) }}
	for _, f := range []Fragment{{Shape: Clean, Current: idA}, {Shape: Verify, Current: idB}, {Shape: Staged, Current: idB, Previous: idA}} {
		b, err := f.render(p)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := CurrentKeyID(b); err != nil || got != f.Current {
			t.Errorf("%s: CurrentKeyID = (%s, %v), want %s", f.Shape, got, err, f.Current)
		}
	}
	for _, bad := range []string{"", "seal \"static\" {\n  current_key = \"file:///x\"\n}\n", "seal \"static\" {\n  current_key_id = \"nope\"\n}\n"} {
		if _, err := CurrentKeyID([]byte(bad)); err == nil {
			t.Errorf("CurrentKeyID(%q) accepted", bad)
		}
	}
}
