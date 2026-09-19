package inventory

import (
	"context"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func excludedRecorder(r *Registry) func() []string {
	var mu sync.Mutex
	var got []string
	r.OnNodeExcluded(func(id string) { mu.Lock(); got = append(got, id); mu.Unlock() })
	return func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(got) }
}

// Admission needs both facts: membership (inventory) and a live token
// (pushed by the token store). Losing either excludes the node once.
func TestRegistry_AdmissionNeedsMembershipAndALiveToken(t *testing.T) {
	ctx := context.Background()
	s, err := OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	r := s.Registry()
	excluded := excludedRecorder(r)
	now := time.Now().UTC()

	if r.Admitted("c1") {
		t.Fatal("an unknown node is admitted")
	}
	r.SetTokenLive("c1", true)
	if r.Admitted("c1") {
		t.Fatal("a live token without membership is admitted")
	}
	if err := s.Insert(ctx, &proto.Node{ID: "c1", Role: proto.RoleCompute, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if !r.Admitted("c1") {
		t.Fatal("a member with a live token is not admitted")
	}
	if e, ok := r.Lookup("c1"); !ok || !e.Member || !e.TokenLive || e.Role != proto.RoleCompute {
		t.Fatalf("Lookup = %+v, %v", e, ok)
	}

	r.SetTokenLive("c1", false)
	if r.Admitted("c1") || !slices.Equal(excluded(), []string{"c1"}) {
		t.Fatalf("token lost: admitted=%v excluded=%v", r.Admitted("c1"), excluded())
	}
	r.SetTokenLive("c1", false) // no second event for a node already out
	if len(excluded()) != 1 {
		t.Fatalf("excluded twice: %v", excluded())
	}

	r.SetTokenLive("c1", true)
	if err := s.Delete(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if r.Admitted("c1") || !slices.Equal(excluded(), []string{"c1", "c1"}) {
		t.Fatalf("removal: admitted=%v excluded=%v", r.Admitted("c1"), excluded())
	}
}

// Membership is loaded once at OpenStore; the whole-set token push replaces
// every node's liveness; and Admitted answers from memory with the database
// closed.
func TestRegistry_LoadedAtOpenAndServedFromMemory(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "inv.db")
	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, id := range []string{"a", "b", "c"} {
		if err := s.Insert(ctx, &proto.Node{ID: id, Role: proto.RoleCompute, FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()

	s, err = OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	r := s.Registry()
	excluded := excludedRecorder(r)
	r.ReplaceTokenLive(map[string]bool{"a": true, "b": true, "z": true})
	r.ReplaceTokenLive(map[string]bool{"a": true, "z": true}) // b's token went
	_ = s.Close()

	for id, want := range map[string]bool{"a": true, "b": false, "c": false, "z": false} {
		if got := r.Admitted(id); got != want {
			t.Errorf("Admitted(%q) = %v with the database closed, want %v", id, got, want)
		}
	}
	if !slices.Equal(excluded(), []string{"b"}) {
		t.Errorf("excluded = %v, want [b]", excluded())
	}
}
