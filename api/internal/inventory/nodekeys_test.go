package inventory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func spki(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h, err := proto.NodeKeySPKIHash(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func openInv(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inv.db")
	s, err := OpenStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	// The whole-set token load the api does at start. Without it the registry
	// is deliberately not "loaded" and admits nobody — see the fail-closed
	// rule on Registry — so every admission test below would pass for the
	// wrong reason.
	s.Registry().ReplaceLiveTokens(map[string][]string{})
	return s, path
}

func member(t *testing.T, s *Store, id string) {
	t.Helper()
	now := time.Now().UTC()
	if err := s.Insert(context.Background(), &proto.Node{ID: id, Role: proto.RoleCompute, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	s.Registry().SetLiveTokens(id, []string{"tok-" + id})
}

func retiredRecorder(r *Registry) func() map[string][]string {
	var mu sync.Mutex
	got := map[string][]string{}
	r.OnKeysRetired(func(id string, retired []string) {
		mu.Lock()
		got[id] = append(got[id], retired...)
		mu.Unlock()
	})
	return func() map[string][]string {
		mu.Lock()
		defer mu.Unlock()
		out := map[string][]string{}
		for k, v := range got {
			out[k] = slices.Clone(v)
		}
		return out
	}
}

// The first report registers; the same report again changes nothing (so a
// reconnecting agent does not look like a key change); a different hash for a
// purpose is a REPLACEMENT, named as such, and retires the old key.
func TestSetNodeKeys_RegisterThenReplace(t *testing.T) {
	ctx := context.Background()
	s, _ := openInv(t)
	member(t, s, "c1")
	retired := retiredRecorder(s.Registry())
	a1, c1 := spki(t), spki(t)

	change, err := s.SetNodeKeys(ctx, "c1", proto.NodeKeys{proto.NodeKeyAgent: a1, proto.NodeKeyCollector: c1})
	if err != nil {
		t.Fatal(err)
	}
	if !change.Changed() || len(change.Replaced) != 0 {
		t.Fatalf("first registration: %+v, want a change with nothing replaced", change)
	}
	if o, ok := s.Registry().AdmitKey(a1); !ok || o.NodeID != "c1" || o.Purpose != proto.NodeKeyAgent {
		t.Fatalf("AdmitKey(agent key) = %+v, %v", o, ok)
	}
	if len(retired()) != 0 {
		t.Fatalf("a first registration retired keys: %v", retired())
	}

	same, err := s.SetNodeKeys(ctx, "c1", proto.NodeKeys{proto.NodeKeyAgent: a1, proto.NodeKeyCollector: c1})
	if err != nil {
		t.Fatal(err)
	}
	if same.Changed() {
		t.Fatalf("re-reporting the same keys read as a change: %+v", same)
	}

	a2 := spki(t)
	change, err = s.SetNodeKeys(ctx, "c1", proto.NodeKeys{proto.NodeKeyAgent: a2})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(change.Replaced, []proto.NodeKeyPurpose{proto.NodeKeyAgent}) {
		t.Fatalf("Replaced = %v, want [agent]", change.Replaced)
	}
	if change.Previous[proto.NodeKeyAgent] != a1 || change.Current[proto.NodeKeyAgent] != a2 {
		t.Fatalf("change = %+v, want %s -> %s", change, a1, a2)
	}
	// The collector key was not mentioned, so it is untouched: an older
	// agent that knows one purpose must not retire the other.
	if change.Current[proto.NodeKeyCollector] != c1 {
		t.Errorf("an unmentioned purpose was dropped: %v", change.Current)
	}
	if _, ok := s.Registry().AdmitKey(a1); ok {
		t.Error("the replaced key is still admitted")
	}
	if o, ok := s.Registry().AdmitKey(a2); !ok || o.NodeID != "c1" {
		t.Errorf("the new key is not admitted: %+v, %v", o, ok)
	}
	if got := retired(); !reflect.DeepEqual(got, map[string][]string{"c1": {a1}}) {
		t.Errorf("retired = %v, want the old agent key for c1", got)
	}
}

// Two nodes cannot share an HTTPS identity. The one way it happens is a key
// file copied off one node onto another, which is what this refuses.
func TestSetNodeKeys_RefusesAKeyAnotherNodeHolds(t *testing.T) {
	ctx := context.Background()
	s, _ := openInv(t)
	member(t, s, "c1")
	member(t, s, "c2")
	shared := spki(t)

	if _, err := s.SetNodeKeys(ctx, "c1", proto.NodeKeys{proto.NodeKeyAgent: shared}); err != nil {
		t.Fatal(err)
	}
	_, err := s.SetNodeKeys(ctx, "c2", proto.NodeKeys{proto.NodeKeyAgent: shared})
	if !errors.Is(err, ErrNodeKeyTaken) {
		t.Fatalf("err = %v, want ErrNodeKeyTaken", err)
	}
	if o, ok := s.Registry().AdmitKey(shared); !ok || o.NodeID != "c1" {
		t.Errorf("the refused report moved the key: %+v, %v", o, ok)
	}
	if keys, err := s.NodeKeys(ctx, "c2"); err != nil || len(keys) != 0 {
		t.Errorf("c2 recorded keys from a refused report: %v, %v", keys, err)
	}
}

// The registry is filled from the table once, at OpenStore. A node that
// registered before this api process started is admitted on its first
// connection, not only after it re-registers.
func TestOpenStore_LoadsRegisteredKeys(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "inv.db")
	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	member(t, s, "c1")
	key := spki(t)
	if _, err := s.SetNodeKeys(ctx, "c1", proto.NodeKeys{proto.NodeKeyAgent: key}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	// Token liveness has NOT loaded yet on this fresh store, which is the
	// point of the next assertion.
	if o, ok := reopened.Registry().KeyOwner(key); !ok || o.NodeID != "c1" {
		t.Fatalf("KeyOwner after restart = %+v, %v", o, ok)
	}
	// Membership was loaded too, but the token liveness push has not
	// happened yet, so the node is not admitted until busauth says so —
	// fail closed across a restart.
	if _, ok := reopened.Registry().AdmitKey(key); ok {
		t.Error("a key is admitted before token liveness has been loaded")
	}
	reopened.Registry().ReplaceLiveTokens(map[string][]string{"c1": {"tok-c1"}})
	if _, ok := reopened.Registry().AdmitKey(key); !ok {
		t.Error("a key is not admitted once its node's token is live")
	}
}

// Removal clears the node's registrations — from the table and from the
// registry — and retires its keys so open sessions under them are closed.
func TestDelete_ClearsRegisteredKeys(t *testing.T) {
	ctx := context.Background()
	s, _ := openInv(t)
	member(t, s, "c1")
	retired := retiredRecorder(s.Registry())
	key := spki(t)
	if _, err := s.SetNodeKeys(ctx, "c1", proto.NodeKeys{proto.NodeKeyAgent: key}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Registry().KeyOwner(key); ok {
		t.Error("a removed node's key is still registered")
	}
	if got, err := s.NodeKeys(ctx, "c1"); err != nil || len(got) != 0 {
		t.Errorf("a removed node's keys are still in the table: %v, %v", got, err)
	}
	if got := retired(); !reflect.DeepEqual(got, map[string][]string{"c1": {key}}) {
		t.Errorf("retired = %v, want the removed node's key", got)
	}
}

// Revoking the token does NOT clear the registration — the token can be
// re-minted — but it does stop admitting the key. Registered and admitted are
// two different questions, asked separately for exactly this case.
func TestAdmitKey_FollowsTokenLiveness(t *testing.T) {
	ctx := context.Background()
	s, _ := openInv(t)
	member(t, s, "c1")
	key := spki(t)
	if _, err := s.SetNodeKeys(ctx, "c1", proto.NodeKeys{proto.NodeKeyAgent: key}); err != nil {
		t.Fatal(err)
	}
	s.Registry().SetLiveTokens("c1", nil)
	if _, ok := s.Registry().AdmitKey(key); ok {
		t.Error("a key is admitted while its node's token is revoked")
	}
	if _, ok := s.Registry().KeyOwner(key); !ok {
		t.Error("a revoke cleared the key registration")
	}
	s.Registry().SetLiveTokens("c1", []string{"tok-c1"})
	if _, ok := s.Registry().AdmitKey(key); !ok {
		t.Error("a key is not admitted again once the token is live")
	}
}

// The whole point of the registry: admission reads memory. Proven the only
// way that cannot be faked — the database is CLOSED, so any query on this
// path would return an error, and admission still answers correctly.
func TestAdmitKey_AnswersWithTheDatabaseClosed(t *testing.T) {
	ctx := context.Background()
	s, _ := openInv(t)
	member(t, s, "c1")
	key := spki(t)
	if _, err := s.SetNodeKeys(ctx, "c1", proto.NodeKeys{proto.NodeKeyAgent: key}); err != nil {
		t.Fatal(err)
	}
	reg := s.Registry()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A database read would fail here; NodeKeys proves it.
	if _, err := s.NodeKeys(ctx, "c1"); err == nil {
		t.Fatal("the database is still readable, so this test proves nothing")
	}
	if o, ok := reg.AdmitKey(key); !ok || o.NodeID != "c1" || o.Purpose != proto.NodeKeyAgent {
		t.Fatalf("AdmitKey with the database closed = %+v, %v", o, ok)
	}
	if _, ok := reg.AdmitKey(spki(t)); ok {
		t.Error("an unregistered key was admitted")
	}
	if !reg.Admitted("c1") {
		t.Error("Admitted needed the database")
	}
}

// Lookup hands back a copy: a caller that edits the keys it was given must
// not be editing the registry.
func TestLookup_CopiesTheKeys(t *testing.T) {
	ctx := context.Background()
	s, _ := openInv(t)
	member(t, s, "c1")
	key := spki(t)
	if _, err := s.SetNodeKeys(ctx, "c1", proto.NodeKeys{proto.NodeKeyAgent: key}); err != nil {
		t.Fatal(err)
	}
	e, ok := s.Registry().Lookup("c1")
	if !ok {
		t.Fatal("no entry")
	}
	e.Keys[proto.NodeKeyAgent] = "sha256/tampered"
	if again, _ := s.Registry().Lookup("c1"); again.Keys[proto.NodeKeyAgent] != key {
		t.Error("editing a Lookup result changed the registry")
	}
}

func TestSetNodeKeys_NeedsANodeID(t *testing.T) {
	s, _ := openInv(t)
	if _, err := s.SetNodeKeys(context.Background(), "", proto.NodeKeys{proto.NodeKeyAgent: spki(t)}); err == nil {
		t.Fatal("an empty node id was accepted")
	}
}

// An empty report is a no-op, not a revocation: a node whose bus connection
// is not pinned reports nothing, and that must not retire the keys it
// registered when it was pinned.
func TestSetNodeKeys_EmptyReportKeepsTheRecord(t *testing.T) {
	ctx := context.Background()
	s, _ := openInv(t)
	member(t, s, "c1")
	key := spki(t)
	if _, err := s.SetNodeKeys(ctx, "c1", proto.NodeKeys{proto.NodeKeyAgent: key}); err != nil {
		t.Fatal(err)
	}
	change, err := s.SetNodeKeys(ctx, "c1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if change.Changed() {
		t.Fatalf("an empty report changed the record: %+v", change)
	}
	if _, ok := s.Registry().KeyOwner(key); !ok {
		t.Error("an empty report retired the recorded key")
	}
}
