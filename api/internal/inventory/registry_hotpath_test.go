package inventory

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The heartbeat path does no database work at all: with the database closed,
// a heartbeat from an admitted node still lands — the status transition is
// published from the registry's last-seen and the node row already in hand —
// and nothing errors.
func TestHandleHeartbeat_NoDatabaseWorkOnTheHotPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)

	const nodeID = "hot"
	seen := time.Now().Add(-time.Hour).UTC()
	if err := store.Insert(ctx, &proto.Node{
		ID: nodeID, Role: proto.RoleCompute, Hostname: "hot.test",
		FirstSeen: seen, LastSeen: seen,
	}); err != nil {
		t.Fatal(err)
	}
	store.Registry().ReplaceLiveTokens(map[string][]string{nodeID: {"h1"}})

	svc := NewService(store, nc)
	changeSub, err := nc.SubscribeSync("rasputin.inventory.>")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = changeSub.Unsubscribe() })
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Stop)
	_ = nc.Flush()

	// The first heartbeat crosses offline → online, which emits and therefore
	// reads the row. Let that one through, then close the database: every
	// further heartbeat must be pure memory.
	hb, _ := json.Marshal(proto.HeartbeatEvt{NodeID: nodeID, Ts: time.Now().UTC()})
	if err := nc.Publish(proto.NodeHeartbeatSubject(nodeID), hb); err != nil {
		t.Fatal(err)
	}
	_ = nc.Flush()
	if msg := waitForMsg(t, changeSub, 2*time.Second); msg == nil {
		t.Fatal("no first transition")
	}

	before := store.Registry().lastSeen(nodeID)
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := nc.Publish(proto.NodeHeartbeatSubject(nodeID), hb); err != nil {
			t.Fatal(err)
		}
	}
	_ = nc.Flush()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if store.Registry().lastSeen(nodeID).After(before) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("heartbeats with the database closed never reached the registry")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// No further change event: the node was already online, so nothing to emit.
	if msg, err := changeSub.NextMsg(200 * time.Millisecond); err == nil {
		t.Errorf("a steady-state heartbeat emitted %q", string(msg.Data))
	}
}

// The cluster-size cap counts members in the registry, not rows in the
// database: registration refuses the node past the cap with the nodes table
// unreadable, and a member's re-registration is still recognised as one.
func TestHandleRegistered_CapAndMembershipComeFromTheRegistry(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	r := store.Registry()
	now := time.Now().UTC()
	for i := 0; i < proto.MaxClusterNodes; i++ {
		id := "n" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		if err := store.Insert(ctx, &proto.Node{ID: id, Role: proto.RoleCompute, FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.MemberCount(); got != proto.MaxClusterNodes {
		t.Fatalf("MemberCount = %d, want %d", got, proto.MaxClusterNodes)
	}

	svc := NewService(store, nil) // nc nil: the refusal returns before any emit
	svc.ctx = ctx
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	ev := proto.NodeRegisteredEvt{NodeID: "one-too-many", Role: proto.RoleCompute}
	payload, _ := json.Marshal(ev)
	svc.handleRegistered(&nats.Msg{Subject: "rasputin.node.one-too-many.evt.registered", Data: payload})
	if _, ok := r.Lookup("one-too-many"); ok {
		t.Error("a node past the cluster-size cap was let in")
	}
}

// A store reopened from disk loads membership AND last-seen, so a restart
// does not make every node look offline until its next registration.
func TestRegistry_LoadsLastSeenAtOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "inv.db")
	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	seen := time.Now().Add(-5 * time.Second).UTC()
	if err := s.Insert(ctx, &proto.Node{ID: "n1", Role: proto.RoleCompute, FirstSeen: seen, LastSeen: seen}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s, err = OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	e, ok := s.Registry().Lookup("n1")
	if !ok || e.LastSeen.UnixMilli() != seen.UnixMilli() {
		t.Fatalf("Lookup after reopen = %+v, %v; want last-seen %v", e, ok, seen)
	}
	got, err := s.Get(ctx, "n1")
	if err != nil || got == nil || ComputeStatus(got.LastSeen) != proto.StatusOnline {
		t.Fatalf("Get after reopen = %+v, %v", got, err)
	}
}

// MemberCount counts members and nothing else: a node the registry knows only
// because it holds a live token — it has not registered yet — is not one.
func TestRegistry_MemberCountCountsOnlyMembers(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	r := s.Registry()
	now := time.Now().UTC()
	if err := s.Insert(ctx, &proto.Node{ID: "member", Role: proto.RoleCompute, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	// "pending" holds a live token but has never registered.
	r.ReplaceLiveTokens(map[string][]string{"member": {"h1"}, "pending": {"h2"}})
	if got := r.MemberCount(); got != 1 {
		t.Errorf("MemberCount = %d, want 1 (a node with a token but no row is not a member)", got)
	}
	if err := s.Delete(ctx, "member"); err != nil {
		t.Fatal(err)
	}
	if got := r.MemberCount(); got != 0 {
		t.Errorf("MemberCount after removal = %d, want 0", got)
	}
}

// IsMember answers the same question one node at a time: a registered node is
// one, a node that only holds a token is not, and an unknown id is not.
func TestRegistry_IsMember(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	r := s.Registry()
	now := time.Now().UTC()
	if err := s.Insert(ctx, &proto.Node{ID: "member", Role: proto.RoleCompute, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	r.ReplaceLiveTokens(map[string][]string{"member": {"h1"}, "pending": {"h2"}})
	for id, want := range map[string]bool{"member": true, "pending": false, "ghost": false} {
		if got := r.IsMember(id); got != want {
			t.Errorf("IsMember(%q) = %v, want %v", id, got, want)
		}
	}
	if err := s.Delete(ctx, "member"); err != nil {
		t.Fatal(err)
	}
	if r.IsMember("member") {
		t.Error("a removed node is still a member")
	}
}
