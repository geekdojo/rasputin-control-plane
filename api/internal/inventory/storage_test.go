package inventory

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Storage snapshot persistence (#2): the register event's storage field must
// round-trip the store, and a pre-storage agent re-registering (storage nil)
// must not wipe a snapshot we already learned — same contract as Architecture.

func TestStore_StorageRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	n := makeNode("n-sto", proto.RoleCompute, 0)
	n.Storage = &proto.StorageInfo{
		PersistentTotalBytes: 120 * 1024 * 1024 * 1024,
		PersistentFreeBytes:  118 * 1024 * 1024 * 1024,
		Growpart:             "already-full",
	}
	if err := s.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	got, err := s.Get(ctx, "n-sto")
	if err != nil || got == nil {
		t.Fatalf("Get: %v, %+v", err, got)
	}
	if got.Storage == nil || *got.Storage != *n.Storage {
		t.Errorf("storage not round-tripped: got %+v want %+v", got.Storage, n.Storage)
	}

	// nil storage round-trips as nil, not a zero struct.
	bare := makeNode("n-bare", proto.RoleCompute, 0)
	if err := s.Insert(ctx, bare); err != nil {
		t.Fatalf("Insert bare: %v", err)
	}
	if got, _ := s.Get(ctx, "n-bare"); got == nil || got.Storage != nil {
		t.Errorf("nil storage should stay nil, got %+v", got.Storage)
	}
}

func TestService_Registered_StorageLearnAndKeep(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	svc := NewService(store, nc)

	changeSub, err := nc.SubscribeSync("rasputin.inventory.>")
	if err != nil {
		t.Fatalf("change sub: %v", err)
	}
	defer func() { _ = changeSub.Unsubscribe() }()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(svc.Stop)

	const nodeID = "n-sto"
	register := func(st *proto.StorageInfo) {
		t.Helper()
		reg, _ := json.Marshal(proto.NodeRegisteredEvt{
			NodeID:   nodeID,
			Role:     proto.RoleCompute,
			Hostname: "sto.test",
			Storage:  st,
		})
		if err := nc.Publish(proto.NodeRegisteredSubject(nodeID), reg); err != nil {
			t.Fatalf("publish reg: %v", err)
		}
		_ = nc.Flush()
		waitForMsg(t, changeSub, 2*time.Second) // added/online/updated — sequencing only
	}

	first := &proto.StorageInfo{PersistentTotalBytes: 512 << 20, PersistentFreeBytes: 100 << 20, Growpart: "failed"}
	register(first)
	if got, _ := store.Get(ctx, nodeID); got == nil || got.Storage == nil || *got.Storage != *first {
		t.Fatalf("storage not learned on first register: %+v", got)
	}

	// A pre-storage agent (nil) must not wipe the learned snapshot.
	register(nil)
	if got, _ := store.Get(ctx, nodeID); got == nil || got.Storage == nil || *got.Storage != *first {
		t.Fatalf("nil re-register wiped storage: %+v", got)
	}

	// A fresh report overwrites (the post-fix boot: grown partition).
	second := &proto.StorageInfo{PersistentTotalBytes: 120 << 30, PersistentFreeBytes: 118 << 30, Growpart: "already-full"}
	register(second)
	if got, _ := store.Get(ctx, nodeID); got == nil || got.Storage == nil || *got.Storage != *second {
		t.Fatalf("fresh storage report did not overwrite: %+v", got)
	}
}
