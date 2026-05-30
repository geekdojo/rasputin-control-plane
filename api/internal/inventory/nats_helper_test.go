package inventory

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// startNATS spins up an in-process NATS server on a random port and returns a
// connected client. Server shuts down on test cleanup.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// waitForMsg pulls one message from sub or fails the test on timeout.
func waitForMsg(t *testing.T, sub *nats.Subscription, timeout time.Duration) *nats.Msg {
	t.Helper()
	msg, err := sub.NextMsg(timeout)
	if err != nil {
		t.Fatalf("expected msg, got: %v", err)
	}
	return msg
}

// ============================================================================
// Service.Start subscribes, the heartbeat handler runs end-to-end (including
// emit), and a registered event creates a node row + emits InventoryAdded.
// ============================================================================

func TestService_Start_FullHeartbeatPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)

	// Seed an existing node so handleHeartbeat finds it and TouchLastSeen
	// succeeds. Its prev status is offline (old LastSeen) which means the
	// first heartbeat fires an InventoryOnline emit.
	const nodeID = "n-hb"
	if err := store.Insert(ctx, &proto.Node{
		ID:        nodeID,
		Role:      proto.RoleCompute,
		Hostname:  "n.test",
		FirstSeen: time.Now().Add(-time.Hour).UTC(),
		LastSeen:  time.Now().Add(-10 * time.Minute).UTC(), // offline
	}); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	svc := NewService(store, nc)
	// Subscribe to the inventory change channel before Start so we don't
	// race a fast emit.
	changeSub, err := nc.SubscribeSync("rasputin.inventory.>")
	if err != nil {
		t.Fatalf("change sub: %v", err)
	}
	defer func() { _ = changeSub.Unsubscribe() }()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(svc.Stop)
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Publish a heartbeat — the handler should TouchLastSeen, emit
	// InventoryOnline, and update the in-memory cache.
	hb, _ := json.Marshal(proto.HeartbeatEvt{NodeID: nodeID, Ts: time.Now().UTC()})
	if err := nc.Publish(proto.NodeHeartbeatSubject(nodeID), hb); err != nil {
		t.Fatalf("publish hb: %v", err)
	}
	_ = nc.Flush()

	msg := waitForMsg(t, changeSub, 2*time.Second)
	var ev proto.InventoryChangeEvt
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		t.Fatalf("decode change evt: %v", err)
	}
	if ev.Change != proto.InventoryOnline {
		t.Errorf("change: want online, got %q", ev.Change)
	}
	if ev.Node.ID != nodeID {
		t.Errorf("node id: %q", ev.Node.ID)
	}
}

// TestService_Start_RegisteredCreatesNode covers the handleRegistered
// "existing == nil" branch end-to-end: a new agent registers, the api
// inserts the row, marks it online, publishes InventoryAdded.
func TestService_Start_RegisteredCreatesNode(t *testing.T) {
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

	const nodeID = "n-new"
	reg, _ := json.Marshal(proto.NodeRegisteredEvt{
		NodeID:       nodeID,
		Role:         proto.RoleCompute,
		Hostname:     "new.test",
		AgentVersion: "v0.1.0",
		Capabilities: []string{"docker"},
		Metadata:     map[string]any{"arch": "amd64"},
	})
	if err := nc.Publish(proto.NodeRegisteredSubject(nodeID), reg); err != nil {
		t.Fatalf("publish reg: %v", err)
	}
	_ = nc.Flush()

	msg := waitForMsg(t, changeSub, 2*time.Second)
	var ev proto.InventoryChangeEvt
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Change != proto.InventoryAdded {
		t.Errorf("change: want added, got %q", ev.Change)
	}
	// Node row should be in the store now.
	got, _ := store.Get(ctx, nodeID)
	if got == nil || got.Hostname != "new.test" {
		t.Errorf("Node not persisted, got %+v", got)
	}
}

// TestService_Start_RegisteredUpdatesExistingOnlineToUpdated covers the
// handleRegistered existing-node path where the node was already online — we
// expect an InventoryUpdated emit (not Online).
func TestService_Start_RegisteredUpdatesExistingOnlineToUpdated(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)

	const nodeID = "n-upd"
	if err := store.Insert(ctx, &proto.Node{
		ID:        nodeID,
		Role:      proto.RoleCompute,
		Hostname:  "old.test",
		FirstSeen: time.Now().Add(-time.Hour).UTC(),
		LastSeen:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	svc := NewService(store, nc)
	// Pre-populate cache so prev == Online; handleRegistered should then
	// emit InventoryUpdated, not InventoryOnline.
	svc.statusByNode[nodeID] = proto.StatusOnline

	changeSub, err := nc.SubscribeSync("rasputin.inventory.>")
	if err != nil {
		t.Fatalf("change sub: %v", err)
	}
	defer func() { _ = changeSub.Unsubscribe() }()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(svc.Stop)

	reg, _ := json.Marshal(proto.NodeRegisteredEvt{
		NodeID:   nodeID,
		Role:     proto.RoleCompute,
		Hostname: "renamed.test",
	})
	if err := nc.Publish(proto.NodeRegisteredSubject(nodeID), reg); err != nil {
		t.Fatalf("publish: %v", err)
	}
	_ = nc.Flush()

	msg := waitForMsg(t, changeSub, 2*time.Second)
	var ev proto.InventoryChangeEvt
	_ = json.Unmarshal(msg.Data, &ev)
	if ev.Change != proto.InventoryUpdated {
		t.Errorf("change: want updated, got %q", ev.Change)
	}
	got, _ := store.Get(ctx, nodeID)
	if got.Hostname != "renamed.test" {
		t.Errorf("hostname not updated: %q", got.Hostname)
	}
}

// TestService_ScanForTransitions_EmitsOnStatusChange covers the
// scanForTransitions emit branch for each status — drives transitions by
// inserting nodes at fresh/stale/offline gaps with a pre-populated cache that
// disagrees, so the scan flips them and publishes.
func TestService_ScanForTransitions_EmitsOnStatusChange(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)

	// Each node gets a gap that maps to a real status, but the cache says
	// something else so scan sees a transition.
	type seed struct {
		id       string
		gap      time.Duration
		cacheVal proto.NodeStatus
		wantCh   proto.InventoryChangeType
	}
	seeds := []seed{
		{"toOnline", 1 * time.Second, proto.StatusOffline, proto.InventoryOnline},
		{"toStale", 45 * time.Second, proto.StatusOnline, proto.InventoryStale},
		{"toOffline", 5 * time.Minute, proto.StatusOnline, proto.InventoryOffline},
	}
	for _, s := range seeds {
		if err := store.Insert(ctx, &proto.Node{
			ID:        s.id,
			Role:      proto.RoleCompute,
			Hostname:  s.id + ".test",
			FirstSeen: time.Now().Add(-time.Hour).UTC(),
			LastSeen:  time.Now().Add(-s.gap).UTC(),
		}); err != nil {
			t.Fatalf("insert %s: %v", s.id, err)
		}
	}

	svc := NewService(store, nc)
	svc.ctx = ctx
	for _, s := range seeds {
		svc.statusByNode[s.id] = s.cacheVal
	}

	// Collect all the change events. Use a sync sub.
	sub, err := nc.SubscribeSync("rasputin.inventory.>")
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	_ = nc.Flush()

	svc.scanForTransitions()
	_ = nc.Flush()

	// Drain 3 messages.
	gotChanges := map[string]proto.InventoryChangeType{}
	for i := 0; i < len(seeds); i++ {
		msg, err := sub.NextMsg(2 * time.Second)
		if err != nil {
			t.Fatalf("msg %d: %v", i, err)
		}
		var ev proto.InventoryChangeEvt
		if err := json.Unmarshal(msg.Data, &ev); err != nil {
			t.Fatalf("decode: %v", err)
		}
		gotChanges[ev.Node.ID] = ev.Change
	}
	for _, s := range seeds {
		if gotChanges[s.id] != s.wantCh {
			t.Errorf("%s: want change %q, got %q", s.id, s.wantCh, gotChanges[s.id])
		}
	}
}

// TestService_Start_SubscribeError forces Start's second Subscribe to fail by
// closing the connection. Covers the early-return branches.
func TestService_Start_SubscribeError(t *testing.T) {
	nc := startNATS(t)
	nc.Close()
	store := newStore(t)
	svc := NewService(store, nc)
	if err := svc.Start(context.Background()); err == nil {
		t.Error("Start on a closed conn should error")
	}
}

// TestService_Stop_BeforeStart_IsSafe pins the cancel == nil branch of Stop.
func TestService_Stop_BeforeStart_IsSafe(t *testing.T) {
	store := newStore(t)
	svc := NewService(store, nil)
	svc.Stop()
}

// TestService_Emit_Direct exercises the emit function explicitly with a real
// NATS bus — covers the publish path that nil-bus tests can't reach.
func TestService_Emit_Direct(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	svc := NewService(store, nc)
	svc.ctx = context.Background()

	sub, err := nc.SubscribeSync("rasputin.inventory.>")
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	n := &proto.Node{
		ID: "x", Role: proto.RoleCompute, Hostname: "x.test",
		LastSeen: time.Now().UTC(), FirstSeen: time.Now().UTC(),
	}
	svc.emit(n, proto.InventoryAdded)
	_ = nc.Flush()

	msg := waitForMsg(t, sub, 2*time.Second)
	var ev proto.InventoryChangeEvt
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Change != proto.InventoryAdded || ev.Node.ID != "x" {
		t.Errorf("emit payload: %+v", ev)
	}
}
