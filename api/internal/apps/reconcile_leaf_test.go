package apps

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// seedRoutableFailedApp puts an app on an online node in the state a timed-out
// deploy leaves behind: FAILED in the store, with a published port, so it is
// something the proxy could route if anyone ever minted it a leaf.
func seedRoutableFailedApp(t *testing.T, nodeID, appID string) (*Store, *inventory.Store) {
	t.Helper()
	ctx := context.Background()
	store := newStore(t)
	inv := newInventory(t)
	if err := inv.Insert(ctx, &proto.Node{
		ID: nodeID, Role: proto.RoleCompute, Hostname: nodeID + ".test",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	a := makeApp(appID, "uptime-kuma")
	a.TargetNode = nodeID
	// Set at CREATE time: Store.Update does not persist PublishedPort, and an
	// app with port 0 is deliberately not routable, which would make this test
	// pass for the wrong reason.
	a.PublishedPort = 3001
	if err := store.Create(ctx, a); err != nil {
		t.Fatalf("create app: %v", err)
	}
	if err := store.RecordStatus(ctx, appID, proto.AppStatusFailed,
		"deploy rpc: context deadline exceeded", time.Now().UTC()); err != nil {
		t.Fatalf("record failed: %v", err)
	}
	return store, inv
}

// agentReports makes the fake agent answer every status probe with one status.
func agentReports(t *testing.T, nc *nats.Conn, nodeID, appID string, st proto.AppStatus) {
	t.Helper()
	sub, err := nc.Subscribe(proto.AppStatusSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppStatusAck{AppID: appID, Status: st})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("subscribe status: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
}

// countingLeafNode stands in for the node's proxy handler, recording how many
// leaves it was asked to accept.
func countingLeafNode(t *testing.T, nc *nats.Conn, nodeID string, accept bool) *int32 {
	t.Helper()
	var delivered int32
	sub, err := nc.Subscribe(proto.AppLeafSubject(nodeID), func(m *nats.Msg) {
		atomic.AddInt32(&delivered, 1)
		ack, _ := json.Marshal(proto.AppLeafAck{OK: accept, Detail: "test"})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("subscribe leaf: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return &delivered
}

// An app whose deploy timed out at "push" never reached the saga's "leaf" step,
// so it has no cert, no route and no name — yet its container came up anyway.
// The sweep is the only thing that ever learns this, so it is the only thing
// that can fix it. Without this, the app runs, reports RUNNING, and is
// unreachable forever. Observed on e3bench 2026-08-23.
func TestReconcileSweep_RecoveredAppGetsItsLeaf(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedRoutableFailedApp(t, "n", "a")
	agentReports(t, nc, "n", "a", proto.AppStatusRunning)
	delivered := countingLeafNode(t, nc, "n", true)

	var minted int32
	mint := func(app *App) (proto.AppLeafCmd, error) {
		atomic.AddInt32(&minted, 1)
		return proto.AppLeafCmd{AppID: app.ID, Name: app.Name}, nil
	}

	out, err := reconcileSweep(store, inv, nc, mint)(newStepCtxNATS(`{}`, nc))
	if err != nil {
		t.Fatalf("reconcileSweep: %v", err)
	}
	var counts map[string]int
	_ = json.Unmarshal(out, &counts)

	if got := atomic.LoadInt32(&minted); got != 1 {
		t.Errorf("leaf minted %d times, want 1 — a recovered app never got a cert", got)
	}
	if got := atomic.LoadInt32(delivered); got != 1 {
		t.Errorf("leaf delivered %d times, want 1 — the node never got a proxy route", got)
	}
	if counts["recovered"] != 1 {
		t.Errorf("recovered=%d, want 1 (full: %+v)", counts["recovered"], counts)
	}
	if got, _ := store.Get(context.Background(), "a"); got.LastStatus != proto.AppStatusRunning {
		t.Errorf("LastStatus = %q, want running", got.LastStatus)
	}
}

// Ordinary drift is not a recovery. An app going running→stopped has a route
// already; re-minting on every sweep would be churn, not repair.
func TestReconcileSweep_OrdinaryDriftDoesNotMintALeaf(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")
	_ = store.RecordStatus(context.Background(), "a", proto.AppStatusRunning, "", time.Now().UTC())
	agentReports(t, nc, "n", "a", proto.AppStatusStopped)
	delivered := countingLeafNode(t, nc, "n", true)

	var minted int32
	mint := func(app *App) (proto.AppLeafCmd, error) {
		atomic.AddInt32(&minted, 1)
		return proto.AppLeafCmd{AppID: app.ID}, nil
	}
	if _, err := reconcileSweep(store, inv, nc, mint)(newStepCtxNATS(`{}`, nc)); err != nil {
		t.Fatalf("reconcileSweep: %v", err)
	}
	if got := atomic.LoadInt32(&minted); got != 0 {
		t.Errorf("minted %d leaves on a running→stopped drift, want 0", got)
	}
	if got := atomic.LoadInt32(delivered); got != 0 {
		t.Errorf("delivered %d leaves on a running→stopped drift, want 0", got)
	}
}

// A node that refuses the leaf must not cost the app its RUNNING status: the
// container is genuinely up, and the next sweep can try the route again.
func TestReconcileSweep_LeafRefusalDoesNotUndoTheRecovery(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedRoutableFailedApp(t, "n", "a")
	agentReports(t, nc, "n", "a", proto.AppStatusRunning)
	countingLeafNode(t, nc, "n", false) // node rejects it

	mint := func(app *App) (proto.AppLeafCmd, error) {
		return proto.AppLeafCmd{AppID: app.ID}, nil
	}
	out, err := reconcileSweep(store, inv, nc, mint)(newStepCtxNATS(`{}`, nc))
	if err != nil {
		t.Fatalf("reconcileSweep must not fail because a proxy hiccuped: %v", err)
	}
	var counts map[string]int
	_ = json.Unmarshal(out, &counts)
	if counts["recovered"] != 0 {
		t.Errorf("recovered=%d, want 0 — the route was refused", counts["recovered"])
	}
	if got, _ := store.Get(context.Background(), "a"); got.LastStatus != proto.AppStatusRunning {
		t.Errorf("LastStatus = %q, want running — a refused leaf must not un-run a live container", got.LastStatus)
	}
}
