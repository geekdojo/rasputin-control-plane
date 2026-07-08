package apps

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Online node: deleteStop RPCs the agent's docker.stop and succeeds; deleteRemove
// then drops the row and emits the deleted event.
func TestDelete_OnlineStopsThenRemoves(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "uptime-kuma")

	sub, err := nc.Subscribe(proto.AppStopSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppStopAck{OK: true, Status: proto.AppStatusStopped})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	deletedSub, err := nc.SubscribeSync(proto.AppChangeSubject("a", proto.AppDeleted))
	if err != nil {
		t.Fatalf("change sub: %v", err)
	}
	defer func() { _ = deletedSub.Unsubscribe() }()

	// Step 1: stop.
	if _, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"a"}`, nc)); err != nil {
		t.Fatalf("deleteStop: %v", err)
	}
	// Step 2: remove.
	if _, err := deleteRemove(store, nc)(newStepCtxNATS(`{"appId":"a"}`, nc)); err != nil {
		t.Fatalf("deleteRemove: %v", err)
	}

	if got, _ := store.Get(ctx, "a"); got != nil {
		t.Errorf("app row should be gone, got %+v", got)
	}
	if _, err := deletedSub.NextMsg(time.Second); err != nil {
		t.Errorf("expected AppDeleted change event: %v", err)
	}
}

// Online node whose stop fails: deleteStop returns an error and the row is kept
// (no silent orphan on a reachable node).
func TestDelete_OnlineStopFailsKeepsRow(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "uptime-kuma")

	sub, _ := nc.Subscribe(proto.AppStopSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppStopAck{OK: false, Detail: "compose down failed"})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	if _, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"a"}`, nc)); err == nil {
		t.Fatal("expected deleteStop to fail when the agent reports stop failed")
	}
	if got, _ := store.Get(ctx, "a"); got == nil {
		t.Error("app row must remain after a failed stop on a reachable node")
	}
}

// Offline node: deleteStop can't reach the agent, so it skips the stop (with a
// warning) and lets deleteRemove drop the record anyway.
func TestDelete_OfflineNodeSkipsStopButRemoves(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	stale := time.Now().Add(-5 * time.Minute).UTC()
	if err := inv.Insert(ctx, &proto.Node{
		ID: "n", Role: proto.RoleCompute, Hostname: "n.test", FirstSeen: stale, LastSeen: stale,
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	a := makeApp("a", "uptime-kuma")
	a.TargetNode = "n"
	if err := store.Create(ctx, a); err != nil {
		t.Fatalf("Create app: %v", err)
	}

	// No agent responder — the node is offline; deleteStop must not block on it.
	out, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"a"}`, nc))
	if err != nil {
		t.Fatalf("deleteStop on offline node should not fail: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected a step result")
	}
	if _, err := deleteRemove(store, nc)(newStepCtxNATS(`{"appId":"a"}`, nc)); err != nil {
		t.Fatalf("deleteRemove: %v", err)
	}
	if got, _ := store.Get(ctx, "a"); got != nil {
		t.Errorf("app row should be gone, got %+v", got)
	}
}

// deleteStop is idempotent: a missing app is a success (a retry after remove
// already ran).
func TestDelete_MissingAppIsIdempotent(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	if _, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"ghost"}`, nc)); err != nil {
		t.Errorf("deleteStop on a missing app should succeed, got %v", err)
	}
	if _, err := deleteRemove(store, nc)(newStepCtxNATS(`{"appId":"ghost"}`, nc)); err != nil {
		t.Errorf("deleteRemove on a missing app should succeed, got %v", err)
	}
}
