package apps

import (
	"context"
	"encoding/json"
	"strings"
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

// --- geekdojo/geekdojo-brain#399: "Delete volumes?" rides the delete spec ---

// captureStopCmd installs a fake agent that records the AppStopCmd it was sent
// and acks stopped.
func captureStopCmd(t *testing.T, nc *nats.Conn, nodeID string) *proto.AppStopCmd {
	t.Helper()
	got := &proto.AppStopCmd{}
	sub, err := nc.Subscribe(proto.AppStopSubject(nodeID), func(m *nats.Msg) {
		_ = json.Unmarshal(m.Data, got)
		ack, _ := json.Marshal(proto.AppStopAck{OK: true, Status: proto.AppStatusStopped})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return got
}

// A delete spec without deleteVolumes — every client that predates the field
// — stops with plain `compose down`: the agent sees false.
func TestDelete_DefaultKeepsVolumes(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "immich")
	got := captureStopCmd(t, nc, "n")
	out, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"a"}`, nc))
	if err != nil {
		t.Fatalf("deleteStop: %v", err)
	}
	if got.AppID != "a" || got.DeleteVolumes {
		t.Fatalf("agent received %+v; deleteVolumes must default to false", got)
	}
	if !strings.Contains(string(out), `"volumes":"kept"`) {
		t.Errorf("step result must say the volumes were kept: %s", out)
	}
}

// deleteVolumes:true reaches the agent as DeleteVolumes on the stop command.
func TestDelete_DeleteVolumesReachesAgent(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "immich")
	got := captureStopCmd(t, nc, "n")
	out, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"a","deleteVolumes":true}`, nc))
	if err != nil {
		t.Fatalf("deleteStop: %v", err)
	}
	if !got.DeleteVolumes {
		t.Fatalf("agent received %+v; deleteVolumes:true did not carry", got)
	}
	if !strings.Contains(string(out), `"volumes":"deleted"`) {
		t.Errorf("step result must say the volumes were deleted: %s", out)
	}
}

// The flag is app.delete's alone. A stop or deploy spec carrying it is refused
// outright — it cannot be silently ignored into a plain stop, and it can never
// turn a stop into a `down -v`.
func TestDelete_FlagNeverLeaksIntoOtherKinds(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "immich")
	got := captureStopCmd(t, nc, "n")

	if _, err := stopPush(store, inv, nc)(newStepCtxNATS(`{"appId":"a","deleteVolumes":true}`, nc)); err == nil {
		t.Fatal("app.stop must refuse a spec carrying deleteVolumes")
	}
	if got.DeleteVolumes {
		t.Fatal("app.stop sent deleteVolumes to the agent")
	}
	if _, err := parseSpec(json.RawMessage(`{"appId":"a","deleteVolumes":true}`)); err == nil {
		t.Fatal("parseSpec (deploy/stop) must refuse deleteVolumes")
	}
	// A plain stop never sends the flag at all.
	if _, err := stopPush(store, inv, nc)(newStepCtxNATS(`{"appId":"a"}`, nc)); err != nil {
		t.Fatalf("stopPush: %v", err)
	}
	if got.DeleteVolumes {
		t.Fatal("a plain app.stop must send deleteVolumes:false")
	}
}

// A misspelling of the one field that destroys data is a refusal, not a
// silent false.
func TestDelete_SpecIsStrict(t *testing.T) {
	if _, err := parseDeleteSpec(json.RawMessage(`{"appId":"a","deleteVolume":true}`)); err == nil {
		t.Fatal("parseDeleteSpec must refuse an unknown field")
	}
	spec, err := parseDeleteSpec(json.RawMessage(`{"appId":"a","deleteVolumes":true}`))
	if err != nil || !spec.DeleteVolumes {
		t.Fatalf("parseDeleteSpec: %v %+v", err, spec)
	}
}

// Delete-with-volumes on an offline node is REFUSED, naming the node, and the
// row stays. Removing the row would leave the data behind as an orphan the
// operator believes is gone — the failure #399 exists to prevent.
func TestDelete_DeleteVolumesOnOfflineNodeRefuses(t *testing.T) {
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
	a := makeApp("a", "immich")
	a.TargetNode = "n"
	if err := store.Create(ctx, a); err != nil {
		t.Fatalf("Create app: %v", err)
	}
	_, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"a","deleteVolumes":true}`, nc))
	if err == nil {
		t.Fatal("expected a refusal on an offline node")
	}
	if !strings.Contains(err.Error(), `"n"`) || !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("refusal must name the node: %v", err)
	}
	if got, _ := store.Get(ctx, "a"); got == nil {
		t.Error("the app row must remain when the delete was refused")
	}
	// And the keep path on the same offline node still proceeds, as before.
	if _, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"a"}`, nc)); err != nil {
		t.Errorf("keep-volumes delete on an offline node must still proceed: %v", err)
	}
}
