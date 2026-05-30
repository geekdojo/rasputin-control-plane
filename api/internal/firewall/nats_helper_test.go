package firewall

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
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

func newInventory(t *testing.T) *inventory.Store {
	t.Helper()
	dir := t.TempDir()
	inv, err := inventory.OpenStore(context.Background(), filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatalf("inventory OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	return inv
}

// seedFirewallNode registers a single firewall-role node with the inventory
// store and returns its ID.
func seedFirewallNode(t *testing.T, inv *inventory.Store, id string) string {
	t.Helper()
	if err := inv.Insert(context.Background(), &proto.Node{
		ID:        id,
		Role:      proto.RoleFirewall,
		Hostname:  id + ".test",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	return id
}

func newStepCtxNATS(spec string, nc *nats.Conn) *jobs.StepCtx {
	return &jobs.StepCtx{
		Ctx:   context.Background(),
		JobID: "job-test",
		NATS:  nc,
		Spec:  json.RawMessage(spec),
		Log:   func(level, message string) {},
	}
}

// ============================================================================
// applyFindTarget — happy + edge cases.
// ============================================================================

func TestApplyFindTarget_HappyPath(t *testing.T) {
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw-1")
	sc := newStepCtxNATS(`{}`, nil)
	out, err := applyFindTarget(inv)(sc)
	if err != nil {
		t.Fatalf("applyFindTarget: %v", err)
	}
	var got map[string]string
	_ = json.Unmarshal(out, &got)
	if got["nodeId"] != "fw-1" {
		t.Errorf("nodeId: %q", got["nodeId"])
	}
}

func TestApplyFindTarget_NoFirewallNode(t *testing.T) {
	inv := newInventory(t)
	sc := newStepCtxNATS(`{}`, nil)
	if _, err := applyFindTarget(inv)(sc); err == nil {
		t.Error("no firewall: want error")
	}
}

func TestApplyFindTarget_MultipleFirewallNodes(t *testing.T) {
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw-a")
	seedFirewallNode(t, inv, "fw-b")
	sc := newStepCtxNATS(`{}`, nil)
	if _, err := applyFindTarget(inv)(sc); err == nil {
		t.Error("multiple firewall: want error")
	}
}

// ============================================================================
// applyCompile — exercises store + Compile + logging.
// ============================================================================

func TestApplyCompile_HappyPath(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	if err := store.CreateIntent(ctx, makePortForwardIntent(t, "i", "ssh", true, 2222, 22)); err != nil {
		t.Fatalf("create intent: %v", err)
	}
	sc := newStepCtxNATS(`{}`, nil)
	out, err := applyCompile(store)(sc)
	if err != nil {
		t.Fatalf("applyCompile: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected result JSON")
	}
}

// ============================================================================
// applyPush — happy path via fake agent.
// ============================================================================

func TestApplyPush_HappyPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")
	if err := store.CreateIntent(ctx, makePortForwardIntent(t, "i", "web", true, 8080, 80)); err != nil {
		t.Fatalf("create intent: %v", err)
	}

	// Compute the hash the api will send so the fake agent can echo it back.
	intents, _ := store.ListIntents(ctx)
	_, wantHash, err := Compile(intents)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	sub, err := nc.Subscribe(proto.FirewallApplySubject("fw"), func(m *nats.Msg) {
		var cmd proto.FirewallApplyCmd
		_ = json.Unmarshal(m.Data, &cmd)
		ack, _ := json.Marshal(proto.FirewallApplyAck{OK: true, Hash: cmd.IntentHash})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	// Observe the applied change event.
	chSub, _ := nc.SubscribeSync(proto.FirewallChangeSubject("fw", proto.FirewallApplied))
	defer func() { _ = chSub.Unsubscribe() }()

	sc := newStepCtxNATS(`{}`, nc)
	out, err := applyPush(store, inv, nc)(sc)
	if err != nil {
		t.Fatalf("applyPush: %v", err)
	}
	var got map[string]string
	_ = json.Unmarshal(out, &got)
	if got["nodeId"] != "fw" || got["hash"] != wantHash {
		t.Errorf("result: %+v want hash=%s", got, wantHash)
	}
	// Confirm node state persisted.
	state, _ := store.GetNodeState(ctx, "fw")
	if state == nil || state.IntentHash != wantHash {
		t.Errorf("state: %+v", state)
	}
	// Confirm applied event was published.
	if _, err := chSub.NextMsg(time.Second); err != nil {
		t.Errorf("expected applied event: %v", err)
	}
}

func TestApplyPush_AgentReportsFailure(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")
	sub, _ := nc.Subscribe(proto.FirewallApplySubject("fw"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.FirewallApplyAck{OK: false})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newStepCtxNATS(`{}`, nc)
	if _, err := applyPush(store, inv, nc)(sc); err == nil {
		t.Error("agent OK=false: want error")
	}
}

func TestApplyPush_HashMismatch(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")
	sub, _ := nc.Subscribe(proto.FirewallApplySubject("fw"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.FirewallApplyAck{OK: true, Hash: "deadbeef"})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newStepCtxNATS(`{}`, nc)
	if _, err := applyPush(store, inv, nc)(sc); err == nil {
		t.Error("hash mismatch: want error")
	}
}

func TestApplyPush_RPCTimeout(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")
	tctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sc := newStepCtxNATS(`{}`, nc)
	sc.Ctx = tctx
	if _, err := applyPush(store, inv, nc)(sc); err == nil {
		t.Error("timeout: want error")
	}
}

func TestApplyPush_NoFirewallNode(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t) // no firewall node seeded
	sc := newStepCtxNATS(`{}`, nc)
	if _, err := applyPush(store, inv, nc)(sc); err == nil {
		t.Error("no firewall: want error")
	}
}

func TestApplyPush_BadAck(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")
	sub, _ := nc.Subscribe(proto.FirewallApplySubject("fw"), func(m *nats.Msg) {
		_ = m.Respond([]byte("not-json"))
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newStepCtxNATS(`{}`, nc)
	if _, err := applyPush(store, inv, nc)(sc); err == nil {
		t.Error("bad ack: want error")
	}
}

// ============================================================================
// reconcileFetch — happy path.
// ============================================================================

func TestReconcileFetch_HappyPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")

	sub, _ := nc.Subscribe(proto.FirewallGetSubject("fw"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.FirewallGetAck{
			State: map[string]any{"firewall": map[string]any{}},
			Hash:  "observed-1",
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	sc := newStepCtxNATS(`{}`, nc)
	out, err := reconcileFetch(store, inv, nc)(sc)
	if err != nil {
		t.Fatalf("reconcileFetch: %v", err)
	}
	var got map[string]string
	_ = json.Unmarshal(out, &got)
	if got["observedHash"] != "observed-1" {
		t.Errorf("observed: %q", got["observedHash"])
	}
	// state should have been persisted.
	state, _ := store.GetNodeState(ctx, "fw")
	if state == nil || state.ObservedHash != "observed-1" {
		t.Errorf("state: %+v", state)
	}
}

func TestReconcileFetch_RPCTimeout(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")
	tctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sc := newStepCtxNATS(`{}`, nc)
	sc.Ctx = tctx
	if _, err := reconcileFetch(store, inv, nc)(sc); err == nil {
		t.Error("timeout: want error")
	}
}

func TestReconcileFetch_BadAck(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")
	sub, _ := nc.Subscribe(proto.FirewallGetSubject("fw"), func(m *nats.Msg) {
		_ = m.Respond([]byte("not-json"))
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newStepCtxNATS(`{}`, nc)
	if _, err := reconcileFetch(store, inv, nc)(sc); err == nil {
		t.Error("bad ack: want error")
	}
}

func TestReconcileFetch_NoFirewallNode(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	sc := newStepCtxNATS(`{}`, nc)
	if _, err := reconcileFetch(store, inv, nc)(sc); err == nil {
		t.Error("no node: want error")
	}
}

// ============================================================================
// reconcileCompare — drift + in-sync paths.
// ============================================================================

func TestReconcileCompare_DriftPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")

	// Set up drift: apply then reconcile with different hashes.
	_ = store.UpdateAfterApply(ctx, "fw", "intent-1", time.Now().UTC())
	_ = store.UpdateAfterReconcile(ctx, "fw", "observed-X", time.Now().UTC())

	chSub, _ := nc.SubscribeSync(proto.FirewallChangeSubject("fw", proto.FirewallDrift))
	defer func() { _ = chSub.Unsubscribe() }()

	sc := newStepCtxNATS(`{}`, nc)
	out, err := reconcileCompare(store, inv, nc)(sc)
	if err != nil {
		t.Fatalf("reconcileCompare: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	if drift, _ := got["drift"].(bool); !drift {
		t.Errorf("want drift=true, got %v", got)
	}
	if _, err := chSub.NextMsg(time.Second); err != nil {
		t.Errorf("expected drift event: %v", err)
	}
}

func TestReconcileCompare_InSyncPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")
	_ = store.UpdateAfterApply(ctx, "fw", "hash-x", time.Now().UTC())
	_ = store.UpdateAfterReconcile(ctx, "fw", "hash-x", time.Now().UTC())

	chSub, _ := nc.SubscribeSync(proto.FirewallChangeSubject("fw", proto.FirewallInSync))
	defer func() { _ = chSub.Unsubscribe() }()

	sc := newStepCtxNATS(`{}`, nc)
	if _, err := reconcileCompare(store, inv, nc)(sc); err != nil {
		t.Fatalf("reconcileCompare: %v", err)
	}
	if _, err := chSub.NextMsg(time.Second); err != nil {
		t.Errorf("expected in_sync event: %v", err)
	}
}

func TestReconcileCompare_NoStateRecorded(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")
	// no UpdateAfterApply call — state is nil
	sc := newStepCtxNATS(`{}`, nc)
	if _, err := reconcileCompare(store, inv, nc)(sc); err == nil {
		t.Error("no state recorded: want error")
	}
}

func TestReconcileCompare_NoFirewallNode(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	sc := newStepCtxNATS(`{}`, nc)
	if _, err := reconcileCompare(store, inv, nc)(sc); err == nil {
		t.Error("no node: want error")
	}
}
