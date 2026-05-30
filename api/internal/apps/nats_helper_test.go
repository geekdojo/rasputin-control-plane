package apps

import (
	"context"
	"encoding/json"
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

// newStepCtxNATS builds a StepCtx with a real NATS conn (so the *Push steps
// can dial through to a fake agent).
func newStepCtxNATS(spec string, nc *nats.Conn) *jobs.StepCtx {
	return &jobs.StepCtx{
		Ctx:   context.Background(),
		JobID: "job-test",
		NATS:  nc,
		Spec:  json.RawMessage(spec),
		Log:   func(level, message string) {},
	}
}

// seedOnlineApp seeds a compute node + an app targeting it, both online and
// freshly-created. Returns the populated stores so the test can run further
// assertions on RecordStatus side effects.
func seedOnlineApp(t *testing.T, nodeID, appID, appName string) (*Store, *inventory.Store) {
	t.Helper()
	ctx := context.Background()
	store := newStore(t)
	inv := newInventory(t)
	if err := inv.Insert(ctx, &proto.Node{
		ID:        nodeID,
		Role:      proto.RoleCompute,
		Hostname:  nodeID + ".test",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	a := makeApp(appID, appName)
	a.TargetNode = nodeID
	if err := store.Create(ctx, a); err != nil {
		t.Fatalf("Create app: %v", err)
	}
	return store, inv
}

// ============================================================================
// deployPush — happy path: fake agent acks with OK + Running.
// ============================================================================

func TestDeployPush_HappyPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")

	// Fake agent: handle docker.deploy with an OK ack reporting Running.
	sub, err := nc.Subscribe(proto.AppDeploySubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppDeployAck{
			OK:     true,
			Status: proto.AppStatusRunning,
			Detail: "containers up",
		})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	// Subscribe to the app-change channel to observe emitChange.
	changeSub, err := nc.SubscribeSync(proto.AppChangeSubject("a", proto.AppDeployed))
	if err != nil {
		t.Fatalf("change sub: %v", err)
	}
	defer func() { _ = changeSub.Unsubscribe() }()

	sc := newStepCtxNATS(`{"appId":"a"}`, nc)
	out, err := deployPush(store, inv, nc)(sc)
	if err != nil {
		t.Fatalf("deployPush: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected JSON ack as result")
	}

	// Store should reflect the running state.
	got, _ := store.Get(ctx, "a")
	if got.LastStatus != proto.AppStatusRunning || got.LastDetail != "containers up" {
		t.Errorf("RecordStatus not applied: %+v", got)
	}
	// Change event should have fired.
	if _, err := changeSub.NextMsg(time.Second); err != nil {
		t.Errorf("expected AppDeployed change: %v", err)
	}
}

// TestDeployPush_AgentReportsFailure: ack.OK=false → step returns error +
// records Failed status.
func TestDeployPush_AgentReportsFailure(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")

	sub, err := nc.Subscribe(proto.AppDeploySubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppDeployAck{
			OK:     false,
			Status: proto.AppStatusFailed,
			Detail: "image pull failed",
		})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	sc := newStepCtxNATS(`{"appId":"a"}`, nc)
	if _, err := deployPush(store, inv, nc)(sc); err == nil {
		t.Error("agent failure: want error, got nil")
	}
	got, _ := store.Get(ctx, "a")
	if got.LastStatus != proto.AppStatusFailed {
		t.Errorf("LastStatus: want failed, got %q", got.LastStatus)
	}
}

// TestDeployPush_RPCFails: no agent subscribes, request times out, step
// records "deploy rpc failed" + emits AppFailed.
func TestDeployPush_RPCFails(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")

	sc := newStepCtxNATS(`{"appId":"a"}`, nc)
	tctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sc.Ctx = tctx
	if _, err := deployPush(store, inv, nc)(sc); err == nil {
		t.Error("RPC timeout: want error")
	}
	got, _ := store.Get(ctx, "a")
	if got.LastStatus != proto.AppStatusFailed {
		t.Errorf("LastStatus: want failed, got %q", got.LastStatus)
	}
}

// TestDeployPush_BadAck: agent replies with garbage JSON → decode-ack error.
func TestDeployPush_BadAck(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")
	sub, _ := nc.Subscribe(proto.AppDeploySubject("n"), func(m *nats.Msg) {
		_ = m.Respond([]byte("not-json"))
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newStepCtxNATS(`{"appId":"a"}`, nc)
	if _, err := deployPush(store, inv, nc)(sc); err == nil {
		t.Error("bad ack: want error")
	}
}

// ============================================================================
// stopPush — happy path + failure modes.
// ============================================================================

func TestStopPush_HappyPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")

	sub, err := nc.Subscribe(proto.AppStopSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppStopAck{
			OK:     true,
			Status: proto.AppStatusStopped,
			Detail: "stopped clean",
		})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	sc := newStepCtxNATS(`{"appId":"a"}`, nc)
	if _, err := stopPush(store, inv, nc)(sc); err != nil {
		t.Fatalf("stopPush: %v", err)
	}
	got, _ := store.Get(ctx, "a")
	if got.LastStatus != proto.AppStatusStopped {
		t.Errorf("LastStatus: want stopped, got %q", got.LastStatus)
	}
}

func TestStopPush_AgentReportsFailure(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")
	sub, _ := nc.Subscribe(proto.AppStopSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppStopAck{OK: false, Status: proto.AppStatusFailed, Detail: "kill -9 failed"})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newStepCtxNATS(`{"appId":"a"}`, nc)
	if _, err := stopPush(store, inv, nc)(sc); err == nil {
		t.Error("want error on OK=false")
	}
}

func TestStopPush_RPCFails(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")
	sc := newStepCtxNATS(`{"appId":"a"}`, nc)
	tctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sc.Ctx = tctx
	if _, err := stopPush(store, inv, nc)(sc); err == nil {
		t.Error("RPC timeout: want error")
	}
}

func TestStopPush_BadAck(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")
	sub, _ := nc.Subscribe(proto.AppStopSubject("n"), func(m *nats.Msg) {
		_ = m.Respond([]byte("bogus"))
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newStepCtxNATS(`{"appId":"a"}`, nc)
	if _, err := stopPush(store, inv, nc)(sc); err == nil {
		t.Error("bad ack: want error")
	}
}

// ============================================================================
// reconcileSweep — drift detection + skip-on-offline.
// ============================================================================

func TestReconcileSweep_DriftDetectedUpdatesStore(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")
	// First record the app as Running.
	_ = store.RecordStatus(ctx, "a", proto.AppStatusRunning, "", time.Now().UTC())

	// Agent now reports Failed → drift.
	sub, _ := nc.Subscribe(proto.AppStatusSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppStatusAck{
			AppID:  "a",
			Status: proto.AppStatusFailed,
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	sc := newStepCtxNATS(`{}`, nc)
	out, err := reconcileSweep(store, inv, nc)(sc)
	if err != nil {
		t.Fatalf("reconcileSweep: %v", err)
	}
	var counts map[string]int
	_ = json.Unmarshal(out, &counts)
	if counts["drifted"] != 1 {
		t.Errorf("drift count: want 1, got %d (full: %+v)", counts["drifted"], counts)
	}
	got, _ := store.Get(ctx, "a")
	if got.LastStatus != proto.AppStatusFailed {
		t.Errorf("LastStatus after drift: want failed, got %q", got.LastStatus)
	}
}

func TestReconcileSweep_SkipsOfflineTarget(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	// Node that's offline — gap > 2m.
	if err := inv.Insert(ctx, &proto.Node{
		ID:        "n",
		Role:      proto.RoleCompute,
		FirstSeen: time.Now().Add(-time.Hour).UTC(),
		LastSeen:  time.Now().Add(-10 * time.Minute).UTC(),
	}); err != nil {
		t.Fatalf("inv: %v", err)
	}
	app := makeApp("a", "x")
	app.TargetNode = "n"
	if err := store.Create(ctx, app); err != nil {
		t.Fatalf("create: %v", err)
	}

	sc := newStepCtxNATS(`{}`, nc)
	out, err := reconcileSweep(store, inv, nc)(sc)
	if err != nil {
		t.Fatalf("reconcileSweep: %v", err)
	}
	var counts map[string]int
	_ = json.Unmarshal(out, &counts)
	if counts["skipped"] != 1 || counts["checked"] != 0 || counts["drifted"] != 0 {
		t.Errorf("counts: %+v", counts)
	}
}

func TestReconcileSweep_RPCFailureCounted(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")
	_ = store.RecordStatus(ctx, "a", proto.AppStatusRunning, "", time.Now().UTC())

	// No agent listens — the request will time out.
	sc := newStepCtxNATS(`{}`, nc)
	out, err := reconcileSweep(store, inv, nc)(sc)
	if err != nil {
		t.Fatalf("reconcileSweep: %v", err)
	}
	var counts map[string]int
	_ = json.Unmarshal(out, &counts)
	if counts["failed"] != 1 {
		t.Errorf("failed count: want 1, got %+v", counts)
	}
}

// TestReconcileSweep_NoDrift covers the ack.Status == app.LastStatus continue
// branch (status matches, no update).
func TestReconcileSweep_NoDrift(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")
	_ = store.RecordStatus(ctx, "a", proto.AppStatusRunning, "", time.Now().UTC())

	sub, _ := nc.Subscribe(proto.AppStatusSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppStatusAck{AppID: "a", Status: proto.AppStatusRunning})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	sc := newStepCtxNATS(`{}`, nc)
	out, err := reconcileSweep(store, inv, nc)(sc)
	if err != nil {
		t.Fatalf("reconcileSweep: %v", err)
	}
	var counts map[string]int
	_ = json.Unmarshal(out, &counts)
	if counts["checked"] != 1 || counts["drifted"] != 0 {
		t.Errorf("counts: %+v", counts)
	}
}

// TestReconcileSweep_BadAckCountsAsFailure covers the json.Unmarshal error
// branch on the ack.
func TestReconcileSweep_BadAckCountsAsFailure(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "minecraft")
	_ = store.RecordStatus(ctx, "a", proto.AppStatusRunning, "", time.Now().UTC())

	sub, _ := nc.Subscribe(proto.AppStatusSubject("n"), func(m *nats.Msg) {
		_ = m.Respond([]byte("not-json"))
	})
	defer func() { _ = sub.Unsubscribe() }()

	sc := newStepCtxNATS(`{}`, nc)
	out, err := reconcileSweep(store, inv, nc)(sc)
	if err != nil {
		t.Fatalf("reconcileSweep: %v", err)
	}
	var counts map[string]int
	_ = json.Unmarshal(out, &counts)
	if counts["failed"] != 1 {
		t.Errorf("failed count: want 1, got %+v", counts)
	}
}

// emitChange direct exercise.
func TestEmitChange_Publishes(t *testing.T) {
	nc := startNATS(t)
	sub, err := nc.SubscribeSync(proto.AppChangeSubject("a", proto.AppDeployed))
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	emitChange(nc, "a", proto.AppDeployed, proto.AppStatusRunning, "ok", time.Now().UTC())
	msg, err := sub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("NextMsg: %v", err)
	}
	var ev proto.AppChangeEvt
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Change != proto.AppDeployed {
		t.Errorf("change: %q", ev.Change)
	}
}
