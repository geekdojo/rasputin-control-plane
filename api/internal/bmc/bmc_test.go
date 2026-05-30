package bmc

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// ============================================================================
// Embedded NATS for the SOL session/manager tests
// ============================================================================

func embeddedNATS(t *testing.T) *nats.Conn {
	t.Helper()
	opts := &server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(2 * time.Second) {
		t.Fatal("nats not ready")
	}
	t.Cleanup(func() {
		ns.Shutdown()
		ns.WaitForShutdown()
	})
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { nc.Close() })
	return nc
}

// ============================================================================
// Fixture
// ============================================================================

type fixture struct {
	ctx   context.Context
	dir   string
	store *Store
	nc    *nats.Conn
	svc   *Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := OpenStore(ctx, filepath.Join(dir, "bmc.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	nc := embeddedNATS(t)
	svc := NewService(Config{HostNodeID: "host-1"}, st, nc)
	return &fixture{ctx: ctx, dir: dir, store: st, nc: nc, svc: svc}
}

// ============================================================================
// Store
// ============================================================================

func TestStore_Upsert_NewRow(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	ns := &NodeState{
		TargetNodeID:  "n-1",
		PowerState:    proto.BMCStateOn,
		LastCmd:       "on",
		LastCmdAt:     &now,
		LastCmdResult: "ok",
		UpdatedAt:     now,
	}
	if err := f.store.Upsert(f.ctx, ns); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := f.store.Get(f.ctx, "n-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("not found")
	}
	if got.PowerState != proto.BMCStateOn {
		t.Errorf("PowerState: got %q", got.PowerState)
	}
	if got.LastCmdAt == nil || !got.LastCmdAt.Equal(now) {
		t.Errorf("LastCmdAt: got %v", got.LastCmdAt)
	}
}

func TestStore_Upsert_OverwritesExisting(t *testing.T) {
	f := newFixture(t)
	t0 := time.Now().UTC().Truncate(time.Millisecond)
	_ = f.store.Upsert(f.ctx, &NodeState{
		TargetNodeID: "n", PowerState: proto.BMCStateOn,
		LastCmd: "on", UpdatedAt: t0,
	})
	t1 := t0.Add(time.Minute)
	_ = f.store.Upsert(f.ctx, &NodeState{
		TargetNodeID: "n", PowerState: proto.BMCStateOff,
		LastCmd: "off", UpdatedAt: t1,
	})
	got, _ := f.store.Get(f.ctx, "n")
	if got.PowerState != proto.BMCStateOff {
		t.Errorf("PowerState: got %q", got.PowerState)
	}
	if got.LastCmd != "off" {
		t.Errorf("LastCmd: got %q", got.LastCmd)
	}
}

func TestStore_Upsert_NilLastCmdAt(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := f.store.Upsert(f.ctx, &NodeState{
		TargetNodeID: "n", PowerState: proto.BMCStateUnknown,
		LastCmdAt: nil, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, _ := f.store.Get(f.ctx, "n")
	if got.LastCmdAt != nil {
		t.Errorf("LastCmdAt: want nil, got %v", got.LastCmdAt)
	}
}

func TestStore_Get_NotFound(t *testing.T) {
	f := newFixture(t)
	got, err := f.store.Get(f.ctx, "missing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Errorf("want nil, got %+v", got)
	}
}

func TestStore_List_OrderedByTargetID(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, id := range []string{"c", "a", "b"} {
		_ = f.store.Upsert(f.ctx, &NodeState{
			TargetNodeID: id, PowerState: proto.BMCStateOn, UpdatedAt: now,
		})
	}
	got, err := f.store.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	want := []string{"a", "b", "c"}
	for i, n := range got {
		if n.TargetNodeID != want[i] {
			t.Errorf("idx %d: want %s, got %s", i, want[i], n.TargetNodeID)
		}
	}
}

func TestStore_List_Empty(t *testing.T) {
	f := newFixture(t)
	got, err := f.store.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty, got %+v", got)
	}
}

// ============================================================================
// ms / fromMs round-trip
// ============================================================================

func TestMsRoundTrip_BMC(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	if got := fromMs(ms(now)); !got.Equal(now) {
		t.Errorf("round-trip: %v vs %v", now, got)
	}
}

// ============================================================================
// Service
// ============================================================================

func TestNewService_AccessorsAndMissingHost(t *testing.T) {
	f := newFixture(t)
	if f.svc.HostNodeID() != "host-1" {
		t.Errorf("HostNodeID: got %q", f.svc.HostNodeID())
	}
	if f.svc.Store() != f.store {
		t.Error("Store accessor mismatch")
	}
	if f.svc.NATS() != f.nc {
		t.Error("NATS accessor mismatch")
	}
	// Constructing with no host id logs a warning but still returns a service.
	svc2 := NewService(Config{}, f.store, f.nc)
	if svc2.HostNodeID() != "" {
		t.Errorf("HostNodeID: want empty, got %q", svc2.HostNodeID())
	}
}

// ============================================================================
// Spec parse + verb validation
// ============================================================================

func TestParseSpec_BMC(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"valid on", `{"targetNodeId":"n","verb":"on"}`, false},
		{"valid off", `{"targetNodeId":"n","verb":"off"}`, false},
		{"valid cycle", `{"targetNodeId":"n","verb":"cycle"}`, false},
		{"valid reset", `{"targetNodeId":"n","verb":"reset"}`, false},
		{"valid status", `{"targetNodeId":"n","verb":"status"}`, false},
		{"missing target", `{"verb":"on"}`, true},
		{"bad verb", `{"targetNodeId":"n","verb":"explode"}`, true},
		{"bad json", `{not json`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSpec(json.RawMessage(tc.raw))
			if (err != nil) != tc.wantErr {
				t.Errorf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// ============================================================================
// verbToChange + publishChange
// ============================================================================

func TestVerbToChange(t *testing.T) {
	cases := []struct {
		verb proto.BMCPowerVerb
		want proto.BMCChangeType
	}{
		{proto.BMCPowerOn, proto.BMCPoweredOn},
		{proto.BMCPowerOff, proto.BMCPoweredOff},
		{proto.BMCPowerCycle, proto.BMCCycled},
		{proto.BMCPowerReset, proto.BMCResetSent},
		{proto.BMCPowerQuery, proto.BMCCycled}, // default for the read-only case
	}
	for _, tc := range cases {
		if got := verbToChange(tc.verb); got != tc.want {
			t.Errorf("verb=%q: want %q got %q", tc.verb, tc.want, got)
		}
	}
}

func TestPublishChange_BMC(t *testing.T) {
	f := newFixture(t)
	sub, err := f.nc.SubscribeSync(proto.BMCChangeSubject("n", proto.BMCPoweredOn))
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	publishChange(f.svc, proto.BMCChangeEvt{
		TargetNodeID: "n", Change: proto.BMCPoweredOn,
		State: proto.BMCStateOn, Ts: time.Now().UTC(),
	})
	msg, err := sub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("NextMsg: %v", err)
	}
	if len(msg.Data) == 0 {
		t.Error("empty payload")
	}
}

// ============================================================================
// PowerWorkflow constructor
// ============================================================================

func TestPowerWorkflow_KindAndSteps(t *testing.T) {
	f := newFixture(t)
	wf := PowerWorkflow(f.svc, nil)
	if wf.Kind != "bmc.power" {
		t.Errorf("kind: %q", wf.Kind)
	}
	if len(wf.Steps) != 3 {
		t.Errorf("steps: want 3, got %d", len(wf.Steps))
	}
}

// ============================================================================
// SessionManager bookkeeping
// ============================================================================

func TestNewSessionManager_Empty(t *testing.T) {
	f := newFixture(t)
	mgr := NewSessionManager(f.svc)
	mgr.mu.Lock()
	n := len(mgr.sessions)
	mgr.mu.Unlock()
	if n != 0 {
		t.Errorf("want empty registry, got %d", n)
	}
}

func TestSessionManager_Open_NoHostConfigured(t *testing.T) {
	f := newFixture(t)
	svcNoHost := NewService(Config{}, f.store, f.nc)
	mgr := NewSessionManager(svcNoHost)
	if _, err := mgr.Open(f.ctx, "target-1"); err == nil {
		t.Error("want error when no host configured")
	}
}

// TestSession_Write exercises the publish path. With no responder for the
// open, we have to bypass Open and stitch the Session by hand.
func TestSession_Write(t *testing.T) {
	f := newFixture(t)
	sess := &Session{
		ID:           "sess-1",
		TargetNodeID: "n",
		Backend:      "test",
		Out:          make(chan []byte, 1),
		closed:       make(chan struct{}),
		mgr:          NewSessionManager(f.svc),
	}
	sub, err := f.nc.SubscribeSync(proto.BMCSOLInSubject(sess.ID))
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	if err := sess.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	m, err := sub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("NextMsg: %v", err)
	}
	var ev proto.BMCSOLDataEvt
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.Data != "hello" {
		t.Errorf("Data: %q", ev.Data)
	}
}

// TestSession_Closed verifies the closed channel signals.
func TestSession_Closed(t *testing.T) {
	f := newFixture(t)
	sess := &Session{
		ID:           "sess-2",
		TargetNodeID: "n",
		Out:          make(chan []byte, 1),
		closed:       make(chan struct{}),
		mgr:          NewSessionManager(f.svc),
	}
	// Should not be closed yet.
	select {
	case <-sess.Closed():
		t.Fatal("expected closed channel to block")
	default:
	}

	// Close() does an RPC to bmc.sol.close which we have to respond to so it
	// doesn't time out — but the real value is verifying it unblocks Closed
	// and is idempotent.
	if _, err := f.nc.Subscribe(proto.BMCSOLCloseSubject("host-1"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.BMCSOLCloseAck{OK: true})
		_ = m.Respond(ack)
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	sess.mgr.mu.Lock()
	sess.mgr.sessions[sess.ID] = sess
	sess.mgr.mu.Unlock()

	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	sess.Close(ctx)
	select {
	case <-sess.Closed():
	case <-time.After(time.Second):
		t.Fatal("Closed channel did not close")
	}

	// Removed from registry.
	sess.mgr.mu.Lock()
	_, present := sess.mgr.sessions[sess.ID]
	sess.mgr.mu.Unlock()
	if present {
		t.Error("session not removed from manager registry")
	}

	// Second Close is a no-op (closeOnce); shouldn't panic.
	sess.Close(ctx)
}

// TestSessionManager_OpenFlow exercises Open against a fake agent responder.
func TestSessionManager_OpenFlow(t *testing.T) {
	f := newFixture(t)
	mgr := NewSessionManager(f.svc)

	// Fake agent: responds OK to the open RPC.
	if _, err := f.nc.Subscribe(proto.BMCSOLOpenSubject("host-1"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.BMCSOLOpenAck{OK: true, Backend: "fake"})
		_ = m.Respond(ack)
	}); err != nil {
		t.Fatalf("subscribe open: %v", err)
	}
	// Subscribe before the close RPC fires too.
	if _, err := f.nc.Subscribe(proto.BMCSOLCloseSubject("host-1"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.BMCSOLCloseAck{OK: true})
		_ = m.Respond(ack)
	}); err != nil {
		t.Fatalf("subscribe close: %v", err)
	}

	sess, err := mgr.Open(f.ctx, "target-1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if sess.ID == "" {
		t.Error("want session id")
	}
	if sess.Backend != "fake" {
		t.Errorf("Backend: %q", sess.Backend)
	}
	mgr.mu.Lock()
	n := len(mgr.sessions)
	mgr.mu.Unlock()
	if n != 1 {
		t.Errorf("registry: want 1, got %d", n)
	}

	// Push an out-event from the agent → should land in Out channel.
	ev, _ := json.Marshal(proto.BMCSOLDataEvt{SessionID: sess.ID, Data: "boot..."})
	if err := f.nc.Publish(proto.BMCSOLOutSubject(sess.ID), ev); err != nil {
		t.Fatalf("publish: %v", err)
	}
	select {
	case got := <-sess.Out:
		if string(got) != "boot..." {
			t.Errorf("Out: got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no message arrived on Out")
	}

	// Tear down.
	sess.Close(f.ctx)
}

func TestSessionManager_OpenFlow_AgentRejects(t *testing.T) {
	f := newFixture(t)
	mgr := NewSessionManager(f.svc)

	if _, err := f.nc.Subscribe(proto.BMCSOLOpenSubject("host-1"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.BMCSOLOpenAck{OK: false, Detail: "no port"})
		_ = m.Respond(ack)
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if _, err := mgr.Open(f.ctx, "target-1"); err == nil {
		t.Error("want error when agent rejects")
	}
}
