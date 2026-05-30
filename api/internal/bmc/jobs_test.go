package bmc

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// stepCtx builds a minimal StepCtx targeting the given spec.
func stepCtx(ctx context.Context, nc *nats.Conn, spec any) *jobs.StepCtx {
	raw, _ := json.Marshal(spec)
	return &jobs.StepCtx{
		Ctx:   ctx,
		JobID: "test-job",
		Spec:  raw,
		NATS:  nc,
		Log:   func(string, string) {},
	}
}

func newInvStore(t *testing.T) *inventory.Store {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	inv, err := inventory.OpenStore(ctx, filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatalf("inventory open: %v", err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	return inv
}

// ============================================================================
// powerValidate
// ============================================================================

func TestPowerValidate_RejectsBadSpec(t *testing.T) {
	f := newFixture(t)
	inv := newInvStore(t)
	step := powerValidate(f.svc, inv)
	if _, err := step(stepCtx(f.ctx, f.nc, map[string]string{"verb": "on"})); err == nil {
		t.Error("want error for missing targetNodeId")
	}
}

func TestPowerValidate_NoHostConfigured(t *testing.T) {
	f := newFixture(t)
	inv := newInvStore(t)
	svcNoHost := NewService(Config{}, f.store, f.nc)
	step := powerValidate(svcNoHost, inv)
	sc := stepCtx(f.ctx, f.nc, Spec{TargetNodeID: "n", Verb: proto.BMCPowerOn})
	if _, err := step(sc); err == nil {
		t.Error("want error when host not configured")
	}
}

func TestPowerValidate_UnknownTarget(t *testing.T) {
	f := newFixture(t)
	inv := newInvStore(t)
	step := powerValidate(f.svc, inv)
	sc := stepCtx(f.ctx, f.nc, Spec{TargetNodeID: "ghost", Verb: proto.BMCPowerOn})
	if _, err := step(sc); err == nil {
		t.Error("want error for unknown target node")
	}
}

func TestPowerValidate_Success(t *testing.T) {
	f := newFixture(t)
	inv := newInvStore(t)
	_ = inv.Insert(f.ctx, &proto.Node{
		ID: "node-1", Role: proto.RoleCompute, Hostname: "node-1.local",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	})
	step := powerValidate(f.svc, inv)
	sc := stepCtx(f.ctx, f.nc, Spec{TargetNodeID: "node-1", Verb: proto.BMCPowerOn})
	out, err := step(sc)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected step output")
	}
}

// ============================================================================
// powerDispatch
// ============================================================================

func TestPowerDispatch_AgentAcksOK(t *testing.T) {
	f := newFixture(t)
	// Fake agent responds OK on the host's power subject.
	subj := proto.BMCPowerSubject("host-1", proto.BMCPowerOn)
	if _, err := f.nc.Subscribe(subj, func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.BMCPowerAck{OK: true, State: proto.BMCStateOn})
		_ = m.Respond(ack)
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	step := powerDispatch(f.svc)
	sc := stepCtx(f.ctx, f.nc, Spec{TargetNodeID: "n", Verb: proto.BMCPowerOn})
	out, err := step(sc)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	var ack proto.BMCPowerAck
	if err := json.Unmarshal(out, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.State != proto.BMCStateOn {
		t.Errorf("State: got %q", ack.State)
	}
}

func TestPowerDispatch_AgentRejects(t *testing.T) {
	f := newFixture(t)
	subj := proto.BMCPowerSubject("host-1", proto.BMCPowerOff)
	if _, err := f.nc.Subscribe(subj, func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.BMCPowerAck{OK: false, Detail: "wrong harness"})
		_ = m.Respond(ack)
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	step := powerDispatch(f.svc)
	sc := stepCtx(f.ctx, f.nc, Spec{TargetNodeID: "n", Verb: proto.BMCPowerOff})
	if _, err := step(sc); err == nil {
		t.Error("want error when agent NAKs")
	}
}

// ============================================================================
// powerRecord
// ============================================================================

func TestPowerRecord_Persists(t *testing.T) {
	f := newFixture(t)
	// Status RPC must reply for the post-command read.
	statusSubj := proto.BMCPowerSubject("host-1", proto.BMCPowerQuery)
	if _, err := f.nc.Subscribe(statusSubj, func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.BMCPowerAck{OK: true, State: proto.BMCStateOn, Detail: "x"})
		_ = m.Respond(ack)
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	step := powerRecord(f.svc)
	sc := stepCtx(f.ctx, f.nc, Spec{TargetNodeID: "n", Verb: proto.BMCPowerOn})
	if _, err := step(sc); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, err := f.store.Get(f.ctx, "n")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil || got.PowerState != proto.BMCStateOn {
		t.Errorf("persisted: %+v", got)
	}
}

func TestPowerRecord_PersistsUnknownOnNATSTimeout(t *testing.T) {
	f := newFixture(t)
	// No responder → status RPC errors → state defaults to unknown.
	step := powerRecord(f.svc)
	sc := stepCtx(f.ctx, f.nc, Spec{TargetNodeID: "n2", Verb: proto.BMCPowerOff})

	// Use a short ctx so we don't wait the default 2s for the RPC.
	timed, cancel := context.WithTimeout(f.ctx, 100*time.Millisecond)
	defer cancel()
	sc.Ctx = timed
	if _, err := step(sc); err != nil {
		t.Fatalf("record (should swallow status err): %v", err)
	}
	got, _ := f.store.Get(f.ctx, "n2")
	if got == nil {
		t.Fatal("expected row")
	}
	if got.PowerState != proto.BMCStateUnknown {
		t.Errorf("PowerState: want unknown, got %q", got.PowerState)
	}
}

func TestPowerRecord_BadSpec(t *testing.T) {
	f := newFixture(t)
	step := powerRecord(f.svc)
	sc := stepCtx(f.ctx, f.nc, map[string]string{}) // missing fields
	if _, err := step(sc); err == nil {
		t.Error("want spec parse error")
	}
}

func TestPowerDispatch_BadSpec(t *testing.T) {
	f := newFixture(t)
	step := powerDispatch(f.svc)
	sc := stepCtx(f.ctx, f.nc, map[string]string{})
	if _, err := step(sc); err == nil {
		t.Error("want spec parse error")
	}
}
