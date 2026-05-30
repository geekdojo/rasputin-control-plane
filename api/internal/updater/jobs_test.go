package updater

import (
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// embeddedNATS spins up an in-process NATS server (no JetStream needed) and
// returns a connection. Tests use it just to exercise publish-only helpers
// — exercising the RPC sagas would require a full agent responder, which is
// out of scope here.
func embeddedNATS(t *testing.T) *nats.Conn {
	t.Helper()
	opts := &server.Options{
		Host:   "127.0.0.1",
		Port:   -1, // ephemeral
		NoLog:  true,
		NoSigs: true,
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

func TestPublishChange_DoesNotCrash(t *testing.T) {
	nc := embeddedNATS(t)
	// Subscribe so the publish has somewhere to land.
	sub, err := nc.SubscribeSync(proto.UpdateChangeSubject("n", proto.UpdateStarted))
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	publishChange(nc, proto.UpdateChangeEvt{
		NodeID:   "n",
		JobID:    "j",
		BundleID: "b",
		Change:   proto.UpdateStarted,
		Ts:       time.Now().UTC(),
	})
	msg, err := sub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("NextMsg: %v", err)
	}
	if len(msg.Data) == 0 {
		t.Error("empty payload")
	}
}

func TestPublishSystemChange_DoesNotCrash(t *testing.T) {
	nc := embeddedNATS(t)
	sub, _ := nc.SubscribeSync(proto.SystemUpdateChangeSubject("parent-1", proto.SystemUpdatePlanned))
	defer sub.Unsubscribe()

	publishSystemChange(nc, proto.SystemUpdateChangeEvt{
		ParentJobID: "parent-1",
		Change:      proto.SystemUpdatePlanned,
		Ts:          time.Now().UTC(),
	})
	if _, err := sub.NextMsg(time.Second); err != nil {
		t.Fatalf("NextMsg: %v", err)
	}
}

// ============================================================================
// Workflow constructors don't crash and return the expected kinds.
// ============================================================================

func TestUpdateWorkflow_Kind(t *testing.T) {
	wf := UpdateWorkflow(nil, nil, nil, Config{})
	if wf.Kind != "node.update" {
		t.Errorf("kind: %q", wf.Kind)
	}
	if len(wf.Steps) != 7 {
		t.Errorf("steps: want 7, got %d", len(wf.Steps))
	}
}

func TestSystemUpdateWorkflow_Kind(t *testing.T) {
	wf := SystemUpdateWorkflow(nil, nil, nil, nil, nil, SystemUpdateConfig{})
	if wf.Kind != "system.update" {
		t.Errorf("kind: %q", wf.Kind)
	}
	if len(wf.Steps) != 3 {
		t.Errorf("steps: want 3, got %d", len(wf.Steps))
	}
}
