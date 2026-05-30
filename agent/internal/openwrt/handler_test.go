package openwrt

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// startNATS spins up an in-process NATS server on a random port and returns
// a connected client. Both shut down on test cleanup.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	opts := &natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
	}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("nats new server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(2 * time.Second) {
		t.Fatal("nats not ready in 2s")
	}
	t.Cleanup(func() {
		ns.Shutdown()
		ns.WaitForShutdown()
	})
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func request[T any](t *testing.T, nc *nats.Conn, subj string, cmd any, out *T) {
	t.Helper()
	payload, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg, err := nc.Request(subj, payload, 2*time.Second)
	if err != nil {
		t.Fatalf("request %s: %v", subj, err)
	}
	if err := json.Unmarshal(msg.Data, out); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
}

func TestRegisterHandlers_ApplyHappyPath(t *testing.T) {
	nc := startNATS(t)
	mc, err := NewMockClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockClient: %v", err)
	}
	subs, err := RegisterHandlers(nc, "node-1", mc)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	state := map[string]any{
		"firewall": map[string]any{
			"redirect": []map[string]any{
				{"wan_port": 8080, "lan_host": "10.0.0.5", "lan_port": 80, "proto": "tcp"},
			},
		},
	}
	var ack proto.FirewallApplyAck
	request(t, nc, proto.FirewallApplySubject("node-1"), proto.FirewallApplyCmd{
		State:      state,
		IntentHash: "irrelevant",
	}, &ack)
	if !ack.OK {
		t.Errorf("ack OK=false: %+v", ack)
	}
	if ack.Hash == "" {
		t.Error("expected non-empty hash")
	}

	// Mock store should now contain the applied state — Get returns matching hash.
	got, hash2, err := mc.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if hash2 != ack.Hash {
		t.Errorf("get hash %q != apply hash %q", hash2, ack.Hash)
	}
	if got == nil || got["firewall"] == nil {
		t.Errorf("state: %+v", got)
	}
}

func TestRegisterHandlers_ApplyBadCmd(t *testing.T) {
	nc := startNATS(t)
	mc, err := NewMockClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockClient: %v", err)
	}
	subs, err := RegisterHandlers(nc, "node-1", mc)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	msg, err := nc.Request(proto.FirewallApplySubject("node-1"), []byte("not-json"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.FirewallApplyAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.OK {
		t.Error("expected OK=false on bad cmd")
	}
}

func TestRegisterHandlers_GetReturnsEmptyOnFreshAgent(t *testing.T) {
	nc := startNATS(t)
	mc, err := NewMockClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockClient: %v", err)
	}
	subs, err := RegisterHandlers(nc, "node-1", mc)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	var ack proto.FirewallGetAck
	request(t, nc, proto.FirewallGetSubject("node-1"), proto.FirewallGetCmd{}, &ack)
	if ack.Hash == "" {
		t.Error("expected hash even on fresh agent (empty state)")
	}
	if ack.State == nil {
		t.Error("State should not be nil")
	}
}

// errClient errors from both methods to drive the handlers' failure branches.
type errClient struct{}

func (errClient) Apply(_ context.Context, _ map[string]any) (string, error) {
	return "", errStr("boom")
}
func (errClient) Get(_ context.Context) (map[string]any, string, error) {
	return nil, "", errStr("boom")
}

type errStr string

func (e errStr) Error() string { return string(e) }

func TestRegisterHandlers_ApplyClientError(t *testing.T) {
	nc := startNATS(t)
	subs, err := RegisterHandlers(nc, "node-1", errClient{})
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	var ack proto.FirewallApplyAck
	request(t, nc, proto.FirewallApplySubject("node-1"), proto.FirewallApplyCmd{
		State: map[string]any{},
	}, &ack)
	if ack.OK {
		t.Error("expected OK=false on client error")
	}
}

func TestRegisterHandlers_GetClientError(t *testing.T) {
	nc := startNATS(t)
	subs, err := RegisterHandlers(nc, "node-1", errClient{})
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	var ack proto.FirewallGetAck
	request(t, nc, proto.FirewallGetSubject("node-1"), proto.FirewallGetCmd{}, &ack)
	// Handler returns an empty-but-non-nil state on error so the api can
	// distinguish from "absent" — see handler.handleGet.
	if ack.State == nil {
		t.Error("State should not be nil on error path")
	}
	if ack.Hash != "" {
		t.Errorf("Hash on error: %q want empty", ack.Hash)
	}
}
