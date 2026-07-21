package bmc

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

func newSetupStore(t *testing.T) *setup.Store {
	t.Helper()
	st, err := setup.OpenStore(context.Background(), filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatalf("setup store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func insertNode(t *testing.T, f *fixture, inv *inventory.Store, id string) {
	t.Helper()
	if err := inv.Insert(f.ctx, &proto.Node{
		ID: id, Role: proto.RoleCompute, Hostname: id + ".local",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigHash_Deterministic(t *testing.T) {
	a := ConfigHash("mock", json.RawMessage(`{"targets":["a"]}`))
	b := ConfigHash("mock", json.RawMessage(`{"targets":["a"]}`))
	c := ConfigHash("mock", json.RawMessage(`{"targets":["b"]}`))
	d := ConfigHash("bitscope", json.RawMessage(`{"targets":["a"]}`))
	if a != b {
		t.Error("same input must hash equal")
	}
	if a == c || a == d {
		t.Error("different config or kind must hash different")
	}
}

func TestValidateSelection(t *testing.T) {
	f := newFixture(t)
	inv := newInvStore(t)
	insertNode(t, f, inv, "node-1")

	if err := ValidateSelection(f.ctx, inv, "none", nil); err != nil {
		t.Errorf("none: %v", err)
	}
	if err := ValidateSelection(f.ctx, inv, "mock", json.RawMessage(`{"targets":["node-1"]}`)); err != nil {
		t.Errorf("valid mock: %v", err)
	}
	if err := ValidateSelection(f.ctx, inv, "turingpi", json.RawMessage(`{}`)); err == nil {
		t.Error("planned kind must be rejected")
	}
	if err := ValidateSelection(f.ctx, inv, "mock", json.RawMessage(`{"targets":["ghost"]}`)); err == nil {
		t.Error("unregistered target must be rejected")
	}
	if err := ValidateSelection(f.ctx, inv, "mock", json.RawMessage(`{"targets":[]}`)); err == nil {
		t.Error("empty targets must be rejected")
	}
	if err := ValidateSelection(f.ctx, inv, "mock", json.RawMessage(`{"targets":["node-1","node-1"]}`)); err == nil {
		t.Error("duplicate targets must be rejected")
	}
	if err := ValidateSelection(f.ctx, inv, "bitscope", json.RawMessage(`{"targets":[{"pos":"A-0","node_id":"node-1"}]}`)); err != nil {
		t.Errorf("valid bitscope: %v", err)
	}
}

func TestConfigureValidate_RefusesBusyBus(t *testing.T) {
	f := newFixture(t)
	inv := newInvStore(t)
	insertNode(t, f, inv, "host-1")
	insertNode(t, f, inv, "node-1")
	spec := ConfigureSpec{Kind: "mock", HostNodeID: "host-1",
		Config: json.RawMessage(`{"targets":["node-1"]}`), ConfigHash: "h"}

	sessions := NewSessionManager(f.svc)
	busy := func(context.Context) (bool, error) { return true, nil }
	step := configureValidate(inv, sessions, busy)
	if _, err := step(stepCtx(f.ctx, f.nc, spec)); err == nil || !strings.Contains(err.Error(), "bmc.power") {
		t.Errorf("running power job must refuse: %v", err)
	}

	idle := func(context.Context) (bool, error) { return false, nil }
	step = configureValidate(inv, sessions, idle)
	if _, err := step(stepCtx(f.ctx, f.nc, spec)); err != nil {
		t.Errorf("idle bus must validate: %v", err)
	}
}

func TestConfigurePushAndRecord(t *testing.T) {
	f := newFixture(t)
	st := newSetupStore(t)

	// Fake host agent: ack the configure push, echoing the hash.
	var got proto.BMCConfigureCmd
	sub, err := f.nc.Subscribe(proto.BMCConfigureSubject("host-1"), func(m *nats.Msg) {
		_ = json.Unmarshal(m.Data, &got)
		ack, _ := json.Marshal(proto.BMCConfigureAck{OK: true, ConfigHash: got.ConfigHash})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	spec := ConfigureSpec{Kind: "mock", HostNodeID: "host-1",
		Config: json.RawMessage(`{"targets":["node-1"]}`), ConfigHash: "h42"}

	if _, err := configurePush()(stepCtx(f.ctx, f.nc, spec)); err != nil {
		t.Fatalf("push: %v", err)
	}
	if got.Kind != "mock" || got.ConfigHash != "h42" {
		t.Errorf("agent received %+v", got)
	}

	if _, err := configureRecord(st)(stepCtx(f.ctx, f.nc, spec)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if v, _ := st.Get(f.ctx, setup.KeyBMCBackend); v != "mock" {
		t.Errorf("bmc.backend: %q", v)
	}
	if v, _ := st.Get(f.ctx, setup.KeyBMCHostNode); v != "host-1" {
		t.Errorf("bmc.host_node_id: %q", v)
	}
	if v, _ := st.Get(f.ctx, setup.KeyBMCConfig); v != `{"targets":["node-1"]}` {
		t.Errorf("bmc.config: %q", v)
	}

	// Deconfigure clears backend + config but keeps the host choice.
	none := ConfigureSpec{Kind: "none", HostNodeID: "host-1"}
	if _, err := configureRecord(st)(stepCtx(f.ctx, f.nc, none)); err != nil {
		t.Fatalf("record none: %v", err)
	}
	if v, _ := st.Get(f.ctx, setup.KeyBMCBackend); v != "" {
		t.Errorf("bmc.backend after none: %q", v)
	}
}

func TestConfigurePush_HostRefusalIsTyped(t *testing.T) {
	f := newFixture(t)
	sub, err := f.nc.Subscribe(proto.BMCConfigureSubject("host-1"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.BMCConfigureAck{OK: false, Detail: "pinned by RASPUTIN_BMC_BACKEND"})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	spec := ConfigureSpec{Kind: "mock", HostNodeID: "host-1", Config: json.RawMessage(`{}`), ConfigHash: "h"}
	_, err = configurePush()(stepCtx(f.ctx, f.nc, spec))
	if err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Errorf("pin nack must surface as a typed failure: %v", err)
	}
}
