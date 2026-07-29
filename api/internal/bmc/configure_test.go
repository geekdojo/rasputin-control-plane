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
	a := ConfigHash("mock", json.RawMessage(`{"targets":["a"]}`), "")
	b := ConfigHash("mock", json.RawMessage(`{"targets":["a"]}`), "")
	c := ConfigHash("mock", json.RawMessage(`{"targets":["b"]}`), "")
	d := ConfigHash("bitscope", json.RawMessage(`{"targets":["a"]}`), "")
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

	if _, err := configurePush(st)(stepCtx(f.ctx, f.nc, spec)); err != nil {
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
	_, err = configurePush(newSetupStore(t))(stepCtx(f.ctx, f.nc, spec))
	if err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Errorf("pin nack must surface as a typed failure: %v", err)
	}
}

func TestConfigureWorkflow_StepTimeouts(t *testing.T) {
	// The push budget must absorb a real backend swap (serial open +
	// unlock + re-register); validate/record are local. Pin the numbers.
	f := newFixture(t)
	wf := ConfigureWorkflow(f.svc, newInvStore(t), newSetupStore(t), NewSessionManager(f.svc), nil)
	if wf.Kind != "bmc.configure" || len(wf.Steps) != 3 {
		t.Fatalf("workflow shape: %s / %d steps", wf.Kind, len(wf.Steps))
	}
	want := []time.Duration{3 * time.Second, 15 * time.Second, 3 * time.Second}
	for i, step := range wf.Steps {
		if step.Timeout != want[i] {
			t.Errorf("step %s timeout %v, want %v", step.Name, step.Timeout, want[i])
		}
	}
}

func TestConfigurePush_InjectsUnlockBusSideOnly(t *testing.T) {
	// Security contract (review on CP #34): the job spec never carries
	// the bitscope unlock; the push step injects the stored secret into
	// the bus command at dispatch time only.
	f := newFixture(t)
	st := newSetupStore(t)
	if err := st.Set(f.ctx, setup.KeyBMCBitscopeUnlock, "s3kr1t"); err != nil {
		t.Fatal(err)
	}

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

	spec := ConfigureSpec{Kind: "bitscope", HostNodeID: "host-1",
		Config: json.RawMessage(`{"targets":[{"pos":"A-0","node_id":"n0"}]}`), ConfigHash: "h1"}
	if strings.Contains(string(spec.Config), "s3kr1t") {
		t.Fatal("test setup: spec must not contain the secret")
	}
	if _, err := configurePush(st)(stepCtx(f.ctx, f.nc, spec)); err != nil {
		t.Fatalf("push: %v", err)
	}
	var pushed map[string]any
	if err := json.Unmarshal(got.Config, &pushed); err != nil {
		t.Fatal(err)
	}
	if pushed["unlock"] != "s3kr1t" {
		t.Errorf("bus command must carry the unlock, got %v", pushed)
	}
}

func TestInjectJSONField(t *testing.T) {
	out, err := injectJSONField(json.RawMessage(`{"a":1}`), "unlock", "x")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["unlock"] != "x" || m["a"] != float64(1) {
		t.Errorf("inject: %v", m)
	}
	if _, err := injectJSONField(json.RawMessage(`not-json`), "unlock", "x"); err == nil {
		t.Error("bad json must error")
	}
}

func TestStartReconcile_SubscribesAndSubmits(t *testing.T) {
	// End-to-end through the real subscription: a stale host
	// registration event reaches the reconciler and submits a job.
	f := newFixture(t)
	st := newSetupStore(t)
	desiredMock(t, st)
	submitted := make(chan string, 1)
	stop, err := StartReconcile(f.nc, st,
		func(context.Context) (bool, error) { return false, nil },
		func(_ context.Context, kind string, _ json.RawMessage, _ string) error {
			submitted <- kind
			return nil
		})
	if err != nil || stop == nil {
		t.Fatalf("StartReconcile: stop-nil=%t err=%v", stop == nil, err)
	}
	defer stop()

	if err := f.nc.Publish(proto.NodeRegisteredSubject("host-1"), regEvt(t, "host-1", nil)); err != nil {
		t.Fatal(err)
	}
	select {
	case kind := <-submitted:
		if kind != "bmc.configure" {
			t.Errorf("submitted %q", kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no reconcile submit after stale registration")
	}
}

// The Settings picker lists turingpi as an available backend, so
// ValidateSelection has to accept a well-formed turingpi config. It did
// not until 2026-07-28 — the picker offered a kind that selectionTargets
// had no case for, so choosing it returned `no config schema for backend
// "turingpi"` and the only way to enable this BMC was editing node.env
// over SSH. The whole hardware bench ran on the env pin, which by S-4
// freezes the selection and makes Settings decline to manage it, so the
// gap could not surface there.
func TestTuringPiSelectionAccepted(t *testing.T) {
	good := `{"endpoint":"turingpi.local","user":"root","fingerprint":"41:7C:1E:EA","targets":[{"node_id":"cp-1","slot":1},{"node_id":"n-1","slot":2}]}`
	ids, err := selectionTargets("turingpi", json.RawMessage(good))
	if err != nil {
		t.Fatalf("a well-formed turingpi config must validate: %v", err)
	}
	if len(ids) != 2 || ids[0] != "cp-1" || ids[1] != "n-1" {
		t.Errorf("targets = %v, want [cp-1 n-1]", ids)
	}
}

// Each rejection names the field an operator has to fix. The TLS one is
// deliberate rather than defaulted: the board's certificate is minted at
// the epoch and permanently expired, so CA trust can never pass and a
// silent default would mean silently unverified.
func TestTuringPiSelectionRejections(t *testing.T) {
	for _, tc := range []struct{ name, cfg, want string }{
		{"no endpoint", `{"user":"root","fingerprint":"x","targets":[{"node_id":"a","slot":1}]}`, "endpoint is required"},
		{"no user", `{"endpoint":"e","fingerprint":"x","targets":[{"node_id":"a","slot":1}]}`, "username is required"},
		{"no tls choice", `{"endpoint":"e","user":"root","targets":[{"node_id":"a","slot":1}]}`, "pin the BMC certificate"},
		{"slot out of range", `{"endpoint":"e","user":"root","fingerprint":"x","targets":[{"node_id":"a","slot":9}]}`, "want 1..4"},
		{"duplicate slot", `{"endpoint":"e","user":"root","fingerprint":"x","targets":[{"node_id":"a","slot":1},{"node_id":"b","slot":1}]}`, "both claim slot 1"},
	} {
		_, err := selectionTargets("turingpi", json.RawMessage(tc.cfg))
		if err == nil {
			t.Errorf("%s: should have been rejected", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q should mention %q", tc.name, err, tc.want)
		}
	}
	// insecure_skip_verify is an explicit alternative to pinning.
	if _, err := selectionTargets("turingpi", json.RawMessage(
		`{"endpoint":"e","user":"root","insecure_skip_verify":true,"targets":[{"node_id":"a","slot":1}]}`)); err != nil {
		t.Errorf("explicit insecure opt-in should validate: %v", err)
	}
}

// No backend's credential may sit in the config blob — job specs and step
// results are served unredacted by the jobs API. The kind->credential
// table replaced four hardcoded `kind == "bitscope"` checks; this pins
// that bitscope kept its exact behaviour and that turingpi joined it.
func TestBackendCredentialsTable(t *testing.T) {
	bs, ok := CredentialFor("bitscope")
	if !ok || bs.Field != "unlock" || bs.SettingsKey != setup.KeyBMCBitscopeUnlock {
		t.Errorf("bitscope credential = %+v, ok=%v — must stay unlock/%s", bs, ok, setup.KeyBMCBitscopeUnlock)
	}
	tp, ok := CredentialFor("turingpi")
	if !ok || tp.Field != "pass" || tp.SettingsKey != setup.KeyBMCTuringPiPass {
		t.Errorf("turingpi credential = %+v, ok=%v", tp, ok)
	}
	if _, ok := CredentialFor("mock"); ok {
		t.Error("mock has no credential and must not claim one")
	}
	if bs.SettingsKey == tp.SettingsKey {
		t.Error("each backend's credential needs its own settings key")
	}
}
