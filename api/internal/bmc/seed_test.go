package bmc

import (
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// fakeHostStatus answers power.status RPCs for a host, reporting the
// given per-target states and counting queries.
func fakeHostStatus(t *testing.T, f *fixture, hostID string, states map[string]proto.BMCPowerState, count *atomic.Int64) {
	t.Helper()
	sub, err := f.nc.Subscribe(proto.BMCPowerSubject(hostID, proto.BMCPowerQuery), func(m *nats.Msg) {
		count.Add(1)
		var cmd proto.BMCPowerCmd
		_ = json.Unmarshal(m.Data, &cmd)
		st, ok := states[cmd.TargetNodeID]
		ack, _ := json.Marshal(proto.BMCPowerAck{OK: ok, State: st, Detail: "seeded"})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
}

func publishHostRegistered(t *testing.T, f *fixture, hostID string, targets []string) {
	t.Helper()
	ts := make([]any, 0, len(targets))
	for _, tg := range targets {
		ts = append(ts, tg)
	}
	buf, err := json.Marshal(proto.NodeRegisteredEvt{
		NodeID:   hostID,
		Metadata: map[string]any{proto.MetadataBMCTargets: ts},
		Ts:       time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.nc.Publish(proto.NodeRegisteredSubject(hostID), buf); err != nil {
		t.Fatal(err)
	}
}

func waitForState(t *testing.T, f *fixture, target string, want proto.BMCPowerState) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ns, err := f.store.Get(f.ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		if ns != nil && ns.PowerState == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s state for %s within budget", want, target)
}

func TestStatusSeed_SweepsAdvertisedTargets(t *testing.T) {
	f := newFixture(t)
	var count atomic.Int64
	fakeHostStatus(t, f, "host-1",
		map[string]proto.BMCPowerState{"n1": proto.BMCStateOn, "n2": proto.BMCStateOff}, &count)

	// Watch for the read-only change events too.
	events := make(chan string, 8)
	esub, err := f.nc.Subscribe(proto.AllBMCChangesFilter, func(m *nats.Msg) {
		var ev proto.BMCChangeEvt
		if json.Unmarshal(m.Data, &ev) == nil && ev.Change == proto.BMCStatusChecked {
			events <- ev.TargetNodeID
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = esub.Unsubscribe() }()

	stop, err := StartStatusSeed(f.nc, f.svc)
	if err != nil {
		t.Fatalf("StartStatusSeed: %v", err)
	}
	defer stop()

	publishHostRegistered(t, f, "host-1", []string{"n1", "n2"})
	waitForState(t, f, "n1", proto.BMCStateOn)
	waitForState(t, f, "n2", proto.BMCStateOff)

	got := map[string]bool{}
	timeout := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case id := <-events:
			got[id] = true
		case <-timeout:
			t.Fatalf("status_checked events missing, got %v", got)
		}
	}
}

func TestStatusSeed_DebouncesRegistrationBursts(t *testing.T) {
	f := newFixture(t)
	var count atomic.Int64
	fakeHostStatus(t, f, "host-1",
		map[string]proto.BMCPowerState{"n1": proto.BMCStateOn}, &count)

	stop, err := StartStatusSeed(f.nc, f.svc)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	publishHostRegistered(t, f, "host-1", []string{"n1"})
	waitForState(t, f, "n1", proto.BMCStateOn)

	// A reconnect burst: the sweep just finished, so these are inside
	// the debounce window and must not re-query.
	publishHostRegistered(t, f, "host-1", []string{"n1"})
	publishHostRegistered(t, f, "host-1", []string{"n1"})
	time.Sleep(300 * time.Millisecond)
	if n := count.Load(); n != 1 {
		t.Errorf("queries: want 1 (debounced), got %d", n)
	}
}

func TestStatusSeed_IgnoresNonHostRegistrations(t *testing.T) {
	f := newFixture(t)
	var count atomic.Int64
	fakeHostStatus(t, f, "host-1", map[string]proto.BMCPowerState{}, &count)

	stop, err := StartStatusSeed(f.nc, f.svc)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	// No bmc-targets metadata → not a host → no sweep.
	buf, _ := json.Marshal(proto.NodeRegisteredEvt{NodeID: "worker-7", Ts: time.Now().UTC()})
	if err := f.nc.Publish(proto.NodeRegisteredSubject("worker-7"), buf); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := count.Load(); n != 0 {
		t.Errorf("queries: want 0, got %d", n)
	}
}

func TestStatusSeed_PerTargetFailureSkips(t *testing.T) {
	// One target unmapped (host nacks) — the rest still seed.
	f := newFixture(t)
	var count atomic.Int64
	fakeHostStatus(t, f, "host-1",
		map[string]proto.BMCPowerState{"n2": proto.BMCStateOn}, &count) // n1 → OK:false

	stop, err := StartStatusSeed(f.nc, f.svc)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	publishHostRegistered(t, f, "host-1", []string{"n1", "n2"})
	waitForState(t, f, "n2", proto.BMCStateOn)
	ns, err := f.store.Get(f.ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if ns != nil {
		t.Errorf("n1 must have no row after a nacked query, got %+v", ns)
	}
}
