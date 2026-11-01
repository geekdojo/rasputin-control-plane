package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// healthCountingStore counts the store's sys/health reads and forwards
// everything.
type healthCountingStore struct {
	secretStore
	health atomic.Int32
}

func (c *healthCountingStore) Health(ctx context.Context) (secretstore.Health, error) {
	c.health.Add(1)
	return c.secretStore.Health(ctx)
}

// TC-939-02: the composition root's wiring feeds the store-health counter
// from both places audited calls are observed: the observed store's KV calls
// and the store session's logins.
func TestStoreHealthWiring_TC_939_02_BothCallSitesFeedTheCounts(t *testing.T) {
	log, _ := logkittest.New()
	m := secretstore.NewMock(time.Now)
	p, err := secretstore.NewKVPath("rasputin-secrets", "apps/health")
	if err != nil {
		t.Fatal(err)
	}
	// Seeded straight into the mock, not through the wiring, so it is not
	// counted and the reads below answer nil.
	if _, err := m.Write(t.Context(), secret.Value{}, p, map[string]secret.Value{"k": secret.New([]byte("v"))}, 0); err != nil {
		t.Fatal(err)
	}
	r, err := storeReadinessWiring(storeModeMock, false, storeModeMock, m, openJobStore(t), time.Now, notBlank, log)
	if err != nil {
		t.Fatal(err)
	}
	if r.counter == nil {
		t.Fatal("readiness wiring has no counter with a backend requested")
	}

	// One KV read through the observed store.
	if _, err := r.store.Read(t.Context(), secret.Value{}, p, 0); err != nil {
		t.Fatalf("observed read: %v", err)
	}
	if got := r.counter.Counts(); got != (storestate.Counts{Requests: 1}) {
		t.Fatalf("after one observed read: counts %+v, want {Requests:1}", got)
	}

	// The session's first call logs in (counted at the session) and then
	// reads through the same observed store (counted there).
	sess, err := storeSessionWiring(m, r.store, r.observer, log)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Read(t.Context(), p, 0); err != nil {
		t.Fatalf("session read: %v", err)
	}
	if got := r.counter.Counts(); got != (storestate.Counts{Requests: 3}) {
		t.Fatalf("after a login and a second read: counts %+v, want {Requests:3} (the login counted)", got)
	}
}

// TC-939-11: obsFanout returns the store-health decorator only with a store
// to read and a self node id; otherwise the bare VM sink and one INFO naming
// why. The switch mustWireObs returns, which boot and obs.enable/disable
// share, installs that same value on, and nothing off.
func TestStoreHealthWiring_TC_939_11_ObsFanout(t *testing.T) {
	vm := testVMSink(t)
	withStore := func(t *testing.T) readinessWiring {
		log, _ := logkittest.New()
		r, err := storeReadinessWiring(storeModeMock, false, storeModeMock, secretstore.NewMock(time.Now), openJobStore(t), time.Now, notBlank, log)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	t.Run("store and self id: the decorator", func(t *testing.T) {
		h := &recordsHandler{}
		got := obsFanout(vm, withStore(t), "cp-1", t.TempDir(), slog.New(h))
		if _, ok := got.(*obs.StoreHealthSink); !ok {
			t.Fatalf("obsFanout = %T, want *obs.StoreHealthSink", got)
		}
		if recs := h.matching(slog.LevelInfo, "store health metrics off"); len(recs) != 0 {
			t.Errorf("records %v, want no \"store health metrics off\"", recs)
		}
	})
	for _, tc := range []struct {
		name, self, reason string
		r                  func(t *testing.T) readinessWiring
	}{
		{"no store backend", "cp-1", "no store backend", func(*testing.T) readinessWiring { return readinessWiring{} }},
		{"no self node id", "", "no self node id", withStore},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &recordsHandler{}
			got := obsFanout(vm, tc.r(t), tc.self, t.TempDir(), slog.New(h))
			if got != metrics.Sink(vm) {
				t.Fatalf("obsFanout = %T, want the bare *obs.VMSink", got)
			}
			recs := h.matching(slog.LevelInfo, "store health metrics off")
			if len(recs) != 1 {
				t.Fatalf("%d records, want exactly one INFO \"store health metrics off\"", len(recs))
			}
			attrs := map[string]string{}
			recs[0].Attrs(func(a slog.Attr) bool { attrs[a.Key] = a.Value.String(); return true })
			if attrs["reason"] != tc.reason {
				t.Errorf("reason = %q, want %q", attrs["reason"], tc.reason)
			}
		})
	}

	t.Run("the switch installs the fanout's result on and nil off", func(t *testing.T) {
		t.Setenv("RASPUTIN_OBS_STATE_DIR", "")
		dataDir := t.TempDir()
		set := &recordingSetter{}
		var built metrics.Sink
		fanout := func(vm *obs.VMSink) metrics.Sink {
			built = obsFanout(vm, withStore(t), "cp-1", t.TempDir(), slog.New(&recordsHandler{}))
			return built
		}
		off := func(context.Context) (bool, error) { return false, nil }
		_, setSink, _ := mustWireObs(context.Background(), slog.New(&recordsHandler{}), dataDir, "cp-1", set,
			filepath.Join(dataDir, "obs", "ids-alerts"), storeModeMock, off, fanout)
		if _, ok := built.(*obs.StoreHealthSink); !ok {
			t.Fatalf("fanout built %T, want *obs.StoreHealthSink", built)
		}
		if n := len(set.calls()); n != 0 {
			t.Fatalf("obs off at boot installed %d sinks, want none", n)
		}
		setSink(true) // obs.enable's fan_out step
		setSink(false)
		calls := set.calls()
		if len(calls) != 2 || calls[0] != built || calls[1] != nil {
			t.Fatalf("SetSink calls = %v, want [the fanout's result, nil]", calls)
		}
	})
}

// TC-939-12: only while observability is on is the store read for metrics.
// The real metrics.Service on a real bus: with obs off at boot no sink is
// installed and the control plane's own sample causes no sys/health read;
// enabled, it causes one; disabled again, none.
func TestStoreHealthWiring_TC_939_12_OnlyWhileObsIsOn(t *testing.T) {
	t.Setenv("RASPUTIN_OBS_STATE_DIR", "")
	// Nothing listens here, so the VM sink's own write fails fast and the
	// test reaches no VictoriaMetrics.
	t.Setenv("RASPUTIN_OBS_VM_LISTEN", "127.0.0.1:1")
	log, _ := logkittest.New()
	store := &healthCountingStore{secretStore: secretstore.NewMock(time.Now)}
	r, err := storeReadinessWiring(storeModeMock, false, storeModeMock, store, openJobStore(t), time.Now, notBlank, log)
	if err != nil {
		t.Fatal(err)
	}

	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	mstore, err := metrics.OpenStore(context.Background(), filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mstore.Close() })
	svc := metrics.NewService(mstore, nc)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Stop)

	dataDir := t.TempDir()
	var fan *obs.StoreHealthSink
	fanout := func(vm *obs.VMSink) metrics.Sink {
		s := obsFanout(vm, r, "cp-1", filepath.Join(dataDir, "openbao"), log)
		fan, _ = s.(*obs.StoreHealthSink)
		return s
	}
	off := func(context.Context) (bool, error) { return false, nil }
	_, setSink, _ := mustWireObs(context.Background(), log, dataDir, "cp-1", svc,
		filepath.Join(dataDir, "obs", "ids-alerts"), storeModeMock, off, fanout)
	if fan == nil {
		t.Fatal("the fanout is not the store-health decorator")
	}

	// handled publishes the control plane's sample and then a marker from
	// another node, and waits for the marker's row: the subscription handles
	// messages in order, so by then the control plane's sample has been
	// through the sink (or found none).
	handled := func(t *testing.T) {
		t.Helper()
		ts := time.Now().UTC().Truncate(time.Millisecond)
		publish(t, nc, "cp-1", ts)
		publish(t, nc, "marker", ts)
		waitFor(t, "the marker sample stored", func() bool {
			s, err := mstore.Query(context.Background(), "marker", nil, ts, ts)
			return err == nil && len(s.Series[proto.MetricCPUPercent]) > 0
		})
	}

	handled(t)
	if n := store.health.Load(); n != 0 {
		t.Fatalf("obs off: sys/health reads = %d, want 0", n)
	}

	setSink(true)
	handled(t)
	waitFor(t, "one sys/health read after enable", func() bool { return store.health.Load() == 1 })
	fan.Wait()

	setSink(false)
	handled(t)
	if n := store.health.Load(); n != 1 {
		t.Fatalf("after disable: sys/health reads = %d, want still 1", n)
	}
}

func publish(t *testing.T, nc *nats.Conn, node string, ts time.Time) {
	t.Helper()
	b, err := json.Marshal(proto.MetricsEvt{NodeID: node, Ts: ts, Metrics: map[string]float64{proto.MetricCPUPercent: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Publish(proto.NodeMetricsSubject(node), b); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
}

// waitFor polls cond, the fact the step waits on; the deadline bounds only
// how long an in-process bus and SQLite may take.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// recordingSetter records each SetSink call.
type recordingSetter struct {
	mu  sync.Mutex
	got []metrics.Sink
}

func (r *recordingSetter) SetSink(s metrics.Sink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, s)
}

func (r *recordingSetter) calls() []metrics.Sink {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]metrics.Sink(nil), r.got...)
}

// testVMSink is a VM sink over a supervisor that never runs.
func testVMSink(t *testing.T) *obs.VMSink {
	t.Helper()
	sup, err := obs.NewDockerComposeSupervisor(obs.DockerComposeSupervisorConfig{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	vm, err := obs.NewVMSink(obs.VMSinkConfig{Supervisor: sup})
	if err != nil {
		t.Fatal(err)
	}
	return vm
}
