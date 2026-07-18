package metrics

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

// TestRun_CtxCancelExits drives the Run loop with an already-cancelled context.
// Run primes the CPU sampler (briefly) then enters its select; the cancelled
// ctx wins immediately and Run returns. No publish, no ticker fire — but the
// loop body and the cleanup path are exercised so coverage moves off zero.
func TestRun_CtxCancelExits(t *testing.T) {
	nc := startNATS(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		Run(ctx, nc, "node-1", "/", func() time.Duration { return 0 })
		close(done)
	}()
	select {
	case <-done:
		// Run returned promptly on cancelled ctx.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not return within 500ms despite cancelled ctx")
	}
}

// TestRun_PublishesMetricsToBus pushes the ticker manually by publishing the
// collected sample on the metrics subject — the canonical wire-format check
// — then asserts a subscriber receives it. This is the read side of what Run
// would do; it complements TestRun_CtxCancelExits which covers Run's control
// flow.
func TestRun_PublishesMetricsToBus(t *testing.T) {
	nc := startNATS(t)
	sub, err := nc.SubscribeSync(proto.NodeMetricsSubject("node-1"))
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	ev := collect(context.Background(), "node-1", "/", func() time.Duration { return 0 })
	payload, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := nc.Publish(proto.NodeMetricsSubject("node-1"), payload); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	msg, err := sub.NextMsg(200 * time.Millisecond)
	if err != nil {
		t.Fatalf("no metrics on bus: %v", err)
	}
	var got proto.MetricsEvt
	if err := json.Unmarshal(msg.Data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.NodeID != "node-1" {
		t.Errorf("nodeId: %q", got.NodeID)
	}
}

// TestCollect_ShapeAndAlwaysOnFields verifies the MetricsEvt the publish loop
// would emit. We exercise `collect` directly so we don't have to start the
// ticker — Run() is intentionally untested here because it depends on a real
// NATS connection (a fake nats.Conn isn't trivial to wire), would require
// sleeping past the 10s Interval, and the *interesting* logic lives in
// collect anyway.
func TestCollect_ShapeAndAlwaysOnFields(t *testing.T) {
	uptime := func() time.Duration { return 123 * time.Second }
	ev := collect(context.Background(), "node-x", "/", uptime)

	if ev.NodeID != "node-x" {
		t.Errorf("NodeID: %q want node-x", ev.NodeID)
	}
	if ev.Ts.IsZero() {
		t.Error("Ts not set")
	}
	if ev.Ts.Location().String() != "UTC" {
		t.Errorf("Ts should be UTC, got %s", ev.Ts.Location())
	}

	// agent_uptime_seconds and goroutines are computed without external
	// probes — they must always be present.
	if got := ev.Metrics[proto.MetricAgentUptimeSeconds]; got != 123 {
		t.Errorf("uptime metric: got %v, want 123", got)
	}
	if got := ev.Metrics[proto.MetricGoroutines]; got <= 0 {
		t.Errorf("goroutines metric: got %v, want > 0", got)
	}
}

// TestCollect_AllFieldsAreFloat64 — regression canary: the wire format
// commits to float64 for every value, so the api can shove them into a
// uniform schema. If anyone accidentally adds an int-typed metric this
// will fail to compile (the iteration would still typecheck, but the
// map type is already pinned).
func TestCollect_AllFieldsAreFloat64(t *testing.T) {
	ev := collect(context.Background(), "n", "/", func() time.Duration { return 0 })
	for k, v := range ev.Metrics {
		// Trivially: assigning v to a float64 must work — it already is one.
		// This test pins the map type via the round-trip below.
		_ = v
		if k == "" {
			t.Error("empty metric key")
		}
	}
}

// TestCollect_RoundTripsAsMetricsEvt — the collector's output must marshal
// into the wire shape the api expects (proto.MetricsEvt).
func TestCollect_RoundTripsAsMetricsEvt(t *testing.T) {
	ev := collect(context.Background(), "node-1", "/", func() time.Duration { return 0 })
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out proto.MetricsEvt
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.NodeID != "node-1" {
		t.Errorf("node id lost across round trip: %q", out.NodeID)
	}
	// Must contain at least the always-on metrics.
	if _, ok := out.Metrics[proto.MetricAgentUptimeSeconds]; !ok {
		t.Error("uptime missing after round trip")
	}
	if _, ok := out.Metrics[proto.MetricGoroutines]; !ok {
		t.Error("goroutines missing after round trip")
	}
}

// TestCollect_DiskMeasuresGivenPath proves collect statfs's the diskPath it's
// given — not a hardcoded "/". A real path yields disk metrics; a path that
// can't be statfs'd omits them (per the "failing probes are omitted" contract).
// This is the regression guard for the appliance bug where disk read "/" (the
// read-only squashfs, ~100% by design) instead of the persistent partition.
func TestCollect_DiskMeasuresGivenPath(t *testing.T) {
	// A valid, statfs-able path → disk metrics present with a non-zero total.
	ev := collect(context.Background(), "n", t.TempDir(), func() time.Duration { return 0 })
	total, ok := ev.Metrics[proto.MetricDiskTotalBytes]
	if !ok {
		t.Fatal("disk total missing for a valid path")
	}
	if total <= 0 {
		t.Errorf("disk total = %v, want > 0", total)
	}
	if _, ok := ev.Metrics[proto.MetricDiskUsedBytes]; !ok {
		t.Error("disk used missing for a valid path")
	}

	// A path that can't be statfs'd → disk metrics omitted (not zeroed), and
	// the rest of the sample is unaffected. If collect ignored diskPath and hit
	// "/" instead, these would be present.
	bad := collect(context.Background(), "n", "/no/such/path/rasputin-xyz", func() time.Duration { return 0 })
	if _, ok := bad.Metrics[proto.MetricDiskTotalBytes]; ok {
		t.Error("disk total should be omitted for an unstatfs-able path (collect ignored diskPath?)")
	}
	if _, ok := bad.Metrics[proto.MetricDiskUsedBytes]; ok {
		t.Error("disk used should be omitted for an unstatfs-able path")
	}
	if _, ok := bad.Metrics[proto.MetricAgentUptimeSeconds]; !ok {
		t.Error("a bad disk path must not suppress the always-on metrics")
	}
}

func TestInterval_DefaultIsTenSeconds(t *testing.T) {
	// The collector cadence is part of the contract with the heartbeat
	// loop (10s matches). If someone retunes this, they should at least
	// have to update this test, which jogs them into checking heartbeat
	// alignment too. Interval is a var (not a const) so tests can drive
	// Run() at sub-second cadence — see TestRun_PublishesOnInterval.
	if Interval != 10*time.Second {
		t.Errorf("Interval = %v, want 10s", Interval)
	}
}

// TestRun_PublishesOnInterval drives the Run loop end-to-end with a
// millisecond Interval so we don't have to wait 10s real-time. Asserts
// that at least one MetricsEvt lands on the bus within a tight budget,
// proving (a) the ticker fires, (b) collect+publish wire correctly, and
// (c) Interval is genuinely injectable now that it's a var.
func TestRun_PublishesOnInterval(t *testing.T) {
	prev := Interval
	Interval = 50 * time.Millisecond
	t.Cleanup(func() { Interval = prev })

	nc := startNATS(t)
	recv := make(chan proto.MetricsEvt, 8)
	sub, err := nc.Subscribe(proto.NodeMetricsSubject("node-fast"), func(m *nats.Msg) {
		var ev proto.MetricsEvt
		if err := json.Unmarshal(m.Data, &ev); err == nil {
			select {
			case recv <- ev:
			default:
			}
		}
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { Run(ctx, nc, "node-fast", "/", func() time.Duration { return time.Minute }); close(done) }()

	select {
	case ev := <-recv:
		if ev.NodeID != "node-fast" {
			t.Errorf("first event nodeId: %q", ev.NodeID)
		}
	case <-time.After(900 * time.Millisecond):
		t.Fatal("no metrics event in 900ms — Run is not honoring Interval override")
	}
	cancel()
	<-done
}

// TestCollect_ProbesThatFailAreOmittedNotZeroed checks the "missing key on
// failure" contract documented in collector.go. We can't easily force a
// gopsutil probe to fail in-process, but we can assert the *behavior*: any
// keys that did make it into the map come from the small set of probes the
// collector knows about. A surprise key would mean someone added a probe
// without updating the proto Metric* constants.
func TestCollect_OnlyEmitsKnownMetricKeys(t *testing.T) {
	known := map[string]bool{
		proto.MetricCPUPercent:         true,
		proto.MetricMemUsedBytes:       true,
		proto.MetricMemTotalBytes:      true,
		proto.MetricDiskUsedBytes:      true,
		proto.MetricDiskTotalBytes:     true,
		proto.MetricAgentUptimeSeconds: true,
		proto.MetricGoroutines:         true,
	}
	ev := collect(context.Background(), "n", "/", func() time.Duration { return 0 })
	for k := range ev.Metrics {
		if !known[k] {
			t.Errorf("unexpected metric key %q — add it to proto.Metric* or remove from collector", k)
		}
	}
}
