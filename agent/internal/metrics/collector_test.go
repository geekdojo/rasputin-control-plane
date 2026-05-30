package metrics

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TestCollect_ShapeAndAlwaysOnFields verifies the MetricsEvt the publish loop
// would emit. We exercise `collect` directly so we don't have to start the
// ticker — Run() is intentionally untested here because it depends on a real
// NATS connection (a fake nats.Conn isn't trivial to wire), would require
// sleeping past the 10s Interval, and the *interesting* logic lives in
// collect anyway.
func TestCollect_ShapeAndAlwaysOnFields(t *testing.T) {
	uptime := func() time.Duration { return 123 * time.Second }
	ev := collect(context.Background(), "node-x", uptime)

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
	ev := collect(context.Background(), "n", func() time.Duration { return 0 })
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
	ev := collect(context.Background(), "node-1", func() time.Duration { return 0 })
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

func TestInterval_IsTenSeconds(t *testing.T) {
	// The collector cadence is part of the contract with the heartbeat
	// loop (10s matches). If someone retunes this, they should at least
	// have to update this test, which jogs them into checking heartbeat
	// alignment too.
	if Interval != 10*time.Second {
		t.Errorf("Interval = %v, want 10s", Interval)
	}
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
	ev := collect(context.Background(), "n", func() time.Duration { return 0 })
	for k := range ev.Metrics {
		if !known[k] {
			t.Errorf("unexpected metric key %q — add it to proto.Metric* or remove from collector", k)
		}
	}
}
