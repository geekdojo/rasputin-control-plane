package metrics

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(context.Background(), filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// insertSample is a convenience helper that turns a flat (name, value) map +
// timestamp into a MetricsEvt and lands it in the store. Used by every test
// below — keeps the assertion line short.
func insertSample(t *testing.T, s *Store, nodeID string, ts time.Time, vals map[string]float64) {
	t.Helper()
	ev := &proto.MetricsEvt{
		NodeID:  nodeID,
		Ts:      ts,
		Metrics: vals,
	}
	if err := s.Insert(context.Background(), ev); err != nil {
		t.Fatalf("Insert: %v", err)
	}
}

// ============================================================================
// Insert + Query
// ============================================================================

func TestStore_InsertAndQuery_SingleNodeSingleName(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	base := time.UnixMilli(1717000000000).UTC()
	insertSample(t, s, "n", base, map[string]float64{proto.MetricCPUPercent: 10})
	insertSample(t, s, "n", base.Add(1*time.Second), map[string]float64{proto.MetricCPUPercent: 20})
	insertSample(t, s, "n", base.Add(2*time.Second), map[string]float64{proto.MetricCPUPercent: 30})

	got, err := s.Query(ctx, "n", []string{proto.MetricCPUPercent}, base, base.Add(2*time.Second))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	series := got.Series[proto.MetricCPUPercent]
	if len(series) != 3 {
		t.Fatalf("want 3 points, got %d", len(series))
	}
	wantVals := []float64{10, 20, 30}
	for i, p := range series {
		if p.Value != wantVals[i] {
			t.Errorf("point %d: got %v, want %v", i, p.Value, wantVals[i])
		}
		if i > 0 && !series[i].Ts.After(series[i-1].Ts) {
			t.Errorf("series should be ts ascending")
		}
	}
}

func TestStore_Query_FiltersByNode(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := time.UnixMilli(1717000000000).UTC()
	insertSample(t, s, "a", base, map[string]float64{"x": 1})
	insertSample(t, s, "b", base, map[string]float64{"x": 99})

	got, _ := s.Query(ctx, "a", []string{"x"}, base.Add(-1*time.Second), base.Add(1*time.Second))
	if len(got.Series["x"]) != 1 || got.Series["x"][0].Value != 1 {
		t.Errorf("node filter leaked across nodes: %+v", got.Series)
	}
}

func TestStore_Query_AllNamesWhenNil(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := time.UnixMilli(1717000000000).UTC()
	insertSample(t, s, "n", base, map[string]float64{
		proto.MetricCPUPercent:   25,
		proto.MetricMemUsedBytes: 1024,
		proto.MetricGoroutines:   42,
	})
	got, err := s.Query(ctx, "n", nil, base.Add(-1*time.Second), base.Add(1*time.Second))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Series) != 3 {
		t.Errorf("want 3 series, got %d (%v)", len(got.Series), got.Series)
	}
	for _, name := range []string{proto.MetricCPUPercent, proto.MetricMemUsedBytes, proto.MetricGoroutines} {
		if len(got.Series[name]) != 1 {
			t.Errorf("series %s: want 1 point, got %d", name, len(got.Series[name]))
		}
	}
}

func TestStore_Query_RangeBoundariesInclusive(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := time.UnixMilli(1717000000000).UTC()
	insertSample(t, s, "n", base, map[string]float64{"x": 1})
	insertSample(t, s, "n", base.Add(10*time.Second), map[string]float64{"x": 2})

	// The query window equals the sample timestamps exactly — should include both.
	got, _ := s.Query(ctx, "n", []string{"x"}, base, base.Add(10*time.Second))
	if len(got.Series["x"]) != 2 {
		t.Errorf("range inclusive: want 2 points, got %d", len(got.Series["x"]))
	}
}

func TestStore_Query_OutOfRangeReturnsEmpty(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := time.UnixMilli(1717000000000).UTC()
	insertSample(t, s, "n", base, map[string]float64{"x": 1})

	got, _ := s.Query(ctx, "n", []string{"x"}, base.Add(1*time.Hour), base.Add(2*time.Hour))
	if len(got.Series["x"]) != 0 {
		t.Errorf("out-of-range query should be empty, got %d", len(got.Series["x"]))
	}
	// From/To should still echo back.
	if !got.From.Equal(base.Add(1*time.Hour)) || !got.To.Equal(base.Add(2*time.Hour)) {
		t.Errorf("From/To not round-tripped: %v %v", got.From, got.To)
	}
	if got.NodeID != "n" {
		t.Errorf("NodeID: %q", got.NodeID)
	}
}

func TestStore_Insert_ReplaceConflictingTimestamp(t *testing.T) {
	// The table PK is (node_id, name, ts) and the insert is "OR REPLACE",
	// so a second sample at the same instant overwrites the first.
	ctx := context.Background()
	s := newStore(t)
	t0 := time.UnixMilli(1717000000000).UTC()
	insertSample(t, s, "n", t0, map[string]float64{"x": 1})
	insertSample(t, s, "n", t0, map[string]float64{"x": 99})

	got, _ := s.Query(ctx, "n", []string{"x"}, t0.Add(-1*time.Second), t0.Add(1*time.Second))
	if len(got.Series["x"]) != 1 {
		t.Fatalf("PK conflict should collapse to 1 row, got %d", len(got.Series["x"]))
	}
	if got.Series["x"][0].Value != 99 {
		t.Errorf("OR REPLACE: want 99, got %v", got.Series["x"][0].Value)
	}
}

func TestStore_Insert_EmptyMetricsMapIsNoOp(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	// Insert with empty metrics map: nothing to write, transaction commits cleanly.
	ev := &proto.MetricsEvt{NodeID: "n", Ts: time.Now().UTC(), Metrics: map[string]float64{}}
	if err := s.Insert(ctx, ev); err != nil {
		t.Fatalf("Insert empty: %v", err)
	}
	got, _ := s.Query(ctx, "n", nil, time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour))
	if len(got.Series) != 0 {
		t.Errorf("empty insert should leave store empty, got %+v", got.Series)
	}
}

// ============================================================================
// DeleteBefore — retention sweep.
// ============================================================================

func TestStore_DeleteBefore_KeepsRecentDropsOld(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := time.UnixMilli(1717000000000).UTC()

	// Two old samples, one fresh one.
	insertSample(t, s, "n", base.Add(-3*time.Hour), map[string]float64{"x": 1})
	insertSample(t, s, "n", base.Add(-2*time.Hour), map[string]float64{"x": 2})
	insertSample(t, s, "n", base, map[string]float64{"x": 3})

	cutoff := base.Add(-1 * time.Hour)
	n, err := s.DeleteBefore(ctx, cutoff)
	if err != nil {
		t.Fatalf("DeleteBefore: %v", err)
	}
	if n != 2 {
		t.Errorf("want 2 deleted, got %d", n)
	}

	got, _ := s.Query(ctx, "n", []string{"x"}, base.Add(-10*time.Hour), base.Add(1*time.Hour))
	if len(got.Series["x"]) != 1 || got.Series["x"][0].Value != 3 {
		t.Errorf("expected only the fresh point to survive, got %+v", got.Series["x"])
	}
}

func TestStore_DeleteBefore_NoOpOnEmptyStore(t *testing.T) {
	s := newStore(t)
	n, err := s.DeleteBefore(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("DeleteBefore: %v", err)
	}
	if n != 0 {
		t.Errorf("empty store should report 0 deleted, got %d", n)
	}
}

// ============================================================================
// Service.Store accessor — the only NATS-free bit of the service surface.
// ============================================================================

func TestService_StoreAccessor(t *testing.T) {
	store := newStore(t)
	svc := NewService(store, nil)
	if svc.Store() != store {
		t.Errorf("Store() did not return the wrapped store")
	}
}

// ============================================================================
// Service.handle — the NATS callback. It doesn't publish anything, so it's
// safe to call directly with a fabricated *nats.Msg. nc is nil here.
// ============================================================================

func TestService_Handle_PersistsValidPayload(t *testing.T) {
	store := newStore(t)
	svc := NewService(store, nil)
	svc.ctx = context.Background()

	t0 := time.UnixMilli(1717000000000).UTC()
	ev := proto.MetricsEvt{
		NodeID:  "n",
		Ts:      t0,
		Metrics: map[string]float64{proto.MetricCPUPercent: 42},
	}
	data, _ := json.Marshal(ev)
	svc.handle(&nats.Msg{Subject: proto.NodeMetricsSubject("n"), Data: data})

	got, _ := store.Query(context.Background(), "n", nil,
		t0.Add(-1*time.Second), t0.Add(1*time.Second))
	if len(got.Series[proto.MetricCPUPercent]) != 1 || got.Series[proto.MetricCPUPercent][0].Value != 42 {
		t.Errorf("handle should have persisted the sample, got %+v", got.Series)
	}
}

func TestService_Handle_RejectsEarlyExits(t *testing.T) {
	store := newStore(t)
	svc := NewService(store, nil)
	svc.ctx = context.Background()

	cases := []struct {
		name string
		data []byte
	}{
		{"invalid json", []byte("not-json")},
		{"missing nodeId", mustJSON(t, proto.MetricsEvt{Metrics: map[string]float64{"x": 1}})},
		{"empty metrics", mustJSON(t, proto.MetricsEvt{NodeID: "n", Metrics: nil})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc.handle(&nats.Msg{Subject: "s", Data: tc.data})
		})
	}

	// All early-exits should leave the store empty.
	got, _ := store.Query(context.Background(), "n", nil,
		time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour))
	if len(got.Series) != 0 {
		t.Errorf("expected empty store, got %+v", got.Series)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
