package metrics

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// startNATS spins up an in-process NATS server on a random port and returns a
// connected client. Server shuts down on test cleanup.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// newStoreAt opens a fresh store at a fixed path (test cleanup closes it).
func newStoreAt(t *testing.T, name string) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(context.Background(), filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// ============================================================================
// Service.Start / Stop with the real bus — Start subscribes to the metrics
// filter, then a publish lands in the store via the subscription callback.
// We poll the store to confirm the row arrived, which is what the lines past
// the sub.Subscribe call do.
// ============================================================================

func TestService_StartStop_PersistsPublishedMetrics(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreAt(t, "m.db")
	svc := NewService(store, nc)

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(svc.Stop)

	t0 := time.UnixMilli(1717000000000).UTC()
	ev := proto.MetricsEvt{
		NodeID:  "n-pub",
		Ts:      t0,
		Metrics: map[string]float64{proto.MetricCPUPercent: 7},
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := nc.Publish(proto.NodeMetricsSubject("n-pub"), data); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Flush so the server delivers before we query.
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// The Subscribe handler runs on a NATS dispatcher goroutine — give it a
	// few short retries to land before we query.
	deadline := time.Now().Add(2 * time.Second)
	var got *Series
	for time.Now().Before(deadline) {
		got, err = store.Query(ctx, "n-pub", []string{proto.MetricCPUPercent},
			t0.Add(-time.Second), t0.Add(time.Second))
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if got != nil && len(got.Series[proto.MetricCPUPercent]) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got == nil || len(got.Series[proto.MetricCPUPercent]) != 1 || got.Series[proto.MetricCPUPercent][0].Value != 7 {
		t.Errorf("expected one sample of value 7, got %+v", got)
	}
}

// TestService_Start_SubscribeError forces a Subscribe failure by closing the
// client connection before Start. This covers the "return err" branch of
// Start without needing to manipulate the server.
func TestService_Start_SubscribeError(t *testing.T) {
	nc := startNATS(t)
	nc.Close() // calling Subscribe on a closed conn returns an error.

	store := newStoreAt(t, "m.db")
	svc := NewService(store, nc)
	if err := svc.Start(context.Background()); err == nil {
		t.Error("Start on a closed conn should error")
	}
}

// TestService_Stop_BeforeStart_IsSafe just exercises the cancel == nil branch
// of Stop. (Stop pre-Start has historically panicked in some service code
// — pin the current behavior.)
func TestService_Stop_BeforeStart_IsSafe(t *testing.T) {
	store := newStoreAt(t, "m.db")
	svc := NewService(store, nil)
	// Should not panic.
	svc.Stop()
}
