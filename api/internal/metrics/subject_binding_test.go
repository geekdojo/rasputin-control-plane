package metrics

// A node's identity comes from the subject it publishes on
// (rasputin.node.<id>.metrics), which the bus scopes to the node's credential —
// never from the nodeId field in the payload. A sample whose payload names a
// different node is dropped; one with the matching or an empty id is stored
// under the subject's node.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

func TestService_Handle_PayloadNodeIDMustMatchSubject(t *testing.T) {
	store := newStore(t)
	svc := NewService(store, nil)
	svc.ctx = context.Background()

	t0 := time.UnixMilli(1717000000000).UTC()
	data, _ := json.Marshal(proto.MetricsEvt{
		NodeID:  "beta",
		Ts:      t0,
		Metrics: map[string]float64{proto.MetricCPUPercent: 99},
	})
	svc.handle(&nats.Msg{Subject: proto.NodeMetricsSubject("alpha"), Data: data})

	for _, id := range []string{"alpha", "beta"} {
		got, err := store.Query(context.Background(), id, nil, t0.Add(-time.Second), t0.Add(time.Second))
		if err != nil {
			t.Fatalf("Query %s: %v", id, err)
		}
		if len(got.Series) != 0 {
			t.Errorf("a sample with a mismatched payload node id published on %s landed in node %s's series: %+v",
				proto.NodeMetricsSubject("alpha"), id, got.Series)
		}
	}
}

func TestService_Handle_MatchingOrEmptyNodeIDStoresUnderSubject(t *testing.T) {
	for _, payloadID := range []string{"alpha", ""} {
		t.Run("payload="+payloadID, func(t *testing.T) {
			store := newStore(t)
			svc := NewService(store, nil)
			svc.ctx = context.Background()

			t0 := time.UnixMilli(1717000000000).UTC()
			data, _ := json.Marshal(proto.MetricsEvt{
				NodeID:  payloadID,
				Ts:      t0,
				Metrics: map[string]float64{proto.MetricCPUPercent: 42},
			})
			svc.handle(&nats.Msg{Subject: proto.NodeMetricsSubject("alpha"), Data: data})

			got, err := store.Query(context.Background(), "alpha", nil, t0.Add(-time.Second), t0.Add(time.Second))
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(got.Series[proto.MetricCPUPercent]) != 1 {
				t.Errorf("want one sample stored under alpha, got %+v", got.Series)
			}
		})
	}
}
