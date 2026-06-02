package metrics

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Retention is how long the api keeps per-sample data in SQLite. 24h covers
// the homelab user's "what happened overnight" use case without growing the
// database unboundedly.
const Retention = 24 * time.Hour

// GCInterval is how often the retention sweeper runs.
const GCInterval = 5 * time.Minute

// Sink is the optional second destination for every received event. The
// SQLite ring buffer is the primary store; a Sink (typically obs.VMSink
// for Tier 2's remote-write to VictoriaMetrics) gets a fan-out copy.
// Defined as an interface here, not imported from obs, so the metrics
// package stays free of the obs dependency.
type Sink interface {
	Write(ctx context.Context, evt *proto.MetricsEvt) error
}

// Service subscribes to agent metric publishes and persists them into Store.
// A background GC loop deletes rows older than Retention. When an optional
// Sink is set via SetSink, every event also fans out to it after the SQLite
// insert.
type Service struct {
	store *Store
	nc    *nats.Conn

	mu   sync.RWMutex
	sink Sink

	ctx    context.Context
	cancel context.CancelFunc
	sub    *nats.Subscription
	wg     sync.WaitGroup
}

func NewService(store *Store, nc *nats.Conn) *Service {
	return &Service{store: store, nc: nc}
}

// SetSink installs (or removes, by passing nil) the fan-out Sink. Safe to
// call before or after Start; the next received event will see the new
// sink. Synchronous on purpose — the obs package's lifecycle (build the
// supervisor, build the sink, hand it in) is naturally sequential.
func (s *Service) SetSink(sink Sink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sink = sink
}

func (s *Service) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	sub, err := s.nc.Subscribe(proto.AllMetricsFilter, s.handle)
	if err != nil {
		return err
	}
	s.sub = sub
	s.wg.Add(1)
	go s.gcLoop()
	return nil
}

func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.sub != nil {
		_ = s.sub.Unsubscribe()
	}
	s.wg.Wait()
}

// Store exposes the underlying store for read-only HTTP handlers.
func (s *Service) Store() *Store { return s.store }

func (s *Service) handle(m *nats.Msg) {
	var ev proto.MetricsEvt
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		return
	}
	if ev.NodeID == "" || len(ev.Metrics) == 0 {
		return
	}
	if err := s.store.Insert(s.ctx, &ev); err != nil {
		log.Printf("metrics: insert %s: %v", ev.NodeID, err)
	}
	// Fan out to the optional Tier 2 sink. Sink failures are logged but
	// never block the SQLite path — the sparkline UI must keep working
	// when VM is down. Read the sink under the RLock so SetSink can
	// swap it concurrently.
	s.mu.RLock()
	sink := s.sink
	s.mu.RUnlock()
	if sink != nil {
		if err := sink.Write(s.ctx, &ev); err != nil {
			log.Printf("metrics: sink %s: %v", ev.NodeID, err)
		}
	}
}

func (s *Service) gcLoop() {
	defer s.wg.Done()
	t := time.NewTicker(GCInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			cutoff := now.UTC().Add(-Retention)
			if n, err := s.store.DeleteBefore(s.ctx, cutoff); err != nil {
				log.Printf("metrics: gc: %v", err)
			} else if n > 0 {
				log.Printf("metrics: gc trimmed %d rows older than %s",
					n, cutoff.Format(time.RFC3339))
			}
		}
	}
}
