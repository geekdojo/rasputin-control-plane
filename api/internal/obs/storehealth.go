package obs

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The store-health metric names a sample carries. encodePromText writes each
// as rasputin_<name>{nodeId="<control plane>"}; the "Secret store" dashboard
// plots them (geekdojo/geekdojo-brain#939).
const (
	MetricSecretStoreSealed        = "secretstore_sealed"
	MetricSecretStoreRequestsTotal = "secretstore_requests_total"
	MetricSecretStoreErrorsTotal   = "secretstore_errors_total"
	MetricSecretStoreStorageBytes  = "secretstore_storage_bytes"
)

// StoreReadings is what a store-health sample reads: the store's readiness,
// from the api's one view of it (storestate.Monitor), and the audited calls'
// counts (storestate.Counter).
type StoreReadings interface {
	State(ctx context.Context) (storestate.State, error)
	Counts() storestate.Counts
}

// StoreHealthDeps are a StoreHealthSink's collaborators. NewStoreHealthSink
// refuses a nil one or an empty SelfNodeID.
type StoreHealthDeps struct {
	Readings StoreReadings
	// DataBytes is the size of the store's data on disk. An error leaves the
	// size out of the sample.
	DataBytes func() (uint64, error)
	// SelfNodeID is the control plane's node id: its own agent sample
	// triggers a store sample, and the store sample is labelled with it.
	SelfNodeID string
	Now        func() time.Time
	Log        *slog.Logger
}

// StoreHealthSink is a Sink decorator that adds the secret store's health to
// the metrics VictoriaMetrics receives (geekdojo/geekdojo-brain#939). Every
// event is forwarded to the inner sink unchanged. The control plane's own
// agent sample (one per agent metrics.Interval, about every 10s; timer-audit
// K13) also starts one store sample, so there is no ticker of its own and no
// separate observability-on gate: while observability is off no sink is
// installed and nothing triggers a sample.
//
// A store sample runs in its own goroutine, because Write runs on the
// metrics subscriber's one goroutine and a hung store would otherwise stall
// every node's metrics; at most one runs at a time, and a trigger that
// arrives while one is running is skipped.
type StoreHealthSink struct {
	inner Sink
	d     StoreHealthDeps

	running atomic.Bool
	// wg tracks the running sample (Wait).
	wg sync.WaitGroup

	mu sync.Mutex
	// sizeUnreadable is set while DataBytes fails for a reason other than a
	// missing directory, so its WARN is logged once per outage.
	sizeUnreadable bool
}

// NewStoreHealthSink wraps inner.
func NewStoreHealthSink(inner Sink, d StoreHealthDeps) (*StoreHealthSink, error) {
	switch {
	case inner == nil:
		return nil, errors.New("obs: store health: the inner sink is nil")
	case d.Readings == nil:
		return nil, errors.New("obs: store health: the readings are nil")
	case d.DataBytes == nil:
		return nil, errors.New("obs: store health: DataBytes is nil")
	case d.SelfNodeID == "":
		return nil, errors.New("obs: store health: the self node id is empty")
	case d.Now == nil:
		return nil, errors.New("obs: store health: the clock is nil")
	case d.Log == nil:
		return nil, errors.New("obs: store health: the logger is nil")
	}
	return &StoreHealthSink{inner: inner, d: d}, nil
}

// Write forwards evt to the inner sink and returns its result. When evt is
// the control plane's own sample, it also starts a store sample unless one
// is still running.
func (s *StoreHealthSink) Write(ctx context.Context, evt *proto.MetricsEvt) error {
	err := s.inner.Write(ctx, evt)
	if evt != nil && evt.NodeID == s.d.SelfNodeID {
		if s.running.CompareAndSwap(false, true) {
			s.wg.Add(1)
			go s.sample(ctx)
		} else {
			s.d.Log.LogAttrs(ctx, slog.LevelDebug, "store health sample still running; trigger skipped",
				slog.String("component", "obs"))
		}
	}
	return err
}

// Wait returns once no store sample is running.
func (s *StoreHealthSink) Wait() { s.wg.Wait() }

// sample reads the store's health once and writes it through the inner sink.
func (s *StoreHealthSink) sample(ctx context.Context) {
	defer s.wg.Done()
	defer s.running.Store(false)
	st, err := s.d.Readings.State(ctx)
	if err != nil {
		// Only a ctx that ended (shutdown) fails a reading; it says nothing
		// about the store.
		s.d.Log.LogAttrs(ctx, slog.LevelDebug, "store health sample skipped",
			slog.String("component", "obs"), slog.String("err", err.Error()))
		return
	}
	c := s.d.Readings.Counts()
	m := map[string]float64{
		MetricSecretStoreRequestsTotal: float64(c.Requests),
		MetricSecretStoreErrorsTotal:   float64(c.Errors),
	}
	if sealed, known := st.Sealed(); known {
		m[MetricSecretStoreSealed] = 0
		if sealed {
			m[MetricSecretStoreSealed] = 1
		}
	}
	if n, ok := s.dataBytes(ctx); ok {
		m[MetricSecretStoreStorageBytes] = float64(n)
	}
	evt := &proto.MetricsEvt{NodeID: s.d.SelfNodeID, Ts: s.d.Now(), Metrics: m}
	if err := s.inner.Write(ctx, evt); err != nil {
		// The inner sink records it for /api/obs/status, and metrics.Service
		// already logs a VM outage for every node's sample.
		s.d.Log.LogAttrs(ctx, slog.LevelDebug, "store health sample not written",
			slog.String("component", "obs"), slog.String("err", err.Error()))
	}
}

// dataBytes reads the store's data size. A missing directory (no store data
// on this host, as in mock mode) is DEBUG; any other failure is one WARN per
// outage and one INFO when it reads again.
func (s *StoreHealthSink) dataBytes(ctx context.Context) (uint64, bool) {
	n, err := s.d.DataBytes()
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		s.d.Log.LogAttrs(ctx, slog.LevelDebug, "store size absent; storage series omitted",
			slog.String("component", "obs"), slog.String("err", err.Error()))
		return 0, false
	}
	s.mu.Lock()
	was := s.sizeUnreadable
	s.sizeUnreadable = err != nil
	s.mu.Unlock()
	if err != nil {
		if !was {
			s.d.Log.LogAttrs(ctx, slog.LevelWarn, "store size unreadable; storage series omitted",
				slog.String("component", "obs"), slog.String("event", "obs.store_size_unreadable"),
				slog.String("dir", dirOf(err)), slog.String("err", err.Error()))
		}
		return 0, false
	}
	if was {
		s.d.Log.LogAttrs(ctx, slog.LevelInfo, "store size readable again", slog.String("component", "obs"))
	}
	return n, true
}

// dirOf is the path a size error names, when it carries one.
func dirOf(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Path
	}
	return ""
}
