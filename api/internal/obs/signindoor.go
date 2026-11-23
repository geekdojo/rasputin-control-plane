package obs

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The sign-in doors' metrics (geekdojo/geekdojo-brain#986, signin-origin.md
// §14). Each is written per door as rasputin_<name>{nodeId,door}.
const (
	// MetricSigninDoorUp is 1 while the door is served and reachable, else 0.
	MetricSigninDoorUp = "signin_door_up"
	// MetricSigninDoorRequests is the door's request count since start.
	MetricSigninDoorRequests = "signin_door_requests_total"
	// MetricSigninThrottledSources is how many sources wait at the door now.
	MetricSigninThrottledSources = "signin_throttled_sources"
)

// signinDoors are the {door} values, in the order written.
var signinDoors = []string{"home", "app"}

// SigninDoorReading is a door's up fact, read at a sample. It may do I/O, so
// it runs only in the sample's own goroutine. An error reads 0.
type SigninDoorReading interface {
	DoorUp(ctx context.Context, door string) (bool, error)
}

// SigninDoorCounts are a door's counts at now: its requests and the sources
// waiting at it.
type SigninDoorCounts interface {
	DoorCounts(door string, now time.Time) (requests uint64, throttled int)
}

// SigninDoorDeps are a SigninDoorSink's collaborators. NewSigninDoorSink
// refuses a nil one or an empty SelfNodeID.
type SigninDoorDeps struct {
	Reading SigninDoorReading
	Counts  SigninDoorCounts
	Writer  SeriesWriter
	// SelfNodeID is the control plane's node id: its own agent sample
	// triggers a door sample, which is labelled with it.
	SelfNodeID string
	Now        func() time.Time
	Log        *slog.Logger
}

// SigninDoorSink is a Sink decorator that adds the sign-in doors' metrics to
// the metrics VictoriaMetrics receives. Every event is forwarded to the inner
// sink unchanged; the control plane's own agent sample (timer-audit K13) also
// starts one door sample, so the metrics have no timer of their own.
//
// The door-up reading asks the identity service whether it is ready and reads
// the apps and mesh stores, so a sample runs in its own goroutine, as
// StoreHealthSink's does: Write runs on the metrics subscriber's one goroutine,
// and a slow identity service would otherwise stall every node's metrics. At
// most one sample runs at a time; a trigger that arrives while one is running
// is skipped.
type SigninDoorSink struct {
	inner Sink
	d     SigninDoorDeps

	running atomic.Bool
	// wg tracks the running sample (Wait).
	wg sync.WaitGroup
}

// NewSigninDoorSink wraps inner.
func NewSigninDoorSink(inner Sink, d SigninDoorDeps) (*SigninDoorSink, error) {
	switch {
	case inner == nil:
		return nil, errors.New("obs: sign-in doors: the inner sink is nil")
	case d.Reading == nil:
		return nil, errors.New("obs: sign-in doors: the reading is nil")
	case d.Counts == nil:
		return nil, errors.New("obs: sign-in doors: the counts are nil")
	case d.Writer == nil:
		return nil, errors.New("obs: sign-in doors: the series writer is nil")
	case d.SelfNodeID == "":
		return nil, errors.New("obs: sign-in doors: the self node id is empty")
	case d.Now == nil:
		return nil, errors.New("obs: sign-in doors: the clock is nil")
	case d.Log == nil:
		return nil, errors.New("obs: sign-in doors: the logger is nil")
	}
	return &SigninDoorSink{inner: inner, d: d}, nil
}

// Write forwards evt to the inner sink and returns its result. When evt is
// the control plane's own sample, it also starts a door sample unless one is
// still running.
func (s *SigninDoorSink) Write(ctx context.Context, evt *proto.MetricsEvt) error {
	err := s.inner.Write(ctx, evt)
	if evt != nil && evt.NodeID == s.d.SelfNodeID {
		if s.running.CompareAndSwap(false, true) {
			s.wg.Add(1)
			go s.sample(ctx)
		} else {
			s.d.Log.LogAttrs(ctx, slog.LevelDebug, "sign-in door sample still running; trigger skipped",
				slog.String("component", "obs"))
		}
	}
	return err
}

// Wait returns once no door sample is running.
func (s *SigninDoorSink) Wait() { s.wg.Wait() }

// sample reads each door once and writes its three series.
func (s *SigninDoorSink) sample(ctx context.Context) {
	defer s.wg.Done()
	defer s.running.Store(false)
	now := s.d.Now()
	series := make([]Series, 0, 3*len(signinDoors))
	for _, door := range signinDoors {
		up := 0.0
		ok, err := s.d.Reading.DoorUp(ctx, door)
		switch {
		case err != nil:
			// An unknown fact never reads up (ERR-CLOSED).
			s.d.Log.LogAttrs(ctx, slog.LevelDebug, "sign-in door reads down: a fact could not be read",
				slog.String("component", "obs"), slog.String("door", door), slog.String("err", err.Error()))
		case ok:
			up = 1
		}
		requests, throttled := s.d.Counts.DoorCounts(door, now)
		label := []Label{{Name: "door", Value: door}}
		series = append(series,
			Series{Name: MetricSigninDoorUp, Labels: label, Value: up},
			Series{Name: MetricSigninDoorRequests, Labels: label, Value: float64(requests)},
			Series{Name: MetricSigninThrottledSources, Labels: label, Value: float64(throttled)},
		)
	}
	if err := s.d.Writer.WriteSeries(ctx, s.d.SelfNodeID, now, series); err != nil {
		// The VM sink records it for /api/obs/status, and metrics.Service
		// already logs a VM outage for every node's sample.
		s.d.Log.LogAttrs(ctx, slog.LevelDebug, "sign-in door sample not written",
			slog.String("component", "obs"), slog.String("err", err.Error()))
	}
}
