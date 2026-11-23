package obs

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// MetricSigninNameState is the home sign-in name's state metric
// (geekdojo/geekdojo-brain#995): rasputin_signin_name_state{nodeId,state},
// written one-hot as three series, one per state.
const MetricSigninNameState = "signin_name_state"

// signinNameStates are the metric's {state} values, in the order written.
var signinNameStates = []string{"ok", "conflict", "unpublished"}

// SigninNameReading is what a sign-in name sample reads: the state computed
// at that moment (signinname.Responder.MetricState). false means there is no
// state to write.
type SigninNameReading interface {
	MetricState(now time.Time) (string, bool)
}

// SeriesWriter writes labelled series. *VMSink satisfies it.
type SeriesWriter interface {
	WriteSeries(ctx context.Context, nodeID string, ts time.Time, series []Series) error
}

// SigninNameDeps are a SigninNameSink's collaborators. NewSigninNameSink
// refuses a nil one or an empty SelfNodeID.
type SigninNameDeps struct {
	Reading SigninNameReading
	// SelfNodeID is the control plane's node id: its own agent sample
	// triggers a sign-in name sample, which is labelled with it.
	SelfNodeID string
	Now        func() time.Time
	Log        *slog.Logger
}

// SigninNameSink is a Sink decorator that adds the sign-in name's state to
// the metrics VictoriaMetrics receives. Every event is forwarded to the inner
// sink unchanged; the control plane's own agent sample (timer-audit K13) also
// writes one sign-in name sample, as StoreHealthSink's does, so the metric has
// no timer of its own. The reading is a computation under a mutex, so it runs
// inline.
type SigninNameSink struct {
	inner Sink
	vm    SeriesWriter
	d     SigninNameDeps
}

// NewSigninNameSink wraps inner, writing the sign-in name's series to vm.
func NewSigninNameSink(inner Sink, vm SeriesWriter, d SigninNameDeps) (*SigninNameSink, error) {
	switch {
	case inner == nil:
		return nil, errors.New("obs: sign-in name: the inner sink is nil")
	case vm == nil:
		return nil, errors.New("obs: sign-in name: the series writer is nil")
	case d.Reading == nil:
		return nil, errors.New("obs: sign-in name: the reading is nil")
	case d.SelfNodeID == "":
		return nil, errors.New("obs: sign-in name: the self node id is empty")
	case d.Now == nil:
		return nil, errors.New("obs: sign-in name: the clock is nil")
	case d.Log == nil:
		return nil, errors.New("obs: sign-in name: the logger is nil")
	}
	return &SigninNameSink{inner: inner, vm: vm, d: d}, nil
}

// Write forwards evt to the inner sink and returns its result. When evt is
// the control plane's own sample, it also writes the sign-in name's state.
func (s *SigninNameSink) Write(ctx context.Context, evt *proto.MetricsEvt) error {
	err := s.inner.Write(ctx, evt)
	if evt == nil || evt.NodeID != s.d.SelfNodeID {
		return err
	}
	now := s.d.Now()
	state, ok := s.d.Reading.MetricState(now)
	if !ok {
		return err
	}
	series := make([]Series, 0, len(signinNameStates))
	for _, st := range signinNameStates {
		v := 0.0
		if st == state {
			v = 1
		}
		series = append(series, Series{Name: MetricSigninNameState, Labels: []Label{{Name: "state", Value: st}}, Value: v})
	}
	if werr := s.vm.WriteSeries(ctx, s.d.SelfNodeID, now, series); werr != nil {
		// The VM sink records it for /api/obs/status, and metrics.Service
		// already logs a VM outage for every node's sample.
		s.d.Log.LogAttrs(ctx, slog.LevelDebug, "sign-in name sample not written",
			slog.String("component", "obs"), slog.String("err", werr.Error()))
	}
	return err
}
