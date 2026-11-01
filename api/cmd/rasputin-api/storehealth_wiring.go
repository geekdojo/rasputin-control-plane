package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
)

// storeReadings is obs.StoreReadings from the composition root's two
// collaborators: the readiness view from the monitor, the counts from the
// counter (geekdojo/geekdojo-brain#939, F-939-02).
type storeReadings struct {
	monitor *storestate.Monitor
	counter *storestate.Counter
}

func (r storeReadings) State(ctx context.Context) (storestate.State, error) {
	return r.monitor.State(ctx)
}

func (r storeReadings) Counts() storestate.Counts { return r.counter.Counts() }

// obsFanout returns the metrics sink observability installs: the
// VictoriaMetrics sink, decorated with the secret store's health metrics
// when there is a store to read (a monitor) and a control plane id to
// trigger and label the sample (geekdojo/geekdojo-brain#939). Otherwise it
// returns vm unchanged, with one INFO naming why.
func obsFanout(vm *obs.VMSink, r readinessWiring, selfNodeID, storeDataDir string, logger *slog.Logger) metrics.Sink {
	reason := ""
	switch {
	case r.monitor == nil || r.counter == nil:
		reason = "no store backend"
	case selfNodeID == "":
		reason = "no self node id"
	}
	if reason != "" {
		logger.Info("store health metrics off", "component", "obs", "reason", reason)
		return vm
	}
	sink, err := obs.NewStoreHealthSink(vm, obs.StoreHealthDeps{
		Readings:   storeReadings{monitor: r.monitor, counter: r.counter},
		DataBytes:  func() (uint64, error) { return storage.DirBytes(storeDataDir) },
		SelfNodeID: selfNodeID,
		Now:        time.Now,
		Log:        logger,
	})
	if err != nil {
		// Every collaborator was checked above; this is a wiring bug, and the
		// node metrics still flow.
		logger.Error("store health metrics off", "component", "obs", "reason", "wiring", "err", err.Error())
		return vm
	}
	return sink
}

// sinkSetter is metrics.Service's SetSink.
type sinkSetter interface {
	SetSink(metrics.Sink)
}

// obsSinkSwitch is the one place the obs fan-out is installed and removed:
// at boot with obs on, and by obs.enable and obs.disable. On installs sink,
// off installs nothing.
func obsSinkSwitch(svc sinkSetter, sink metrics.Sink) obs.SetSinkFn {
	return func(on bool) {
		if on {
			svc.SetSink(sink)
			return
		}
		svc.SetSink(nil)
	}
}
