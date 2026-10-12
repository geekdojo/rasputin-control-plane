package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// readinessWiring is what storeReadinessWiring built
// (geekdojo/geekdojo-brain#760).
type readinessWiring struct {
	// monitor is nil when no store backend is requested.
	monitor *storestate.Monitor
	// source is the deploy family's secret source: the inner source itself
	// when no backend is requested, the Gate around it otherwise.
	source apps.SecretSource
	// alerts is the store's readiness alert source, or nil.
	alerts func(ctx context.Context, now time.Time) []proto.Alert
	// store is the store every consumer uses: the one passed in, or the
	// ObservedStore around it.
	store secretStore
}

// storeReadinessWiring builds the store's readiness monitor, the Gate in
// front of inner and the observed store. It keys on requested, the raw
// RASPUTIN_SECRETSTORE_BACKEND, not on the effective mode: a backend that was
// asked for but whose configuration was refused (mode off, a Disabled store)
// still gets the Gate and reads Unreachable, so its alert is raised and
// secret-bearing deploys refuse (F-760-02). With nothing requested the inner
// source is returned unchanged, which is the previous release's behaviour.
//
// It makes no store call: the api starts whatever state the store is in.
func storeReadinessWiring(requested, mode string, store secretStore, inner apps.SecretSource, js *jobs.Store, now func() time.Time, logger *slog.Logger) (readinessWiring, error) {
	switch {
	case store == nil:
		return readinessWiring{}, errors.New("store readiness: the store is nil")
	case inner == nil:
		return readinessWiring{}, errors.New("store readiness: the inner secret source is nil")
	case js == nil:
		return readinessWiring{}, errors.New("store readiness: the job store is nil")
	case now == nil:
		return readinessWiring{}, errors.New("store readiness: the clock is nil")
	case logger == nil:
		return readinessWiring{}, errors.New("store readiness: the logger is nil")
	}
	if requested == "" {
		return readinessWiring{source: inner, store: store}, nil
	}
	monitor, err := storestate.New(storestate.Deps{Store: store, Now: now, Log: logger, JobRunning: jobRunning(js)})
	if err != nil {
		return readinessWiring{}, err
	}
	gate, err := storestate.NewGate(inner, monitor, logger)
	if err != nil {
		return readinessWiring{}, err
	}
	observed, err := storestate.NewObservedStore(store, monitor)
	if err != nil {
		return readinessWiring{}, err
	}
	logger.Info("secret store readiness gate on: secret-bearing deploys wait for the store",
		"component", "secretstore", "requested", requested, "mode", mode)
	return readinessWiring{monitor: monitor, source: gate, alerts: monitor.Alerts, store: observed}, nil
}

// jobRunning is the monitor's quiesce fact: whether the job is running now in
// the job ledger. A job the ledger does not hold is not running.
func jobRunning(js *jobs.Store) func(ctx context.Context, jobID string) (bool, error) {
	return func(ctx context.Context, jobID string) (bool, error) {
		j, err := js.GetJob(ctx, jobID)
		if err != nil {
			return false, err
		}
		return j != nil && j.Status == jobs.StatusRunning, nil
	}
}
