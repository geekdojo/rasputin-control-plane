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
	// alerts is the store's readiness alert source, or nil.
	alerts func(ctx context.Context, now time.Time) []proto.Alert
	// store is the store every consumer uses: the one passed in, or the
	// ObservedStore around it.
	store secretStore
}

// storeReadinessWiring builds the store's readiness monitor and the observed
// store. It keys on requested, the raw RASPUTIN_SECRETSTORE_BACKEND, not on
// the effective mode: a backend that was asked for but whose configuration was
// refused (mode off, a Disabled store) still gets a monitor, which reads
// Unreachable, so its alert is raised and secret-bearing deploys refuse
// (F-760-02). With nothing requested there is no monitor and the store is
// returned unchanged, which is the previous release's behaviour. The deploy
// family's source is deploySourceWiring's, once the secrets service exists.
//
// It makes no store call: the api starts whatever state the store is in.
//
// switched is the switch marker's verdict at boot (geekdojo/geekdojo-brain#604):
// once the cluster has held an operator-supplied value, nothing requested no
// longer means "the previous release's behaviour". The monitor then runs over
// the store passed in (Disabled), reads Unreachable and raises its crit
// alert, and deploySourceWiring returns the Gate, so secret-bearing deploys
// refuse and the HKDF source is never reached.
//
// blank is the empty-store marker's verdict (#765); required.
func storeReadinessWiring(requested string, switched bool, mode string, store secretStore, js *jobs.Store, now func() time.Time,
	blank func(context.Context) (bool, error), logger *slog.Logger) (readinessWiring, error) {
	switch {
	case store == nil:
		return readinessWiring{}, errors.New("store readiness: the store is nil")
	case js == nil:
		return readinessWiring{}, errors.New("store readiness: the job store is nil")
	case now == nil:
		return readinessWiring{}, errors.New("store readiness: the clock is nil")
	case blank == nil:
		return readinessWiring{}, errors.New("store readiness: the blank verdict is nil")
	case logger == nil:
		return readinessWiring{}, errors.New("store readiness: the logger is nil")
	}
	if requested == "" && !switched {
		return readinessWiring{store: store}, nil
	}
	if requested == "" {
		logger.Warn("secret store switched but not configured: secret-bearing deploys are refused until a store is configured",
			"component", "secretstore", "event", "secretstore.switched_unconfigured", "mode", mode)
	}
	monitor, err := storestate.New(storestate.Deps{Store: store, Now: now, Log: logger, JobRunning: jobRunning(js), Blank: blank})
	if err != nil {
		return readinessWiring{}, err
	}
	observed, err := storestate.NewObservedStore(store, monitor)
	if err != nil {
		return readinessWiring{}, err
	}
	logger.Info("secret store readiness gate on: secret-bearing deploys wait for the store",
		"component", "secretstore", "requested", requested, "mode", mode)
	return readinessWiring{monitor: monitor, alerts: monitor.Alerts, store: observed}, nil
}

// deploySourceWiring is the deploy family's secret source
// (geekdojo/geekdojo-brain#762, S14). With a store backend requested (a
// monitor) it is the readiness Gate around storeSource, and hkdf is not
// reachable: every secret-bearing deploy resolves through the store or
// refuses. With none requested it is hkdf, as every release before #762 ran.
// It makes no store call.
func deploySourceWiring(monitor *storestate.Monitor, storeSource, hkdf apps.SecretSource, logger *slog.Logger) (apps.SecretSource, error) {
	switch {
	case storeSource == nil:
		return nil, errors.New("deploy source: the store source is nil")
	case hkdf == nil:
		return nil, errors.New("deploy source: the HKDF source is nil")
	case logger == nil:
		return nil, errors.New("deploy source: the logger is nil")
	}
	if monitor == nil {
		return hkdf, nil
	}
	gate, err := storestate.NewGate(storeSource, monitor, logger)
	if err != nil {
		return nil, err
	}
	return gate, nil
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
