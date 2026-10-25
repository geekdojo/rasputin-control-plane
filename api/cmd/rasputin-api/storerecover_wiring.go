package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storerecover"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storeaudit"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// storeRecoverDeps is what the full-disk recovery's wiring takes from main
// (geekdojo/geekdojo-brain#874).
type storeRecoverDeps struct {
	mode    string
	dataDir string
	// monitor is the store's readiness monitor; nil when no backend was
	// requested, and required under openbao.
	monitor  *storestate.Monitor
	restores interface{ Active() (string, bool) }
	run      runFunc
	// afterStoreRestart runs once after the restart (#833); required under
	// openbao.
	afterStoreRestart func(context.Context)
	log               *slog.Logger
}

// storeRecover is what storeRecoverWiring built.
type storeRecover struct {
	// workflow is registered in every mode, so a recovery job recovered after
	// a mode change still finds its workflow.
	workflow jobs.Workflow
	// entry and arm are set only under openbao: no other mode has a store
	// unit.
	entry *scheduler.Entry
	arm   func(context.Context)
}

// entries is the scheduler entries to append: the recovery's, or none.
func (w storeRecover) entries() []scheduler.Entry {
	if w.entry == nil {
		return nil
	}
	return []scheduler.Entry{*w.entry}
}

// start takes the start-time reading in a goroutine of its own, so a store
// that failed while full before the api started is armed without waiting for
// the scheduler's first check (F-874-02). The trigger is the api's start; no
// delay is chosen. It does nothing outside openbao.
func (w storeRecover) start(ctx context.Context) {
	if w.arm == nil {
		return
	}
	go w.arm(ctx)
}

// errStoreRecoverOff is every stand-in's refusal outside openbao.
var errStoreRecoverOff = errors.New("store recovery: the secret store is not openbao")

// storeRecoverWiring builds the Recoverer in every mode. Under openbao it
// reads the data partition's free space, the store unit's state, the
// monitor's holds and the restore sessions, and restarts the unit the way the
// leaf reload does. Outside openbao it gets refusing stand-ins, and a job
// fails at its first read.
func storeRecoverWiring(d storeRecoverDeps) (storeRecover, error) {
	if d.log == nil {
		return storeRecover{}, errors.New("store recovery: the logger is nil")
	}
	deps := storerecover.Deps{
		Dir: d.dataDir, Free: storage.FreeBytes, FullBelow: storeaudit.FreeCritBelow,
		Unit: storeUnit, Log: d.log, StepTimeout: sealrotate.UnsealWait,
	}
	openbao := d.mode == storeModeOpenBao
	if openbao {
		if d.monitor == nil || d.restores == nil || d.run == nil || d.afterStoreRestart == nil {
			return storeRecover{}, errors.New("store recovery: a collaborator is nil under openbao")
		}
		unit := restartStoreUnit(d.run, d.afterStoreRestart)
		deps.UnitState = storeUnitState(d.run)
		deps.Held = d.monitor.Held
		deps.Restoring = d.restores.Active
		deps.Restart = func(ctx context.Context) error { return unit(ctx, tlsca.LeafPaths{}) }
	} else {
		deps.UnitState = func(context.Context) (string, error) { return "", errStoreRecoverOff }
		deps.Held = func(context.Context) bool { return true }
		deps.Restoring = func() (string, bool) { return "", false }
		deps.Restart = func(context.Context) error { return errStoreRecoverOff }
	}
	rec, err := storerecover.New(deps)
	if err != nil {
		return storeRecover{}, fmt.Errorf("store recovery: %w", err)
	}
	w := storeRecover{workflow: rec.Workflow()}
	if openbao {
		w.entry = &scheduler.Entry{Kind: storerecover.Kind, Interval: storeAuditCheckEvery, Due: rec.Due}
		w.arm = rec.Arm
	}
	return w, nil
}

// storeUnitState reads the store unit's systemd ActiveState through run.
func storeUnitState(run runFunc) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		out, err := run(ctx, "systemctl", "show", "--property=ActiveState", "--value", storeUnit)
		if err != nil {
			return "", fmt.Errorf("reading the state of %s: %w", storeUnit, err)
		}
		return strings.TrimSpace(string(out)), nil
	}
}
