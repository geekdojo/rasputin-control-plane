package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storeaudit"
	"github.com/geekdojo/rasputin-control-plane/api/internal/sysunit"
	"github.com/geekdojo/rasputin-control-plane/api/internal/unitrecover"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The identity service's state, alerts and full-disk recovery
// (geekdojo/geekdojo-brain#979, Identity 3.3), under keycloak only.
//
// The files below are the contract with keycloak.service's hooks, which
// rasputin-os builds (Identity 2.5, #973; the plan's "Contract for #973"):
//
//   - ExecStartPost= waits for /health/started, then removes the start-hold
//     count file; it exits non-zero as soon as Keycloak's main process
//     ($MAINPID) is gone, and the unit's TimeoutStartSec= is bounded rather
//     than infinity, so a crash during start never leaves the unit
//     activating. So active means started. The api never reads or removes
//     the count file.
//   - ExecStopPost= writes one exit record per invocation into
//     identityExitsDir, then the `last` pointer. The api consumes the records
//     and never writes `last`.
//   - ExecStartPre='s start hold writes identityStartHoldPath when it refuses
//     a start.
//   - The version gate writes identityVersionMarker.

const (
	// identityExitsDir holds keycloak.service's exit records.
	identityExitsDir = "/run/rasputin-identity-exits"
	// identityStartHoldPath is the start hold's record.
	identityStartHoldPath = "/run/rasputin-identity-start-hold/outcome"
	// identityVersionMarker is the version gate's marker (lifecycle.md §1.4).
	identityVersionMarker = "/var/lib/rasputin/identity/keycloak-version"
	// identityRecoverKind is the full-disk recovery's workflow kind.
	identityRecoverKind = "identity.recover"
)

// identityFactAbsent stands in for an identity fact whose producer is a later
// story; it is never raised.
func identityFactAbsent(context.Context) (bool, error) { return false, nil }

// identityStateDeps is what the identity state's wiring takes from main.
type identityStateDeps struct {
	mode     string
	client   identitystate.Health
	ledger   identitystate.Ledger
	settings identitystate.Settings
	// outcomes reads one declared outcome kind (osoutcome.Reader.ReadKind).
	outcomes interface {
		ReadKind(ctx context.Context, kind string) error
	}
	jobRunning func(ctx context.Context, jobID string) (bool, error)
	run        runFunc
	// fsys is the file system rooted at "/" (os.DirFS("/")), remove removes
	// a file (os.Remove) and free reads a directory's free bytes
	// (storage.FreeBytes).
	fsys     fs.FS
	remove   func(name string) error
	free     func(dir string) (uint64, error)
	dataDir  string
	restores interface{ Active() (string, bool) }
	now      func() time.Time
	log      *slog.Logger
}

// identityState is what identityStateWiring built. Every field is nil
// outside keycloak: no other mode has an identity service.
type identityState struct {
	monitor  *identitystate.Monitor
	workflow *jobs.Workflow
	entry    *scheduler.Entry
	arm      func(context.Context)
}

// register registers identity.recover, a System job, so POST /api/jobs
// refuses it.
func (w identityState) register(r interface{ Register(jobs.Workflow) }) {
	if w.workflow != nil {
		r.Register(*w.workflow)
	}
}

// entries is the scheduler entries to append: the recovery's, or none.
func (w identityState) entries() []scheduler.Entry {
	if w.entry == nil {
		return nil
	}
	return []scheduler.Entry{*w.entry}
}

// start takes the recovery's reading on the fact of this start, in a
// goroutine of its own, as the store's does.
func (w identityState) start(ctx context.Context) {
	if w.arm != nil {
		go w.arm(ctx)
	}
}

// wireAlerts hands the monitor's alert to the alerts aggregator.
func (w identityState) wireAlerts(svc interface {
	SetIdentityAlerts(func(context.Context, time.Time) []proto.Alert)
}) {
	if w.monitor != nil {
		svc.SetIdentityAlerts(w.monitor.Alerts)
	}
}

// identityStateWiring builds the monitor and identity.recover under keycloak.
// It does no I/O. An error is a programming error, which main treats as
// fatal.
func identityStateWiring(d identityStateDeps) (identityState, error) {
	if d.mode != identityModeKeycloak {
		return identityState{}, nil
	}
	if d.client == nil || d.ledger == nil || d.settings == nil || d.outcomes == nil || d.jobRunning == nil ||
		d.run == nil || d.fsys == nil || d.remove == nil || d.free == nil || d.restores == nil || d.now == nil || d.log == nil {
		return identityState{}, errors.New("identity state: a collaborator is nil under keycloak")
	}
	units := identitystate.SystemctlUnits(identitystate.RunFunc(d.run), identityUnit, identityDBUnit)
	log := d.log
	mon, err := identitystate.New(identitystate.Deps{
		Units:      units,
		Exits:      identitystate.ExitRecords(d.fsys, identityExitsDir),
		RemoveExit: identitystate.RemoveExitRecord(d.remove, identityExitsDir),
		Health:     d.client,
		Ledger:     d.ledger,
		ReadRecords: func(ctx context.Context) {
			for _, kind := range []string{identitystate.DBInitKind, identitystate.RollbackKind} {
				if err := d.outcomes.ReadKind(ctx, kind); err != nil {
					log.ErrorContext(ctx, "identity outcome record not read", "component", "identity", "kind", kind, "err", err.Error())
				}
			}
		},
		StartHold:  identitystate.StartHoldRecord(d.fsys, identityStartHoldPath),
		Marker:     identitystate.MarkerFile(d.fsys, identityVersionMarker),
		Settings:   d.settings,
		JobRunning: d.jobRunning,
		// Identity 5.7 (#1010) produces blank.
		Blank: identityFactAbsent,
		// Identity 7.3 (#1027) produces apps-paused.
		AppsPaused: identityFactAbsent,
		// Identity 4.3 (#985) produces history-behind.
		HistoryBehind: identityFactAbsent,
		Now:           d.now,
		Log:           log,
	})
	if err != nil {
		return identityState{}, fmt.Errorf("identity state: %w", err)
	}
	rec, err := unitrecover.New(unitrecover.Deps{
		Kind: identityRecoverKind, Service: "sign-in service", Component: "identity",
		Dir: d.dataDir, Free: d.free, FullBelow: storeaudit.FreeCritBelow,
		Unit:      identityUnit,
		UnitState: identitystate.PairStateOf(units),
		Held:      mon.Held,
		Restoring: d.restores.Active,
		Restart: func(ctx context.Context) error {
			return sysunit.RestartUnits(ctx, d.run, []string{identityDBUnit, identityUnit}, identityUnit)
		},
		Log:         log,
		StepTimeout: identityRecoverStepTimeout,
	})
	if err != nil {
		return identityState{}, fmt.Errorf("identity state: %w", err)
	}
	wf := rec.Workflow()
	wf.System = true
	return identityState{
		monitor:  mon,
		workflow: &wf,
		entry:    &scheduler.Entry{Kind: identityRecoverKind, Interval: storeAuditCheckEvery, Due: rec.Due},
		arm:      rec.Arm,
	}, nil
}
