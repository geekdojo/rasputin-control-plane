package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storemigrate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/sysunit"
)

// The secret store's roll-forward (geekdojo/geekdojo-brain#1132): a store
// initialised before rasputin-os 2026.11.3 has no rasputin-author role, and
// is re-initialised with every entry the api can reach copied across. Wired
// only under openbao; under the mock or off nothing is wired, and the Hold
// that stands in front of the secrets service is never put on.

// storeMigrateHeld puts the Hold in front of the secrets service's two
// sessions under openbao, and returns them unchanged otherwise.
func storeMigrateHeld(mode string, hold *storemigrate.Hold, kv secrets.Store, keys secrets.TransitStore) (secrets.Store, secrets.TransitStore) {
	if mode != storeModeOpenBao {
		return kv, keys
	}
	return hold.KV(kv), hold.Transit(keys)
}

// storeMigrateRecover runs storemigrate.Recover under openbao, restarting
// the store through control. main runs it before the secrets service, the
// app relay and the job runner are built.
func storeMigrateRecover(ctx context.Context, mode string, files storemigrate.Files, control storage.SecretStore, log *slog.Logger) error {
	if mode != storeModeOpenBao {
		return nil
	}
	if control == nil {
		return errors.New("store migration: the store control is nil under openbao")
	}
	return storemigrate.Recover(ctx, storemigrate.RecoverDeps{Files: files, Start: control.Start, Log: log})
}

// outcomeRecords reads the store's provision and migrate records from their
// declared files, for the migration, which acts on the record's fact.
type outcomeRecords struct {
	provision, migrate osoutcome.Source
}

// newOutcomeRecords finds the two declarations under runDir.
func newOutcomeRecords(runDir string) (outcomeRecords, error) {
	var out outcomeRecords
	found := 0
	for _, s := range outcomeSources(runDir, outcomeObservers{}) {
		switch s.Kind {
		case storeProvisionKind:
			out.provision = s
			found++
		case storeMigrateKind:
			out.migrate = s
			found++
		}
	}
	if found != 2 {
		return outcomeRecords{}, errors.New("store migration: the provision or migrate record is not declared")
	}
	return out, nil
}

// Provision reads the provision record now.
func (r outcomeRecords) Provision() (osoutcome.Record, error) { return osoutcome.ReadFile(r.provision) }

// Migrate reads the migrate record now.
func (r outcomeRecords) Migrate() (osoutcome.Record, error) { return osoutcome.ReadFile(r.migrate) }

// storeUnitProps reads the store unit's systemd properties through run.
func storeUnitProps(run runFunc) func(ctx context.Context) (sysunit.Unit, error) {
	return func(ctx context.Context) (sysunit.Unit, error) {
		u, err := sysunit.Show(ctx, run, storeUnit)
		if err != nil {
			return sysunit.Unit{}, err
		}
		return u[0], nil
	}
}

// storeMigrateDeps is what the roll-forward's wiring takes from main.
type storeMigrateDeps struct {
	mode      string
	hold      *storemigrate.Hold
	files     storemigrate.Files
	provision *storemigrate.LastRecord
	inventory storemigrate.Inventory
	// repo reads and writes over the raw store session, not the Hold.
	repo     storemigrate.Repo
	control  storage.SecretStore
	lock     storage.CaptureLock
	marker   storemigrate.Marker
	settings storemigrate.Settings
	records  storemigrate.Records
	run      runFunc
	bootID   func() (string, error)
	monitor  storemigrate.Ready
	runner   rollbackRunner
	// check submits the reference check (storeRollback.check).
	check func(context.Context)
	log   *slog.Logger
}

// storeMigrate is what storeMigrateWiring built.
type storeMigrate struct {
	// arm runs the store's first-ready coordinator; main runs it after the
	// start-time outcome read. It does nothing outside openbao.
	arm func(ctx context.Context)
}

// storeMigrateWiring builds the trigger and the migration job and registers
// the job, under openbao. The trigger is the one first-ready callback: it
// replaces the reference check's own (F-1132-05).
func storeMigrateWiring(d storeMigrateDeps) (storeMigrate, error) {
	off := storeMigrate{arm: func(context.Context) {}}
	if d.mode != storeModeOpenBao {
		return off, nil
	}
	switch {
	case d.control == nil || d.lock == nil:
		return off, errors.New("store migration: the store control or the capture gate is nil under openbao")
	case d.provision == nil || d.runner == nil || d.check == nil || d.run == nil:
		return off, errors.New("store migration: a collaborator is nil")
	}
	trigger, err := storemigrate.NewTrigger(storemigrate.TriggerDeps{
		Ready: d.monitor, Runner: d.runner, Settings: d.settings, BootID: d.bootID,
		Provision: d.provision.Last, Check: d.check, Log: d.log,
	})
	if err != nil {
		return off, fmt.Errorf("store migration: %w", err)
	}
	m, err := storemigrate.New(storemigrate.Deps{
		Inventory: d.inventory, Repo: d.repo, Control: d.control, Lock: d.lock, Marker: d.marker,
		Settings: d.settings, Records: d.records, StoreUnit: storeUnitProps(d.run), Files: d.files,
		BootID: d.bootID, Hold: d.hold, AfterTerminal: trigger.ReferenceCheck, Log: d.log,
	})
	if err != nil {
		return off, fmt.Errorf("store migration: %w", err)
	}
	d.runner.Register(m.Workflow())
	return storeMigrate{arm: trigger.Arm}, nil
}
