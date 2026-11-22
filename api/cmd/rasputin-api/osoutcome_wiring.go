package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
)

// The OS's pre-api outcome records (geekdojo/geekdojo-brain#833): the seal
// key (#803), the store's first init (#804), the store provisioner (#805),
// the store's version gate (#801), the store's roll-forward (#1132), and the
// identity database's first-init gate (#975) and version gate (#1009) each
// write a record under /run that the api turns into a job and, when it
// failed or cannot be read, a crit alert.

const (
	// outcomeRunDir is where rasputin-os writes the records.
	outcomeRunDir = "/run"
	// procBootIDPath is the kernel's boot id for this boot.
	procBootIDPath = "/proc/sys/kernel/random/boot_id"
	// storeProvisionUnit is #805's oneshot; every store start pulls it in.
	storeProvisionUnit = "rasputin-store-provision.service"
	// storeProvisionKind and storeMigrateKind are the store provisioner's
	// and the store roll-forward's records (#805, #1132), which the
	// roll-forward also reads itself.
	storeProvisionKind = "os.store_provision"
	storeMigrateKind   = "os.store_migrate"
)

// outcomeObservers are the Observe hooks the declared records feed. Each is
// required.
type outcomeObservers struct {
	// init is given each parsed os.store_init record: the empty-store
	// marker's ObserveInit (#765).
	init func(context.Context, osoutcome.Record)
	// provision is given each parsed os.store_provision record: the store
	// roll-forward's trigger keeps the last (#1132).
	provision func(context.Context, osoutcome.Record)
	// migrate is given each parsed os.store_migrate record: the roll-forward's
	// Hold, released by it after an abort that could not confirm the old
	// tree is live (#1132).
	migrate func(context.Context, osoutcome.Record)
}

// outcomeSources are the declared records, under runDir, feeding obs.
func outcomeSources(runDir string, obs outcomeObservers) []osoutcome.Source {
	return []osoutcome.Source{
		{
			Kind:     "os.seal_key",
			Path:     filepath.Join(runDir, "rasputin-seal-key", "outcome"),
			Fields:   []string{osoutcome.FieldBootID, osoutcome.FieldKeyID, osoutcome.FieldReason},
			KeyField: osoutcome.FieldBootID,
			// refused never reaches the api (its unit gates the api's start),
			// but a record saying it is not misread as malformed.
			Outcomes: map[string]osoutcome.Verdict{
				"created": osoutcome.OK, "untouched": osoutcome.OK,
				"failed": osoutcome.Alert, "refused": osoutcome.Alert,
			},
			Title: "The secret store's seal key did not come up",
		},
		{
			Kind:              "os.store_init",
			Path:              filepath.Join(runDir, "rasputin-store-init", "outcome"),
			Fields:            []string{osoutcome.FieldBootID, osoutcome.FieldReason},
			KeyField:          osoutcome.FieldBootID,
			Outcomes:          map[string]osoutcome.Verdict{"initialised": osoutcome.OK, "failed": osoutcome.Alert},
			Title:             "The secret store did not initialise",
			AfterStoreRestart: true,
			Observe:           obs.init,
		},
		{
			// author (#1132) is whether the store holds the rasputin-author
			// role: absent on a store initialised before 2026.11.3, which the
			// roll-forward migrates; - when the run did not finish reading it.
			Kind: storeProvisionKind,
			Path: filepath.Join(runDir, "rasputin-store-provision", "outcome"),
			Fields: []string{osoutcome.FieldBootID, osoutcome.FieldRunID, osoutcome.FieldReason,
				osoutcome.FieldAuthor},
			KeyField: osoutcome.FieldRunID,
			Outcomes: map[string]osoutcome.Verdict{
				"applied": osoutcome.OK, "unchanged": osoutcome.OK, "failed": osoutcome.Alert,
			},
			Title:             "The secret store's provisioning failed",
			AfterStoreRestart: true,
			StartUnit:         storeProvisionUnit,
			Observe:           obs.provision,
		},
		{
			// The store's version gate (#801), run in every start of the
			// store before bao: current when the data is not newer than the
			// binary; restored when the pre-update copy was put back; refused
			// or failed when the store was held stopped. restored alerts too:
			// secrets written since the update are gone.
			Kind:     "os.store_rollback",
			Path:     filepath.Join(runDir, "rasputin-store-rollback", "outcome"),
			Fields:   []string{osoutcome.FieldBootID, osoutcome.FieldReason},
			KeyField: osoutcome.FieldBootID,
			Outcomes: map[string]osoutcome.Verdict{
				"current": osoutcome.OK, "restored": osoutcome.Alert,
				"refused": osoutcome.Alert, "failed": osoutcome.Alert,
			},
			Title:             "The secret store's data was rolled back, or the store was held stopped",
			AfterStoreRestart: true,
		},
		{
			// The store's roll-forward step (#1132), run in every start of
			// the store after the version gate: moved when it set the old
			// tree aside for a re-initialisation, finished when the api's
			// commit let it delete that tree, restored when it put the old
			// tree back, superseded when a restore's data replaced the
			// migration's, failed when the request could not be acted on. A
			// start with nothing to do writes no record. Keyed on run_id: a
			// boot can hold several starts.
			Kind:     storeMigrateKind,
			Path:     filepath.Join(runDir, "rasputin-store-migrate", "outcome"),
			Fields:   []string{osoutcome.FieldBootID, osoutcome.FieldRunID, osoutcome.FieldReason},
			KeyField: osoutcome.FieldRunID,
			Outcomes: map[string]osoutcome.Verdict{
				"moved": osoutcome.OK, "finished": osoutcome.OK,
				"restored": osoutcome.Alert, "superseded": osoutcome.Alert, "failed": osoutcome.Alert,
			},
			Title:             "The secret store's upgrade did not finish",
			AfterStoreRestart: true,
			Observe:           obs.migrate,
		},
		{
			// The identity database's first-init gate (#975), run in every
			// start of keycloak-db.service: created on a first start,
			// untouched on every other, refused when it would not initialise
			// over data it found. Read at start and on each new database run
			// the identity state monitor sees (geekdojo/geekdojo-brain#979).
			Kind:     "os.identity_db_init",
			Path:     filepath.Join(runDir, "rasputin-identity-db-init", "outcome"),
			Fields:   []string{osoutcome.FieldBootID, osoutcome.FieldReason},
			KeyField: osoutcome.FieldBootID,
			Outcomes: map[string]osoutcome.Verdict{
				"created": osoutcome.OK, "untouched": osoutcome.OK, "refused": osoutcome.Alert,
			},
			Title: "The sign-in service's database did not start",
		},
		{
			// The identity data's version gate (#1009, lifecycle.md §1.4),
			// run in every start of keycloak-db.service: current when the data
			// is not newer than this slot; restored when the pre-update copy
			// was put back; refused or failed when the pair was held stopped.
			// restored alerts too: changes made since the update are only in
			// the set-aside copy.
			Kind:     "os.identity_rollback",
			Path:     filepath.Join(runDir, "rasputin-identity-rollback", "outcome"),
			Fields:   []string{osoutcome.FieldBootID, osoutcome.FieldReason},
			KeyField: osoutcome.FieldBootID,
			Outcomes: map[string]osoutcome.Verdict{
				"current": osoutcome.OK, "restored": osoutcome.Alert,
				"refused": osoutcome.Alert, "failed": osoutcome.Alert,
			},
			Title: "The sign-in service's data was rolled back, or sign-in was held stopped",
		},
	}
}

// outcomeReaderWiring builds the reader over the records under runDir, with
// the api's boot id read from bootIDPath, units started through run, and the
// records observed by obs (each required).
func outcomeReaderWiring(ledger osoutcome.Ledger, logger *slog.Logger, runDir, bootIDPath string, run runFunc,
	obs outcomeObservers) (*osoutcome.Reader, error) {
	if run == nil {
		return nil, errors.New("os outcomes: the run func is nil")
	}
	if obs.init == nil || obs.provision == nil || obs.migrate == nil {
		return nil, errors.New("os outcomes: a record observer is nil")
	}
	r, err := osoutcome.New(osoutcome.Deps{
		Ledger: ledger,
		Log:    logger,
		Now:    time.Now,
		BootID: fileBootID(bootIDPath),
		StartUnit: func(ctx context.Context, unit string) error {
			out, err := run(ctx, "systemctl", "start", unit)
			if err != nil {
				return fmt.Errorf("systemctl start %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
			}
			return nil
		},
	}, outcomeSources(runDir, obs))
	if err != nil {
		return nil, fmt.Errorf("os outcomes: %w", err)
	}
	return r, nil
}

// fileBootID reads the boot id at path on each call.
func fileBootID(path string) func() (string, error) {
	return func() (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		id := strings.TrimSpace(string(b))
		if id == "" {
			return "", fmt.Errorf("%s is empty", path)
		}
		return id, nil
	}
}

// wireOutcomeAlerts hands the records' alert, and the kinds it covers, to the
// alerts aggregator.
func wireOutcomeAlerts(svc *alerts.Service, r *osoutcome.Reader) {
	svc.SetOutcomeAlerts(r.Kinds(), r.Alerts)
}

// readyAfterOutcomes reads the records, then arms the empty-store marker on
// what the read recorded (#765), and only then declares the api ready, so
// the seal-key job is committed before READY=1 (#853 orders on it).
func readyAfterOutcomes(ctx context.Context, r interface{ ReadAtStart(context.Context) }, arm func(context.Context), ready func()) {
	r.ReadAtStart(ctx)
	arm(ctx)
	ready()
}

// rebaseAfterRestore re-bases the empty-store marker on this boot when the
// restore this start applied carried the store (#765): the restored
// database's marker names the backed-up cluster's boot. It runs right after
// the restore is recorded, before any outcome read.
func rebaseAfterRestore(ctx context.Context, m interface{ Rebase(context.Context) }, rep *storage.RestoreReport) {
	if rep != nil && rep.RestoredStore() {
		m.Rebase(ctx)
	}
}

// restoreRestartHook is the prepared restore's restart: under openbao the
// store unit is stopped first, so the store's own start step applies the
// staged store before the store runs again (S15 part 5). A stop that fails
// is one ERROR and the exit goes ahead: the next start refuses until a
// reboot applies the store.
func restoreRestartHook(logger *slog.Logger, backend string, run runFunc, exit func()) func() {
	return func() {
		if backend == storeModeOpenBao {
			ctx, cancel := context.WithTimeout(context.Background(), storeCallTimeout)
			out, err := run(ctx, "systemctl", "stop", storeUnit)
			cancel()
			if err != nil {
				logger.Error("restore: stopping the secret store before the restart failed",
					"event", "storage.restore_store_stop_failed", "unit", storeUnit,
					"err", fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out))))
			}
		}
		exit()
	}
}
