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
// key (#803), the store's first init (#804) and the store provisioner (#805)
// each write a record under /run that the api turns into a job and, when it
// failed or cannot be read, a crit alert.

const (
	// outcomeRunDir is where rasputin-os writes the records.
	outcomeRunDir = "/run"
	// procBootIDPath is the kernel's boot id for this boot.
	procBootIDPath = "/proc/sys/kernel/random/boot_id"
	// storeProvisionUnit is #805's oneshot; every store start pulls it in.
	storeProvisionUnit = "rasputin-store-provision.service"
)

// outcomeSources are the declared records, under runDir. observeInit is
// given each parsed os.store_init record: the empty-store marker's
// ObserveInit (#765).
func outcomeSources(runDir string, observeInit func(context.Context, osoutcome.Record)) []osoutcome.Source {
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
			Observe:           observeInit,
		},
		{
			Kind:     "os.store_provision",
			Path:     filepath.Join(runDir, "rasputin-store-provision", "outcome"),
			Fields:   []string{osoutcome.FieldBootID, osoutcome.FieldRunID, osoutcome.FieldReason},
			KeyField: osoutcome.FieldRunID,
			Outcomes: map[string]osoutcome.Verdict{
				"applied": osoutcome.OK, "unchanged": osoutcome.OK, "failed": osoutcome.Alert,
			},
			Title:             "The secret store's provisioning failed",
			AfterStoreRestart: true,
			StartUnit:         storeProvisionUnit,
		},
	}
}

// outcomeReaderWiring builds the reader over the records under runDir, with
// the api's boot id read from bootIDPath, units started through run, and the
// store's init record observed by observeInit (required).
func outcomeReaderWiring(ledger osoutcome.Ledger, logger *slog.Logger, runDir, bootIDPath string, run runFunc,
	observeInit func(context.Context, osoutcome.Record)) (*osoutcome.Reader, error) {
	if run == nil {
		return nil, errors.New("os outcomes: the run func is nil")
	}
	if observeInit == nil {
		return nil, errors.New("os outcomes: the store init observer is nil")
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
	}, outcomeSources(runDir, observeInit))
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
