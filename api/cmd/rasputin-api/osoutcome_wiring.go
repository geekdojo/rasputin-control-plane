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

// outcomeSources are the declared records, under runDir.
func outcomeSources(runDir string) []osoutcome.Source {
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
// the api's boot id read from bootIDPath and units started through run.
func outcomeReaderWiring(ledger osoutcome.Ledger, logger *slog.Logger, runDir, bootIDPath string, run runFunc) (*osoutcome.Reader, error) {
	if run == nil {
		return nil, errors.New("os outcomes: the run func is nil")
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
	}, outcomeSources(runDir))
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

// readyAfterOutcomes reads the records and only then declares the api ready,
// so the seal-key job is committed before READY=1 (#853 orders on it).
func readyAfterOutcomes(ctx context.Context, r interface{ ReadAtStart(context.Context) }, ready func()) {
	r.ReadAtStart(ctx)
	ready()
}
