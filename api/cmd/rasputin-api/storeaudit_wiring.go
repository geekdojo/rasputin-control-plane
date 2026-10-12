package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storeaudit"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// storeAuditCheckEvery is how often the scheduler asks the rotator's Due gate
// whether the audit file has passed its size. The gate decides; the interval
// only sets how soon a crossed threshold is seen (timer-audit row K03).
const storeAuditCheckEvery = time.Minute

// storeAudit is what storeAuditWiring built (geekdojo/geekdojo-brain#799).
type storeAudit struct {
	// workflow is registered in every mode, so a rotation job recovered after
	// a mode change still finds its workflow.
	workflow jobs.Workflow
	// entry is the rotation's scheduler entry, set only when the store is
	// openbao: no other mode has an audit file.
	entry *scheduler.Entry
	// diskAlerts is the data partition's free-space alert source, in every
	// mode: the partition holds the api's database and Docker as well as the
	// store.
	diskAlerts func(time.Time) []proto.Alert
}

// storeAuditWiring builds the audit rotator and the free-space alert over
// dataDir. The rotator reopens the audit file by signalling storeUnit through
// run.
func storeAuditWiring(mode, dataDir string, store storeaudit.Store, run runFunc, logger *slog.Logger) (storeAudit, error) {
	rot, err := storeaudit.NewRotator(storeaudit.Defaults(dataDir), storeaudit.Deps{
		Store:  store,
		Reopen: storeaudit.SystemdReopener(storeaudit.RunFunc(run), storeUnit),
		Files:  storeaudit.OSFiles{},
		Log:    logger,
	})
	if err != nil {
		return storeAudit{}, fmt.Errorf("store audit: %w", err)
	}
	free, err := storeaudit.NewFreeSpace(dataDir, storage.FreeBytes, logger)
	if err != nil {
		return storeAudit{}, fmt.Errorf("store audit: %w", err)
	}
	w := storeAudit{workflow: rot.Workflow(), diskAlerts: free.Alerts}
	if mode == storeModeOpenBao {
		w.entry = &scheduler.Entry{Kind: storeaudit.RotateKind, Interval: storeAuditCheckEvery, Due: rot.Due}
	}
	return w, nil
}

// entries is the scheduler entries to append: the rotation's, or none.
func (w storeAudit) entries() []scheduler.Entry {
	if w.entry == nil {
		return nil
	}
	return []scheduler.Entry{*w.entry}
}
