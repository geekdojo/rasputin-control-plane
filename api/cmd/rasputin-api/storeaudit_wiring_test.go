package main

import (
	"context"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storeaudit"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-799-26: the rotation's scheduler entry, with its Due gate, exists only
// when the store is openbao; the workflow and the disk-alert source exist in
// every mode.
func TestStoreAuditWiring(t *testing.T) {
	log, _ := logkittest.New()
	run := func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	for _, mode := range []string{storeModeOpenBao, storeModeOff, storeModeMock} {
		t.Run(mode, func(t *testing.T) {
			w, err := storeAuditWiring(mode, t.TempDir(), secretstore.Disabled{}, run, log)
			if err != nil {
				t.Fatal(err)
			}
			if w.workflow.Kind != storeaudit.RotateKind || len(w.workflow.Steps) != 2 {
				t.Errorf("workflow = %q with %d steps", w.workflow.Kind, len(w.workflow.Steps))
			}
			if w.diskAlerts == nil {
				t.Error("no disk-alert source")
			} else {
				_ = w.diskAlerts(time.Now()) // reads the real temp dir's free space
			}
			entries := w.entries()
			if mode != storeModeOpenBao {
				if len(entries) != 0 {
					t.Errorf("entries = %+v, want none outside openbao", entries)
				}
				return
			}
			if len(entries) != 1 {
				t.Fatalf("entries = %+v, want the rotation's", entries)
			}
			e := entries[0]
			if e.Kind != storeaudit.RotateKind || e.Due == nil || e.Interval != time.Minute {
				t.Errorf("entry = %+v", e)
			}
			// The gate is the rotator's: an empty data dir is not due.
			if due, reason := e.Due(t.Context()); due || reason != "" {
				t.Errorf("Due on an empty data dir = %v, %q", due, reason)
			}
		})
	}
}

// storeAuditWiring refuses a store it cannot ask.
func TestStoreAuditWiring_RefusesNilStore(t *testing.T) {
	log, _ := logkittest.New()
	if _, err := storeAuditWiring(storeModeOpenBao, t.TempDir(), nil, nil, log); err == nil {
		t.Error("storeAuditWiring with a nil store = nil error")
	}
	if _, err := storeAuditWiring(storeModeOpenBao, "", secretstore.Disabled{}, nil, log); err == nil {
		t.Error("storeAuditWiring with an empty data dir = nil error")
	}
}
