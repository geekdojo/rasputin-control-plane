package main

import (
	"context"
	"crypto/rand"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// tlsValue is a stand-in token.
func tlsValue() secret.Value { return secret.New([]byte("test-token")) }

type noRestores struct{}

func (noRestores) Active() (string, bool) { return "", false }

// sealDeps is a complete set of wiring inputs for mode.
func sealDeps(t *testing.T, mode string) sealRotateDeps {
	t.Helper()
	log, _ := logkittest.New()
	ca, err := tlsca.Ensure(tlsca.StoreConfig(), t.TempDir(), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	mon, err := storestate.New(storestate.Deps{
		Store: secretstore.Disabled{}, Now: time.Now, Log: log,
		JobRunning: func(context.Context, string) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return sealRotateDeps{
		mode: mode, addr: "https://127.0.0.1:8200", storeCA: ca, store: secretstore.Disabled{},
		run:        func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
		monitor:    mon,
		restores:   noRestores{},
		jobRunning: func(context.Context, string) (bool, error) { return false, nil },
		rand:       rand.Reader, now: time.Now, log: log,
		afterStoreRestart: noRestartHook,
	}
}

// TC-830-14: the workflow is registered in every mode and never scheduled;
// under openbao the capture lock is the rotator's gate and SetStoreAlerts
// gets the joined source; outside it there is no lock and readiness passes
// through unchanged.
func TestSealRotateWiring_EveryMode(t *testing.T) {
	readiness := func(context.Context, time.Time) []proto.Alert {
		return []proto.Alert{{ID: "secret-store:sealed"}}
	}
	for _, mode := range []string{storeModeOpenBao, storeModeMock, storeModeOff} {
		t.Run(mode, func(t *testing.T) {
			w, err := sealRotateWiring(sealDeps(t, mode))
			if err != nil {
				t.Fatal(err)
			}
			if w.workflow.Kind != sealrotate.Kind || len(w.workflow.Steps) != 6 || w.workflow.OnTerminal == nil {
				t.Fatalf("workflow = %q with %d steps", w.workflow.Kind, len(w.workflow.Steps))
			}
			if w.storeAlerts(nil) != nil {
				t.Error("a store-alert source with no readiness source")
			}
			got := w.storeAlerts(readiness)(t.Context(), time.Now())
			if mode != storeModeOpenBao {
				if w.captureLock() != nil || w.gate != nil {
					t.Error("a capture lock outside openbao")
				}
				if len(got) != 1 {
					t.Errorf("alerts = %+v, want readiness's alone", got)
				}
				return
			}
			if w.gate == nil || w.captureLock() != w.gate {
				t.Fatal("RunConfig.CaptureLock is not the rotator's gate")
			}
			// The production seal dir is absent here, so the incomplete
			// alert reads the unreadable tree and joins readiness's.
			ids := []string{}
			for _, a := range got {
				ids = append(ids, a.ID)
			}
			if !slices.Equal(ids, []string{"secret-store:sealed", sealrotate.IncompleteAlertID}) {
				t.Errorf("joined alerts = %v", ids)
			}
		})
	}
	// Never scheduled: no entry main builds has the rotation's kind.
	entries := append(reconcileEntries(time.Minute, time.Minute, time.Minute, time.Minute),
		backupRunEntry(time.Hour, func(context.Context) (bool, string) { return false, "" }))
	aud, err := storeAuditWiring(storeModeOpenBao, t.TempDir(), secretstore.Disabled{},
		func(context.Context, string, ...string) ([]byte, error) { return nil, nil }, sealDeps(t, storeModeOff).log)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range append(entries, aud.entries()...) {
		if e.Kind == sealrotate.Kind {
			t.Errorf("a scheduler entry has kind %s", e.Kind)
		}
	}
}

// TC-830-14, F-830-04: in mock mode a submitted rotation (what POST /api/jobs
// does, through SubmitRawSpec) is a job, not "unknown job kind", and it fails
// at validate with the not-openbao sentence and a job-failed record.
func TestSealRotateWiring_MockModeRecordsAJob(t *testing.T) {
	w, err := sealRotateWiring(sealDeps(t, storeModeMock))
	if err != nil {
		t.Fatal(err)
	}
	js := openJobStore(t)
	r := jobs.NewRunner(js, nil)
	r.Register(w.workflow)
	j, err := r.SubmitRawSpec(t.Context(), sealrotate.Kind, nil, "operator")
	if err != nil {
		t.Fatalf("submit = %v, want a job", err)
	}
	r.Wait()
	got, err := js.GetJob(t.Context(), j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != jobs.StatusFailed || got.Error == "" || got.Error[0] != 'T' {
		t.Fatalf("job %s: %q", got.Status, got.Error)
	}
}

// TC-830-14: wiring refuses what it cannot build with.
func TestSealRotateWiring_Refuses(t *testing.T) {
	for name, mut := range map[string]func(*sealRotateDeps){
		"nil logger":        func(d *sealRotateDeps) { d.log = nil },
		"nil store CA":      func(d *sealRotateDeps) { d.storeCA = nil },
		"nil monitor":       func(d *sealRotateDeps) { d.monitor = nil },
		"nil store":         func(d *sealRotateDeps) { d.store = nil },
		"nil run":           func(d *sealRotateDeps) { d.run = nil },
		"nil restores":      func(d *sealRotateDeps) { d.restores = nil },
		"nil jobRunning":    func(d *sealRotateDeps) { d.jobRunning = nil },
		"nil rand":          func(d *sealRotateDeps) { d.rand = nil },
		"nil clock":         func(d *sealRotateDeps) { d.now = nil },
		"nil restart hook":  func(d *sealRotateDeps) { d.afterStoreRestart = nil },
		"a refused address": func(d *sealRotateDeps) { d.addr = "http://example.com" },
	} {
		d := sealDeps(t, storeModeOpenBao)
		mut(&d)
		if _, err := sealRotateWiring(d); err == nil {
			t.Errorf("%s: wiring accepted", name)
		}
	}
}

// The off-mode stand-ins all refuse.
func TestOffSealDeps_Refuse(t *testing.T) {
	log, _ := logkittest.New()
	d := offSealDeps(log)
	ctx := context.Background()
	off := offSeal{}
	if _, err := off.CertLogin(ctx, "r"); err == nil {
		t.Error("CertLogin")
	}
	if off.RotateRoot(ctx, tlsValue()) == nil || d.Restart(ctx) == nil {
		t.Error("RotateRoot or Restart")
	}
	if _, err := off.State(); err == nil {
		t.Error("State")
	}
	if off.WriteRotationKey("", tlsValue()) == nil || off.WriteSealKey(tlsValue()) == nil ||
		off.WriteFragment(sealrotate.Fragment{}) == nil || off.RemoveRotation() == nil || off.TryAcquire("j") == nil {
		t.Error("a write")
	}
	if _, err := off.ReadRotationKey(""); err == nil {
		t.Error("ReadRotationKey")
	}
	if _, err := off.Read(make([]byte, 1)); err == nil {
		t.Error("Read")
	}
	if _, err := d.KeyID(); err == nil {
		t.Error("KeyID")
	}
	if _, err := d.JobRunning(ctx, "j"); err == nil {
		t.Error("JobRunning")
	}
	off.Release("j")
	d.Quiesce("j", storestate.QuiesceSealRotation)()
	if off.RotationHolder() != "" {
		t.Error("RotationHolder")
	}
	if _, active := off.Active(); active {
		t.Error("Active")
	}
}

// TC-833-30 (F-833-01): the rotator's store restart runs the after-restart
// hook once, after the store's reset-failed/restart pair.
func TestSealRotateWiring_RestartRunsTheHook(t *testing.T) {
	var mu sync.Mutex
	var order []string
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }
	d := sealDeps(t, storeModeOpenBao)
	d.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		note(strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	}
	d.afterStoreRestart = func(context.Context) { note("hook") }
	w, err := sealRotateWiring(d)
	if err != nil {
		t.Fatal(err)
	}
	if w.restart == nil {
		t.Fatal("no restart under openbao")
	}
	if err := w.restart(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := append(slices.Clone(restartPair), "hook")
	if !slices.Equal(order, want) {
		t.Errorf("order = %v, want %v", order, want)
	}
	off, err := sealRotateWiring(sealDeps(t, storeModeMock))
	if err != nil || off.restart != nil {
		t.Errorf("mock mode: restart %v, err %v; want none", off.restart != nil, err)
	}
}
