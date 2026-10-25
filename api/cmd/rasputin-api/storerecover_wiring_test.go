package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storerecover"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-874-14: storeUnitState runs exactly systemctl show for the store unit's
// ActiveState and returns the trimmed state, or an error naming the unit.
func TestStoreUnitState(t *testing.T) {
	want := []string{"systemctl", "show", "--property=ActiveState", "--value", "openbao.service"}
	for _, tc := range []struct{ out, state string }{
		{"failed\n", "failed"}, {"inactive", "inactive"}, {"activating\n", "activating"}, {"active", "active"}, {"", ""},
	} {
		var argv []string
		run := func(_ context.Context, name string, args ...string) ([]byte, error) {
			argv = append([]string{name}, args...)
			return []byte(tc.out), nil
		}
		got, err := storeUnitState(run)(t.Context())
		if err != nil || got != tc.state {
			t.Errorf("out %q: state %q, %v, want %q", tc.out, got, err, tc.state)
		}
		if !slices.Equal(argv, want) {
			t.Errorf("argv = %q, want %q", argv, want)
		}
	}
	run := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("exit status 1") }
	if _, err := storeUnitState(run)(t.Context()); err == nil || !strings.Contains(err.Error(), "openbao.service") {
		t.Errorf("err = %v, want one naming the unit", err)
	}
}

// recoverDeps is a complete set of wiring inputs for mode, over a recorded run.
func recoverDeps(t *testing.T, mode string, run runFunc, after func(context.Context)) storeRecoverDeps {
	t.Helper()
	log, _ := logkittest.New()
	mon, err := storestate.New(storestate.Deps{
		Store: secretstore.Disabled{}, Now: time.Now, Log: log,
		JobRunning: func(context.Context, string) (bool, error) { return false, nil },
		Blank:      func(context.Context) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return storeRecoverDeps{mode: mode, dataDir: t.TempDir(), monitor: mon, restores: noRestores{}, run: run, afterStoreRestart: after, log: log}
}

// TC-874-15: the recovery workflow is registered in every mode; its scheduler
// entry, on the audit's one-minute check with a Due gate, and its start-time
// Arm exist only under openbao, where the step restarts the store unit.
func TestStoreRecoverWiring(t *testing.T) {
	for _, mode := range []string{storeModeOff, storeModeMock, storeModeOpenBao} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var calls []string
			run := func(_ context.Context, name string, args ...string) ([]byte, error) {
				mu.Lock()
				defer mu.Unlock()
				calls = append(calls, name+" "+strings.Join(args, " "))
				if slices.Contains(args, "show") {
					return []byte("failed\n"), nil
				}
				return nil, nil
			}
			restarted := 0
			w, err := storeRecoverWiring(recoverDeps(t, mode, run, func(context.Context) { restarted++ }))
			if err != nil {
				t.Fatal(err)
			}
			if w.workflow.Kind != storerecover.Kind || len(w.workflow.Steps) != 1 {
				t.Fatalf("workflow = %q with %d steps", w.workflow.Kind, len(w.workflow.Steps))
			}
			entries := w.entries()
			_, stepErr := w.workflow.Steps[0].Do(&jobs.StepCtx{Ctx: t.Context(), JobID: "job-1"})
			if mode != storeModeOpenBao {
				if len(entries) != 0 || w.arm != nil {
					t.Errorf("entries %+v, arm set %v: want neither outside openbao", entries, w.arm != nil)
				}
				w.start(t.Context()) // nothing to start
				if stepErr == nil || len(calls) != 0 {
					t.Errorf("step outside openbao = %v with calls %q, want a refusal and no command", stepErr, calls)
				}
				return
			}
			if len(entries) != 1 {
				t.Fatalf("entries = %+v, want the recovery's", entries)
			}
			e := entries[0]
			if e.Kind != storerecover.Kind || e.Interval != storeAuditCheckEvery || e.Due == nil || e.InitialDelay != 0 {
				t.Errorf("entry = %+v", e)
			}
			if w.arm == nil {
				t.Fatal("no start-time Arm under openbao")
			}
			// The temp dir has room, so the start-time reading arms nothing.
			w.start(t.Context())
			if stepErr != nil {
				t.Fatalf("step = %v", stepErr)
			}
			if !slices.Contains(calls, "systemctl restart openbao.service") || restarted != 1 {
				t.Errorf("calls %q, after-restart %d: want the unit restarted once", calls, restarted)
			}
		})
	}
}

// storeRecoverWiring refuses a missing collaborator under openbao and a nil
// logger in any mode.
func TestStoreRecoverWiring_Refuses(t *testing.T) {
	run := func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	d := recoverDeps(t, storeModeOpenBao, run, noRestartHook)
	d.monitor = nil
	if _, err := storeRecoverWiring(d); err == nil {
		t.Error("openbao with no monitor = nil error")
	}
	d = recoverDeps(t, storeModeOff, run, noRestartHook)
	d.log = nil
	if _, err := storeRecoverWiring(d); err == nil {
		t.Error("nil logger = nil error")
	}
}
