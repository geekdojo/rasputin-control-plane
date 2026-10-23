package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The functional tests for the OS outcome records (#833) run the composition
// root's own functions (outcomeSources, outcomeReaderWiring, wireOutcomeAlerts,
// wireSecretStore, startStoreSweep, restartStoreUnit, readyAfterOutcomes)
// against record fixtures under a temp run dir, over a real job ledger and a
// real alerts.Service. Restarting the api is a fresh Reader over the same
// database file.

const (
	fxBoot  = "0f3c5b2a-1d4e-4f6a-9b8c-7d6e5f4a3b2c"
	fxBoot2 = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	fxRun   = "0123456789abcdef0123456789abcdef"
	fxRun2  = "fedcba9876543210fedcba9876543210"
	fxKeyID = "rasputin-3e1c9a52-7b4d-4c8e-a0f1-2d3b4c5e6f70"
)

// outcomeEnv is one node: a run dir, a database file, and a boot id file.
type outcomeEnv struct {
	runDir, dbPath, bootIDPath string
	ledger                     *jobs.Store
}

func newOutcomeEnv(t *testing.T) *outcomeEnv {
	t.Helper()
	dir := t.TempDir()
	e := &outcomeEnv{runDir: filepath.Join(dir, "run"), dbPath: filepath.Join(dir, "jobs.db"), bootIDPath: filepath.Join(dir, "boot_id")}
	for _, d := range []string{"rasputin-seal-key", "rasputin-store-init", "rasputin-store-provision"} {
		if err := os.MkdirAll(filepath.Join(e.runDir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(e.bootIDPath, []byte(fxBoot2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.ledger = openLedgerAt(t, e.dbPath)
	return e
}

func openLedgerAt(t *testing.T, path string) *jobs.Store {
	t.Helper()
	js, err := jobs.OpenStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	return js
}

// reader is an api start: a fresh Reader over the same database file.
func (e *outcomeEnv) reader(t *testing.T, run runFunc) *osoutcome.Reader {
	t.Helper()
	log, _ := logkittest.New()
	r, err := outcomeReaderWiring(openLedgerAt(t, e.dbPath), log, e.runDir, e.bootIDPath, run, noObserve)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *outcomeEnv) write(t *testing.T, unit, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.runDir, unit, "outcome"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *outcomeEnv) count(t *testing.T, kind string) int {
	t.Helper()
	js, err := e.ledger.ListAllJobsByKind(t.Context(), kind)
	if err != nil {
		t.Fatal(err)
	}
	return len(js)
}

// alertsService is a real aggregator over the env's ledger with the outcome
// alert wired the way main wires it.
func (e *outcomeEnv) alertsService(t *testing.T, r *osoutcome.Reader) *alerts.Service {
	t.Helper()
	ctx, dir := context.Background(), t.TempDir()
	inv, err := inventory.OpenStore(ctx, filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	ap, err := apps.OpenStore(ctx, filepath.Join(dir, "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ap.Close() })
	st, err := setup.OpenStore(ctx, filepath.Join(dir, "setup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	no := func(context.Context) (bool, error) { return false, nil }
	svc := alerts.New(inv, e.ledger, ap, setup.NewService(st, setup.Probes{HasUsers: no, ConsoleRootSet: no}, "", "", ""), nil, nil, true)
	wireOutcomeAlerts(svc, r)
	return svc
}

// jobAlertIDs are List's os-outcome and job-failed alert IDs.
func jobAlertIDs(t *testing.T, svc *alerts.Service) []string {
	t.Helper()
	all, err := svc.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, a := range all {
		if strings.HasPrefix(a.ID, osoutcome.AlertIDPrefix) || strings.HasPrefix(a.ID, "job-failed:") {
			out = append(out, a.ID)
		}
	}
	return out
}

// outcomeRun is a runFunc that records each command and runs on for it.
type outcomeRun struct {
	mu    sync.Mutex
	calls []string
	on    func(cmd string)
	err   error
}

func (r *outcomeRun) run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	r.mu.Lock()
	r.calls = append(r.calls, cmd)
	r.mu.Unlock()
	if r.on != nil {
		r.on(cmd)
	}
	return []byte("unit output"), r.err
}

func (r *outcomeRun) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

func sealBody(outcome, boot string) string {
	return "outcome=" + outcome + "\nboot_id=" + boot + "\nkey_id=" + fxKeyID + "\nreason=The seal key said " + outcome + ".\n"
}

// The declarations are at the contract's paths under /run.
func TestOutcomeSources_Paths(t *testing.T) {
	var paths []string
	for _, s := range outcomeSources(outcomeRunDir, noObserve) {
		paths = append(paths, s.Path)
	}
	want := []string{"/run/rasputin-seal-key/outcome", "/run/rasputin-store-init/outcome", "/run/rasputin-store-provision/outcome"}
	if !slices.Equal(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
}

// TC-833-26: the seal-key record end to end. created and untouched are one
// job and no alert; failed is one job, one crit, and no job-failed warn. A
// restart in the same boot adds no job; a new boot adds one.
func TestFunctional_SealKeyOutcome(t *testing.T) {
	for _, tc := range []struct {
		outcome string
		alerts  []string
	}{
		{"created", nil},
		{"untouched", nil},
		{"failed", []string{"os-outcome:os.seal_key"}},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			e := newOutcomeEnv(t)
			e.write(t, "rasputin-seal-key", sealBody(tc.outcome, fxBoot))
			r := e.reader(t, (&outcomeRun{}).run)
			r.ReadAtStart(t.Context())
			if n := e.count(t, "os.seal_key"); n != 1 {
				t.Fatalf("%d jobs, want 1", n)
			}
			svc := e.alertsService(t, r)
			if got := jobAlertIDs(t, svc); !slices.Equal(got, tc.alerts) {
				t.Errorf("alerts = %v, want %v", got, tc.alerts)
			}
			e.reader(t, (&outcomeRun{}).run).ReadAtStart(t.Context())
			if n := e.count(t, "os.seal_key"); n != 1 {
				t.Errorf("same boot restart: %d jobs, want 1", n)
			}
			e.write(t, "rasputin-seal-key", sealBody(tc.outcome, fxBoot2))
			e.reader(t, (&outcomeRun{}).run).ReadAtStart(t.Context())
			if n := e.count(t, "os.seal_key"); n != 2 {
				t.Errorf("new boot: %d jobs, want 2", n)
			}
		})
	}
}

// TC-833-27: store init is recorded by the leaf reload's store restart, as
// the real wireSecretStore and startStoreSweep run it.
func TestFunctional_StoreInitAfterRestartHook(t *testing.T) {
	for _, tc := range []struct {
		outcome string
		alerts  []string
	}{
		{"initialised", nil},
		{"failed", []string{"os-outcome:os.store_init"}},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			e := newOutcomeEnv(t)
			// The store's first start writes the record; nothing else does.
			run := &outcomeRun{on: func(cmd string) {
				if cmd == "systemctl restart openbao.service" {
					e.write(t, "rasputin-store-init", "outcome="+tc.outcome+"\nboot_id="+fxBoot+"\nreason=Init said "+tc.outcome+".\n")
				}
			}}
			r := e.reader(t, run.run)
			r.ReadAtStart(t.Context())
			if n := e.count(t, "os.store_init"); n != 0 {
				t.Fatalf("before the restart: %d jobs, want 0", n)
			}
			log := slog.New(slog.DiscardHandler)
			w, err := wireSecretStore(t.Context(), log, storeModeOpenBao, defaultSecretStoreAddr,
				ensureStoreCA(t, t.TempDir(), tlscatest.Deps()), t.TempDir(), run.run, r.AfterStoreRestart)
			if err != nil {
				t.Fatal(err)
			}
			waitSweep(t, startStoreSweep(t.Context(), w.sweeper, log))
			if n := e.count(t, "os.store_init"); n != 1 {
				t.Fatalf("after the restart: %d jobs, want 1 (run calls %v)", n, run.got())
			}
			if got := jobAlertIDs(t, e.alertsService(t, r)); !slices.Equal(got, tc.alerts) {
				t.Errorf("alerts = %v, want %v", got, tc.alerts)
			}
			e.reader(t, run.run).ReadAtStart(t.Context())
			if n := e.count(t, "os.store_init"); n != 1 {
				t.Errorf("same boot restart: %d jobs, want 1", n)
			}
		})
	}
}

// TC-833-28: the provisioner's record is recorded after the store-restart
// hook, which starts its unit first, and at start when it is already there.
func TestFunctional_StoreProvisionAfterRestartHook(t *testing.T) {
	provBody := func(outcome, run string) string {
		return "outcome=" + outcome + "\nboot_id=" + fxBoot + "\nrun_id=" + run + "\nreason=Provision said " + outcome + ".\n"
	}
	for _, tc := range []struct {
		outcome string
		alerts  []string
	}{
		{"applied", nil},
		{"unchanged", nil},
		{"failed", []string{"os-outcome:os.store_provision"}},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			e := newOutcomeEnv(t)
			runID := fxRun
			run := &outcomeRun{on: func(cmd string) {
				if cmd == "systemctl start "+storeProvisionUnit {
					e.write(t, "rasputin-store-provision", provBody(tc.outcome, runID))
				}
			}}
			r := e.reader(t, run.run)
			restart := restartStoreUnit(run.run, r.AfterStoreRestart)
			if err := restart(t.Context(), tlsca.LeafPaths{}); err != nil {
				t.Fatal(err)
			}
			want := []string{"systemctl reset-failed openbao.service", "systemctl restart openbao.service", "systemctl start " + storeProvisionUnit}
			if !slices.Equal(run.got(), want) {
				t.Errorf("run calls = %v, want %v", run.got(), want)
			}
			if n := e.count(t, "os.store_provision"); n != 1 {
				t.Fatalf("after the hook: %d jobs, want 1", n)
			}
			if got := jobAlertIDs(t, e.alertsService(t, r)); !slices.Equal(got, tc.alerts) {
				t.Errorf("alerts = %v, want %v", got, tc.alerts)
			}
			e.reader(t, run.run).AfterStoreRestart(t.Context())
			if n := e.count(t, "os.store_provision"); n != 1 {
				t.Errorf("same run_id on a fresh reader: %d jobs, want 1", n)
			}
			runID = fxRun2
			e.reader(t, run.run).AfterStoreRestart(t.Context())
			if n := e.count(t, "os.store_provision"); n != 2 {
				t.Errorf("a new run_id in the same boot: %d jobs, want 2", n)
			}
		})
	}

	// A record already there when the api starts is recorded by the start
	// read, which starts no unit.
	e := newOutcomeEnv(t)
	e.write(t, "rasputin-store-provision", provBody("applied", fxRun))
	run := &outcomeRun{}
	e.reader(t, run.run).ReadAtStart(t.Context())
	if n := e.count(t, "os.store_provision"); n != 1 || len(run.got()) != 0 {
		t.Errorf("start read: %d jobs and run calls %v; want 1 and none", n, run.got())
	}
}

// TC-833-29: the seal-key job is in the ledger when READY fires, and READY
// fires once.
func TestFunctional_JobCommittedBeforeReady(t *testing.T) {
	e := newOutcomeEnv(t)
	e.write(t, "rasputin-seal-key", sealBody("created", fxBoot))
	r := e.reader(t, (&outcomeRun{}).run)
	calls := 0
	var snapshot []*jobs.Job
	readyAfterOutcomes(t.Context(), r, func(context.Context) {}, func() {
		calls++
		js, err := e.ledger.ListAllJobsByKind(context.Background(), "os.seal_key")
		if err != nil {
			t.Error(err)
		}
		snapshot = js
	})
	if calls != 1 {
		t.Errorf("ready called %d times, want 1", calls)
	}
	if len(snapshot) != 1 || snapshot[0].Status != jobs.StatusSucceeded {
		t.Errorf("at READY the ledger held %+v, want the created job", snapshot)
	}
}

// The reader wiring refuses a nil run func; a unit that will not start is a
// WARN naming its output; the boot id is read from its file.
func TestOutcomeReaderWiring(t *testing.T) {
	e := newOutcomeEnv(t)
	log, _ := logkittest.New()
	if _, err := outcomeReaderWiring(e.ledger, log, e.runDir, e.bootIDPath, nil, noObserve); err == nil {
		t.Error("a nil run func was accepted")
	}
	if _, err := outcomeReaderWiring(nil, log, e.runDir, e.bootIDPath, (&outcomeRun{}).run, noObserve); err == nil {
		t.Error("a nil ledger was accepted")
	}
	wlog, rec := logkittest.New()
	r, err := outcomeReaderWiring(e.ledger, wlog, e.runDir, e.bootIDPath, (&outcomeRun{err: errors.New("exit status 5")}).run, noObserve)
	if err != nil {
		t.Fatal(err)
	}
	r.AfterStoreRestart(t.Context())
	warns := rec.AtLevel(slog.LevelWarn)
	if len(warns) != 1 {
		t.Fatalf("log:\n%s", rec.Text())
	}
	if msg, _ := logkittest.Attr(warns[0], "err"); !strings.Contains(msg, "systemctl start "+storeProvisionUnit) ||
		!strings.Contains(msg, "exit status 5") || !strings.Contains(msg, "unit output") {
		t.Errorf("WARN err = %q", msg)
	}

	// An unreadable record is keyed to the boot id in the file.
	if err := os.Mkdir(filepath.Join(e.runDir, "rasputin-seal-key", "outcome"), 0o700); err != nil {
		t.Fatal(err)
	}
	r.ReadAtStart(t.Context())
	js, err := e.ledger.ListAllJobsByKind(t.Context(), "os.seal_key")
	if err != nil || len(js) != 1 || !strings.Contains(string(js[0].Spec), fxBoot2) {
		t.Errorf("unreadable job = %+v, %v; want one keyed to the file's boot id", js, err)
	}
}

func TestFileBootID(t *testing.T) {
	dir := t.TempDir()
	good, empty := filepath.Join(dir, "good"), filepath.Join(dir, "empty")
	if err := os.WriteFile(good, []byte(" "+fxBoot+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if id, err := fileBootID(good)(); err != nil || id != fxBoot {
		t.Errorf("good = %q, %v", id, err)
	}
	if _, err := fileBootID(empty)(); err == nil {
		t.Error("an empty boot id was accepted")
	}
	if _, err := fileBootID(filepath.Join(dir, "absent"))(); err == nil {
		t.Error("an absent boot id file was accepted")
	}
}

// noObserve is a store init observer that does nothing.
func noObserve(context.Context, osoutcome.Record) {}
