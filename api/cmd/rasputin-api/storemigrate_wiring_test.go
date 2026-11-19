package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storemigrate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const migrateBoot = "0f3c5b2a-1d4e-4f6a-9b8c-7d6e5f4a3b2c"

// sourceOf is the production declaration of kind.
func sourceOf(t *testing.T, runDir, kind string) osoutcome.Source {
	t.Helper()
	for _, s := range outcomeSources(runDir, noObservers) {
		if s.Kind == kind {
			return s
		}
	}
	t.Fatalf("no %s source is declared", kind)
	return osoutcome.Source{}
}

// TC-1132-24: the production declarations. A provision record with author
// present, absent or - parses; a missing author line, any other value and a
// duplicate line are refused. An os.store_migrate record with each of its
// five outcomes, boot_id, run_id and reason parses; moved and finished are
// OK, and restored, superseded and failed alert. A restore after a finished
// migration raises no alert (F-1132-11): the root step checks the commit
// first and records finished, never superseded, then.
func TestOutcomeSources_StoreMigrateAndAuthor(t *testing.T) {
	prov := sourceOf(t, outcomeRunDir, storeProvisionKind)
	base := "outcome=applied\nboot_id=" + fxBoot + "\nrun_id=" + fxRun + "\nreason=Provisioned.\n"
	for _, a := range []string{"present", "absent", "-"} {
		rec, err := osoutcome.Parse(prov, []byte(base+"author="+a+"\n"))
		if err != nil || rec.Author != a {
			t.Errorf("author=%s: (%+v, %v)", a, rec, err)
		}
	}
	for name, body := range map[string]string{
		"missing":   base,
		"other":     base + "author=yes\n",
		"empty":     base + "author=\n",
		"duplicate": base + "author=present\nauthor=present\n",
	} {
		if _, err := osoutcome.Parse(prov, []byte(body)); err == nil {
			t.Errorf("%s author line was accepted", name)
		}
	}

	mig := sourceOf(t, outcomeRunDir, storeMigrateKind)
	if mig.Path != "/run/rasputin-store-migrate/outcome" || mig.KeyField != osoutcome.FieldRunID || !mig.AfterStoreRestart || mig.Observe == nil {
		t.Errorf("os.store_migrate declared as %+v", mig)
	}
	verdicts := map[string]osoutcome.Verdict{
		"moved": osoutcome.OK, "finished": osoutcome.OK,
		"restored": osoutcome.Alert, "superseded": osoutcome.Alert, "failed": osoutcome.Alert,
	}
	if len(mig.Outcomes) != len(verdicts) {
		t.Errorf("Outcomes = %v", mig.Outcomes)
	}
	for w, v := range verdicts {
		if mig.Outcomes[w] != v {
			t.Errorf("verdict of %s = %v, want %v", w, mig.Outcomes[w], v)
		}
		rec, err := osoutcome.Parse(mig, []byte("outcome="+w+"\nboot_id="+fxBoot+"\nrun_id="+fxRun+"\nreason=The step said "+w+".\n"))
		if err != nil || rec.Outcome != w || rec.RunID != fxRun || rec.BootID != fxBoot {
			t.Errorf("%s: (%+v, %v)", w, rec, err)
		}
	}
	// outcomeReaderWiring hands these declarations to osoutcome.New.
	log, _ := logkittest.New()
	if _, err := outcomeReaderWiring(openLedgerAt(t, filepath.Join(t.TempDir(), "jobs.db")), log, outcomeRunDir,
		procBootIDPath, (&outcomeRun{}).run, noObservers); err != nil {
		t.Errorf("osoutcome.New refused the declarations: %v", err)
	}
	if _, err := outcomeReaderWiring(openLedgerAt(t, filepath.Join(t.TempDir(), "jobs.db")), log, outcomeRunDir,
		procBootIDPath, (&outcomeRun{}).run, outcomeObservers{init: noObserve, provision: noObserve}); err == nil {
		t.Error("a nil migrate observer was accepted")
	}
}

// The migration reads both records from their declared files.
func TestOutcomeRecords(t *testing.T) {
	dir := t.TempDir()
	r, err := newOutcomeRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Provision(); err == nil {
		t.Error("an absent record read")
	}
	for sub, body := range map[string]string{
		"rasputin-store-provision": "outcome=unchanged\nboot_id=" + fxBoot + "\nrun_id=" + fxRun + "\nreason=r.\nauthor=absent\n",
		"rasputin-store-migrate":   "outcome=moved\nboot_id=" + fxBoot + "\nrun_id=" + fxRun + "\nreason=r.\n",
	} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, sub, "outcome"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if p, err := r.Provision(); err != nil || p.Author != "absent" {
		t.Errorf("Provision = (%+v, %v)", p, err)
	}
	if m, err := r.Migrate(); err != nil || m.Outcome != "moved" || m.RunID != fxRun {
		t.Errorf("Migrate = (%+v, %v)", m, err)
	}
}

// TC-1132-22 (the ordering): main runs the migration's Recover before it
// builds the secrets service, subscribes the app relay or recovers the job
// runner, and arms the first-ready coordinator only after the start-time
// outcome read.
func TestStoreMigrateRecoverRunsFirst(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	at := func(s string) int {
		t.Helper()
		i := strings.Index(code, s)
		if i < 0 {
			t.Fatalf("main.go has no %q", s)
		}
		return i
	}
	recov := at("storeMigrateRecover(ctx,")
	for _, later := range []string{"secretsWiring(", "wireAppRelay(", "runner.Recover(ctx)"} {
		if at(later) < recov {
			t.Errorf("%s comes before the migration's Recover", later)
		}
	}
	if at("storeMig.arm(ctx)") < at("readyAfterOutcomes(ctx, outcomes,") {
		t.Error("the first-ready coordinator is armed before the start-time outcome read")
	}
	if strings.Contains(code, "rollback.arm(") {
		t.Error("the reference check still arms its own first-ready callback (F-1132-05)")
	}
}

// storeMigrateRecover runs only under openbao, and restarts the store
// through the control it was given.
func TestStoreMigrateRecover(t *testing.T) {
	dir := t.TempDir()
	files, err := storemigrate.NewStateDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.Write(storemigrate.NameAside, []byte("x")); err != nil {
		t.Fatal(err)
	}
	log, _ := logkittest.New()
	if err := storeMigrateRecover(context.Background(), storeModeMock, files, nil, log); err != nil {
		t.Fatalf("mock: %v", err)
	}
	if err := storeMigrateRecover(context.Background(), storeModeOpenBao, files, nil, log); err == nil {
		t.Error("a nil control was accepted under openbao")
	}
	run := &recordedRun{}
	ctl := &storeBackupControl{log: log, start: restartStoreUnit(run.run, noRestartHook)}
	if err := storeMigrateRecover(context.Background(), storeModeOpenBao, files, ctl, log); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(run.got(), ";"); !strings.Contains(got, "systemctl restart openbao.service") {
		t.Errorf("run calls %q, want the store restarted", got)
	}
}

// storeMigrateHeld puts the Hold in front of both sessions under openbao
// only.
func TestStoreMigrateHeld(t *testing.T) {
	log, _ := logkittest.New()
	files, _ := storemigrate.NewStateDir(t.TempDir(), nil)
	hold, err := storemigrate.NewHold(files, log)
	if err != nil {
		t.Fatal(err)
	}
	sess := offKeySession(t)
	kv, keys := storeMigrateHeld(storeModeMock, hold, sess, sess)
	if kv != secrets.Store(sess) || keys != secrets.TransitStore(sess) {
		t.Error("the mock's sessions were wrapped")
	}
	kv, keys = storeMigrateHeld(storeModeOpenBao, hold, sess, sess)
	if _, ok := kv.(*storemigrate.HeldKV); !ok {
		t.Errorf("kv is %T, want the Hold's", kv)
	}
	if _, ok := keys.(*storemigrate.HeldTransit); !ok {
		t.Errorf("keys is %T, want the Hold's", keys)
	}
}

// migrateStubs are the migration's collaborators the wiring test never
// reaches.
type migrateStubs struct{}

func (migrateStubs) SecretInventory(context.Context) ([]apps.AppSecretInventory, error) {
	return nil, nil
}
func (migrateStubs) Get(context.Context, secrets.Ref) (secrets.Secret, error) {
	return secrets.Secret{}, errors.New("unused")
}
func (migrateStubs) Write(context.Context, secrets.Ref, secret.Value, int) (int, error) {
	return 0, errors.New("unused")
}
func (migrateStubs) RebaseChecked(context.Context) (string, error) { return "", nil }
func (migrateStubs) RestoreSetUp(context.Context, string) error    { return nil }
func (migrateStubs) Provision() (osoutcome.Record, error)          { return osoutcome.Record{}, nil }
func (migrateStubs) Migrate() (osoutcome.Record, error)            { return osoutcome.Record{}, nil }

// migrateSettings is an in-memory settings table.
type migrateSettings map[string]string

func (s migrateSettings) Get(_ context.Context, k string) (string, error) { return s[k], nil }
func (s migrateSettings) Set(_ context.Context, k, v string) error        { s[k] = v; return nil }

// TC-1132-23 (the coordinator in the composition root) and TC-800-20's
// first-ready half, which moved here when the coordinator replaced the
// check's own callback: under openbao the migration is registered beside
// the check; a store not ready at start submits nothing, and the first
// ready reading submits the check once when no migration is wanted, or the
// migration alone when this boot's provision record says author=absent.
// Under the mock nothing is registered and arming does nothing.
func TestStoreMigrateWiring(t *testing.T) {
	wire := func(t *testing.T, mode string, provision *storemigrate.LastRecord, store secretStore) (storeMigrate, *fakeRollbackRunner, func()) {
		t.Helper()
		log, _ := logkittest.New()
		run := newFakeRollbackRunner()
		r, err := storeReadinessWiring(storeModeOpenBao, false, storeModeOpenBao, store, openJobStore(t), time.Now, notBlank, log)
		if err != nil {
			t.Fatal(err)
		}
		rb, err := storeRollbackWiring(storeRollbackDeps{mode: mode, refs: noRefs{}, secrets: noExists{}, runner: run, log: log})
		if err != nil {
			t.Fatal(err)
		}
		files, _ := storemigrate.NewStateDir(t.TempDir(), nil)
		hold, _ := storemigrate.NewHold(files, log)
		gate, err := sealrotate.NewGate(sealAt{}, func(context.Context, string) (bool, error) { return true, nil }, log)
		if err != nil {
			t.Fatal(err)
		}
		w, err := storeMigrateWiring(storeMigrateDeps{
			mode: mode, hold: hold, files: files, provision: provision, inventory: migrateStubs{}, repo: migrateStubs{},
			control: &storeBackupControl{}, lock: gate, marker: migrateStubs{}, settings: migrateSettings{},
			records: migrateStubs{}, run: (&recordedRun{}).run, bootID: func() (string, error) { return migrateBoot, nil },
			monitor: r.monitor, runner: run, check: rb.check, log: log,
		})
		if err != nil {
			t.Fatal(err)
		}
		return w, run, func() {
			if _, err := r.monitor.State(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("no migration wanted, store not ready at start", func(t *testing.T) {
		store := &switchableHealth{secretStore: secretstore.NewMock(time.Now), down: true}
		w, run, read := wire(t, storeModeOpenBao, &storemigrate.LastRecord{}, store)
		if reg, _ := run.counts(); reg != 2 || run.registered[0] != appsecret.ReferenceCheckKind || run.registered[1] != storemigrate.Kind {
			t.Fatalf("registered %v, want the check and the migration", run.registered)
		}
		w.arm(context.Background())
		if _, sub := run.counts(); sub != 0 {
			t.Fatalf("a store not ready at start submitted %d job(s)", sub)
		}
		store.set(false)
		read()
		<-run.done
		read()
		if _, sub := run.counts(); sub != 1 || !strings.HasPrefix(run.submitted[0], appsecret.ReferenceCheckKind) {
			t.Fatalf("submitted %v, want one check on the first ready reading", run.submitted)
		}
	})
	t.Run("migration wanted", func(t *testing.T) {
		last := &storemigrate.LastRecord{}
		last.Observe(context.Background(), osoutcome.Record{Outcome: "applied", BootID: migrateBoot, RunID: fxRun,
			Reason: "r.", Author: osoutcome.AuthorAbsent})
		w, run, _ := wire(t, storeModeOpenBao, last, secretstore.NewMock(time.Now))
		w.arm(context.Background())
		<-run.done
		if _, sub := run.counts(); sub != 1 || !strings.HasPrefix(run.submitted[0], storemigrate.Kind) {
			t.Fatalf("submitted %v, want the migration alone", run.submitted)
		}
	})
	t.Run("mock", func(t *testing.T) {
		w, run, _ := wire(t, storeModeMock, &storemigrate.LastRecord{}, secretstore.NewMock(time.Now))
		w.arm(context.Background())
		if reg, sub := run.counts(); reg != 0 || sub != 0 {
			t.Fatalf("registered %d, submitted %d under the mock", reg, sub)
		}
	})
	t.Run("refusals", func(t *testing.T) {
		if _, err := storeMigrateWiring(storeMigrateDeps{mode: storeModeOpenBao}); err == nil {
			t.Error("a nil control was accepted")
		}
		if _, err := storeMigrateWiring(storeMigrateDeps{mode: storeModeOpenBao, control: &storeBackupControl{},
			lock: noCaptureLock{}}); err == nil {
			t.Error("nil collaborators were accepted")
		}
	})
}

// noCaptureLock is a capture lock the refusal test never takes.
type noCaptureLock struct{}

func (noCaptureLock) Acquire(context.Context, string) error { return nil }
func (noCaptureLock) Release(string)                        {}
