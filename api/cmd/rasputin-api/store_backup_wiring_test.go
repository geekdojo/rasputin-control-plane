package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storemarker"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

func initBody(outcome, boot string) string {
	return "outcome=" + outcome + "\nboot_id=" + boot + "\nreason=The store init said " + outcome + ".\n"
}

// TC-765-30: on the start that applied a restore carrying the store, the
// restored database's marker names another cluster's boot and /run holds an
// initialised record for this boot. Run in main's order — the restore
// record, rebaseAfterRestore, then the outcome read and arm in
// readyAfterOutcomes — no blank_boot_id is written, no blank ERROR is
// logged, and readiness is not blank. Without the re-base the same start
// reads blank, so the case is not vacuous.
func TestRestoreBootIsNotAFalseBlank(t *testing.T) {
	for _, rebase := range []bool{true, false} {
		t.Run(map[bool]string{true: "main's order", false: "no re-base"}[rebase], func(t *testing.T) {
			ctx := context.Background()
			e := newOutcomeEnv(t)
			dataDir := t.TempDir()
			dbPath := filepath.Join(dataDir, "rasputin.db")
			settings, err := setup.OpenStore(ctx, dbPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = settings.Close() })
			// The restored database: set up on the backed-up cluster's boot.
			if err := settings.Set(ctx, storemarker.KeySetUpBootID, fxBoot); err != nil {
				t.Fatal(err)
			}
			backupStore, err := storage.OpenStore(ctx, dbPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backupStore.Close() })
			applied := storage.RestoreReport{ID: "rs-1", Phase: storage.RestorePhase, GenerationID: "g1", PreparedAt: time.Now().UTC(),
				Restored: []storage.RestoredEntry{{Path: "rasputin.db"}, {Path: "store/data/000001.log"}, {Path: "store/seal-key"}}}
			b, _ := json.Marshal(applied)
			if err := os.MkdirAll(filepath.Join(dataDir, "restore-applied"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dataDir, "restore-applied", "restore.json"), b, 0o600); err != nil {
				t.Fatal(err)
			}
			e.write(t, "rasputin-store-init", initBody("initialised", fxBoot2))

			log, rec := logkittest.New()
			marker, err := storemarker.New(storemarker.Deps{Settings: settings, BootID: fileBootID(e.bootIDPath), Log: log})
			if err != nil {
				t.Fatal(err)
			}
			rep, err := storage.RecordAppliedRestore(ctx, backupStore, dataDir)
			if err != nil || rep == nil || !rep.RestoredStore() {
				t.Fatalf("RecordAppliedRestore = (%+v, %v)", rep, err)
			}
			if rebase {
				rebaseAfterRestore(ctx, marker, rep)
			}
			outcomes, err := outcomeReaderWiring(e.ledger, log, e.runDir, e.bootIDPath, (&outcomeRun{}).run, marker.ObserveInit)
			if err != nil {
				t.Fatal(err)
			}
			readyAfterOutcomes(ctx, outcomes, func(ctx context.Context) { marker.Arm(ctx, true) }, func() {})

			blankID, _ := settings.Get(ctx, storemarker.KeyBlankBootID)
			errs := rec.Matching(slog.LevelError, "started blank")
			r, err := storeReadinessWiring(storeModeMock, storeModeMock, secretstore.NewMock(time.Now), openJobStore(t), time.Now, marker.Blank, log)
			if err != nil {
				t.Fatal(err)
			}
			st, err := r.monitor.State(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if rebase {
				if blankID != "" || len(errs) != 0 || st == storestate.Blank {
					t.Fatalf("blank_boot_id=%q, %d blank ERROR(s), state %s: a false blank on the restore boot", blankID, len(errs), st)
				}
				return
			}
			if blankID != fxBoot2 || len(errs) != 1 || st != storestate.Blank {
				t.Fatalf("without the re-base: blank_boot_id=%q, %d ERROR(s), state %s; want the blank the re-base prevents", blankID, len(errs), st)
			}
		})
	}
	// A report without store members, and none at all, re-bases nothing.
	m := &rebaseCounter{}
	rebaseAfterRestore(context.Background(), m, &storage.RestoreReport{Restored: []storage.RestoredEntry{{Path: "rasputin.db"}}})
	rebaseAfterRestore(context.Background(), m, nil)
	if m.n != 0 {
		t.Errorf("re-based %d time(s) for a restore without the store", m.n)
	}
}

type rebaseCounter struct{ n int }

func (r *rebaseCounter) Rebase(context.Context) { r.n++ }

// TC-765-31: with both store CA files absent, a data dir that is absent or
// empty lets the CA be created; one that holds data, or cannot be read,
// creates none, logs one ERROR tlsca.store_ca_refused with store_data_dir,
// and on main's chain wires the store off as a configfault, reads
// unreachable with its crit alert, and refuses a secret-bearing deploy. A CA
// already present loads unchanged beside data.
func TestEnsureCAs_StoreCAGuard(t *testing.T) {
	ctx := context.Background()
	run := func(t *testing.T, trust, dataDir string) (*tlsca.CA, *recordsHandler) {
		t.Helper()
		h := &recordsHandler{}
		d := tlscatest.Deps()
		d.Log = slog.New(h)
		cp, store := ensureCAs(ctx, slog.New(h), func(c int) { t.Fatalf("exit %d", c) }, trust, "home1", d, dataDir, storeDataPresent(dataDir))
		if cp == nil {
			t.Fatal("no controlplane CA")
		}
		return store, h
	}
	for name, mk := range map[string]func(t *testing.T, dir string){
		"absent": func(*testing.T, string) {},
		"empty":  func(t *testing.T, dir string) { mustMkdir(t, dir) },
	} {
		t.Run(name, func(t *testing.T) {
			trust, dataDir := t.TempDir(), filepath.Join(t.TempDir(), "openbao")
			mk(t, dataDir)
			if store, _ := run(t, trust, dataDir); store == nil {
				t.Fatal("no store CA was created")
			}
			if _, err := os.Stat(filepath.Join(trust, tlsca.StoreCertFile)); err != nil {
				t.Fatalf("store-ca.pem: %v", err)
			}
		})
	}
	for name, mk := range map[string]func(t *testing.T, dir string){
		"data present": func(t *testing.T, dir string) {
			mustMkdir(t, dir)
			if err := os.WriteFile(filepath.Join(dir, "000001.log"), []byte("store data"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"unreadable": func(t *testing.T, dir string) {
			mustMkdir(t, dir)
			if err := os.Chmod(dir, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		},
	} {
		t.Run(name, func(t *testing.T) {
			trust, dataDir := t.TempDir(), filepath.Join(t.TempDir(), "openbao")
			mk(t, dataDir)
			store, h := run(t, trust, dataDir)
			if store != nil {
				t.Fatal("a store CA was created over store data")
			}
			for _, f := range []string{tlsca.StoreKeyFile, tlsca.StoreCertFile} {
				if _, err := os.Lstat(filepath.Join(trust, f)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s exists: %v", f, err)
				}
			}
			recs := h.matching(slog.LevelError, "store CA refused")
			if len(recs) != 1 || attrOf(recs[0], "event") != "tlsca.store_ca_refused" || attrOf(recs[0], "store_data_dir") != dataDir {
				t.Fatalf("%d refusal records, want one with event and store_data_dir", len(recs))
			}
			log, _ := logkittest.New()
			w, err := wireSecretStore(ctx, log, storeModeOpenBao, defaultSecretStoreAddr, store, t.TempDir(), (&recordedRun{}).run, noRestartHook)
			if err != nil || w.mode != storeModeOff {
				t.Fatalf("wiring = (%s, %v), want the store off", w.mode, err)
			}
			r, err := storeReadinessWiring(storeModeOpenBao, w.mode, w.store, openJobStore(t), time.Now, notBlank, log)
			if err != nil {
				t.Fatal(err)
			}
			if a := r.alerts(ctx, time.Now()); len(a) != 1 || a[0].ID != "secret-store:unreachable" {
				t.Fatalf("alerts = %+v, want secret-store:unreachable", a)
			}
			src, err := deploySourceWiring(r.monitor, &countingSource{}, &countingSource{}, log)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := src.ResolveCompose(ctx, "a", "services:\n  web:\n    environment:\n      P: ${secret:db-password}\n"); !errors.Is(err, storestate.ErrNotReady) {
				t.Fatalf("a secret-bearing deploy = %v, want refused", err)
			}
		})
	}
	t.Run("CA present with data", func(t *testing.T) {
		trust, dataDir := t.TempDir(), filepath.Join(t.TempDir(), "openbao")
		first, _ := run(t, trust, filepath.Join(t.TempDir(), "absent"))
		mustMkdir(t, dataDir)
		if err := os.WriteFile(filepath.Join(dataDir, "000001.log"), []byte("store data"), 0o600); err != nil {
			t.Fatal(err)
		}
		again, h := run(t, trust, dataDir)
		if again == nil || string(again.CertPEM) != string(first.CertPEM) {
			t.Fatal("the existing store CA did not load unchanged")
		}
		if len(h.matching(slog.LevelError, "store CA refused")) != 0 {
			t.Error("a present CA was refused")
		}
	})
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

// TC-765-32: under openbao a prepared restore's restart hook stops the store
// unit before it asks for the exit; under mock or nothing it runs no
// systemctl; a stop that fails logs one ERROR with the unit and the error
// and the exit still goes ahead (F-765-06).
func TestRestoreRestartStopsTheStoreFirst(t *testing.T) {
	for _, tc := range []struct {
		backend string
		stopErr error
		want    []string
	}{
		{storeModeOpenBao, nil, []string{"systemctl stop openbao.service", "exit"}},
		{storeModeOpenBao, errors.New("exit status 5"), []string{"systemctl stop openbao.service", "exit"}},
		{storeModeMock, nil, []string{"exit"}},
		{"", nil, []string{"exit"}},
	} {
		var order []string
		run := func(_ context.Context, name string, args ...string) ([]byte, error) {
			order = append(order, strings.Join(append([]string{name}, args...), " "))
			return []byte("Unit not loaded."), tc.stopErr
		}
		log, rec := logkittest.New()
		restoreRestartHook(log, tc.backend, run, func() { order = append(order, "exit") })()
		if !reflect.DeepEqual(order, tc.want) {
			t.Errorf("backend %q: calls %v, want %v", tc.backend, order, tc.want)
		}
		errs := rec.Matching(slog.LevelError, "stopping the secret store before the restart failed")
		if tc.stopErr == nil {
			if len(errs) != 0 {
				t.Errorf("backend %q: an ERROR without a failure", tc.backend)
			}
			continue
		}
		if len(errs) != 1 {
			t.Fatalf("%d ERRORs, want 1:\n%s", len(errs), rec.Text())
		}
		for k, want := range map[string]string{"event": "storage.restore_store_stop_failed", "unit": "openbao.service"} {
			if got, _ := logkittest.Attr(errs[0], k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		if got, _ := logkittest.Attr(errs[0], "err"); !strings.Contains(got, "exit status 5") {
			t.Errorf("err = %q", got)
		}
	}
}

// sealAt is a seal tree reader returning one tree.
type sealAt struct {
	tree sealrotate.Tree
	err  error
}

func (s sealAt) State() (sealrotate.Tree, error) { return s.tree, s.err }

// TC-765-33: the backup's store adapter keys on the requested backend:
// wired for openbao, wired for a refused value (whose capture then refuses
// as unreachable), and nil for mock or nothing, whose archives are version 2
// (backupSources adds no store source).
func TestStoreBackupWiringKeysOnTheRequestedBackend(t *testing.T) {
	ctx := context.Background()
	log, _ := logkittest.New()
	key, _ := sealrotate.ParseKeyID("rasputin-11111111-1111-4111-8111-111111111111")
	clean := sealAt{tree: sealrotate.Tree{Fragment: sealrotate.Fragment{Shape: sealrotate.Clean, Current: key}}}
	for _, tc := range []struct {
		requested, mode string
		store           secretStore
		wired           bool
		notReady        string
	}{
		{"openbao", storeModeOpenBao, secretstore.NewMock(time.Now), true, ""},
		{"vault", storeModeOff, secretstore.Disabled{}, true, storestate.Clause(storestate.Unreachable)},
		{"mock", storeModeMock, secretstore.NewMock(time.Now), false, ""},
		{"", storeModeOff, secretstore.Disabled{}, false, ""},
	} {
		t.Run(tc.requested, func(t *testing.T) {
			r, err := storeReadinessWiring(tc.requested, tc.mode, tc.store, openJobStore(t), time.Now, notBlank, log)
			if err != nil {
				t.Fatal(err)
			}
			got, err := storeBackupWiring(tc.requested, r.monitor, r.store, clean, (&recordedRun{}).run, noRestartHook, log)
			if err != nil {
				t.Fatal(err)
			}
			src := backupSources(storage.IdentitySources{TrustDir: "/t"}, got, "/var/lib/rasputin/openbao")
			if !tc.wired {
				if got != nil || src.StoreDataDir != "" || src.SealDir != "" {
					t.Fatalf("wired %v with sources %+v, want nil and no store source", got, src)
				}
				return
			}
			if got == nil || src.StoreDataDir != "/var/lib/rasputin/openbao" || src.SealDir != sealrotate.ProductionSealDir {
				t.Fatalf("wired %v with sources %+v", got, src)
			}
			notReady, err := got.Readiness(ctx)
			if err != nil || notReady != tc.notReady {
				t.Fatalf("Readiness = (%q, %v), want %q", notReady, err, tc.notReady)
			}
		})
	}
	if _, err := storeBackupWiring("openbao", nil, secretstore.Disabled{}, clean, (&recordedRun{}).run, noRestartHook, log); err == nil {
		t.Error("a nil monitor was accepted under openbao")
	}
}

// The adapter's own calls: the key id only from a Clean tree, the version
// from sys/health, stop and start through systemctl with the job id in
// their records, and the wait on the store's 200.
func TestStoreBackupControl(t *testing.T) {
	ctx := jobs.ContextWithJobID(context.Background(), "job-b")
	log, rec := logkittest.New()
	key, _ := sealrotate.ParseKeyID("rasputin-11111111-1111-4111-8111-111111111111")
	store := versionedStore{secretStore: secretstore.NewMock(time.Now)}
	r, err := storeReadinessWiring(storeModeOpenBao, storeModeOpenBao, store, openJobStore(t), time.Now, notBlank, log)
	if err != nil {
		t.Fatal(err)
	}
	run := &recordedRun{}
	var afters int
	ss, err := storeBackupWiring(storeModeOpenBao, r.monitor, r.store,
		sealAt{tree: sealrotate.Tree{Fragment: sealrotate.Fragment{Shape: sealrotate.Clean, Current: key}}},
		run.run, func(context.Context) { afters++ }, log)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := ss.SealKeyID(); err != nil || id != key.String() {
		t.Errorf("SealKeyID = (%q, %v)", id, err)
	}
	staged := ss.(*storeBackupControl)
	staged.seal = sealAt{tree: sealrotate.Tree{Fragment: sealrotate.Fragment{Shape: sealrotate.Staged, Current: key}}}
	if _, err := ss.SealKeyID(); err == nil {
		t.Error("a Staged tree gave a key id")
	}
	staged.seal = sealAt{err: errors.New("permission denied")}
	if _, err := ss.SealKeyID(); err == nil {
		t.Error("an unreadable tree gave a key id")
	}
	if v, err := ss.Version(ctx); err != nil || v != "2.7.1" {
		t.Errorf("Version = (%q, %v)", v, err)
	}
	if err := ss.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ss.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ss.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if want := append([]string{"systemctl stop openbao.service"}, restartPair...); !reflect.DeepEqual(run.got(), want) || afters != 1 {
		t.Errorf("calls %v (after-hook %d), want %v and one after-restart read", run.got(), afters, want)
	}
	for _, ev := range []string{"secretstore.backup_stop", "secretstore.backup_start"} {
		found := false
		for _, rc := range rec.Records() {
			if e, _ := logkittest.Attr(rc, "event"); e == ev {
				id, _ := logkittest.Attr(rc, "job_id")
				found = id == "job-b"
			}
		}
		if !found {
			t.Errorf("no %s record with job_id job-b", ev)
		}
	}
	release := ss.Quiesce("job-b")
	release()
}

// versionedStore answers sys/health with a release, as the real store does.
type versionedStore struct{ secretStore }

func (versionedStore) Health(context.Context) (secretstore.Health, error) {
	return secretstore.Health{Initialized: true, Version: "2.7.1"}, nil
}
