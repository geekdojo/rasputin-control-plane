package main

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fakeRollbackRunner records the workflows registered and the jobs
// submitted; submitErr fails every Submit.
type fakeRollbackRunner struct {
	mu         sync.Mutex
	registered []string
	submitted  []string
	submitErr  error
	done       chan struct{}
}

func newFakeRollbackRunner() *fakeRollbackRunner {
	return &fakeRollbackRunner{done: make(chan struct{}, 8)}
}

func (r *fakeRollbackRunner) Register(w jobs.Workflow) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registered = append(r.registered, w.Kind)
}

func (r *fakeRollbackRunner) Submit(_ context.Context, kind string, _ any, createdBy string) (*jobs.Job, error) {
	defer func() { r.done <- struct{}{} }()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.submitErr != nil {
		return nil, r.submitErr
	}
	r.submitted = append(r.submitted, kind+" by "+createdBy)
	return &jobs.Job{ID: "j1", Kind: kind}, nil
}

func (r *fakeRollbackRunner) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.registered), len(r.submitted)
}

// noRefs and noExists stand in for the apps table and the secrets service:
// the wiring test never runs the check's step.
type noRefs struct{}

func (noRefs) ListSecretRefs(context.Context) ([]appsecret.SecretRef, error) { return nil, nil }

type noExists struct{}

func (noExists) Exists(context.Context, secrets.Actor, secrets.Ref) (bool, error) { return false, nil }

// rollbackFor wires the store's rollback for requested, as main does: the
// readiness monitor, the OS update's copy control, and the gate under
// openbao.
func rollbackFor(t *testing.T, requested, mode string, store secretStore, runner *fakeRollbackRunner, log *slog.Logger) (storeRollback, *storeRollbackDeps) {
	t.Helper()
	r, err := storeReadinessWiring(requested, mode, store, openJobStore(t), time.Now, notBlank, log)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := sealrotate.ParseKeyID("rasputin-11111111-1111-4111-8111-111111111111")
	clean := sealAt{tree: sealrotate.Tree{Fragment: sealrotate.Fragment{Shape: sealrotate.Clean, Current: key}}}
	copyStore, err := storeBackupWiring(requested, storestate.QuiesceOSUpdate, r.monitor, r.store, clean, (&recordedRun{}).run, noRestartHook, log)
	if err != nil {
		t.Fatal(err)
	}
	d := storeRollbackDeps{mode: mode, copyStore: copyStore, storeDataDir: t.TempDir(), copyPath: t.TempDir() + "/openbao-preupdate.tar",
		refs: noRefs{}, secrets: noExists{}, runner: runner, log: log}
	if r.monitor != nil {
		d.monitor = r.monitor
	}
	if mode == storeModeOpenBao {
		g, err := sealrotate.NewGate(clean, func(context.Context, string) (bool, error) { return true, nil }, log)
		if err != nil {
			t.Fatal(err)
		}
		d.lock = g
	}
	w, err := storeRollbackWiring(d)
	if err != nil {
		t.Fatal(err)
	}
	return w, &d
}

// TC-800-20: the composition root's rollback wiring. Under openbao the copy
// is wired, the check is registered, and arming it (main runs arm after
// runner.Recover) submits exactly one check on the first ready reading.
// With nothing or the mock requested there is no copy and no check. A
// refused selector wires the copy, which refuses an update of the store's
// host because the store reads unreachable (fail closed). A failed submit is
// one ERROR record, and start carries on. The pre-revision case text has the
// check submitted "after runner.Recover"; the approved plan submits it on
// the first ready reading after arm (F-800-03).
func TestStoreRollbackWiring(t *testing.T) {
	t.Run("openbao", func(t *testing.T) {
		log, _ := logkittest.New()
		run := newFakeRollbackRunner()
		w, _ := rollbackFor(t, storeModeOpenBao, storeModeOpenBao, secretstore.NewMock(time.Now), run, log)
		if w.copier == nil {
			t.Fatal("no copier under openbao")
		}
		if reg, sub := run.counts(); reg != 1 || sub != 0 || run.registered[0] != appsecret.ReferenceCheckKind {
			t.Fatalf("registered %v, submitted %d before arm", run.registered, sub)
		}
		w.arm(context.Background())
		<-run.done
		if _, sub := run.counts(); sub != 1 || run.submitted[0] != appsecret.ReferenceCheckKind+" by "+storeRollbackCreatedBy {
			t.Fatalf("submitted %v, want one check", run.submitted)
		}
	})
	t.Run("openbao, store not ready at start", func(t *testing.T) {
		log, _ := logkittest.New()
		run := newFakeRollbackRunner()
		store := &switchableHealth{secretStore: secretstore.NewMock(time.Now), down: true}
		r, err := storeReadinessWiring(storeModeOpenBao, storeModeOpenBao, store, openJobStore(t), time.Now, notBlank, log)
		if err != nil {
			t.Fatal(err)
		}
		w, err := storeRollbackWiring(storeRollbackDeps{mode: storeModeOpenBao, refs: noRefs{}, secrets: noExists{}, monitor: r.monitor, runner: run, log: log})
		if err != nil {
			t.Fatal(err)
		}
		w.arm(context.Background())
		if _, sub := run.counts(); sub != 0 {
			t.Fatalf("a store not ready at start submitted %d check(s)", sub)
		}
		store.set(false)
		for range 3 {
			if _, err := r.monitor.State(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		<-run.done
		if _, sub := run.counts(); sub != 1 {
			t.Fatalf("submitted %d check(s), want one on the first ready reading", sub)
		}
	})
	for _, requested := range []string{"", storeModeMock} {
		t.Run("requested "+requested, func(t *testing.T) {
			log, _ := logkittest.New()
			run := newFakeRollbackRunner()
			mode, store := storeModeOff, secretStore(secretstore.Disabled{})
			if requested == storeModeMock {
				mode, store = storeModeMock, secretstore.NewMock(time.Now)
			}
			w, _ := rollbackFor(t, requested, mode, store, run, log)
			w.arm(context.Background())
			if reg, sub := run.counts(); w.copier != nil || reg != 0 || sub != 0 {
				t.Fatalf("copier %v, registered %d, submitted %d; want none", w.copier, reg, sub)
			}
		})
	}
	t.Run("refused selector", func(t *testing.T) {
		log, _ := logkittest.New()
		run := newFakeRollbackRunner()
		w, _ := rollbackFor(t, "vault", storeModeOff, secretstore.Disabled{}, run, log)
		if w.copier == nil {
			t.Fatal("no copier for a refused selector")
		}
		sc := &jobs.StepCtx{Ctx: context.Background(), JobID: "upd-1", Log: func(string, string) {}}
		_, err := w.copier.CopyBeforeUpdate(sc)
		if err == nil || !strings.HasPrefix(err.Error(), sealrotate.UpdateCopyRefused) || !strings.Contains(err.Error(), "cannot be reached") {
			t.Fatalf("err = %v, want the update refused as unreachable", err)
		}
		if reg, _ := run.counts(); reg != 0 {
			t.Errorf("a refused selector registered %d check(s)", reg)
		}
	})
	t.Run("a failed submit", func(t *testing.T) {
		log, rec := logkittest.New()
		run := newFakeRollbackRunner()
		run.submitErr = errors.New("jobs: database is locked")
		w, _ := rollbackFor(t, storeModeOpenBao, storeModeOpenBao, secretstore.NewMock(time.Now), run, log)
		w.arm(context.Background())
		<-run.done
		deadline := time.Now().Add(5 * time.Second)
		for len(rec.Matching(slog.LevelError, "secret store reference check not submitted")) == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if n := len(rec.Matching(slog.LevelError, "secret store reference check not submitted")); n != 1 {
			t.Fatalf("%d ERROR record(s), want 1", n)
		}
	})
	t.Run("refusals", func(t *testing.T) {
		log, _ := logkittest.New()
		if _, err := storeRollbackWiring(storeRollbackDeps{mode: storeModeOpenBao}); err == nil {
			t.Error("a nil logger was accepted")
		}
		if _, err := storeRollbackWiring(storeRollbackDeps{mode: storeModeOpenBao, log: log}); err == nil {
			t.Error("a nil monitor and runner were accepted under openbao")
		}
		if _, err := storeRollbackWiring(storeRollbackDeps{mode: storeModeOpenBao, log: log, monitor: &fakeReady{}, runner: newFakeRollbackRunner()}); err == nil {
			t.Error("a nil reference lister was accepted")
		}
		if _, err := storeRollbackWiring(storeRollbackDeps{mode: storeModeOff, log: log, copyStore: &storeBackupControl{}}); err == nil {
			t.Error("a copy with no data dir was accepted")
		}
	})
}

// fakeReady is a readyReader that is never read.
type fakeReady struct{}

func (*fakeReady) OnFirstReady(context.Context, func(context.Context)) {}
func (*fakeReady) State(context.Context) (storestate.State, error)     { return storestate.Ready, nil }

// switchableHealth answers sys/health unreachable while down.
type switchableHealth struct {
	secretStore
	mu   sync.Mutex
	down bool
}

func (s *switchableHealth) set(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

func (s *switchableHealth) Health(ctx context.Context) (secretstore.Health, error) {
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if down {
		return secretstore.Health{}, &secretstore.Error{Op: "health", Kind: secretstore.ErrUnreachable}
	}
	return s.secretStore.Health(ctx)
}

// TC-800-14: the cold-copy control carries its reason: the monitor's hold
// and the stop and start records say backup or os-update.
func TestStoreBackupControl_CarriesItsReason(t *testing.T) {
	for _, reason := range []storestate.QuiesceReason{storestate.QuiesceBackup, storestate.QuiesceOSUpdate} {
		t.Run(reason.String(), func(t *testing.T) {
			ctx := jobs.ContextWithJobID(context.Background(), "job-r")
			log, rec := logkittest.New()
			r, err := storeReadinessWiring(storeModeOpenBao, storeModeOpenBao, secretstore.NewMock(time.Now), openJobStore(t), time.Now, notBlank, log)
			if err != nil {
				t.Fatal(err)
			}
			ss, err := storeBackupWiring(storeModeOpenBao, reason, r.monitor, r.store, sealAt{}, (&recordedRun{}).run, noRestartHook, log)
			if err != nil {
				t.Fatal(err)
			}
			release := ss.Quiesce("job-r")
			release()
			if err := ss.Stop(ctx); err != nil {
				t.Fatal(err)
			}
			if err := ss.Start(ctx); err != nil {
				t.Fatal(err)
			}
			for _, ev := range []string{"secretstore.quiesced", "secretstore.backup_stop", "secretstore.backup_start"} {
				var got string
				for _, rc := range rec.Records() {
					if e, _ := logkittest.Attr(rc, "event"); e == ev {
						got, _ = logkittest.Attr(rc, "reason")
					}
				}
				if got != reason.String() {
					t.Errorf("%s reason = %q, want %q", ev, got, reason.String())
				}
			}
		})
	}
}

var _ storage.UpdateLock = noStoreRotationLock{}

// The apps table's references reach the check through main's adapter, and
// the copy's lock is the gate only under openbao.
func TestAppSecretRefsAndUpdateLock(t *testing.T) {
	ctx := context.Background()
	as, err := apps.OpenStore(ctx, filepath.Join(t.TempDir(), "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = as.Close() })
	const id = "01J8Z3K5QW6X7Y8Z9A0B1C2D3A"
	now := time.Now().UTC()
	if err := as.Create(ctx, &apps.App{ID: id, Name: "a", ComposeYAML: "x", TargetNode: "n", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	refs := appSecretRefs{store: as}
	if err := refs.RecordSecretRef(ctx, id, "db-pass"); err != nil {
		t.Fatal(err)
	}
	got, err := refs.ListSecretRefs(ctx)
	if err != nil || len(got) != 1 || got[0] != (appsecret.SecretRef{AppID: id, Name: "db-pass"}) {
		t.Fatalf("ListSecretRefs = (%v, %v)", got, err)
	}
	_ = as.Close()
	if _, err := refs.ListSecretRefs(ctx); err == nil {
		t.Error("a closed table listed")
	}
	if l := (sealRotate{}).updateLock(); l != nil {
		t.Errorf("updateLock with no gate = %v, want nil", l)
	}
	log, _ := logkittest.New()
	g, err := sealrotate.NewGate(sealAt{}, func(context.Context, string) (bool, error) { return true, nil }, log)
	if err != nil {
		t.Fatal(err)
	}
	if l := (sealRotate{gate: g}).updateLock(); l == nil {
		t.Error("updateLock with a gate = nil")
	}
}
