package storage

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The secret store functional test's variables (docs/testing-secret-store.md).
const (
	storeBinEnv    = "RASPUTIN_SECRETSTORE_BIN"
	storeSwitchEnv = "RASPUTIN_SECRETSTORE_FUNCTIONAL"
	// fnAppID is the app whose secret the round trip writes and reads.
	fnAppID = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	// The values the round trip writes: the deploy's, then the operator's.
	fnDeployValue   = "functional-deploy-value-7c1d"
	fnOperatorValue = "functional-operator-value-3f8e"
)

// realStore is one harness store with the shipped api and rotation roles,
// its seal outside the main config as the image has it, and the api's chain
// over it: the production client, a readiness Monitor, the login session and
// the secrets service.
type realStore struct {
	s      *secretstoretest.Store
	client *secretstore.Client
	mon    *storestate.Monitor
	files  *sealrotate.Files
	svc    *secrets.Service
	// repo is the KV repository under svc, for a test that needs its own
	// service over other apps (geekdojo/geekdojo-brain#800).
	repo *secrets.KVRepository
}

func startRealStore(t *testing.T, h *secretstoretest.Harness) *secretstoretest.Store {
	t.Helper()
	var roles []secretstoretest.Role
	for _, name := range []string{storepolicy.APIPolicy, storepolicy.SealRotatePolicy} {
		text, err := storepolicy.Text(name)
		if err != nil {
			t.Fatal(err)
		}
		roles = append(roles, secretstoretest.Role{Name: name, Policy: name, PolicyText: text})
	}
	s, err := h.StartWith(t.Context(), secretstoretest.Bootstrap{Mount: storepolicy.Mount, Roles: roles})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return s
}

// harnessSealFiles is sealrotate's Files over a harness store, whose
// fragment names its key at its own seal directory.
func harnessSealFiles(t *testing.T, s *secretstoretest.Store) *sealrotate.Files {
	t.Helper()
	dir := s.SealDir()
	f, err := sealrotate.NewFiles(sealrotate.Paths{SealDir: dir, CredDir: dir, RotationCred: func(id sealrotate.KeyID) string {
		return filepath.Join(dir, sealrotate.RotationDirName, string(id))
	}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// apiChain is the api's chain over s, logged in as rasputin-api with a
// leaf minted by s's store CA.
func apiChain(t *testing.T, s *secretstoretest.Store, logger *slog.Logger, jobRunning func(context.Context, string) (bool, error)) *realStore {
	t.Helper()
	tc, err := s.ClientTLSFor(storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	client, err := secretstore.New(secretstore.Config{Addr: u, TLS: tc, CallTimeout: 10 * time.Second, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	mon, err := storestate.New(storestate.Deps{Store: client, Now: time.Now, Log: logger, JobRunning: jobRunning,
		Blank: func(context.Context) (bool, error) { return false, nil }})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := storestate.NewObservedStore(client, mon)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := storesession.New(storesession.Config{Role: storepolicy.APIPolicy, Login: client, Store: observed, Observer: mon, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := secrets.NewRepository(sess)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := secrets.NewService(secrets.Deps{Repo: repo, Apps: fnApps{}, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	rs := &realStore{s: s, client: client, mon: mon, svc: svc, repo: repo}
	if s.SealDir() != "" {
		rs.files = harnessSealFiles(t, s)
	}
	return rs
}

// fnApps places fnAppID on the run harness's node.
type fnApps struct{}

func (fnApps) TargetNode(_ context.Context, appID string) (string, bool, error) {
	return runNodeID, appID == fnAppID, nil
}

// realControl is storage.SecretStore over a real harness store, as main's
// storeBackupControl is over the unit: stop and start are the process's.
type realControl struct {
	rs *realStore
	// beforeStop runs right before the stop: after VACUUM INTO.
	beforeStop func(ctx context.Context)
	// duringStop runs with the store stopped.
	duringStop func()
}

func (c *realControl) Readiness(ctx context.Context) (string, error) {
	st, err := c.rs.mon.State(ctx)
	if err != nil || st == storestate.Ready {
		return "", err
	}
	return storestate.Clause(st), nil
}

func (c *realControl) SealKeyID() (string, error) {
	tree, err := c.rs.files.State()
	if err != nil {
		return "", err
	}
	if tree.Fragment.Shape != sealrotate.Clean {
		return "", errStoreSealUnknown
	}
	return tree.Fragment.Current.String(), nil
}

func (c *realControl) Version(ctx context.Context) (string, error) {
	h, err := c.rs.client.Health(ctx)
	return h.Version, err
}

func (c *realControl) Stop(ctx context.Context) error {
	if c.beforeStop != nil {
		c.beforeStop(ctx)
	}
	if err := c.rs.s.Stop(ctx); err != nil {
		return err
	}
	if c.duringStop != nil {
		c.duringStop()
	}
	return nil
}

func (c *realControl) Start(ctx context.Context) error { return c.rs.s.StartNoWait(ctx) }

func (c *realControl) WaitReady(ctx context.Context) error {
	return secretstore.WaitReady(ctx, c.rs.client, sealrotate.UnsealWait)
}

func (c *realControl) Quiesce(jobID string) func() {
	return c.rs.mon.Quiesce(jobID, storestate.QuiesceBackup)
}

// harnessJobRunning is the monitor's quiesce fact over the run harness's
// job ledger.
func harnessJobRunning(h **runHarness) func(context.Context, string) (bool, error) {
	return func(ctx context.Context, id string) (bool, error) {
		j, err := (*h).jobStore.GetJob(ctx, id)
		return j != nil && j.Status == jobs.StatusRunning, err
	}
}

// restoredMembers are a prepared restore's staged store members.
func restoredMembers(fresh string) secretstoretest.Restored {
	p := filepath.Join(fresh, restorePendingDirName)
	return secretstoretest.Restored{
		DataDir: filepath.Join(p, "store", "data"),
		SealKey: filepath.Join(p, "store", storeSealKeyFileName),
		SealHCL: filepath.Join(p, "store", storeSealFragmentName),
		CAKey:   filepath.Join(p, "trust", tlsca.StoreKeyFile),
		CACert:  filepath.Join(p, "trust", tlsca.StoreCertFile),
	}
}

// adoptInto starts a fresh store, stops it, and has it adopt fresh's staged
// members (#766's hook and the api's leaf re-mint), then applies the
// restore as the next api start does.
func adoptInto(t *testing.T, hs *secretstoretest.Harness, fresh string) *secretstoretest.Store {
	t.Helper()
	b := startRealStore(t, hs)
	if err := b.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := b.Adopt(t.Context(), restoredMembers(fresh)); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	markStoreApplied(t, fresh)
	if _, applied, err := ApplyPendingRestore(storeLayout(fresh)); err != nil || !applied {
		t.Fatalf("ApplyPendingRestore = (%v, %v)", applied, err)
	}
	return b
}

func readSecret(t *testing.T, svc *secrets.Service, ref secrets.Ref) string {
	t.Helper()
	got, err := svc.Read(t.Context(), secrets.DeployActor(fnAppID, runNodeID), ref)
	if err != nil {
		t.Fatalf("Read %s: %v", ref, err)
	}
	defer got.Value.Destroy()
	return string(got.Value.Reveal())
}

// TestStoreBackupRestore_AgainstTheRealStore is F1.4's round trip of the
// secret store through a backup (geekdojo/geekdojo-brain#765, TC-765-34 to
// TC-765-38), against the pinned OpenBao with the shipped policies and the
// seal outside the main config. Without the store binary it skips, and with
// RASPUTIN_SECRETSTORE_FUNCTIONAL=required it fails instead.
func TestStoreBackupRestore_AgainstTheRealStore(t *testing.T) {
	bin := os.Getenv(storeBinEnv)
	if bin == "" {
		functest.SkipOrFail(t, storeSwitchEnv, "%s is not set, so there is no secret store binary to run", storeBinEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, storeSwitchEnv, "%s=%s: no secret store binary there: %v", storeBinEnv, bin, err)
		return
	}
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelInfo}))
	hs, err := secretstoretest.New(secretstoretest.Config{
		BinaryPath: bin, TempParent: t.TempDir(), Logger: logger, Now: time.Now, Rand: rand.Reader, ExternalSeal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := secrets.AppSecret(fnAppID, "db-pass")
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.TrimPrefix(secretstoretest.OpenBaoRelease[strings.LastIndex(secretstoretest.OpenBaoRelease, ":")+1:], "v")

	t.Run("TC-765-34 TC-765-35 TC-765-38 write, back up, wipe, restore, log in, read", func(t *testing.T) {
		a := startRealStore(t, hs)
		var h *runHarness
		late := &lateStore{}
		h = newRunHarness(t, nil, runHarnessOpts{secretStore: late, storeSources: &IdentitySources{
			StoreDataDir: a.DataDir(), SealDir: a.SealDir(), TrustDir: a.CADir(),
		}})
		ra := apiChain(t, a, logger, harnessJobRunning(&h))
		ctl := &realControl{rs: ra}
		late.inner = ctl
		ctx := t.Context()
		// An app row naming the secret by path, so the restored database has
		// a reference to resolve.
		as, err := apps.OpenStore(ctx, h.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		if err := as.Create(ctx, &apps.App{ID: fnAppID, Name: "restored-app", TargetNode: runNodeID, CreatedAt: now, UpdatedAt: now,
			ComposeYAML: "services:\n  db:\n    environment:\n      PW: ${secret:db-pass}\n"}); err != nil {
			t.Fatal(err)
		}
		_ = as.Close()
		if _, err := ra.svc.Create(ctx, secrets.DeployActor(fnAppID, runNodeID), ref, secret.New([]byte(fnDeployValue))); err != nil {
			t.Fatal(err)
		}
		// TC-765-35: the operator's value lands after VACUUM INTO and before
		// the stop.
		ctl.beforeStop = func(ctx context.Context) {
			if _, err := ra.svc.Replace(ctx, secrets.OperatorActor("u1"), ref, secret.New([]byte(fnOperatorValue))); err != nil {
				t.Errorf("operator Replace: %v", err)
			}
		}
		var sampled []string
		ctl.duringStop = func() {
			for _, al := range ra.mon.Alerts(context.Background(), time.Now()) {
				sampled = append(sampled, al.ID)
			}
		}
		jobID := h.submit(t, RunSpec{Reason: ReasonManual})
		if j := h.waitTerminal(t, jobID); j.Status != jobs.StatusSucceeded {
			t.Fatalf("backup %s: %s", j.Status, j.Error)
		}
		if !slices.Equal(sampled, []string{"secret-store:quiesced"}) {
			t.Errorf("alerts during the stop = %v, want secret-store:quiesced", sampled)
		}
		names := stepNames(t, h, jobID)
		if i := slices.Index(names, "snapshot_db"); i < 0 || slices.Index(names, storeCaptureStepName) != i+1 {
			t.Errorf("steps %v: want snapshot_db then %s", names, storeCaptureStepName)
		}
		genID := h.run(t, jobID).GenerationID
		if err := a.Close(context.Background()); err != nil {
			t.Fatal(err)
		}

		fresh := prepareFromRun(t, h, genID)
		// TC-765-38: the version member is the pinned release's.
		if got := readString(t, filepath.Join(fresh, restorePendingDirName, filepath.FromSlash(storeVersionArchivePath))); got != pin {
			t.Errorf("%s = %q, want the pin's %q", storeVersionArchivePath, got, pin)
		}
		b := adoptInto(t, hs, fresh)
		if got, want := readString(t, filepath.Join(fresh, "trust", tlsca.StoreCertFile)), string(b.StoreCA().CertPEM); got != want {
			t.Error("the api's live store CA is not the restored one the store trusts")
		}
		// A rasputin-api leaf minted from the restored CA logs in and reads
		// the secret by path: the operator's value (TC-765-34, TC-765-35).
		rb := apiChain(t, b, logger, func(context.Context, string) (bool, error) { return false, nil })
		if got := readSecret(t, rb.svc, ref); got != fnOperatorValue {
			t.Fatalf("read after the restore = %d bytes, want the operator's value", len(got))
		}
		// Every reference in the restored database resolves.
		restored, err := apps.OpenStore(ctx, filepath.Join(fresh, "rasputin.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = restored.Close() }()
		list, err := restored.List(ctx)
		if err != nil || len(list) != 1 {
			t.Fatalf("restored apps = %v, %v", list, err)
		}
		toks, err := tileschema.ScanSecretTokens(list[0].ComposeYAML)
		if err != nil || len(toks) == 0 {
			t.Fatalf("tokens = %v, %v", toks, err)
		}
		for _, tok := range toks {
			r, err := secrets.AppSecret(list[0].ID, tok.Name)
			if err != nil {
				t.Fatal(err)
			}
			readSecret(t, rb.svc, r)
		}
	})

	t.Run("TC-765-36 rotation across real stores", func(t *testing.T) {
		r := startRealStore(t, hs)
		var h *runHarness
		late, lock := &lateStore{}, &lateLock{}
		h = newRunHarness(t, nil, runHarnessOpts{secretStore: late, captureLock: lock, storeSources: &IdentitySources{
			StoreDataDir: r.DataDir(), SealDir: r.SealDir(), TrustDir: r.CADir(),
		}})
		jr := harnessJobRunning(&h)
		rr := apiChain(t, r, logger, jr)
		late.inner = &realControl{rs: rr}
		gate, err := sealrotate.NewGate(rr.files, jr, logger)
		if err != nil {
			t.Fatal(err)
		}
		lock.inner = gate
		const canary = "functional-canary-9a2b"
		cref, err := secrets.AppSecret(fnAppID, "canary")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rr.svc.Create(t.Context(), secrets.DeployActor(fnAppID, runNodeID), cref, secret.New([]byte(canary))); err != nil {
			t.Fatal(err)
		}
		backup := func() (string, sealrotate.KeyID) {
			t.Helper()
			tree, err := rr.files.State()
			if err != nil {
				t.Fatal(err)
			}
			jobID := h.submit(t, RunSpec{Reason: ReasonManual})
			if j := h.waitTerminal(t, jobID); j.Status != jobs.StatusSucceeded {
				t.Fatalf("backup %s: %s", j.Status, j.Error)
			}
			return h.run(t, jobID).GenerationID, tree.Fragment.Current
		}
		g1, k1 := backup()
		rotTLS, err := secretstore.NewMintedTLSConfig(r.StoreCA().CertPEM, sealrotate.MintRotationLeaf(r.StoreCA()))
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(r.URL())
		rotClient, err := secretstore.New(secretstore.Config{Addr: u, TLS: rotTLS, CallTimeout: 10 * time.Second, Logger: logger})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(rotClient.CloseIdleConnections)
		rot, err := sealrotate.NewRotator(sealrotate.Config{Enabled: true, UnsealWait: sealrotate.UnsealWait}, sealrotate.Deps{
			Store: rr.client, Rotate: rotClient, Files: rr.files, Gate: gate,
			Restart: func(ctx context.Context) error {
				if r.Running() {
					if err := r.Stop(ctx); err != nil {
						return err
					}
				}
				return r.StartNoWait(ctx)
			},
			Quiesce:  func(id string, reason storestate.QuiesceReason) func() { return rr.mon.Quiesce(id, reason) },
			Restores: rotationFakes{}, Rand: rand.Reader,
			KeyID: func() (sealrotate.KeyID, error) {
				id, err := secretstoretest.SealKeyID(rand.Reader)
				if err != nil {
					return "", err
				}
				return sealrotate.ParseKeyID(id)
			},
			Log: logger, JobRunning: jr, Now: time.Now,
		})
		if err != nil {
			t.Fatal(err)
		}
		h.runner.Register(rot.Workflow())
		rj, err := h.runner.Submit(t.Context(), sealrotate.Kind, nil, "functional-test")
		if err != nil {
			t.Fatal(err)
		}
		if j := h.waitTerminal(t, rj.ID); j.Status != jobs.StatusSucceeded {
			t.Fatalf("rotation %s: %s", j.Status, j.Error)
		}
		g2, k2 := backup()
		if k1 == k2 {
			t.Fatal("the rotation did not change the key id")
		}
		for _, tc := range []struct {
			gen string
			key sealrotate.KeyID
		}{{g1, k1}, {g2, k2}} {
			fresh := prepareFromRun(t, h, tc.gen)
			c := adoptInto(t, hs, fresh)
			frag, err := os.ReadFile(filepath.Join(c.SealDir(), storeSealFragmentName))
			if err != nil {
				t.Fatal(err)
			}
			if id, err := sealrotate.CurrentKeyID(frag); err != nil || id != tc.key {
				t.Errorf("generation %s unsealed under %s (%v), want %s", tc.gen, id, err, tc.key)
			}
			rc := apiChain(t, c, logger, func(context.Context, string) (bool, error) { return false, nil })
			if hl, err := rc.client.Health(t.Context()); err != nil || hl.Sealed || !hl.Initialized {
				t.Fatalf("generation %s's store: %+v, %v", tc.gen, hl, err)
			}
			if got := readSecret(t, rc.svc, cref); got != canary {
				t.Errorf("generation %s's canary did not read back", tc.gen)
			}
		}
	})

	t.Run("TC-765-37 a pre-store archive onto a running store", func(t *testing.T) {
		c := startRealStore(t, hs)
		rc := apiChain(t, c, logger, func(context.Context, string) (bool, error) { return false, nil })
		if _, err := rc.svc.Create(t.Context(), secrets.DeployActor(fnAppID, runNodeID), ref, secret.New([]byte(fnDeployValue))); err != nil {
			t.Fatal(err)
		}
		h := newRunHarness(t, nil, runHarnessOpts{})
		jobID := h.submit(t, RunSpec{Reason: ReasonManual})
		if j := h.waitTerminal(t, jobID); j.Status != jobs.StatusSucceeded {
			t.Fatalf("backup %s: %s", j.Status, j.Error)
		}
		if m := writtenManifest(t, h, jobID); m.ManifestVersion != 2 {
			t.Fatalf("manifest version %d, want 2", m.ManifestVersion)
		}
		live := []string{c.DataDir(), c.SealDir(), filepath.Join(c.CADir(), tlsca.StoreKeyFile), filepath.Join(c.CADir(), tlsca.StoreCertFile)}
		before := hashes(t, live...)
		fresh := filepath.Join(t.TempDir(), "var-lib-rasputin")
		mustMkdirAll(t, fresh)
		report := prepareInto(t, h, h.run(t, jobID).GenerationID, fresh)
		if !strings.Contains(report.Warning, "the cluster's current secret store, seal key and store CA were kept") {
			t.Errorf("warning %q lacks the store-kept sentence", report.Warning)
		}
		// The node's trust dir is the one the running store's CA is in.
		layout := storeLayout(fresh)
		layout.TrustDir = c.CADir()
		if _, applied, err := ApplyPendingRestore(layout); err != nil || !applied {
			t.Fatalf("apply = (%v, %v)", applied, err)
		}
		sameHashes(t, "the running store", before, hashes(t, live...))
		if got := readSecret(t, rc.svc, ref); got != fnDeployValue {
			t.Error("the running store's secret does not read after the restore")
		}
	})
}

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}
