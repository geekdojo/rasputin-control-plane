package apps_test

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storeswitch"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// storeCallTimeout is the client's bound on one store call in this test. It
// bounds a single I/O call on loopback and decides no state; it is also the
// bound the audit-blocked leg waits on to see a read run out of time, so it
// is short.
const storeCallTimeout = 3 * time.Second

// fillCap bounds the audit-blocked leg's fill loop: a pipe that never fills
// within this many audited reads means the sink never blocked.
const fillCap = 5000

// appNodes is the secrets service's view of the apps table, as main's
// appTargetNodes is.
type appNodes struct{ s *apps.Store }

func (a appNodes) TargetNode(ctx context.Context, appID string) (string, bool, error) {
	app, err := a.s.Get(ctx, appID)
	if err != nil || app == nil {
		return "", false, err
	}
	return app.TargetNode, true, nil
}

// appDecls is the app's operator-secret declarations as appsecret reads
// them, as main's appOperatorSecrets is.
type appDecls struct{ s *apps.Store }

func (a appDecls) OperatorSecrets(ctx context.Context, appID string) ([]tileschema.OperatorSecret, error) {
	app, err := a.s.Get(ctx, appID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, errors.New("the app does not exist")
	}
	return app.OperatorSecrets, nil
}

// TestStoreSource_AgainstTheRealStore runs the deploy family's store source
// (geekdojo/geekdojo-brain#762) against the real pinned store, under the
// shipped rasputin-api policy, with its audit device on the store's stdout:
// the real client, Monitor, ObservedStore, login session, repository and
// secrets service, appsecret.StoreSource behind the readiness Gate, and a
// real runner with a fake deploy agent. The legs run in order on one store,
// because each changes it (TC-762-21 to TC-762-25, TC-780-17, and the sealed
// leg).
//
// The source is wired as main wires it: the readiness Gate around the
// operator-secret gate (geekdojo/geekdojo-brain#780) around StoreSource.
func TestStoreSource_AgainstTheRealStore(t *testing.T) {
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return
	}
	ctx := context.Background()
	log, rec := logkittest.New()
	apiPolicy, err := storepolicy.Text(storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	h, err := secretstoretest.New(secretstoretest.Config{
		BinaryPath: bin, TempParent: t.TempDir(), Logger: slog.New(slog.DiscardHandler), Now: time.Now, Rand: rand.Reader,
		AuditStdout: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := h.StartWith(t.Context(), secretstoretest.Bootstrap{Mount: storepolicy.Mount, Roles: []secretstoretest.Role{
		{Name: storepolicy.APIPolicy, Policy: storepolicy.APIPolicy, PolicyText: apiPolicy},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(context.Background()); err != nil {
			t.Errorf("cleanup Close: %v", err)
		}
	})
	tc, err := store.ClientTLSFor(storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := url.Parse(store.URL())
	if err != nil {
		t.Fatal(err)
	}
	client, err := secretstore.New(secretstore.Config{Addr: addr, TLS: tc, CallTimeout: storeCallTimeout, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	nc := apps.StartNATS(t)
	deploys := apps.FakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	appStore, inv := apps.SeedComposeApp(t, id, apps.SecretComposeV1)

	var jst *jobs.Store
	monitor, err := storestate.New(storestate.Deps{Store: client, Now: time.Now, Log: log,
		JobRunning: func(ctx context.Context, id string) (bool, error) {
			j, err := jst.GetJob(ctx, id)
			return j != nil && j.Status == jobs.StatusRunning, err
		},
		Blank: func(context.Context) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := storestate.NewObservedStore(client, monitor)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := storesession.New(storesession.Config{Role: storepolicy.APIPolicy, Login: client, Store: observed, Observer: monitor, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := secrets.NewRepository(sess)
	if err != nil {
		t.Fatal(err)
	}
	// The switch marker over a real settings table (geekdojo/geekdojo-brain#604).
	settings, err := setup.OpenStore(ctx, filepath.Join(t.TempDir(), "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = settings.Close() })
	sw, err := storeswitch.New(storeswitch.Deps{Settings: settings, Now: time.Now, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := secrets.NewService(secrets.Deps{Repo: repo, Apps: appNodes{s: appStore}, Switch: sw, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, appsecret.SeedLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	seed, err := appsecret.NewSeed(key, appsecret.DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	src, err := appsecret.NewStoreSource(appsecret.StoreSourceDeps{Secrets: svc, Apps: appNodes{s: appStore}, Refs: appStore, Seed: seed, Operator: appDecls{s: appStore}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	opGate, err := apps.NewOperatorSecretGate(apps.OperatorSecretGateDeps{Next: src, Apps: appStore, Secrets: svc, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := storestate.NewGate(opGate, monitor, log)
	if err != nil {
		t.Fatal(err)
	}
	w, err := apps.DeployWorkflow(appStore, inv, nc, nil, gate)
	if err != nil {
		t.Fatal(err)
	}
	runner, js := apps.RealRunner(t, nc, w)
	jst = js

	derivedV, err := seed.Derive(id, "db-password", appsecret.InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	derived := string(derivedV.Reveal())
	const replaced = "S-762-replaced"
	ref, err := secrets.AppSecret(id, "db-password")
	if err != nil {
		t.Fatal(err)
	}
	path, err := secretstore.NewKVPath(storepolicy.Mount, ref.String())
	if err != nil {
		t.Fatal(err)
	}

	var texts []string // every job error and alert a person reads
	var jobIDs []string
	deployApp := func(t *testing.T, appID string) *jobs.Job {
		t.Helper()
		j, err := runner.Submit(ctx, "app.deploy", apps.DeploySpec{AppID: appID}, "test")
		if err != nil {
			t.Fatal(err)
		}
		runner.Wait()
		got, err := jst.GetJob(ctx, j.ID)
		if err != nil || got == nil {
			t.Fatalf("GetJob(%s): %v", j.ID, err)
		}
		jobIDs = append(jobIDs, j.ID)
		texts = append(texts, got.Error)
		for _, a := range monitor.Alerts(ctx, time.Now()) {
			texts = append(texts, a.Title, a.Detail)
		}
		return got
	}
	deploy := func(t *testing.T) *jobs.Job {
		t.Helper()
		return deployApp(t, id)
	}
	deploysWith := func(t *testing.T, want string) *jobs.Job {
		t.Helper()
		j := deploy(t)
		if j.Status != jobs.StatusSucceeded {
			t.Fatalf("the deploy ended %s: %s", j.Status, j.Error)
		}
		cmd := apps.ReceiveDeployWithin(t, deploys, "the agent never received the deploy command")
		if cmd.SecretEnv[proto.SecretEnvName("db-password")] != want || strings.Contains(cmd.ComposeYAML, want) ||
			!strings.Contains(cmd.ComposeYAML, "DB_PASSWORD: ${RASPUTIN_SECRET_DB_PASSWORD}\n") {
			t.Fatal("the deploy command does not carry the expected value beside a reference compose")
		}
		return j
	}
	refused := func(t *testing.T) {
		t.Helper()
		j := deploy(t)
		if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, storestate.Code) {
			t.Fatalf("the deploy ended %s with %q, want failed with %s", j.Status, j.Error, storestate.Code)
		}
		if err := nc.Flush(); err != nil {
			t.Fatal(err)
		}
		if n := len(deploys); n != 0 {
			t.Fatalf("%d AppDeployCmd(s) reached the agent for a refused deploy", n)
		}
		row, err := appStore.Get(ctx, id)
		if err != nil || row.LastStatus != proto.AppStatusRunning {
			t.Fatalf("the app row moved to %v (%v), want RUNNING", row, err)
		}
	}
	version := func(t *testing.T) int {
		t.Helper()
		md, err := sess.Versions(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		return md.CurrentVersion
	}
	creates := func(jobID string) int {
		n := 0
		for _, r := range rec.Records() {
			ev, _ := logkittest.Attr(r, "event")
			jid, _ := logkittest.Attr(r, "job_id")
			if ev == "secrets.create" && jid == jobID {
				n++
			}
		}
		return n
	}

	t.Run("TC-762-21 the first deploy creates version 1 equal to HKDF", func(t *testing.T) {
		j := deploysWith(t, derived)
		if v := version(t); v != 1 {
			t.Fatalf("current_version %d, want 1", v)
		}
		kv, err := sess.Read(ctx, path, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer kv.Destroy()
		if string(kv.Data["value"].Reveal()) != derived {
			t.Fatal("the stored value is not Seed.Derive at InitialVersion")
		}
		if n := creates(j.ID); n != 1 {
			t.Fatalf("%d secrets.create records for the job, want 1", n)
		}
	})
	t.Run("TC-762-22 a redeploy reads and writes nothing", func(t *testing.T) {
		j := deploysWith(t, derived)
		if v := version(t); v != 1 {
			t.Fatalf("current_version %d, want 1", v)
		}
		if n := creates(j.ID); n != 0 {
			t.Fatalf("%d secrets.create records for the redeploy, want 0", n)
		}
	})
	t.Run("TC-762-23 the store is the source after creation", func(t *testing.T) {
		if v, err := svc.Replace(ctx, secrets.OperatorActor("u1"), ref, secret.New([]byte(replaced))); err != nil || v != 2 {
			t.Fatalf("Replace = %d, %v; want version 2", v, err)
		}
		deploysWith(t, replaced)
		if v := version(t); v != 2 {
			t.Fatalf("current_version %d, want 2", v)
		}
	})
	const operatorValue = "S-780-owner-supplied"
	t.Run("TC-780-17 an unset operator secret refuses and creates nothing; the owner's value is delivered", func(t *testing.T) {
		const opID = "01J9ZK3Q0M8X7Y6W5V4T3S2FD0"
		now := time.Now().UTC()
		if err := appStore.Create(ctx, &apps.App{
			ID: opID, Name: "feeds", TargetNode: "n", PublishedPort: 8081, DeployBudgetSeconds: 300,
			ComposeYAML:     "services:\n  feeds:\n    image: me/feeds:1\n    environment:\n      FEED_KEY: ${secret:feed-key}\n",
			OperatorSecrets: []tileschema.OperatorSecret{{Name: "feed-key", Label: "Feed API key"}},
			LastStatus:      proto.AppStatusStopped, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		opRef, err := secrets.AppSecret(opID, "feed-key")
		if err != nil {
			t.Fatal(err)
		}
		opPath, err := secretstore.NewKVPath(storepolicy.Mount, opRef.String())
		if err != nil {
			t.Fatal(err)
		}

		j := deployApp(t, opID)
		if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, apps.CodeOperatorSecretUnset) {
			t.Fatalf("the deploy ended %s with %q, want failed with %s", j.Status, j.Error, apps.CodeOperatorSecretUnset)
		}
		if err := nc.Flush(); err != nil {
			t.Fatal(err)
		}
		if n := len(deploys); n != 0 {
			t.Fatalf("%d AppDeployCmd(s) reached the agent for a refused deploy", n)
		}
		if _, err := sess.Versions(ctx, opPath); !errors.Is(err, secretstore.ErrNotFound) {
			t.Fatalf("after the refusal the store answers %v for %s, want not found: the name was derived", err, opRef)
		}

		if _, err := svc.Create(ctx, secrets.OperatorActor("u1"), opRef, secret.New([]byte(operatorValue))); err != nil {
			t.Fatalf("the operator could not set the value: %v", err)
		}
		j = deployApp(t, opID)
		if j.Status != jobs.StatusSucceeded {
			t.Fatalf("the deploy after the value was set ended %s: %s", j.Status, j.Error)
		}
		cmd := apps.ReceiveDeployWithin(t, deploys, "the agent never received the deploy command")
		if cmd.SecretEnv[proto.SecretEnvName("feed-key")] != operatorValue {
			t.Fatal("the agent did not receive the owner's value byte-exact")
		}
		if strings.Contains(cmd.ComposeYAML, operatorValue) {
			t.Fatal("the owner's value reached the compose")
		}
	})
	const ownerFirst, ownerSecond = "S-604-owner-first", "S-604-owner-second"
	t.Run("TC-604-19 an optional name is never derived; the owner's value is replaced and delivered", func(t *testing.T) {
		const optID = "01J9ZK3Q0M8X7Y6W5V4T3S2FD1"
		no := false
		now := time.Now().UTC()
		if err := appStore.Create(ctx, &apps.App{
			ID: optID, Name: "radar", TargetNode: "n", PublishedPort: 8082, DeployBudgetSeconds: 300,
			ComposeYAML: "services:\n  radar:\n    image: me/radar:1\n    environment:\n      FEED_KEY: ${secret:feed-key}\n      OPT_KEY: ${secret:opt-key}\n",
			OperatorSecrets: []tileschema.OperatorSecret{
				{Name: "feed-key", Label: "Feed API key"},
				{Name: "opt-key", Label: "Optional key", Required: &no},
			},
			LastStatus: proto.AppStatusStopped, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		ops, err := apps.NewOperatorSecrets(apps.OperatorSecretsDeps{Apps: appStore, Secrets: svc, Refs: appStore, Log: log})
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{ownerFirst, ownerSecond} {
			if err := ops.Set(ctx, "u1", optID, "feed-key", secret.New([]byte(v))); err != nil {
				t.Fatalf("Set: %v", err)
			}
		}
		if on, err := sw.Switched(ctx); err != nil || !on {
			t.Fatalf("after the owner's write the marker reads %v (%v), want set", on, err)
		}
		feedRef, err := secrets.AppSecret(optID, "feed-key")
		if err != nil {
			t.Fatal(err)
		}
		feedPath, err := secretstore.NewKVPath(storepolicy.Mount, feedRef.String())
		if err != nil {
			t.Fatal(err)
		}
		if md, err := sess.Versions(ctx, feedPath); err != nil || md.CurrentVersion != 2 {
			t.Fatalf("the required name's version = %+v (%v), want 2", md, err)
		}

		j := deployApp(t, optID)
		if j.Status != jobs.StatusSucceeded {
			t.Fatalf("the deploy ended %s: %s", j.Status, j.Error)
		}
		cmd := apps.ReceiveDeployWithin(t, deploys, "the agent never received the deploy command")
		if cmd.SecretEnv[proto.SecretEnvName("feed-key")] != ownerSecond {
			t.Fatal("the deploy does not carry the owner's second value")
		}
		if v, ok := cmd.SecretEnv[proto.SecretEnvName("opt-key")]; !ok || v != "" {
			t.Fatalf("the optional key is %q (present %v), want present and empty", v, ok)
		}
		optRef, err := secrets.AppSecret(optID, "opt-key")
		if err != nil {
			t.Fatal(err)
		}
		optPath, err := secretstore.NewKVPath(storepolicy.Mount, optRef.String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sess.Versions(ctx, optPath); !errors.Is(err, secretstore.ErrNotFound) {
			t.Fatalf("the store answers %v for %s, want not found: the optional name was derived or stored", err, optRef)
		}
		refs, err := appStore.ListSecretRefs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, r := range refs {
			if r.AppID == optID {
				names = append(names, r.Name)
			}
		}
		if len(names) != 1 || names[0] != "feed-key" {
			t.Fatalf("refs for the app %v, want feed-key only", names)
		}
	})
	t.Run("TC-762-24 T42: a blocked audit sink reads audit-blocked and refuses", func(t *testing.T) {
		release := store.HoldStdout()
		defer release()
		blocked := false
		for i := 0; i < fillCap; i++ {
			kv, err := sess.Read(ctx, path, 0)
			kv.Destroy()
			if err == nil {
				continue
			}
			if errors.Is(err, secretstore.ErrUnreachable) && errors.Is(err, context.DeadlineExceeded) {
				t.Logf("the audited read %d ran out of time on the client's bound: the sink is blocked", i+1)
				blocked = true
				break
			}
			t.Fatalf("audited read %d = %v, want it answered or timed out", i+1, err)
		}
		if !blocked {
			t.Fatalf("the audit sink never blocked in %d audited reads", fillCap)
		}
		health, err := client.Health(ctx)
		if err != nil || !health.Initialized || health.Sealed {
			t.Fatalf("sys/health while the sink is blocked = %+v, %v; want 200 unsealed (T42)", health, err)
		}
		if st, err := monitor.State(ctx); err != nil || st != storestate.AuditBlocked {
			t.Fatalf("monitor reads %s (%v), want audit-blocked", st, err)
		}
		refused(t)
		release()
		deploysWith(t, replaced)
		if st, err := monitor.State(ctx); err != nil || st == storestate.AuditBlocked {
			t.Fatalf("monitor reads %s (%v) after the sink drained, want not audit-blocked", st, err)
		}
	})
	t.Run("sealed: the deploy refuses and the app is untouched", func(t *testing.T) {
		if err := store.RestartSealed(t.Context()); err != nil {
			t.Fatal(err)
		}
		refused(t)
	})
	t.Run("TC-762-25 nothing leaks across the legs", func(t *testing.T) {
		for _, s := range texts {
			low := strings.ToLower(s)
			for _, word := range []string{"openbao", "bao", "vault"} {
				if strings.Contains(low, word) {
					t.Errorf("%q names the vendor: %s", word, s)
				}
			}
		}
		row, err := appStore.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{derived, replaced, operatorValue, ownerFirst, ownerSecond} {
			if strings.Contains(rec.Text(), v) {
				t.Error("a value reached a log record")
			}
			if strings.Contains(row.ComposeYAML, v) {
				t.Error("a value reached the apps row")
			}
			for _, s := range texts {
				if strings.Contains(s, v) {
					t.Errorf("a value reached a job error or alert: %s", s)
				}
			}
			for _, jid := range jobIDs {
				apps.AssertLedgerLacks(t, jst, jid, v)
				evs, err := jst.ListEvents(ctx, jid)
				if err != nil {
					t.Fatal(err)
				}
				for _, ev := range evs {
					if strings.Contains(string(ev.Data), v) {
						t.Errorf("job %s event %s carries a value", jid, ev.Type)
					}
				}
			}
		}
	})
}
