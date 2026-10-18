package apps_test

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/url"
	"os"
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
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
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

// TestStoreSource_AgainstTheRealStore runs the deploy family's store source
// (geekdojo/geekdojo-brain#762) against the real pinned store, under the
// shipped rasputin-api policy, with its audit device on the store's stdout:
// the real client, Monitor, ObservedStore, login session, repository and
// secrets service, appsecret.StoreSource behind the readiness Gate, and a
// real runner with a fake deploy agent. The legs run in order on one store,
// because each changes it (TC-762-21 to TC-762-25, and the sealed leg).
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
		}})
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
	svc, err := secrets.NewService(secrets.Deps{Repo: repo, Apps: appNodes{s: appStore}, Log: log})
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
	src, err := appsecret.NewStoreSource(appsecret.StoreSourceDeps{Secrets: svc, Apps: appNodes{s: appStore}, Seed: seed, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := storestate.NewGate(src, monitor, log)
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
	deploy := func(t *testing.T) *jobs.Job {
		t.Helper()
		j, err := runner.Submit(ctx, "app.deploy", apps.DeploySpec{AppID: id}, "test")
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
	deploysWith := func(t *testing.T, want string) *jobs.Job {
		t.Helper()
		j := deploy(t)
		if j.Status != jobs.StatusSucceeded {
			t.Fatalf("the deploy ended %s: %s", j.Status, j.Error)
		}
		cmd := apps.ReceiveDeployWithin(t, deploys, "the agent never received the deploy command")
		if !strings.Contains(cmd.ComposeYAML, "DB_PASSWORD: "+want+"\n") {
			t.Fatal("the deploy command does not carry the expected value")
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
		for _, v := range []string{derived, replaced} {
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
