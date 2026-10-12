package apps_test

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The functional switch and binary are the secret store smoke test's
// (docs/testing-secret-store.md): CI installs the pinned release and sets
// RASPUTIN_SECRETSTORE_FUNCTIONAL=required, so a missing binary fails the
// backend job instead of skipping.
const (
	binEnv    = "RASPUTIN_SECRETSTORE_BIN"
	switchEnv = "RASPUTIN_SECRETSTORE_FUNCTIONAL"
)

// TestStoreGate_AgainstTheRealStore runs the readiness gate against the real
// pinned store (geekdojo/geekdojo-brain#760): the real secretstore.Client, a
// real Monitor and Gate around the HKDF source, a real jobs.Runner with
// in-process NATS and a fake deploy agent, and alerts.Service with the store
// source wired. The legs run in order on one store, because each one changes
// it: up (TC-760-25), stopped (TC-760-26), restarted (TC-760-27) and sealed
// (TC-760-28), with the copy and redaction scans across all of them
// (TC-760-29). No leg sleeps: each reads the state the store is in when it
// asks.
func TestStoreGate_AgainstTheRealStore(t *testing.T) {
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

	h, err := secretstoretest.New(secretstoretest.Config{
		BinaryPath: bin, TempParent: t.TempDir(), Logger: slog.New(slog.DiscardHandler), Now: time.Now, Rand: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := h.Start(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(context.Background()); err != nil {
			t.Errorf("cleanup Close: %v", err)
		}
	})
	addr, err := url.Parse(store.URL())
	if err != nil {
		t.Fatal(err)
	}
	client, err := secretstore.New(secretstore.Config{Addr: addr, TLS: store.ClientTLS(), CallTimeout: 10 * time.Second, Logger: log})
	if err != nil {
		t.Fatal(err)
	}

	const (
		gatedApp = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
		plainApp = "01J9ZK3Q0M8X7Y6W5V4T3S2R1Q"
	)
	nc := apps.StartNATS(t)
	deploys := apps.FakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	deploying := apps.WatchDeploying(t, nc)
	appStore, inv := apps.SeedComposeApp(t, gatedApp, apps.SecretComposeV1)
	now := time.Now().UTC()
	if err := appStore.Create(ctx, &apps.App{
		ID: plainApp, Name: "plain", ComposeYAML: "services:\n  web:\n    image: me/web:1\n", TargetNode: "n",
		DeployBudgetSeconds: 300, LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	inner, derived := apps.WiringSource(t)
	want := derived(gatedApp, "db-password")
	var jst *jobs.Store
	monitor, err := storestate.New(storestate.Deps{Store: client, Now: time.Now, Log: log,
		JobRunning: func(ctx context.Context, id string) (bool, error) {
			j, err := jst.GetJob(ctx, id)
			return j != nil && j.Status == jobs.StatusRunning, err
		}})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := storestate.NewGate(inner, monitor, log)
	if err != nil {
		t.Fatal(err)
	}
	w, err := apps.DeployWorkflow(appStore, inv, nc, nil, gate)
	if err != nil {
		t.Fatal(err)
	}
	runner, js := apps.RealRunner(t, nc, w)
	jst = js

	setupStore, err := setup.OpenStore(ctx, filepath.Join(t.TempDir(), "setup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = setupStore.Close() })
	svc := alerts.New(inv, jst, appStore, setup.NewService(setupStore, setup.Probes{}, "", "", ""), nil, nil, true)
	svc.SetStoreAlerts(monitor.Alerts)

	var texts []string // every alert and job error a person reads
	var jobIDs []string
	storeAlerts := func(t *testing.T) []proto.Alert {
		t.Helper()
		list, err := svc.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		var out []proto.Alert
		for _, a := range list {
			if strings.HasPrefix(a.ID, "secret-store:") {
				out = append(out, a)
				texts = append(texts, a.Title, a.Detail)
			}
		}
		return out
	}
	deploy := func(t *testing.T, id string) *jobs.Job {
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
		return got
	}
	deploysOK := func(t *testing.T) {
		t.Helper()
		if j := deploy(t, gatedApp); j.Status != jobs.StatusSucceeded {
			t.Fatalf("the secret-bearing deploy ended %s: %s", j.Status, j.Error)
		}
		cmd := apps.ReceiveDeployWithin(t, deploys, "the agent never received the deploy command")
		if !strings.Contains(cmd.ComposeYAML, "DB_PASSWORD: "+want) {
			t.Fatal("the deploy command does not carry the derived value")
		}
	}
	refused := func(t *testing.T) {
		t.Helper()
		before := deploying.Load()
		j := deploy(t, gatedApp)
		if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, storestate.Code) {
			t.Fatalf("the secret-bearing deploy ended %s with %q, want failed with %s", j.Status, j.Error, storestate.Code)
		}
		if err := nc.Flush(); err != nil {
			t.Fatal(err)
		}
		if n := len(deploys); n != 0 {
			t.Fatalf("%d AppDeployCmd(s) reached the agent for a refused deploy", n)
		}
		if deploying.Load() != before {
			t.Fatal("a refused deploy announced DEPLOYING")
		}
	}

	t.Run("TC-760-25 up", func(t *testing.T) {
		if a := storeAlerts(t); len(a) != 0 {
			t.Fatalf("store alerts %+v while the store is up", a)
		}
		deploysOK(t)
	})
	t.Run("TC-760-26 stopped", func(t *testing.T) {
		if err := store.Stop(t.Context()); err != nil {
			t.Fatal(err)
		}
		a := storeAlerts(t)
		if len(a) != 1 || a[0].ID != "secret-store:unreachable" || a[0].Severity != proto.AlertCrit {
			t.Fatalf("store alerts %+v, want the unreachable crit", a)
		}
		refused(t)
		if j := deploy(t, plainApp); j.Status != jobs.StatusSucceeded {
			t.Fatalf("the token-free deploy ended %s: %s", j.Status, j.Error)
		}
		apps.ReceiveDeployWithin(t, deploys, "the token-free deploy never reached the agent")
	})
	t.Run("TC-760-27 restarted", func(t *testing.T) {
		if err := store.Restart(t.Context()); err != nil {
			t.Fatal(err)
		}
		if a := storeAlerts(t); len(a) != 0 {
			t.Fatalf("store alerts %+v after the restart", a)
		}
		deploysOK(t)
	})
	t.Run("TC-760-28 sealed", func(t *testing.T) {
		if err := store.RestartSealed(t.Context()); err != nil {
			t.Fatal(err)
		}
		a := storeAlerts(t)
		if len(a) != 1 || a[0].ID != "secret-store:sealed" || a[0].Severity != proto.AlertCrit {
			t.Fatalf("store alerts %+v, want only the sealed crit", a)
		}
		refused(t)
	})
	t.Run("TC-760-29 copy and redaction", func(t *testing.T) {
		for _, s := range texts {
			low := strings.ToLower(s)
			for _, word := range []string{"openbao", "bao", "vault"} {
				if strings.Contains(low, word) {
					t.Errorf("%q names the vendor: %s", word, s)
				}
			}
		}
		if strings.Contains(rec.Text(), want) {
			t.Error("the derived value reached a log record")
		}
		for _, id := range jobIDs {
			apps.AssertLedgerLacks(t, jst, id, want)
			evs, err := jst.ListEvents(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			for _, ev := range evs {
				if strings.Contains(string(ev.Data), want) {
					t.Errorf("job %s event %s carries the derived value", id, ev.Type)
				}
			}
		}
	})
}
