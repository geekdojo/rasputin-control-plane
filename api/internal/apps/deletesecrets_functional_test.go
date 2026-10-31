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
)

// monitorState is apps.SecretStoreState over a real monitor, as main's
// appStoreState is.
type monitorState struct{ m *storestate.Monitor }

func (s monitorState) Configured() bool { return true }
func (s monitorState) State(ctx context.Context) (storestate.State, error) {
	return s.m.State(ctx)
}

// TestDelete_AgainstTheRealStore is the F1.4 functional test of every path
// that destroys an app's secrets (geekdojo/geekdojo-brain#783): the delete
// saga's steps over embedded NATS with a fake agent, the release step of a
// compose change, and node removal, with the real apps SQLite and the real
// secrets service on the real chain (client, Monitor, ObservedStore, login
// session, repository), against the pinned OpenBao under the shipped
// rasputin-api policy. The legs run in order on one store (TC-783-20 to
// TC-783-24, TC-783-58 to TC-783-60).
func TestDelete_AgainstTheRealStore(t *testing.T) {
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

	// A, D: deleted with volumes. B: deleted keeping them, which destroys its
	// secrets all the same (F-783-05). C: a reinstall under a new ULID with
	// B's secret names, while B is not yet deleted.
	const (
		idA = "01J9ZK3Q0M8X7Y6W5V4T3S2R1A"
		idB = "01J9ZK3Q0M8X7Y6W5V4T3S2R1B"
		idC = "01J9ZK3Q0M8X7Y6W5V4T3S2R1C"
		idD = "01J9ZK3Q0M8X7Y6W5V4T3S2R1D"
	)
	nc := apps.StartNATS(t)
	composeA := "services:\n  web:\n    image: me/web:1\n    environment:\n      P: ${secret:db-password}\n      K: ${secret:api-key}\n"
	composeD := "services:\n  web:\n    image: me/web:1\n    environment:\n      T: ${secret:legacy-token}\n"
	composeB := "services:\n  web:\n    image: me/web:1\n    environment:\n      P: ${secret:db-password}\n      K: ${secret:api-key}\n"
	appStore, inv := apps.SeedComposeApp(t, idA, composeA)
	now := time.Now().UTC()
	for id, compose := range map[string]string{idB: composeB, idD: composeD} {
		if err := appStore.Create(ctx, &apps.App{ID: id, Name: "app-" + id[len(id)-1:], ComposeYAML: compose, TargetNode: "n",
			LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	vol := func(id string) proto.AppVolumeInfo {
		return proto.AppVolumeInfo{Name: proto.AppVolumeName(id, "data"), AppID: id, Volume: "data"}
	}
	apps.FakeDeleteAgent(t, nc, "n", vol(idA), vol(idB), vol(idD))

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
	w, err := apps.DeleteWorkflow(appStore, inv, nc, nil, apps.DeleteSecretsDeps{Secrets: svc, Store: monitorState{m: monitor}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	runner, js := apps.RealRunner(t, nc, w)
	jst = js

	operator := secrets.OperatorActor("alice")
	var written []string // every value this test writes, for TC-783-24
	var texts []string   // every error a person or the ledger reads
	ref := func(t *testing.T, appID, name string) (secrets.Ref, secretstore.KVPath) {
		t.Helper()
		r, err := secrets.AppSecret(appID, name)
		if err != nil {
			t.Fatal(err)
		}
		p, err := secretstore.NewKVPath(storepolicy.Mount, r.String())
		if err != nil {
			t.Fatal(err)
		}
		return r, p
	}
	put := func(t *testing.T, appID, name string, values ...string) {
		t.Helper()
		r, _ := ref(t, appID, name)
		for i, v := range values {
			written = append(written, v)
			var err error
			if i == 0 {
				_, err = svc.Create(ctx, operator, r, secret.New([]byte(v)))
			} else {
				_, err = svc.Replace(ctx, operator, r, secret.New([]byte(v)))
			}
			if err != nil {
				t.Fatalf("write %s/%s: %v", appID, name, err)
			}
		}
	}
	record := func(t *testing.T, appID string, names ...string) {
		t.Helper()
		for _, n := range names {
			if err := appStore.RecordSecretRef(ctx, appID, n); err != nil {
				t.Fatal(err)
			}
		}
	}
	gone := func(t *testing.T, appID, name string, versions int) {
		t.Helper()
		_, p := ref(t, appID, name)
		for v := 1; v <= versions; v++ {
			kv, err := sess.Read(ctx, p, v)
			kv.Destroy()
			if !errors.Is(err, secretstore.ErrNotFound) {
				t.Errorf("%s/%s version %d after delete: %v; want ErrNotFound", appID, name, v, err)
			}
		}
		if _, err := sess.Versions(ctx, p); !errors.Is(err, secretstore.ErrNotFound) {
			t.Errorf("%s/%s metadata after delete: %v; want ErrNotFound", appID, name, err)
		}
	}
	reads := func(t *testing.T, appID, name, want string, version int) {
		t.Helper()
		_, p := ref(t, appID, name)
		kv, err := sess.Read(ctx, p, 0)
		if err != nil {
			t.Fatalf("%s/%s: %v", appID, name, err)
		}
		defer kv.Destroy()
		if v := kv.Data["value"]; string(v.Reveal()) != want || kv.Version != version {
			t.Errorf("%s/%s = version %d (%d bytes); want version %d holding the value written", appID, name, kv.Version, v.Len(), version)
		}
	}
	deleteApp := func(t *testing.T, appID string, withVolumes bool) *jobs.Job {
		t.Helper()
		spec := apps.DeleteSpec{AppID: appID}
		if withVolumes {
			spec.DeleteVolumes = []string{vol(appID).Name}
		}
		j, err := runner.Submit(ctx, "app.delete", spec, "alice")
		if err != nil {
			t.Fatal(err)
		}
		runner.Wait()
		got, err := jst.GetJob(ctx, j.ID)
		if err != nil || got == nil {
			t.Fatalf("GetJob: %v", err)
		}
		texts = append(texts, got.Error)
		if got.Status != jobs.StatusSucceeded {
			t.Fatalf("app.delete of %s ended %s: %s", appID, got.Status, got.Error)
		}
		return got
	}
	// audited checks one INFO secrets.delete record per name of appID, as
	// alice, under job jobID.
	audited := func(t *testing.T, appID, jobID string, names ...string) {
		t.Helper()
		for _, name := range names {
			r, _ := ref(t, appID, name)
			var n int
			for _, rc := range rec.Matching(slog.LevelInfo, "secret deleted") {
				if v, _ := logkittest.Attr(rc, "ref"); v != r.String() {
					continue
				}
				n++
				event, _ := logkittest.Attr(rc, "event")
				user, _ := logkittest.Attr(rc, "user_id")
				job, _ := logkittest.Attr(rc, "job_id")
				if event != "secrets.delete" || user != "alice" || job != jobID {
					t.Errorf("%s: record event=%q user_id=%q job_id=%q; want secrets.delete, alice, %s", name, event, user, job, jobID)
				}
			}
			if n != 1 {
				t.Errorf("%s: %d secrets.delete records; want 1", name, n)
			}
		}
	}
	var jobIDs []string

	t.Run("TC-783-20 delete with volumes leaves nothing readable", func(t *testing.T) {
		put(t, idA, "db-password", "S-783-a-pw-v1", "S-783-a-pw-v2")
		put(t, idA, "api-key", "S-783-a-key-v1")
		record(t, idA, "db-password", "api-key")
		j := deleteApp(t, idA, true)
		jobIDs = append(jobIDs, j.ID)
		gone(t, idA, "db-password", 2)
		gone(t, idA, "api-key", 1)
		if row, _ := appStore.Get(ctx, idA); row != nil {
			t.Error("A's row survived")
		}
		if names, _ := appStore.SecretRefNames(ctx, idA); len(names) != 0 {
			t.Errorf("A's refs survived: %v", names)
		}
		audited(t, idA, j.ID, "db-password", "api-key")
	})

	t.Run("TC-783-21 unrecorded entries are deleted too", func(t *testing.T) {
		put(t, idD, "legacy-token", "S-783-d-token-v1")
		j := deleteApp(t, idD, true)
		jobIDs = append(jobIDs, j.ID)
		gone(t, idD, "legacy-token", 1)
	})

	t.Run("TC-783-22 a new ULID starts empty", func(t *testing.T) {
		put(t, idB, "db-password", "S-783-b-pw-v1", "S-783-b-pw-v2")
		put(t, idB, "api-key", "S-783-b-key-v1")
		record(t, idB, "db-password", "api-key")
		if err := appStore.Create(ctx, &apps.App{ID: idC, Name: "app-C", ComposeYAML: composeB, TargetNode: "n",
			LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"db-password", "api-key"} {
			r, _ := ref(t, idC, name)
			if ok, err := svc.Exists(ctx, secrets.CheckActor(), r); err != nil || ok {
				t.Fatalf("Exists(C %s) = %v, %v; want false", name, ok, err)
			}
		}
		put(t, idC, "db-password", "S-783-c-pw-v1")
		reads(t, idC, "db-password", "S-783-c-pw-v1", 1)
		reads(t, idB, "db-password", "S-783-b-pw-v2", 2)
	})

	t.Run("TC-783-23 keep-volumes delete leaves nothing readable", func(t *testing.T) {
		j := deleteApp(t, idB, false)
		jobIDs = append(jobIDs, j.ID)
		gone(t, idB, "db-password", 2)
		gone(t, idB, "api-key", 1)
		audited(t, idB, j.ID, "db-password", "api-key")
		steps, err := jst.ListSteps(ctx, j.ID)
		if err != nil {
			t.Fatal(err)
		}
		var named bool
		for _, st := range steps {
			if st.Name == "remove" {
				named = strings.Contains(string(st.Result), `"secretNames":["api-key","db-password"]`)
			}
		}
		if !named {
			t.Error("the ledger's remove result does not name both of B's entries")
		}
	})

	deps := apps.DeleteSecretsDeps{Secrets: svc, Store: monitorState{m: monitor}, Log: log}
	var released []string // the release steps' results and errors, for TC-783-60

	t.Run("TC-783-58 a compose change releases only what both composes dropped", func(t *testing.T) {
		const idE = "01J9ZK3Q0M8X7Y6W5V4T3S2R1E"
		composeE := "services:\n  web:\n    image: me/web:1\n    environment:\n      X: ${secret:x}\n      Y: ${secret:y}\n"
		if err := appStore.Create(ctx, &apps.App{ID: idE, Name: "app-E", ComposeYAML: composeE, TargetNode: "n",
			LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		put(t, idE, "x", "S-783-e-x-v1", "S-783-e-x-v2")
		put(t, idE, "y", "S-783-e-y-v1")
		record(t, idE, "x", "y")
		release := func(t *testing.T, jobID, from, to string) {
			t.Helper()
			if err := appStore.EditCompose(ctx, idE, apps.ComposeHash(from), to, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			out, err := apps.ReleaseUnusedSecrets(appStore, deps)(&jobs.StepCtx{Ctx: ctx, JobID: jobID, CreatedBy: "alice",
				Spec: []byte(`{"appId":"` + idE + `"}`), Log: func(_, msg string) { released = append(released, msg) }})
			released = append(released, string(out))
			if err != nil {
				released = append(released, err.Error())
				t.Fatalf("release_secrets after %s: %v", jobID, err)
			}
		}
		composeB := "services:\n  web:\n    image: me/web:2\n    environment:\n      Y: ${secret:y}\n"
		composeC := "services:\n  web:\n    image: me/web:3\n    environment:\n      Y: ${secret:y}\n"
		release(t, "job-783-58-b", composeE, composeB)
		reads(t, idE, "x", "S-783-e-x-v2", 2)
		release(t, "job-783-58-c", composeB, composeC)
		gone(t, idE, "x", 2)
		reads(t, idE, "y", "S-783-e-y-v1", 1)
		audited(t, idE, "job-783-58-c", "x")
		if names, _ := appStore.SecretRefNames(ctx, idE); len(names) != 1 || names[0] != "y" {
			t.Errorf("E's refs = %v; want [y]", names)
		}
	})

	t.Run("TC-783-59 node removal deletes every secret of the node's apps", func(t *testing.T) {
		const (
			idP = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
			idR = "01J9ZK3Q0M8X7Y6W5V4T3S2R1R"
			idS = "01J9ZK3Q0M8X7Y6W5V4T3S2R1S"
		)
		for id, node := range map[string]string{idP: "m", idR: "m", idS: "other"} {
			if err := appStore.Create(ctx, &apps.App{ID: id, Name: "app-" + id[len(id)-1:], ComposeYAML: composeA, TargetNode: node,
				LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
		}
		put(t, idP, "db-password", "S-783-p-pw-v1", "S-783-p-pw-v2")
		put(t, idP, "api-key", "S-783-p-key-v1")
		put(t, idR, "db-password", "S-783-r-pw-v1", "S-783-r-pw-v2")
		put(t, idR, "api-key", "S-783-r-key-v1")
		put(t, idS, "db-password", "S-783-s-pw-v1")
		record(t, idP, "db-password", "api-key")
		record(t, idR, "db-password", "api-key")
		record(t, idS, "db-password")
		nodeApps, err := apps.NewNodeApps(appStore, deps)
		if err != nil {
			t.Fatal(err)
		}
		if err := nodeApps.CheckSecrets(ctx, "m"); err != nil {
			t.Fatalf("CheckSecrets: %v", err)
		}
		ids, err := nodeApps.Remove(ctx, "alice", "m")
		if err != nil {
			released = append(released, err.Error())
			t.Fatalf("Remove: %v", err)
		}
		if len(ids) != 2 {
			t.Errorf("removed %v; want P and R", ids)
		}
		for _, id := range []string{idP, idR} {
			gone(t, id, "db-password", 2)
			gone(t, id, "api-key", 1)
			audited(t, id, "", "db-password", "api-key")
		}
		reads(t, idS, "db-password", "S-783-s-pw-v1", 1)
	})

	t.Run("TC-783-60 no value leaks from a release or a node removal", func(t *testing.T) {
		all := strings.Join(append([]string{rec.Text()}, released...), "\n")
		if len(released) == 0 || !strings.Contains(all, "secrets.delete") {
			t.Fatal("the scan holds no delete record, so it read the wrong thing")
		}
		for _, v := range written {
			if strings.Contains(all, v) {
				t.Errorf("a written value appears in a log, error or result")
			}
		}
	})

	t.Run("TC-783-24 no value leaks", func(t *testing.T) {
		if len(written) == 0 || len(jobIDs) != 3 {
			t.Fatalf("written %d values over %d jobs; the scan would read too little", len(written), len(jobIDs))
		}
		var hay []string
		hay = append(hay, rec.Text())
		hay = append(hay, texts...)
		for _, id := range jobIDs {
			steps, err := jst.ListSteps(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			for _, st := range steps {
				hay = append(hay, string(st.Result), st.Error)
			}
			events, err := jst.ListEvents(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			for _, ev := range events {
				hay = append(hay, string(ev.Data))
			}
		}
		all := strings.Join(hay, "\n")
		if !strings.Contains(all, "secrets.delete") {
			t.Fatal("the scan holds no delete record, so it read the wrong thing")
		}
		for _, v := range written {
			if strings.Contains(all, v) {
				t.Errorf("a written value appears in a log, error, event or result")
			}
		}
	})
}
