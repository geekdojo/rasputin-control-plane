package apps

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// The push step's side of the secret store's readiness gate
// (geekdojo/geekdojo-brain#760): a coded refusal is the job's error as it is,
// the step hands the source its job's id, and nothing is announced or sent.

// watchDeploying counts the app change events that announce DEPLOYING.
func watchDeploying(t *testing.T, nc *nats.Conn) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	sub, err := nc.Subscribe(proto.AllAppsFilter, func(m *nats.Msg) {
		var ev proto.AppChangeEvt
		if json.Unmarshal(m.Data, &ev) == nil && ev.Status == proto.AppStatusDeploying {
			n.Add(1)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return &n
}

// jobIDSource records the job id each call's ctx carries and refuses with err.
type jobIDSource struct {
	mu  sync.Mutex
	ids []string
	err error
}

func (s *jobIDSource) ResolveCompose(ctx context.Context, _, _ string) (secret.Value, map[string]secret.Value, error) {
	s.mu.Lock()
	s.ids = append(s.ids, jobs.JobIDFromContext(ctx))
	s.mu.Unlock()
	return secret.Value{}, nil, s.err
}

// TC-760-11: app.deploy and app.upgrade, on the real Runner, fail with the
// coded sentence exactly as the job's error, the source sees that job's own
// id, the push step announces no DEPLOYING and no AppDeployCmd is sent.
//
// An upgrade's pull step marks the app DEPLOYING before it pulls
// (pull.go's pullStep), ahead of the push, so for app.upgrade the one
// announcement is the pull's and the push adds none; app.deploy has none.
func TestPushStep_CodedRefusalIsTheJobError(t *testing.T) {
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	refusal := &storestate.NotReadyError{State: storestate.Sealed}
	for _, tc := range []struct {
		kind string
		// pullMarks is how many DEPLOYING announcements precede the push.
		pullMarks int32
		setup     func(t *testing.T, nc *nats.Conn, src SecretSource) (jobs.Workflow, any)
	}{
		{"app.deploy", 0, func(t *testing.T, nc *nats.Conn, src SecretSource) (jobs.Workflow, any) {
			store, inv := seedComposeApp(t, id, secretComposeV1)
			return wf(t)(DeployWorkflow(store, inv, nc, nil, src)), DeploySpec{AppID: id}
		}},
		{"app.upgrade", 1, func(t *testing.T, nc *nats.Conn, src SecretSource) (jobs.Workflow, any) {
			store, inv := seedUpgradeApp(t, id)
			fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
			tile := strings.Replace(composeV2, "    volumes:", "    environment:\n      DB_PASSWORD: ${secret:db-password}\n    volumes:", 1)
			return wf(t)(UpgradeWorkflow(store, inv, nc, nil, lookupOf(upgradeTile(tile), 2), src)), ComposeChangeSpec{AppID: id}
		}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			ctx := context.Background()
			nc := startNATS(t)
			deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
			deploying := watchDeploying(t, nc)
			src := &jobIDSource{err: refusal}
			w, spec := tc.setup(t, nc, src)
			runner, jst := realRunner(t, nc, w)
			j, err := runner.Submit(ctx, tc.kind, spec, "test")
			if err != nil {
				t.Fatal(err)
			}
			runner.Wait()
			got, err := jst.GetJob(ctx, j.ID)
			if err != nil || got == nil || got.Status != jobs.StatusFailed {
				t.Fatalf("job ended %+v (%v), want failed", got, err)
			}
			if got.Error != refusal.Error() {
				t.Fatalf("job error = %q, want exactly the sentence %q", got.Error, refusal.Error())
			}
			src.mu.Lock()
			ids := append([]string(nil), src.ids...)
			src.mu.Unlock()
			if len(ids) == 0 || ids[0] != j.ID {
				t.Fatalf("the source saw job ids %v, want this job's %s", ids, j.ID)
			}
			if err := nc.Flush(); err != nil {
				t.Fatal(err)
			}
			if n := deploying.Load(); n != tc.pullMarks {
				t.Errorf("%d DEPLOYING announcement(s), want %d: the push step must announce none", n, tc.pullMarks)
			}
			if n := len(deploys); n != 0 {
				t.Errorf("%d AppDeployCmd(s) reached the agent, want none", n)
			}
		})
	}
}

// TC-760-12: any other source error keeps today's wrap, naming the app.
func TestPushStep_OtherResolveErrorsKeepTheWrap(t *testing.T) {
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedComposeApp(t, id, secretComposeV1)
	cause := errors.New("test source: refused")
	runner, jst := realRunner(t, nc, wf(t)(DeployWorkflow(store, inv, nc, nil, failingSource{err: cause})))
	j, err := runner.Submit(ctx, "app.deploy", DeploySpec{AppID: id}, "test")
	if err != nil {
		t.Fatal(err)
	}
	runner.Wait()
	got, err := jst.GetJob(ctx, j.ID)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if want := "apps: resolve compose for " + id + ": " + cause.Error(); got.Error != want {
		t.Fatalf("job error = %q, want %q", got.Error, want)
	}
	if err := resolveError(id, cause); !errors.Is(err, cause) {
		t.Fatalf("resolveError = %v, does not wrap the cause", err)
	}
}

// healthStore answers Health with whatever was last set.
type healthStore struct {
	mu  sync.Mutex
	err error
}

func (h *healthStore) set(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.err = err
}

func (h *healthStore) Health(context.Context) (secretstore.Health, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return secretstore.Health{}, h.err
	}
	return secretstore.Health{Initialized: true, Version: "2.7.1"}, nil
}

// TC-760-23: a deploy refused while the store is sealed, then the same deploy
// once it is ready: neither the token's name nor its value appears in an
// alert, the job's error, its steps, its events or any log record.
func TestStoreGate_Redaction(t *testing.T) {
	const (
		id       = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
		name     = "sentinel-name-760"
		compose0 = "services:\n  web:\n    image: me/web:1\n    environment:\n      DB_PASSWORD: ${secret:" + name + "}\n"
	)
	ctx := context.Background()
	nc := startNATS(t)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	store, inv := seedComposeApp(t, id, compose0)
	inner, derived := wiringSource(t)
	value := derived(id, name)

	log, rec := logkittest.New()
	hs := &healthStore{err: &secretstore.Error{Op: "health", Status: 503, Kind: secretstore.ErrSealed}}
	m, err := storestate.New(storestate.Deps{Store: hs, Now: time.Now, Log: log,
		JobRunning: func(context.Context, string) (bool, error) { return false, nil },
		Blank:      func(context.Context) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := storestate.NewGate(inner, m, log)
	if err != nil {
		t.Fatal(err)
	}
	runner, jst := realRunner(t, nc, wf(t)(DeployWorkflow(store, inv, nc, nil, gate)))

	var seen []string
	run := func(want jobs.Status) string {
		t.Helper()
		for _, a := range m.Alerts(ctx, time.Now()) {
			seen = append(seen, a.ID, a.Title, a.Detail)
		}
		j, err := runner.Submit(ctx, "app.deploy", DeploySpec{AppID: id}, "test")
		if err != nil {
			t.Fatal(err)
		}
		runner.Wait()
		got, err := jst.GetJob(ctx, j.ID)
		if err != nil || got == nil || got.Status != want {
			t.Fatalf("job ended %+v (%v), want %s", got, err, want)
		}
		seen = append(seen, got.Error)
		evs, err := jst.ListEvents(ctx, j.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range evs {
			seen = append(seen, string(ev.Data))
		}
		for _, needle := range []string{name, value} {
			assertLedgerLacks(t, jst, j.ID, needle)
		}
		return got.Error
	}
	if msg := run(jobs.StatusFailed); !strings.Contains(msg, storestate.Code) {
		t.Fatalf("the sealed deploy's error %q lacks the code", msg)
	}
	hs.set(nil)
	run(jobs.StatusSucceeded)
	if cmd := receiveWithin(t, deploys, "the ready deploy never reached the agent"); cmd.SecretEnv[proto.SecretEnvName(name)] != value || strings.Contains(cmd.ComposeYAML, value) {
		t.Fatal("the ready deploy did not carry the derived value")
	}
	seen = append(seen, rec.Text())
	for _, s := range seen {
		for _, needle := range []string{name, value} {
			if strings.Contains(s, needle) {
				t.Errorf("%q leaked into: %s", needle, s)
			}
		}
	}
}
