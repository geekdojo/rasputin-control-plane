package apps

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// The deploy family over the store source (geekdojo/geekdojo-brain#762): the
// readiness Gate around appsecret.StoreSource, as main wires it when a store
// backend is requested, over an in-memory secrets service.

// storedSentinel is the value the in-memory service holds.
const storedSentinel = "S-762-stored"

// memSecrets is the secrets service as the store source calls it, in memory.
// readHook, when it reports handled, answers the n-th read (from 0) in place
// of the entries.
type memSecrets struct {
	mu       sync.Mutex
	entries  map[string][]byte
	reads    int
	readHook func(n int, r secrets.Ref) ([]byte, error, bool)
}

func (m *memSecrets) Read(_ context.Context, _ secrets.Actor, r secrets.Ref) (secrets.Secret, error) {
	m.mu.Lock()
	n := m.reads
	m.reads++
	hook := m.readHook
	m.mu.Unlock()
	if hook != nil {
		if v, err, ok := hook(n, r); ok {
			if err != nil {
				return secrets.Secret{}, err
			}
			return secrets.Secret{Value: secret.New(v), Version: 1}, nil
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.entries[r.String()]
	if !ok {
		return secrets.Secret{}, memStoreErr(r, secretstore.ErrNotFound, nil)
	}
	return secrets.Secret{Value: secret.New(v), Version: 1}, nil
}

func (m *memSecrets) Create(_ context.Context, _ secrets.Actor, r secrets.Ref, v secret.Value) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[r.String()]; ok {
		return 0, fmt.Errorf("%w: %s", secrets.ErrExists, r)
	}
	m.entries[r.String()] = bytes.Clone(v.Reveal())
	return 1, nil
}

// memStoreErr is a store failure as the repository returns it.
func memStoreErr(r secrets.Ref, kind, cause error) error {
	return fmt.Errorf("secrets: read %s: %w", r, &secretstore.Error{Op: "read", Mount: "rasputin-secrets", Path: r.String(), Kind: kind, Err: cause})
}

// nodeN is the node every fixture app here is deployed to.
type nodeN struct{}

func (nodeN) TargetNode(context.Context, string) (string, bool, error) { return "n", true, nil }

// refSink accepts every recorded reference (geekdojo/geekdojo-brain#800).
type refSink struct{}

func (refSink) RecordSecretRef(context.Context, string, string) error { return nil }

// gatedStoreSource is the Gate around a StoreSource over svc, with a Monitor
// reading hs, all logging to one recorder.
func gatedStoreSource(t *testing.T, svc *memSecrets, hs *healthStore) (SecretSource, *storestate.Monitor, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	key := make([]byte, appsecret.SeedLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	seed, err := appsecret.NewSeed(key, appsecret.DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	src, err := appsecret.NewStoreSource(appsecret.StoreSourceDeps{Secrets: svc, Apps: nodeN{}, Refs: refSink{}, Seed: seed, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	m, err := storestate.New(storestate.Deps{Store: hs, Now: time.Now, Log: log,
		JobRunning: func(context.Context, string) (bool, error) { return false, nil },
		Blank:      func(context.Context) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := storestate.NewGate(src, m, log)
	if err != nil {
		t.Fatal(err)
	}
	return gate, m, rec
}

// busTap records every bus payload except the deploy command's.
func busTap(t *testing.T, nc *nats.Conn) func() []string {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	sub, err := nc.Subscribe(">", func(m *nats.Msg) {
		if m.Subject == proto.AppDeploySubject("n") || m.Subject == proto.AppDeploySecretsSubject("n") {
			return
		}
		mu.Lock()
		seen = append(seen, m.Subject+" "+string(m.Data))
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return func() []string {
		_ = nc.Flush()
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// TC-762-07 (the apps half): a store-source refusal is a coded refusal, so
// the push step returns it unchanged.
func TestResolveError_PassesTheStoreRefusalThrough(t *testing.T) {
	ctx := jobs.ContextWithJobID(context.Background(), "j")
	svc := &memSecrets{entries: map[string][]byte{}, readHook: func(_ int, r secrets.Ref) ([]byte, error, bool) {
		return nil, memStoreErr(r, secretstore.ErrSealed, nil), true
	}}
	log, _ := logkittest.New()
	key := make([]byte, appsecret.SeedLen)
	seed, err := appsecret.NewSeed(key, appsecret.DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	src, err := appsecret.NewStoreSource(appsecret.StoreSourceDeps{Secrets: svc, Apps: nodeN{}, Refs: refSink{}, Seed: seed, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	_, _, refusal := src.ResolveCompose(ctx, testAppID, secretCompose)
	var r *appsecret.Refusal
	if !errors.As(refusal, &r) {
		t.Fatalf("source error %v is not a refusal", refusal)
	}
	if got := resolveError(testAppID, refusal); got != refusal {
		t.Fatalf("resolveError = %v, want the refusal itself", got)
	}
}

// TC-762-15 (AC1): each workflow of the deploy family, on the real runner
// over the Gate and the store source, sends the stored value in AppDeployCmd
// and nowhere else: not the job spec, a step result, a job event, the app row,
// any other bus message (the pull and the volume check included) or a log
// record.
func TestDeployFamily_StoredSecretReachesOnlyTheBus(t *testing.T) {
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	ref, err := secrets.AppSecret(id, "db-password")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range deployFamilyCases(id) {
		t.Run(tc.kind, func(t *testing.T) {
			ctx := context.Background()
			nc := startNATS(t)
			deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
			tap := busTap(t, nc)
			svc := &memSecrets{entries: map[string][]byte{ref.String(): []byte(storedSentinel)}}
			src, _, rec := gatedStoreSource(t, svc, &healthStore{})
			store, w, spec, prepare, rowCompose := tc.setup(t, nc, src)
			runner, jst := realRunner(t, nc, w)
			if prepare == nil {
				prepare = func(string) error { return nil }
			}
			j, err := runner.SubmitPrepared(ctx, tc.kind, spec, "test", prepare)
			if err != nil {
				t.Fatalf("submit: %v", err)
			}
			runner.Wait()
			if got, _ := jst.GetJob(ctx, j.ID); got == nil || got.Status != jobs.StatusSucceeded {
				t.Fatalf("job ended %+v", got)
			}
			cmd := receiveWithin(t, deploys, "the agent never received the deploy command")
			// #776: the stored value travels in SecretEnv, beside a compose
			// that holds only the reference.
			if cmd.SecretEnv["RASPUTIN_SECRET_DB_PASSWORD"] != storedSentinel || strings.Contains(cmd.ComposeYAML, storedSentinel) {
				t.Fatalf("the deploy command does not carry the stored value beside a reference compose:\n%s", cmd.ComposeYAML)
			}
			row, err := store.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if row.ComposeYAML != rowCompose {
				t.Fatalf("the app row does not hold the placeholder compose:\n%s", row.ComposeYAML)
			}
			assertLedgerLacks(t, jst, j.ID, storedSentinel)
			evs, err := jst.ListEvents(ctx, j.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, ev := range evs {
				if strings.Contains(string(ev.Data), storedSentinel) {
					t.Errorf("job event %s carries the stored value", ev.Type)
				}
			}
			msgs := tap()
			if len(msgs) == 0 {
				t.Fatal("the bus tap saw nothing, so the scan would read nothing")
			}
			for _, m := range msgs {
				if strings.Contains(m, storedSentinel) {
					t.Errorf("a bus message other than the deploy command carries the stored value: %s", m)
				}
			}
			if strings.Contains(rec.Text(), storedSentinel) {
				t.Error("the stored value reached a log record")
			}
		})
	}
}

// TC-762-16 (AC2): each closed outcome of a secret-bearing app.deploy over the
// Gate and the store source fails the job with its code, sends no
// AppDeployCmd and leaves the RUNNING app's row as it was.
//
// The HKDF source is not in this chain at all: main wires it only when no
// store backend is requested, and TestDeploySourceWiring (TC-762-17) proves a
// requested store never reaches it.
func TestStoreSource_ClosedOutcomesLeaveTheAppUntouched(t *testing.T) {
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	sealed := &secretstore.Error{Op: "health", Status: 503, Kind: secretstore.ErrSealed}
	for _, tc := range []struct {
		name string
		// health is what sys/health answers; auditBlocked raises the fact.
		health       error
		auditBlocked bool
		readHook     func(n int, r secrets.Ref) ([]byte, error, bool)
		code         string
	}{
		{name: "sealed at the gate", health: sealed, code: storestate.Code},
		{name: "audit-blocked, the probe read times out", auditBlocked: true, code: storestate.Code,
			readHook: func(_ int, r secrets.Ref) ([]byte, error, bool) {
				return nil, memStoreErr(r, secretstore.ErrUnreachable, context.DeadlineExceeded), true
			}},
		{name: "ready, then sealed on the read", code: appsecret.CodeStoreUnavailable,
			readHook: func(_ int, r secrets.Ref) ([]byte, error, bool) {
				return nil, memStoreErr(r, secretstore.ErrSealed, nil), true
			}},
		{name: "denied on the read", code: appsecret.CodeStoreUnavailable,
			readHook: func(_ int, r secrets.Ref) ([]byte, error, bool) {
				return nil, memStoreErr(r, secretstore.ErrDenied, nil), true
			}},
		{name: "conflict on the read-back", code: appsecret.CodeValueConflict,
			readHook: func(n int, r secrets.Ref) ([]byte, error, bool) {
				if n == 0 {
					return nil, nil, false
				}
				return []byte("S-762-other"), nil, true
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			nc := startNATS(t)
			deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
			store, inv := seedComposeApp(t, id, secretComposeV1)
			before, err := store.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			hs := &healthStore{err: tc.health}
			svc := &memSecrets{entries: map[string][]byte{}, readHook: tc.readHook}
			src, m, _ := gatedStoreSource(t, svc, hs)
			if tc.auditBlocked {
				m.ObserveAudited(ctx, memStoreErr(secrets.Ref{}, secretstore.ErrUnreachable, context.DeadlineExceeded))
				if st, _ := m.State(ctx); st != storestate.AuditBlocked {
					t.Fatalf("monitor reads %s, want audit-blocked", st)
				}
			}
			runner, jst := realRunner(t, nc, wf(t)(DeployWorkflow(store, inv, nc, nil, src)))
			j, err := runner.Submit(ctx, "app.deploy", DeploySpec{AppID: id}, "test")
			if err != nil {
				t.Fatal(err)
			}
			runner.Wait()
			got, err := jst.GetJob(ctx, j.ID)
			if err != nil || got == nil || got.Status != jobs.StatusFailed {
				t.Fatalf("job ended %+v (%v), want failed", got, err)
			}
			if !strings.Contains(got.Error, "Error code: "+tc.code+".") {
				t.Fatalf("job error %q, want the %s sentence", got.Error, tc.code)
			}
			if err := nc.Flush(); err != nil {
				t.Fatal(err)
			}
			if n := len(deploys); n != 0 {
				t.Fatalf("%d AppDeployCmd(s) reached the agent", n)
			}
			after, err := store.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if after.LastStatus != proto.AppStatusRunning || after.LastStatus != before.LastStatus || !after.UpdatedAt.Equal(before.UpdatedAt) {
				t.Fatalf("the app row moved: status %q updated %v (was %q, %v)", after.LastStatus, after.UpdatedAt, before.LastStatus, before.UpdatedAt)
			}
		})
	}
}
