package appsecret

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storeswitch"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"gopkg.in/yaml.v3"
)

// The sentinels the store-source tests plant, so a leak scan has something
// unique to look for.
const (
	sentinelStored = "S-762-stored"
	sentinelOther  = "S-762-other"
	// storeText is what the fake store puts in a store error's StoreMessages:
	// the store's own words, which reach the log and never an error string.
	storeText = "S-762-store-message"
	node      = "node-a"
	tokened   = "services:\n  db:\n    environment:\n      PW: ${secret:db-password}\n"
)

// fakeCall is one call the fake service saw.
type fakeCall struct {
	op    string
	ref   secrets.Ref
	actor secrets.Actor
	value string // what Create was given
}

// fakeSecrets is the secrets service as StoreSource sees it: an in-memory
// entry per reference, a log of every call in order, and a hook that can
// answer a call in its place.
type fakeSecrets struct {
	mu      sync.Mutex
	entries map[string][]byte
	calls   []fakeCall
	// hook, when it reports handled, answers call i instead of the entries:
	// for a read, value (or err); for a create, err, storing value when err
	// is nil.
	hook func(i int, c fakeCall) (value []byte, err error, handled bool)
}

func newFakeSecrets(entries map[string]string) *fakeSecrets {
	f := &fakeSecrets{entries: map[string][]byte{}}
	for k, v := range entries {
		f.entries[k] = []byte(v)
	}
	return f
}

func (f *fakeSecrets) record(c fakeCall) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
	return len(f.calls) - 1
}

func (f *fakeSecrets) Read(_ context.Context, a secrets.Actor, r secrets.Ref) (secrets.Secret, error) {
	c := fakeCall{op: "read", ref: r, actor: a}
	i := f.record(c)
	if f.hook != nil {
		if v, err, ok := f.hook(i, c); ok {
			if err != nil {
				return secrets.Secret{}, err
			}
			return secrets.Secret{Value: secret.New(v), Version: 1}, nil
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.entries[r.String()]
	if !ok {
		return secrets.Secret{}, storeErr("read", r, 404, secretstore.ErrNotFound, nil)
	}
	return secrets.Secret{Value: secret.New(v), Version: 1}, nil
}

func (f *fakeSecrets) Create(_ context.Context, a secrets.Actor, r secrets.Ref, value secret.Value) (int, error) {
	c := fakeCall{op: "create", ref: r, actor: a, value: string(value.Reveal())}
	i := f.record(c)
	if f.hook != nil {
		if _, err, ok := f.hook(i, c); ok && err != nil {
			return 0, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.entries[r.String()]; ok {
		return 0, fmt.Errorf("%w: %s", secrets.ErrExists, r)
	}
	f.entries[r.String()] = bytes.Clone(value.Reveal())
	return 1, nil
}

func (f *fakeSecrets) callLog() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.calls...)
}

func (f *fakeSecrets) ops() []string {
	var out []string
	for _, c := range f.callLog() {
		out = append(out, c.op+" "+c.ref.String())
	}
	return out
}

// storeErr is a store failure as the repository returns it: the client's
// *secretstore.Error wrapped with the reference, carrying the store's own
// words in StoreMessages.
func storeErr(op string, r secrets.Ref, status int, kind, cause error) error {
	return fmt.Errorf("secrets: %s %s: %w", op, r, &secretstore.Error{
		Op: op, Mount: storepolicy.Mount, Path: r.String(), Status: status, Kind: kind, Err: cause,
		StoreMessages: []string{storeText},
	})
}

// fakeNodes answers TargetNode from a map, or with err.
type fakeNodes struct {
	nodes map[string]string
	err   error
	calls int
}

func (f *fakeNodes) TargetNode(_ context.Context, appID string) (string, bool, error) {
	f.calls++
	if f.err != nil {
		return "", false, f.err
	}
	n, ok := f.nodes[appID]
	return n, ok, nil
}

// harness is a StoreSource over a fake service and a fake node lookup, with a
// log recorder.
type harness struct {
	src   *StoreSource
	svc   *fakeSecrets
	nodes *fakeNodes
	refs  *fakeRefs
	rec   *logkittest.Recorder
	seed  *Seed
}

func newHarness(t *testing.T, seed *Seed, entries map[string]string) *harness {
	t.Helper()
	log, rec := logkittest.New()
	svc := newFakeSecrets(entries)
	nodes := &fakeNodes{nodes: map[string]string{appID: node}}
	refs := &fakeRefs{}
	src, err := NewStoreSource(StoreSourceDeps{Secrets: svc, Apps: nodes, Refs: refs, Seed: seed, Operator: noOperatorSecrets{}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{src: src, svc: svc, nodes: nodes, refs: refs, rec: rec, seed: seed}
}

func mustRef(t *testing.T, app, name string) secrets.Ref {
	t.Helper()
	r, err := secrets.AppSecret(app, name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func derivedValue(t *testing.T, seed *Seed, app, name string) string {
	t.Helper()
	v, err := seed.Derive(app, name, InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	return string(v.Reveal())
}

// jobCtx is a ctx carrying a job id, as the runner's step ctx does.
func jobCtx() context.Context { return jobs.ContextWithJobID(context.Background(), "job-762") }

// TC-762-12: the leak scan every store-source test ends with. None of the
// needles may appear in any error string or its %v, %+v and JSON renderings,
// or in any log record's message or attributes, the recorder taking DEBUG
// and up.
func assertNoLeak(t *testing.T, rec *logkittest.Recorder, errs []error, needles ...string) {
	t.Helper()
	var texts []string
	for _, err := range errs {
		if err == nil {
			continue
		}
		j, _ := json.Marshal(err)
		texts = append(texts, err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), string(j))
	}
	texts = append(texts, rec.Text())
	for _, n := range needles {
		if n == "" {
			continue
		}
		for _, s := range texts {
			if strings.Contains(s, n) {
				t.Errorf("a value leaked: %q found in %q", n, s)
			}
		}
	}
}

// TC-762-01, TC-776-09: a compose with no token comes back as the same bytes,
// with no map, no app lookup and no service call, however a re-renderer would
// normalise it.
func TestStoreSource_TokenFreeComposeIsUntouched(t *testing.T) {
	h := newHarness(t, testSeed(t), nil)
	for name, compose := range map[string]string{
		"plain":           "services:\n  web:\n    image: nginx\n",
		"trailing spaces": "services:  \n  web:   \n    image: nginx   \n",
		"crlf":            "services:\r\n  web:\r\n    image: nginx\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, env, err := h.src.ResolveCompose(jobCtx(), appID, compose)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Reveal(), []byte(compose)) || len(env) != 0 {
				t.Fatalf("got %q with %d entries, want the input bytes and no map", got.Reveal(), len(env))
			}
		})
	}
	if n := len(h.svc.callLog()); n != 0 || h.nodes.calls != 0 {
		t.Fatalf("service calls %d, node lookups %d; want none", n, h.nodes.calls)
	}
}

// TC-762-02: a stored value is spliced in as stored, not the HKDF value; one
// read as the app's deploy job on its target node, and no create.
func TestStoreSource_StoredValueIsUsedAsStored(t *testing.T) {
	ref := mustRef(t, appID, "db-password")
	h := newHarness(t, testSeed(t), map[string]string{ref.String(): sentinelStored})
	got, env, err := resolved(h.src.ResolveCompose(jobCtx(), appID, tokened))
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(tokened, "${secret:db-password}", "${RASPUTIN_SECRET_DB_PASSWORD}", 1); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if env["RASPUTIN_SECRET_DB_PASSWORD"] != sentinelStored {
		t.Fatal("the stored value is not the map's entry")
	}
	derived := derivedValue(t, h.seed, appID, "db-password")
	calls := h.svc.callLog()
	if len(calls) != 1 || calls[0].op != "read" || calls[0].ref != ref || calls[0].actor != secrets.DeployActor(appID, node) {
		t.Fatalf("calls %+v, want one read of %s as DeployActor(%s, %s)", calls, ref, appID, node)
	}
	assertNoLeak(t, h.rec, nil, sentinelStored, derived)
}

// TC-776-08: the one substitution site, store path. A stored value used
// twice is read once, the compose holds only references, the map has one
// entry, and that entry is still readable after ResolveCompose returns (its
// ownership moved to the caller; it was not destroyed).
func TestStoreSource_ReferencesAndOneLiveEntryPerName(t *testing.T) {
	ref := mustRef(t, appID, "db-password")
	h := newHarness(t, testSeed(t), map[string]string{ref.String(): sentinelStored})
	const twice = "services:\n  db:\n    environment:\n      PW: ${secret:db-password}\n      AGAIN: ${secret:db-password}\n"
	got, env, err := h.src.ResolveCompose(jobCtx(), appID, twice)
	if err != nil {
		t.Fatal(err)
	}
	if want := "services:\n  db:\n    environment:\n      PW: ${RASPUTIN_SECRET_DB_PASSWORD}\n      AGAIN: ${RASPUTIN_SECRET_DB_PASSWORD}\n"; string(got.Reveal()) != want {
		t.Fatalf("compose %q, want %q", got.Reveal(), want)
	}
	if len(env) != 1 || string(env["RASPUTIN_SECRET_DB_PASSWORD"].Reveal()) != sentinelStored {
		t.Fatalf("map has %d entries; want one holding the stored value after return", len(env))
	}
	if ops := h.svc.ops(); len(ops) != 1 || ops[0] != "read "+ref.String() {
		t.Fatalf("calls %v, want one read for the one distinct name", ops)
	}
}

// TC-762-03: an absent entry is derived at InitialVersion, created, read back
// and used: read, create (with the value an independent Derive gives), read.
func TestStoreSource_AbsentEntryIsDerivedCreatedAndReadBack(t *testing.T) {
	h := newHarness(t, testSeed(t), nil)
	_, env, err := resolved(h.src.ResolveCompose(jobCtx(), appID, tokened))
	if err != nil {
		t.Fatal(err)
	}
	ref := mustRef(t, appID, "db-password")
	derived := derivedValue(t, h.seed, appID, "db-password")
	calls := h.svc.callLog()
	if ops := h.svc.ops(); strings.Join(ops, ",") != "read "+ref.String()+",create "+ref.String()+",read "+ref.String() {
		t.Fatalf("calls %v, want read, create, read", ops)
	}
	if calls[1].value != derived {
		t.Fatal("the value created is not Seed.Derive at InitialVersion")
	}
	if env["RASPUTIN_SECRET_DB_PASSWORD"] != derived {
		t.Fatal("the map's entry is not the derived value")
	}
	assertNoLeak(t, h.rec, nil, derived)
}

// TC-762-04: a create that loses the race to another deploy (ErrExists) whose
// read-back holds the derived value deploys with it.
func TestStoreSource_CreateRaceWithTheSameValueDeploys(t *testing.T) {
	h := newHarness(t, testSeed(t), nil)
	derived := derivedValue(t, h.seed, appID, "db-password")
	h.svc.hook = func(i int, c fakeCall) ([]byte, error, bool) {
		switch i {
		case 0:
			return nil, storeErr("read", c.ref, 404, secretstore.ErrNotFound, nil), true
		case 1:
			return nil, fmt.Errorf("%w: %s", secrets.ErrExists, c.ref), true
		case 2:
			return []byte(derived), nil, true
		}
		return nil, nil, false
	}
	_, env, err := resolved(h.src.ResolveCompose(jobCtx(), appID, tokened))
	if err != nil {
		t.Fatal(err)
	}
	if env["RASPUTIN_SECRET_DB_PASSWORD"] != derived {
		t.Fatal("the map's entry is not the derived value")
	}
	if n := len(h.svc.callLog()); n != 3 {
		t.Fatalf("%d calls, want 3", n)
	}
	assertNoLeak(t, h.rec, nil, derived)
}

// TC-762-05: a read-back that differs from the derived value refuses with
// secret_value_conflict, after a lost race (a) and after a create that
// succeeded (b), with one ERROR record and no value anywhere.
func TestStoreSource_ReadBackMismatchRefuses(t *testing.T) {
	for _, tc := range []struct {
		name      string
		createErr bool
	}{{"a: ErrExists then a different value", true}, {"b: created then a different value", false}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, testSeed(t), nil)
			derived := derivedValue(t, h.seed, appID, "db-password")
			h.svc.hook = func(i int, c fakeCall) ([]byte, error, bool) {
				switch i {
				case 0:
					return nil, storeErr("read", c.ref, 404, secretstore.ErrNotFound, nil), true
				case 1:
					if tc.createErr {
						return nil, fmt.Errorf("%w: %s", secrets.ErrExists, c.ref), true
					}
					return nil, nil, false
				case 2:
					return []byte(sentinelOther), nil, true
				}
				return nil, nil, false
			}
			got, _, err := h.src.ResolveCompose(jobCtx(), appID, tokened)
			if got.Len() != 0 {
				t.Fatal("a refusal returned a value")
			}
			var r *Refusal
			if !errors.As(err, &r) || r.Code() != CodeValueConflict {
				t.Fatalf("err = %v, want the %s refusal", err, CodeValueConflict)
			}
			recs := h.rec.AtLevel(slog.LevelError)
			if len(recs) != 1 {
				t.Fatalf("%d ERROR records, want 1", len(recs))
			}
			ref := mustRef(t, appID, "db-password")
			for k, want := range map[string]string{"app_id": appID, "ref": ref.String(), "outcome": CodeValueConflict, "job_id": "job-762"} {
				if v, _ := logkittest.Attr(recs[0], k); v != want {
					t.Errorf("record %s = %q, want %q", k, v, want)
				}
			}
			assertNoLeak(t, h.rec, []error{err}, derived, sentinelOther)
		})
	}
}

// TC-762-06: a store failure at each call position, of each kind, refuses
// with secret_store_unavailable and the zero Value; errors.Is reaches the
// kind; no later call is made; one WARN record carries the refusal's fields
// and the store error's own.
func TestStoreSource_StoreFailuresRefuse(t *testing.T) {
	kinds := []struct {
		name  string
		kind  error
		cause error
	}{
		{"sealed", secretstore.ErrSealed, nil},
		{"unreachable", secretstore.ErrUnreachable, errors.New("connection refused")},
		{"client timeout", secretstore.ErrUnreachable, fmt.Errorf("round trip: %w", context.DeadlineExceeded)},
		{"denied", secretstore.ErrDenied, nil},
		{"protocol", secretstore.ErrProtocol, nil},
	}
	positions := []struct {
		name string
		at   int
	}{{"first read", 0}, {"create", 1}, {"read-back", 2}}
	for _, p := range positions {
		for _, k := range kinds {
			t.Run(p.name+"/"+k.name, func(t *testing.T) {
				h := newHarness(t, testSeed(t), nil)
				derived := derivedValue(t, h.seed, appID, "db-password")
				h.svc.hook = func(i int, c fakeCall) ([]byte, error, bool) {
					if i == p.at {
						return nil, storeErr(c.op, c.ref, 503, k.kind, k.cause), true
					}
					return nil, nil, false
				}
				got, _, err := h.src.ResolveCompose(jobCtx(), appID, tokened)
				if got.Len() != 0 {
					t.Fatal("a refusal returned a value")
				}
				var r *Refusal
				if !errors.As(err, &r) || r.Code() != CodeStoreUnavailable {
					t.Fatalf("err = %v, want the %s refusal", err, CodeStoreUnavailable)
				}
				if !errors.Is(err, k.kind) {
					t.Errorf("errors.Is(err, %v) = false", k.kind)
				}
				if k.cause != nil && errors.Is(k.cause, context.DeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
					t.Error("the client timeout is not reachable through the refusal")
				}
				if n := len(h.svc.callLog()); n != p.at+1 {
					t.Fatalf("%d calls, want %d: nothing after the failure", n, p.at+1)
				}
				recs := h.rec.AtLevel(slog.LevelWarn)
				if len(recs) != 1 {
					t.Fatalf("%d WARN records, want 1", len(recs))
				}
				ref := mustRef(t, appID, "db-password")
				for key, want := range map[string]string{"app_id": appID, "ref": ref.String(), "outcome": CodeStoreUnavailable,
					"job_id": "job-762", "path": ref.String(), "status": "503"} {
					if v, _ := logkittest.Attr(recs[0], key); v != want {
						t.Errorf("record %s = %q, want %q", key, v, want)
					}
				}
				if !strings.Contains(h.rec.Text(), storeText) {
					t.Error("the store's own words did not reach the log")
				}
				assertNoLeak(t, h.rec, []error{err}, derived)
				if strings.Contains(err.Error(), storeText) {
					t.Error("the store's own words reached the error")
				}
			})
		}
	}
}

// TC-762-07: the refusal's sentence is one a person reads: a capital, a full
// stop, the code, and no path, status or vendor. Behind the Gate in
// audit-blocked, a store read that times out on the client's bound is the
// Gate's not-ready refusal, not the source's.
func TestStoreSource_RefusalSentenceAndTheGate(t *testing.T) {
	ref := mustRef(t, appID, "db-password")
	for _, r := range []*Refusal{storeUnavailable(storeErr("read", ref, 503, secretstore.ErrSealed, nil)), valueConflict()} {
		s := r.Error()
		if s == "" || s[0] < 'A' || s[0] > 'Z' || !strings.HasSuffix(s, ".") || !strings.Contains(s, r.Code()) {
			t.Errorf("sentence %q: want a capital, a full stop and the code", s)
		}
		low := strings.ToLower(s)
		for _, bad := range []string{"openbao", "bao", "vault", storepolicy.Mount, "apps/", "503"} {
			if strings.Contains(low, bad) {
				t.Errorf("sentence %q contains %q", s, bad)
			}
		}
	}

	log, _ := logkittest.New()
	m, err := storestate.New(storestate.Deps{Store: readyHealth{}, Now: time.Now, Log: log,
		JobRunning: func(context.Context, string) (bool, error) { return false, nil },
		Blank:      func(context.Context) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	timeout := storeErr("read", ref, 0, secretstore.ErrUnreachable, context.DeadlineExceeded)
	m.ObserveAudited(context.Background(), timeout)
	if st, _ := m.State(context.Background()); st != storestate.AuditBlocked {
		t.Fatalf("monitor reads %s, want audit-blocked", st)
	}
	h := newHarness(t, testSeed(t), nil)
	h.svc.hook = func(int, fakeCall) ([]byte, error, bool) { return nil, timeout, true }
	gate, err := storestate.NewGate(h.src, m, log)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = gate.ResolveCompose(jobCtx(), appID, tokened)
	var nr *storestate.NotReadyError
	if !errors.As(err, &nr) || nr.Code() != storestate.Code {
		t.Fatalf("gate err = %v, want the not-ready refusal", err)
	}
	var r *Refusal
	if errors.As(err, &r) {
		t.Fatal("the gate returned the source's refusal")
	}
}

// readyHealth answers sys/health 200 unsealed.
type readyHealth struct{}

func (readyHealth) Health(context.Context) (secretstore.Health, error) {
	return secretstore.Health{Initialized: true, Version: "2.7.1"}, nil
}

// TC-762-08: failures that are not store errors fail closed: no value, an
// error, no store call after the failure, and no value or store text.
func TestStoreSource_OtherFailuresFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		appID string
		seed  *Seed
		setup func(h *harness)
		// calls is how many service calls are made.
		calls int
	}{
		{"forbidden", appID, nil, func(h *harness) {
			h.svc.hook = func(_ int, c fakeCall) ([]byte, error, bool) {
				return nil, fmt.Errorf("%w: read %s: the node is not the app's target node", secrets.ErrForbidden, c.ref), true
			}
		}, 1},
		// A lower-case ULID is not a canonical app ID, so the reference does
		// not parse and the service is never called.
		{"non-canonical app ID", strings.ToLower(appID), nil, func(h *harness) {
			h.nodes.nodes[strings.ToLower(appID)] = node
		}, 0},
		// A seed with no derivation (the zero Seed, which NewSeed never makes)
		// fails Derive after the read finds nothing.
		{"derive error", appID, &Seed{}, nil, 1},
		{"node lookup error", appID, nil, func(h *harness) { h.nodes.err = errors.New("apps: database is closed") }, 0},
		{"app not found", appID, nil, func(h *harness) { h.nodes.nodes = map[string]string{} }, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seed := tc.seed
			if seed == nil {
				seed = testSeed(t)
			}
			h := newHarness(t, seed, nil)
			if tc.setup != nil {
				tc.setup(h)
			}
			got, _, err := h.src.ResolveCompose(jobCtx(), tc.appID, tokened)
			if err == nil || got.Len() != 0 {
				t.Fatalf("got %d bytes, %v; want the zero Value and an error", got.Len(), err)
			}
			var r *Refusal
			if errors.As(err, &r) {
				t.Fatalf("err = %v, want a plain error, not a store refusal", err)
			}
			if n := len(h.svc.callLog()); n != tc.calls {
				t.Fatalf("%d service calls, want %d", n, tc.calls)
			}
			assertNoLeak(t, h.rec, []error{err}, derivedValue(t, testSeed(t), appID, "db-password"), storeText)
		})
	}
}

// TC-762-10: a repeated name is read and created once and both places carry
// it; a failure partway refuses the whole compose and keeps what was
// created; the retry reads it back without creating it again.
func TestStoreSource_SeveralTokensRepeatsAndPartialFailure(t *testing.T) {
	const compose = "services:\n  a:\n    environment:\n      A1: ${secret:a}\n      B: ${secret:b}\n      A2: ${secret:a}\n"
	h := newHarness(t, testSeed(t), nil)
	refA, refB := mustRef(t, appID, "a"), mustRef(t, appID, "b")
	failB := true
	h.svc.hook = func(_ int, c fakeCall) ([]byte, error, bool) {
		if failB && c.op == "create" && c.ref == refB {
			return nil, storeErr("write", c.ref, 0, secretstore.ErrUnreachable, errors.New("connection refused")), true
		}
		return nil, nil, false
	}
	got, gotEnv, err := h.src.ResolveCompose(jobCtx(), appID, compose)
	var r *Refusal
	if got.Len() != 0 || gotEnv != nil || !errors.As(err, &r) || r.Code() != CodeStoreUnavailable {
		t.Fatalf("got %d bytes, map %v, %v; want the zero Value, no map and the unavailable refusal", got.Len(), gotEnv != nil, err)
	}
	if strings.Join(h.svc.ops(), ",") != strings.Join([]string{"read " + refA.String(), "create " + refA.String(), "read " + refA.String(),
		"read " + refB.String(), "create " + refB.String()}, ",") {
		t.Fatalf("calls %v", h.svc.ops())
	}
	if _, ok := h.svc.entries[refA.String()]; !ok {
		t.Fatal("a's entry did not stay")
	}

	failB = false
	before := len(h.svc.callLog())
	resolvedCompose, env, err := resolved(h.src.ResolveCompose(jobCtx(), appID, compose))
	if err != nil {
		t.Fatal(err)
	}
	a, b := derivedValue(t, h.seed, appID, "a"), derivedValue(t, h.seed, appID, "b")
	want := "services:\n  a:\n    environment:\n      A1: ${RASPUTIN_SECRET_A}\n      B: ${RASPUTIN_SECRET_B}\n      A2: ${RASPUTIN_SECRET_A}\n"
	if resolvedCompose != want || len(env) != 2 || env["RASPUTIN_SECRET_A"] != a || env["RASPUTIN_SECRET_B"] != b {
		t.Fatalf("got %q with %d entries, want %q and the two derived values", resolvedCompose, len(env), want)
	}
	retry := h.svc.ops()[before:]
	if strings.Join(retry, ",") != strings.Join([]string{"read " + refA.String(), "read " + refB.String(), "create " + refB.String(), "read " + refB.String()}, ",") {
		t.Fatalf("retry calls %v, want a read once and b created", retry)
	}
	assertNoLeak(t, h.rec, []error{err}, a, b)
}

// TC-762-11: the constructor refuses each nil collaborator.
func TestNewStoreSource_RefusesNil(t *testing.T) {
	log, _ := logkittest.New()
	full := StoreSourceDeps{Secrets: newFakeSecrets(nil), Apps: &fakeNodes{}, Refs: &fakeRefs{}, Seed: testSeed(t), Operator: noOperatorSecrets{}, Log: log}
	for name, clear := range map[string]func(*StoreSourceDeps){
		"Secrets":  func(d *StoreSourceDeps) { d.Secrets = nil },
		"Apps":     func(d *StoreSourceDeps) { d.Apps = nil },
		"Refs":     func(d *StoreSourceDeps) { d.Refs = nil },
		"Seed":     func(d *StoreSourceDeps) { d.Seed = nil },
		"Operator": func(d *StoreSourceDeps) { d.Operator = nil }, // TC-604-09
		"Log":      func(d *StoreSourceDeps) { d.Log = nil },
	} {
		d := full
		clear(&d)
		if s, err := NewStoreSource(d); err == nil || s != nil {
			t.Errorf("nil %s: %v, %v; want an error and no source", name, s, err)
		}
	}
}

// TC-762-13 (AC3): through StoreSource over an empty store, the value created
// and the value spliced both equal the frozen vector for cases 0, 1, 2 and 7.
func TestStoreSource_CreatedValuesEqualTheFrozenVectors(t *testing.T) {
	cases := loadVectors(t).Cases
	for _, i := range []int{0, 1, 2, 7} {
		c := cases[i]
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			key, err := hex.DecodeString(c.SeedHex)
			if err != nil {
				t.Fatal(err)
			}
			seed, err := NewSeed(key, DerivationVersion)
			if err != nil {
				t.Fatal(err)
			}
			if c.Version != InitialVersion {
				t.Fatalf("case %d is at version %d, not InitialVersion", i, c.Version)
			}
			h := newHarness(t, seed, nil)
			h.nodes.nodes[c.AppID] = node
			_, env, err := resolved(h.src.ResolveCompose(jobCtx(), c.AppID, "x: ${secret:"+c.Name+"}\n"))
			if err != nil {
				t.Fatal(err)
			}
			if len(env) != 1 || env[proto.SecretEnvName(c.Name)] != c.Want {
				t.Fatalf("the map does not hold the vector %q", c.Want)
			}
			calls := h.svc.callLog()
			if len(calls) != 3 || calls[1].op != "create" || calls[1].value != c.Want {
				t.Fatalf("the value created is not the vector: %+v", calls)
			}
		})
	}
}

// noopObserver takes the session's login outcomes.
type noopObserver struct{}

func (noopObserver) ObserveAudited(context.Context, error) {}

// TC-762-14: an upgrade and a rollback keep the credential. The previous
// release (HKDFSource), the first deploy after the upgrade (StoreSource over
// an empty Mock behind the real service), the next deploy (entry present) and
// a rollback (HKDFSource again) all give the same bytes, and the store then
// holds version 1 of each name.
func TestStoreSource_UpgradeAndRollbackKeepTheCredential(t *testing.T) {
	const compose = "services:\n  db:\n    environment:\n      PW: ${secret:db-password}\n      KEY: ${secret:session-key}\n"
	ctx := jobCtx()
	log, rec := logkittest.New()
	seed := testSeed(t)
	mock := secretstore.NewMock(time.Now)
	sess, err := storesession.New(storesession.Config{Role: "rasputin-api", Login: mock, Store: mock, Observer: noopObserver{}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := secrets.NewRepository(sess)
	if err != nil {
		t.Fatal(err)
	}
	nodes := &fakeNodes{nodes: map[string]string{appID: node}}
	svc, err := secrets.NewService(secrets.Deps{Repo: repo, Apps: nodes, Switch: realSwitch(t, log), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStoreSource(StoreSourceDeps{Secrets: svc, Apps: nodes, Refs: &fakeRefs{}, Seed: seed, Operator: noOperatorSecrets{}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	hkdf, err := NewHKDFSource(seed)
	if err != nil {
		t.Fatal(err)
	}
	var results [][]byte
	for _, src := range []interface {
		ResolveCompose(context.Context, string, string) (secret.Value, map[string]secret.Value, error)
	}{hkdf, store, store, hkdf} {
		v, env, err := resolved(src.ResolveCompose(ctx, appID, compose))
		if err != nil {
			t.Fatal(err)
		}
		r := []byte(v)
		for _, k := range slices.Sorted(maps.Keys(env)) {
			r = append(r, "\x00"+k+"="+env[k]...)
		}
		results = append(results, r)
	}
	for i, r := range results[1:] {
		if !bytes.Equal(r, results[0]) {
			t.Fatalf("resolution %d differs from the previous release's", i+1)
		}
	}
	for _, name := range []string{"db-password", "session-key"} {
		p, err := secretstore.NewKVPath(storepolicy.Mount, mustRef(t, appID, name).String())
		if err != nil {
			t.Fatal(err)
		}
		md, err := mock.Versions(ctx, secret.Value{}, p)
		if err != nil || md.CurrentVersion != 1 {
			t.Fatalf("%s: version %d, %v; want 1", name, md.CurrentVersion, err)
		}
	}
	assertNoLeak(t, rec, nil, derivedValue(t, seed, appID, "db-password"), derivedValue(t, seed, appID, "session-key"))
}

// hostileValues are stored values that would change compose text if they
// were ever written into it (geekdojo/geekdojo-brain#779, TC-779-04's list).
var hostileValues = []string{
	"a$b",
	"x${HOME}y",
	"$$z",
	"${RASPUTIN_SECRET_OTHER}",
	"${RASPUTIN_SECRET_OTHER:-leak}",
	"a\nprivileged: true\nvolumes: [\"/:/host\"]",
	"it's",
	`say "hi"`,
	"- a: b # c & *x !t | > % @",
}

// hostileTile carries a secret token beside a non-secret key and a volume.
const hostileTile = `services:
  app:
    image: alpine:3.20
    environment:
      SESSION_KEY: ${secret:session-key}
      DATA_DIR: /data
    volumes:
      - ./data:/data
`

// keyPaths is the set of mapping-key paths in a YAML document, a sequence
// item's index standing in for its key.
func keyPaths(t *testing.T, doc string) []string {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatalf("the compose does not parse: %v", err)
	}
	var out []string
	var walk func(n *yaml.Node, prefix string)
	walk = func(n *yaml.Node, prefix string) {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				walk(c, prefix)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				p := prefix + "/" + n.Content[i].Value
				out = append(out, p)
				walk(n.Content[i+1], p)
			}
		case yaml.SequenceNode:
			for i, c := range n.Content {
				p := fmt.Sprintf("%s/%d", prefix, i)
				out = append(out, p)
				walk(c, p)
			}
		}
	}
	walk(&root, "")
	slices.Sort(out)
	return out
}

// TC-779-06: the issue's acceptance. Over each stored hostile value the
// resolved compose is (a) byte-identical to the one for a benign base64url
// value and free of the hostile value, (b) parses to the key paths of the
// tile before substitution, and (c) the value reaches the map byte-exact.
func TestStoreSource_HostileValueCannotChangeTheCompose(t *testing.T) {
	ref := mustRef(t, appID, "session-key")
	resolveWith := func(t *testing.T, v string) (string, map[string]string) {
		t.Helper()
		h := newHarness(t, testSeed(t), map[string]string{ref.String(): v})
		got, env, err := resolved(h.src.ResolveCompose(jobCtx(), appID, hostileTile))
		if err != nil {
			t.Fatal(err)
		}
		return got, env
	}
	benign, _ := resolveWith(t, "AbCdEf-_0123456789")
	want := keyPaths(t, hostileTile)
	for _, v := range hostileValues {
		t.Run(fmt.Sprintf("%q", v), func(t *testing.T) {
			got, env := resolveWith(t, v)
			if got != benign {
				t.Errorf("(a) the compose differs from the benign value's:\n%s\nwant:\n%s", got, benign)
			}
			if strings.Contains(got, v) {
				t.Errorf("(a) the compose holds the value:\n%s", got)
			}
			if paths := keyPaths(t, got); !slices.Equal(paths, want) {
				t.Errorf("(b) key paths %v, want %v", paths, want)
			}
			if e, ok := env["RASPUTIN_SECRET_SESSION_KEY"]; !ok || e != v {
				t.Errorf("(c) the map holds %q, want %q", e, v)
			}
		})
	}
}

// realSwitch is the secret store's switch marker over a real settings table
// in a temporary rasputin.db (geekdojo/geekdojo-brain#604).
func realSwitch(t *testing.T, log *slog.Logger) *storeswitch.Marker {
	t.Helper()
	st, err := setup.OpenStore(context.Background(), filepath.Join(t.TempDir(), "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	m, err := storeswitch.New(storeswitch.Deps{Settings: st, Now: time.Now, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// noOperatorSecrets is an app that declares no operator secrets.
type noOperatorSecrets struct{}

func (noOperatorSecrets) OperatorSecrets(context.Context, string) ([]tileschema.OperatorSecret, error) {
	return nil, nil
}
