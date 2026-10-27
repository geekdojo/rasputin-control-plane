package storestate

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// readyHealth is a 200 initialised, unsealed answer.
var readyHealth = secretstore.Health{Initialized: true, Version: "2.7.1"}

// healthErr is the client's error for a failed Health call of kind.
func healthErr(kind error) error { return &secretstore.Error{Op: "health", Kind: kind} }

// clientTimeout is the client's error for an audited call that ran out of
// time on its own per-call bound.
func clientTimeout(op string) error {
	return &secretstore.Error{Op: op, Kind: secretstore.ErrUnreachable, Err: context.DeadlineExceeded}
}

// fakeStore answers Health with whatever was last set, counts the calls, and
// appends "health" to order when one is given.
type fakeStore struct {
	mu    sync.Mutex
	h     secretstore.Health
	err   error
	calls int
	order *[]string
}

func newFakeStore(h secretstore.Health, err error) *fakeStore { return &fakeStore{h: h, err: err} }

func (f *fakeStore) set(h secretstore.Health, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.h, f.err = h, err
}

func (f *fakeStore) Health(context.Context) (secretstore.Health, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.order != nil {
		*f.order = append(*f.order, "health")
	}
	return f.h, f.err
}

func (f *fakeStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// clock is an injected clock a test moves by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	return c.t
}

// fixture is a Monitor over a fakeStore, with a recorded log and a clock.
type fixture struct {
	store   *fakeStore
	clock   *clock
	rec     *logkittest.Recorder
	log     *slog.Logger
	m       *Monitor
	running map[string]bool
	runErr  error
	// blank and blankErr are the blank verdict Deps.Blank reports.
	blank    bool
	blankErr error
}

func newFixture(t *testing.T, h secretstore.Health, err error) *fixture {
	t.Helper()
	f := &fixture{store: newFakeStore(h, err), clock: newClock(), running: map[string]bool{}}
	f.log, f.rec = logkittest.New()
	m, merr := New(Deps{Store: f.store, Now: f.clock.now, Log: f.log, JobRunning: func(_ context.Context, id string) (bool, error) {
		return f.running[id], f.runErr
	}, Blank: func(context.Context) (bool, error) { return f.blank, f.blankErr }})
	if merr != nil {
		t.Fatal(merr)
	}
	f.m = m
	return f
}

func (f *fixture) state(t *testing.T) State {
	t.Helper()
	st, err := f.m.State(context.Background())
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	return st
}

// innerSource is a Source that counts its calls and returns value or err; a
// non-nil do runs first and may replace the outcome.
type innerSource struct {
	mu    sync.Mutex
	calls int
	value string
	// env is the value map returned beside the compose (#776); nil returns
	// none.
	env map[string]secret.Value
	err error
	do  func(ctx context.Context) error
}

func (s *innerSource) ResolveCompose(ctx context.Context, _, _ string) (secret.Value, map[string]secret.Value, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	err := s.err
	if s.do != nil {
		err = s.do(ctx)
	}
	if err != nil {
		return secret.Value{}, nil, err
	}
	return secret.New([]byte(s.value)), s.env, nil
}

func (s *innerSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// kvStore is a KVStore whose audited calls return err, recording their
// arguments, and appending the op to order.
type kvStore struct {
	*fakeStore
	err   error
	order *[]string
	args  []any
}

func (k *kvStore) Read(_ context.Context, token secret.Value, p secretstore.KVPath, version int) (secretstore.KV, error) {
	k.note("read", string(token.Reveal()), p, version)
	return secretstore.KV{Version: 3}, k.err
}

func (k *kvStore) Write(_ context.Context, token secret.Value, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error) {
	k.note("write", string(token.Reveal()), p, len(data), cas)
	return 4, k.err
}

func (k *kvStore) Versions(_ context.Context, token secret.Value, p secretstore.KVPath) (secretstore.Metadata, error) {
	k.note("versions", string(token.Reveal()), p)
	return secretstore.Metadata{CurrentVersion: 5}, k.err
}

func (k *kvStore) Delete(_ context.Context, token secret.Value, p secretstore.KVPath) error {
	k.note("delete", string(token.Reveal()), p)
	return k.err
}

func (k *kvStore) note(op string, args ...any) {
	if k.order != nil {
		*k.order = append(*k.order, op)
	}
	k.args = append([]any{op}, args...)
}

// vendorWords are the names no copy a person reads may carry.
var vendorWords = []string{"openbao", "bao", "vault"}

func assertNoVendor(t *testing.T, what, s string) {
	t.Helper()
	low := strings.ToLower(s)
	for _, w := range vendorWords {
		if strings.Contains(low, w) {
			t.Errorf("%s names the vendor (%q): %s", what, w, s)
		}
	}
}

func assertSentence(t *testing.T, what, s string) {
	t.Helper()
	if s == "" || s[0] < 'A' || s[0] > 'Z' || !strings.HasSuffix(s, ".") {
		t.Errorf("%s is not a sentence (capital, full stop): %q", what, s)
	}
}

var errUnclassified = errors.New("something else")
