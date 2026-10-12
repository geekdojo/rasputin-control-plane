package storestate

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

const (
	tokened   = "services:\n  web:\n    environment:\n      DB_PASSWORD: ${secret:db-password}\n"
	tokenFree = "services:\n  web:\n    image: me/web:1\n"
	escaped   = "services:\n  web:\n    environment:\n      DB_PASSWORD: $${secret:x}\n"
)

func tokenOf(s string) secret.Value { return secret.New([]byte(s)) }

func pathOf(t *testing.T) secretstore.KVPath {
	t.Helper()
	p, err := secretstore.NewKVPath("kv", "apps/a")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newGate(t *testing.T, f *fixture, inner Source) *Gate {
	t.Helper()
	g, err := NewGate(inner, f.m, f.log)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TC-760-04 (the Gate half): NewGate refuses each nil collaborator.
func TestNewGate_RefusesNil(t *testing.T) {
	f := newFixture(t, readyHealth, nil)
	inner := &innerSource{}
	for name, args := range map[string]struct {
		inner Source
		m     *Monitor
		log   *slog.Logger
	}{
		"inner":   {nil, f.m, f.log},
		"monitor": {inner, nil, f.log},
		"logger":  {inner, f.m, nil},
	} {
		g, err := NewGate(args.inner, args.m, args.log)
		if err == nil || g != nil {
			t.Errorf("NewGate without %s = (%v, %v), want a nil Gate and an error", name, g, err)
		}
	}
}

// TC-760-05: a compose with no token goes to the inner source whatever the
// store's state, and the store is never asked.
func TestGate_TokenFreeIsNeverGated(t *testing.T) {
	f := newFixture(t, secretstore.Health{}, healthErr(secretstore.ErrSealed))
	inner := &innerSource{value: "inner-result"}
	v, err := newGate(t, f, inner).ResolveCompose(context.Background(), "a", tokenFree)
	if err != nil || string(v.Reveal()) != "inner-result" {
		t.Fatalf("ResolveCompose = (%q, %v), want the inner result", v.Reveal(), err)
	}
	if n := f.store.count(); n != 0 {
		t.Fatalf("Health called %d time(s), want 0", n)
	}
}

// TC-760-06: an escaped token is refused with the scan error wrapped, and
// neither the store nor the inner source is asked.
func TestGate_MalformedTokenRefusedWithoutTheStore(t *testing.T) {
	f := newFixture(t, readyHealth, nil)
	inner := &innerSource{value: "x"}
	_, scanErr := tileschema.ScanSecretTokens(escaped)
	if scanErr == nil {
		t.Fatal("the fixture compose is not malformed")
	}
	v, err := newGate(t, f, inner).ResolveCompose(context.Background(), "a", escaped)
	if err == nil || errors.Unwrap(err) == nil || errors.Unwrap(err).Error() != scanErr.Error() {
		t.Fatalf("error = %v, want one wrapping the scan error %v", err, scanErr)
	}
	if v.Len() != 0 || f.store.count() != 0 || inner.count() != 0 {
		t.Fatalf("value %d bytes, Health %d calls, inner %d calls; want 0, 0, 0", v.Len(), f.store.count(), inner.count())
	}
}

// TC-760-07: a ready store delegates once, and the inner value comes back
// unchanged.
func TestGate_ReadyDelegates(t *testing.T) {
	f := newFixture(t, readyHealth, nil)
	inner := &innerSource{value: "resolved"}
	v, err := newGate(t, f, inner).ResolveCompose(context.Background(), "a", tokened)
	if err != nil || string(v.Reveal()) != "resolved" || inner.count() != 1 {
		t.Fatalf("ResolveCompose = (%q, %v) after %d inner call(s), want the inner value after 1", v.Reveal(), err, inner.count())
	}
}

// TC-760-08: each not-ready state but AuditBlocked refuses with the coded
// error and the zero Value, never calls the inner source, and logs one WARN
// carrying the job's id from the ctx (F-760-03).
func TestGate_NotReadyRefuses(t *testing.T) {
	for _, tc := range []struct {
		state State
		setup func(f *fixture)
	}{
		{Sealed, func(f *fixture) { f.store.set(secretstore.Health{}, healthErr(secretstore.ErrSealed)) }},
		{Uninitialised, func(f *fixture) { f.store.set(secretstore.Health{}, healthErr(secretstore.ErrUninitialised)) }},
		{Unreachable, func(f *fixture) { f.store.set(secretstore.Health{}, healthErr(secretstore.ErrUnreachable)) }},
		{Quiesced, func(f *fixture) {
			f.store.set(secretstore.Health{}, healthErr(secretstore.ErrUnreachable))
			f.running["job-backup"] = true
			f.m.Quiesce("job-backup")
		}},
	} {
		t.Run(string(tc.state), func(t *testing.T) {
			f := newFixture(t, readyHealth, nil)
			tc.setup(f)
			inner := &innerSource{value: "x"}
			ctx := jobs.ContextWithJobID(context.Background(), "job-7")
			v, err := newGate(t, f, inner).ResolveCompose(ctx, "app-1", tokened)
			assertRefusal(t, f.rec, v, err, tc.state, "job-7")
			if n := inner.count(); n != 0 {
				t.Fatalf("the inner source was called %d time(s), want 0", n)
			}
		})
	}
}

// assertRefusal checks a coded refusal for state and its one WARN.
func assertRefusal(t *testing.T, rec *logkittest.Recorder, v secret.Value, err error, state State, jobID string) {
	t.Helper()
	var nr *NotReadyError
	if !errors.As(err, &nr) || nr.State != state || !errors.Is(err, ErrNotReady) || nr.Code() != "secret_store_not_ready" {
		t.Fatalf("error = %#v, want *NotReadyError{%s} matching ErrNotReady with the code", err, state)
	}
	if v.Len() != 0 {
		t.Fatalf("a refusal returned %d bytes, want the zero Value", v.Len())
	}
	w := rec.Matching(slog.LevelWarn, "secret-bearing deploy refused")
	if len(w) != 1 {
		t.Fatalf("%d refusal records, want 1", len(w))
	}
	for key, want := range map[string]string{"component": "secretstore", "app_id": "app-1", "state": string(state), "job_id": jobID} {
		if got, _ := logkittest.Attr(w[0], key); got != want {
			t.Errorf("refusal record %s = %q, want %q", key, got, want)
		}
	}
}

// TC-760-09: a reading that fails because the caller's ctx ended refuses:
// an error, the zero Value, and no inner call.
func TestGate_ReadingErrorRefuses(t *testing.T) {
	f := newFixture(t, readyHealth, nil)
	inner := &innerSource{value: "x"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v, err := newGate(t, f, inner).ResolveCompose(ctx, "a", tokened)
	if err == nil || v.Len() != 0 || inner.count() != 0 {
		t.Fatalf("ResolveCompose = (%d bytes, %v) after %d inner call(s), want an error, 0 bytes, 0 calls", v.Len(), err, inner.count())
	}
}

// TC-760-10: each state's refusal is one sentence that names the state in its
// own words, says the app was not deployed and its containers are unchanged,
// names the recovery and the code, does not claim nothing reached the node,
// and never names the vendor.
func TestNotReadyError_Copy(t *testing.T) {
	seen := map[string]bool{}
	for _, st := range []State{Sealed, Uninitialised, Unreachable, AuditBlocked, Quiesced} {
		msg := (&NotReadyError{State: st}).Error()
		assertSentence(t, string(st), msg)
		assertNoVendor(t, string(st), msg)
		for _, want := range []string{
			"the app was not deployed", "Its running containers are unchanged",
			"deploy the app again once the store is ready",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: %q lacks %q", st, msg, want)
			}
		}
		if !strings.HasSuffix(msg, "Error code: secret_store_not_ready.") {
			t.Errorf("%s: %q does not end with the code", st, msg)
		}
		if strings.Contains(strings.ToLower(msg), "nothing was sent") {
			t.Errorf("%s: %q says nothing was sent to the node", st, msg)
		}
		clause := stateClause(st)
		if seen[clause] || !strings.Contains(msg, "The secret store "+clause+",") {
			t.Errorf("%s: clause %q is not its own, or not in %q", st, clause, msg)
		}
		seen[clause] = true
	}
}

// TC-760-30: in AuditBlocked the Gate calls the inner source once as the
// probe. An answered read returns its value and clears the state; a read that
// times out again refuses with the code and leaves it raised; any other inner
// error is returned as is, with no refusal record.
func TestGate_AuditBlockedProbe(t *testing.T) {
	setup := func(t *testing.T, readErr error) (*fixture, *innerSource, *Gate) {
		f := newFixture(t, readyHealth, nil)
		f.m.ObserveAudited(context.Background(), clientTimeout("read"))
		if got := f.state(t); got != AuditBlocked {
			t.Fatalf("State = %q, want audit-blocked", got)
		}
		kv := &kvStore{fakeStore: f.store, err: readErr}
		obs, err := NewObservedStore(kv, f.m)
		if err != nil {
			t.Fatal(err)
		}
		inner := &innerSource{value: "from-store", do: func(ctx context.Context) error {
			_, err := obs.Read(ctx, tokenOf("t"), pathOf(t), 0)
			return err
		}}
		return f, inner, newGate(t, f, inner)
	}
	ctx := jobs.ContextWithJobID(context.Background(), "job-9")

	t.Run("answered", func(t *testing.T) {
		f, inner, g := setup(t, nil)
		v, err := g.ResolveCompose(ctx, "app-1", tokened)
		if err != nil || string(v.Reveal()) != "from-store" || inner.count() != 1 {
			t.Fatalf("ResolveCompose = (%q, %v) after %d inner call(s), want the value after 1", v.Reveal(), err, inner.count())
		}
		if got := f.state(t); got != Ready {
			t.Fatalf("State = %q, want ready", got)
		}
	})
	t.Run("times out again", func(t *testing.T) {
		f, inner, g := setup(t, clientTimeout("read"))
		v, err := g.ResolveCompose(ctx, "app-1", tokened)
		if inner.count() != 1 {
			t.Fatalf("the inner source was called %d time(s), want 1", inner.count())
		}
		assertRefusal(t, f.rec, v, err, AuditBlocked, "job-9")
		if got := f.state(t); got != AuditBlocked {
			t.Fatalf("State = %q, want audit-blocked still", got)
		}
	})
	t.Run("another inner error", func(t *testing.T) {
		other := errors.New("inner: no such secret")
		f, inner, g := setup(t, nil)
		inner.do = func(context.Context) error { return other }
		v, err := g.ResolveCompose(ctx, "app-1", tokened)
		if !errors.Is(err, other) || v.Len() != 0 || inner.count() != 1 {
			t.Fatalf("ResolveCompose = (%d bytes, %v), want the inner error as is", v.Len(), err)
		}
		if w := f.rec.Matching(slog.LevelWarn, "secret-bearing deploy refused"); len(w) != 0 {
			t.Fatalf("%d refusal records, want 0", len(w))
		}
	})
}

// TC-760-19 (through the Gate): with the Gate around a store-reading source
// as the only audited caller, a drained sink clears audit-blocked on the next
// secret-bearing deploy, the alert clears, and the following deploy
// delegates.
func TestGate_AuditBlockedClearsWithoutRestart(t *testing.T) {
	f := newFixture(t, readyHealth, nil)
	kv := &kvStore{fakeStore: f.store, err: clientTimeout("read")}
	obs, err := NewObservedStore(kv, f.m)
	if err != nil {
		t.Fatal(err)
	}
	inner := &innerSource{value: "v", do: func(ctx context.Context) error {
		_, err := obs.Read(ctx, tokenOf("t"), pathOf(t), 0)
		return err
	}}
	g := newGate(t, f, inner)
	// The first deploy's read times out with health 200: raised.
	if _, err := g.ResolveCompose(context.Background(), "a", tokened); err == nil {
		t.Fatal("a read that timed out resolved")
	}
	if a := f.m.Alerts(context.Background(), f.clock.now()); len(a) != 1 || a[0].ID != "secret-store:audit-blocked" {
		t.Fatalf("alerts %+v, want audit-blocked", a)
	}
	kv.err = nil // the sink drains
	for i := range 2 {
		if _, err := g.ResolveCompose(context.Background(), "a", tokened); err != nil {
			t.Fatalf("deploy %d after the drain: %v", i+1, err)
		}
		if a := f.m.Alerts(context.Background(), f.clock.now()); len(a) != 0 {
			t.Fatalf("alerts after the drain %+v, want none", a)
		}
	}
	if inner.count() != 3 {
		t.Fatalf("inner calls %d, want 3", inner.count())
	}
}

// TC-760-20: ObservedStore forwards every call's arguments and results
// unchanged, reports Read, Write and Versions to the observer with the
// caller's own ctx, and never reports Health.
func TestObservedStore_Transparent(t *testing.T) {
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "caller")
	want := &secretstore.Error{Op: "x", Kind: secretstore.ErrNotFound}
	kv := &kvStore{fakeStore: newFakeStore(readyHealth, nil), err: want}
	spy := &spyObserver{}
	o, err := NewObservedStore(kv, spy)
	if err != nil {
		t.Fatal(err)
	}
	p := pathOf(t)

	kvGot, err := o.Read(ctx, tokenOf("t1"), p, 2)
	check(t, spy, ctx, "read", kv.args, []any{"read", "t1", p, 2}, kvGot.Version == 3, err, want)
	n, err := o.Write(ctx, tokenOf("t2"), p, map[string]secret.Value{"k": tokenOf("v")}, 1)
	check(t, spy, ctx, "write", kv.args, []any{"write", "t2", p, 1, 1}, n == 4, err, want)
	md, err := o.Versions(ctx, tokenOf("t3"), p)
	check(t, spy, ctx, "versions", kv.args, []any{"versions", "t3", p}, md.CurrentVersion == 5, err, want)

	before := len(spy.errs)
	h, err := o.Health(ctx)
	if err != nil || h != readyHealth || kv.count() != 1 {
		t.Fatalf("Health = (%+v, %v), want the store's answer", h, err)
	}
	if len(spy.errs) != before {
		t.Fatal("Health was reported to the observer")
	}

	if s, err := NewObservedStore(nil, spy); err == nil || s != nil {
		t.Error("NewObservedStore(nil store) did not refuse")
	}
	if s, err := NewObservedStore(kv, nil); err == nil || s != nil {
		t.Error("NewObservedStore(nil observer) did not refuse")
	}
}

type spyObserver struct {
	ctxs []context.Context
	errs []error
}

func (s *spyObserver) ObserveAudited(ctx context.Context, err error) {
	s.ctxs = append(s.ctxs, ctx)
	s.errs = append(s.errs, err)
}

func check(t *testing.T, spy *spyObserver, ctx context.Context, op string, gotArgs, wantArgs []any, resultOK bool, err, wantErr error) {
	t.Helper()
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Errorf("%s: the store got %v, want %v", op, gotArgs, wantArgs)
	}
	if !resultOK || err != wantErr {
		t.Errorf("%s: the caller got a different result or error (%v)", op, err)
	}
	last := len(spy.errs) - 1
	if last < 0 || spy.ctxs[last] != ctx || spy.errs[last] != wantErr {
		t.Errorf("%s: the observer did not see the caller's ctx and the call's error", op)
	}
}
