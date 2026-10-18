package storesession_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const role = "rasputin-api"

// sentinel is the text of the nth token the fake login mints. Each is unique,
// so the redaction scan can look for every one.
func sentinel(n int) string { return fmt.Sprintf("sentinel-store-token-%d-c0ffee", n) }

// observation is one ObserveAudited call.
type observation struct {
	ctx context.Context
	err error
}

// rig is the fake Login, Store and Observer behind one Session, recording
// every call in order.
type rig struct {
	t *testing.T

	mu      sync.Mutex
	events  []string // "login" or "kv:<token>", in call order
	logins  int
	roles   []string
	kvCalls int
	kvToks  []string
	deleted []secretstore.KVPath
	obs     []observation

	// loginFn answers the nth login (1-based); nil mints sentinel(n).
	loginFn func(ctx context.Context, n int) (secret.Value, error)
	// kvFn answers the nth KV call (1-based) carrying tok; nil succeeds.
	kvFn func(n int, tok string) error

	rec  *logkittest.Recorder
	sess *storesession.Session
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t}
	var log *slog.Logger
	log, r.rec = logkittest.New()
	keepRecorder(r.rec)
	s, err := storesession.New(storesession.Config{Role: role, Login: r, Store: r, Observer: r, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	r.sess = s
	return r
}

func (r *rig) CertLogin(ctx context.Context, rl string) (secret.Value, error) {
	r.mu.Lock()
	r.logins++
	n := r.logins
	r.roles = append(r.roles, rl)
	r.events = append(r.events, "login")
	fn := r.loginFn
	r.mu.Unlock()
	if fn != nil {
		return fn(ctx, n)
	}
	return secret.New([]byte(sentinel(n))), nil
}

func (r *rig) kv(tok secret.Value) error {
	r.mu.Lock()
	r.kvCalls++
	n := r.kvCalls
	text := string(tok.Reveal())
	r.kvToks = append(r.kvToks, text)
	r.events = append(r.events, "kv:"+text)
	fn := r.kvFn
	r.mu.Unlock()
	if fn != nil {
		return fn(n, text)
	}
	return nil
}

func (r *rig) Read(_ context.Context, tok secret.Value, _ secretstore.KVPath, _ int) (secretstore.KV, error) {
	if err := r.kv(tok); err != nil {
		return secretstore.KV{}, err
	}
	return secretstore.KV{Version: 7}, nil
}

func (r *rig) Write(_ context.Context, tok secret.Value, _ secretstore.KVPath, _ map[string]secret.Value, cas int) (int, error) {
	if err := r.kv(tok); err != nil {
		return 0, err
	}
	return cas + 1, nil
}

func (r *rig) Versions(_ context.Context, tok secret.Value, _ secretstore.KVPath) (secretstore.Metadata, error) {
	if err := r.kv(tok); err != nil {
		return secretstore.Metadata{}, err
	}
	return secretstore.Metadata{CurrentVersion: 7}, nil
}

func (r *rig) Delete(_ context.Context, tok secret.Value, p secretstore.KVPath) error {
	r.mu.Lock()
	r.deleted = append(r.deleted, p)
	r.mu.Unlock()
	return r.kv(tok)
}

func (r *rig) ObserveAudited(ctx context.Context, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.obs = append(r.obs, observation{ctx, err})
}

func (r *rig) counts() (logins, kvCalls, obs int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.logins, r.kvCalls, len(r.obs)
}

func (r *rig) snapshot() (events, kvToks []string, obs []observation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...), append([]string(nil), r.kvToks...), append([]observation(nil), r.obs...)
}

// read is one Session.Read with the test's ctx.
func (r *rig) read() error {
	r.t.Helper()
	_, err := r.sess.Read(r.t.Context(), path(r.t), 0)
	return err
}

// warm makes one successful call, so the session holds sentinel(1).
func (r *rig) warm() {
	r.t.Helper()
	if err := r.read(); err != nil {
		r.t.Fatalf("warm-up Read: %v", err)
	}
}

// loginRecords are the INFO login records.
func (r *rig) loginRecords() []slog.Record {
	return r.rec.Matching(slog.LevelInfo, "secret store login")
}

func path(t *testing.T) secretstore.KVPath {
	t.Helper()
	p, err := secretstore.NewKVPath("rasputin-secrets", "apps/a")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// denied is a 403 as the client reports it.
func denied(op string) error {
	return &secretstore.Error{Op: op, Status: 403, Kind: secretstore.ErrDenied}
}

// seenErrs and seenRecs collect every error the tests below return and every
// log they write, for the redaction scan.
var (
	errsMu   sync.Mutex
	seenErrs []error
	seenRecs []*logkittest.Recorder
)

func keepRecorder(rec *logkittest.Recorder) {
	errsMu.Lock()
	seenRecs = append(seenRecs, rec)
	errsMu.Unlock()
}

// seenLogText is the text of every log kept so far.
func seenLogText() string {
	errsMu.Lock()
	defer errsMu.Unlock()
	var b strings.Builder
	for _, rec := range seenRecs {
		b.WriteString(rec.Text())
		b.WriteString("\n")
	}
	return b.String()
}

func keep(err error) error {
	if err != nil {
		errsMu.Lock()
		seenErrs = append(seenErrs, err)
		errsMu.Unlock()
	}
	return err
}

// TC-759-01: the first call logs in once as rasputin-api, the second reuses
// the token, both KV calls carry it, and one INFO record names the login.
func TestSession_LazyLoginReusesTheToken(t *testing.T) {
	r := newRig(t)
	for range 2 {
		if err := keep(r.read()); err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	logins, _, _ := r.counts()
	_, toks, _ := r.snapshot()
	if logins != 1 || len(r.roles) != 1 || r.roles[0] != role {
		t.Fatalf("logins = %d roles = %v, want one as %s", logins, r.roles, role)
	}
	if len(toks) != 2 || toks[0] != sentinel(1) || toks[1] != sentinel(1) {
		t.Fatalf("KV tokens = %v, want the login's token twice", toks)
	}
	recs := r.loginRecords()
	if len(recs) != 1 {
		t.Fatalf("login records = %d, want 1:\n%s", len(recs), r.rec.Text())
	}
	for k, want := range map[string]string{"component": "secretstore", "event": "secretstore.login", "role": role, "reason": "no-token"} {
		if got, _ := logkittest.Attr(recs[0], k); got != want {
			t.Errorf("record %s = %q, want %q", k, got, want)
		}
	}
}

// TC-759-02: a token from an earlier call that the store refuses gets exactly
// one re-login and one retry carrying the new token, and the call succeeds,
// for each method.
func TestSession_RefusedTokenGetsOneReloginAndSucceeds(t *testing.T) {
	for name, do := range map[string]func(*rig) (any, error){
		"Read": func(r *rig) (any, error) { kv, err := r.sess.Read(t.Context(), path(t), 0); return kv.Version, err },
		"Write": func(r *rig) (any, error) {
			return r.sess.Write(t.Context(), path(t), map[string]secret.Value{"k": secret.New([]byte("v"))}, 6)
		},
		"Versions": func(r *rig) (any, error) {
			m, err := r.sess.Versions(t.Context(), path(t))
			return m.CurrentVersion, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.warm()
			r.kvFn = func(n int, _ string) error {
				if n == 2 {
					return denied(strings.ToLower(name))
				}
				return nil
			}
			v, err := do(r)
			if keep(err) != nil {
				t.Fatalf("%s = %v, want success after the re-login", name, err)
			}
			if v != 7 {
				t.Errorf("%s returned %v, want 7", name, v)
			}
			logins, kvCalls, _ := r.counts()
			_, toks, _ := r.snapshot()
			if logins != 2 || kvCalls != 3 {
				t.Fatalf("logins = %d KV calls = %d, want 2 and 3", logins, kvCalls)
			}
			if toks[1] != sentinel(1) || toks[2] != sentinel(2) {
				t.Errorf("KV tokens = %v, want the refused token then the new one", toks)
			}
			recs := r.loginRecords()
			if len(recs) != 2 {
				t.Fatalf("login records = %d, want 2", len(recs))
			}
			if got, _ := logkittest.Attr(recs[1], "reason"); got != "refused" {
				t.Errorf("second record reason = %q, want refused", got)
			}
		})
	}
}

// TC-761-19: Session.Delete passes the held token and the path unchanged,
// and a token an earlier call obtained that the store refuses gets exactly one
// re-login and one retry carrying the new token.
func TestSession_Delete(t *testing.T) {
	r := newRig(t)
	r.warm()
	if err := keep(r.sess.Delete(t.Context(), path(t))); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	r.kvFn = func(n int, _ string) error {
		if n == 3 {
			return denied("delete")
		}
		return nil
	}
	if err := keep(r.sess.Delete(t.Context(), path(t))); err != nil {
		t.Fatalf("Delete after a refusal = %v, want success after the re-login", err)
	}
	logins, kvCalls, _ := r.counts()
	_, toks, _ := r.snapshot()
	if logins != 2 || kvCalls != 4 {
		t.Fatalf("logins = %d KV calls = %d, want 2 and 4", logins, kvCalls)
	}
	if toks[1] != sentinel(1) || toks[2] != sentinel(1) || toks[3] != sentinel(2) {
		t.Errorf("KV tokens = %v, want the held token, the refused one, then the new one", toks)
	}
	r.mu.Lock()
	deleted := append([]secretstore.KVPath(nil), r.deleted...)
	r.mu.Unlock()
	if len(deleted) != 3 || deleted[0] != path(t) || deleted[2] != path(t) {
		t.Errorf("deleted paths = %v, want %v three times", deleted, path(t))
	}
}

// TC-759-03: N calls refused on the same stale token at once cost exactly one
// re-login, every call succeeds, and each login is observed once (TC-759-12's
// "another call already logged in" leg). Run under -race.
func TestSession_ConcurrentRefusalsShareOneRelogin(t *testing.T) {
	const n = 16
	r := newRig(t)
	r.warm()
	var arrived sync.WaitGroup
	arrived.Add(n)
	all := make(chan struct{})
	go func() { arrived.Wait(); close(all) }()
	r.kvFn = func(_ int, tok string) error {
		if tok != sentinel(1) {
			return nil
		}
		// Every goroutine reaches the store with the stale token before any
		// is refused, so all of them are refused at once.
		arrived.Done()
		<-all
		return denied("read")
	}
	errs := make(chan error, n)
	for range n {
		go func() { errs <- r.read() }()
	}
	for range n {
		if err := keep(<-errs); err != nil {
			t.Errorf("Read = %v, want success", err)
		}
	}
	logins, _, obs := r.counts()
	if logins != 2 {
		t.Fatalf("logins = %d, want 2 (the first and one re-login)", logins)
	}
	if obs != logins {
		t.Errorf("observations = %d, want one per login (%d)", obs, logins)
	}
}

// F-759-01: a caller waiting behind a stalled login returns as soon as its own
// ctx ends, with ErrUnreachable carrying ctx.Err(), and makes no login and no
// observation. The stalled login still completes afterwards. (TC-759-03 above
// still holds with the slot.)
func TestSession_WaiterLeavesWhenItsCtxEnds(t *testing.T) {
	r := newRig(t)
	inLogin := make(chan struct{})
	release := make(chan struct{})
	r.loginFn = func(_ context.Context, n int) (secret.Value, error) {
		if n == 1 {
			close(inLogin)
			<-release
		}
		return secret.New([]byte(sentinel(n))), nil
	}
	stalled := make(chan error, 1)
	go func() { stalled <- r.read() }()
	<-inLogin

	ctx, cancel := context.WithCancel(t.Context())
	waiter := make(chan error, 1)
	go func() {
		_, err := r.sess.Read(ctx, path(t), 0)
		waiter <- err
	}()
	cancel()
	var err error
	select {
	case err = <-waiter:
	case <-time.After(5 * time.Second):
		// Only the failure case reaches this bound: the pass case is the
		// waiter returning while the first login is still held.
		t.Fatal("the waiter is still queued behind the stalled login after its ctx was cancelled")
	}
	keep(err)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, secretstore.ErrUnreachable) {
		t.Fatalf("waiter err = %v, want ErrUnreachable carrying context.Canceled", err)
	}
	if !strings.HasPrefix(err.Error(), "storesession: log in as rasputin-api: ") {
		t.Errorf("waiter err = %q, want the login wrap", err)
	}
	if logins, kvCalls, obs := r.counts(); logins != 1 || kvCalls != 0 || obs != 0 {
		t.Fatalf("while stalled: logins = %d KV = %d observations = %d, want 1, 0, 0", logins, kvCalls, obs)
	}
	close(release)
	if err := <-stalled; err != nil {
		t.Fatalf("stalled Read = %v, want success once released", err)
	}
	if logins, _, obs := r.counts(); logins != 1 || obs != 1 {
		t.Errorf("after release: logins = %d observations = %d, want 1 and 1", logins, obs)
	}
}

// TC-759-07: when the retry is refused again, ErrDenied is returned after one
// re-login and no third KV call.
func TestSession_RetryRefusedAgainFailsClosed(t *testing.T) {
	r := newRig(t)
	r.warm()
	r.kvFn = func(int, string) error { return denied("read") }
	err := keep(r.read())
	if !errors.Is(err, secretstore.ErrDenied) {
		t.Fatalf("Read = %v, want ErrDenied", err)
	}
	if logins, kvCalls, _ := r.counts(); logins != 2 || kvCalls != 3 {
		t.Fatalf("logins = %d KV calls = %d, want 2 and 3 (one warm-up, two for this call)", logins, kvCalls)
	}
}

// TC-759-08: a failed re-login returns the wrapped login error, sends nothing
// after it, holds no token, and the next call logs in before any KV call and
// never carries the refused token.
func TestSession_FailedReloginFailsClosed(t *testing.T) {
	for name, loginErr := range map[string]error{
		"denied":      &secretstore.Error{Op: "login", Status: 403, Kind: secretstore.ErrDenied},
		"unreachable": &secretstore.Error{Op: "login", Kind: secretstore.ErrUnreachable, Err: errors.New("connection refused")},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.warm()
			r.kvFn = func(_ int, tok string) error {
				if tok == sentinel(1) {
					return denied("read")
				}
				return nil
			}
			r.loginFn = func(_ context.Context, n int) (secret.Value, error) {
				if n == 2 {
					return secret.Value{}, loginErr
				}
				return secret.New([]byte(sentinel(n))), nil
			}
			err := keep(r.read())
			if !errors.Is(err, loginErr) || !strings.HasPrefix(err.Error(), "storesession: log in as rasputin-api: ") {
				t.Fatalf("Read = %v, want the wrapped login error", err)
			}
			kind := loginErr.(*secretstore.Error).Kind
			if !errors.Is(err, kind) {
				t.Errorf("Read = %v, want errors.Is %v", err, kind)
			}
			events, _, _ := r.snapshot()
			if last := events[len(events)-1]; last != "login" {
				t.Fatalf("events = %v: something was sent after the failed login", events)
			}
			refusedAt := len(events)
			if err := keep(r.read()); err != nil {
				t.Fatalf("next Read = %v, want success", err)
			}
			events, _, _ = r.snapshot()
			after := events[refusedAt:]
			if len(after) != 2 || after[0] != "login" || after[1] != "kv:"+sentinel(3) {
				t.Fatalf("events after the failed login = %v, want [login kv:%s]", after, sentinel(3))
			}
		})
	}
}

// TC-759-09: a token this call minted that is then refused gets no second
// login in the same call.
func TestSession_OneLoginPerCall(t *testing.T) {
	r := newRig(t)
	r.kvFn = func(int, string) error { return denied("read") }
	err := keep(r.read())
	if !errors.Is(err, secretstore.ErrDenied) {
		t.Fatalf("Read = %v, want ErrDenied", err)
	}
	if logins, kvCalls, _ := r.counts(); logins != 1 || kvCalls != 1 {
		t.Fatalf("logins = %d KV calls = %d, want 1 and 1", logins, kvCalls)
	}
}

// TC-759-10: every other outcome is returned unchanged with no login, and the
// next call uses the same token.
func TestSession_OtherErrorsKeepTheToken(t *testing.T) {
	for name, want := range map[string]error{
		"sealed":      &secretstore.Error{Op: "read", Status: 503, Kind: secretstore.ErrSealed},
		"unreachable": &secretstore.Error{Op: "read", Kind: secretstore.ErrUnreachable, Err: errors.New("connection refused")},
		"timeout":     &secretstore.Error{Op: "read", Kind: secretstore.ErrUnreachable, Err: context.DeadlineExceeded},
		"not found":   &secretstore.Error{Op: "read", Status: 404, Kind: secretstore.ErrNotFound},
		"cas":         &secretstore.Error{Op: "write", Status: 400, Kind: secretstore.ErrCASMismatch},
		"protocol":    &secretstore.Error{Op: "read", Status: 200, Kind: secretstore.ErrProtocol},
		"invalid":     &secretstore.Error{Op: "read", Kind: secretstore.ErrInvalidValue},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.warm()
			r.kvFn = func(n int, _ string) error {
				if n == 2 {
					return want
				}
				return nil
			}
			err := keep(r.read())
			if err != want || !errors.Is(err, want.(*secretstore.Error).Kind) {
				t.Fatalf("Read = %v, want %v unchanged", err, want)
			}
			if err := r.read(); err != nil {
				t.Fatalf("next Read = %v", err)
			}
			logins, _, _ := r.counts()
			_, toks, _ := r.snapshot()
			if logins != 1 {
				t.Fatalf("logins = %d, want 1", logins)
			}
			if toks[2] != sentinel(1) {
				t.Errorf("next call carried %q, want the held token", toks[2])
			}
		})
	}
}

type ctxKey struct{}

// TC-759-12: each login is reported once, with the caller's own ctx and the
// login's error (nil on success); a client-bound timeout leaves the caller's
// ctx live; a call that reuses the token makes no observation.
func TestSession_LoginIsObservedWithTheCallersCtx(t *testing.T) {
	timeout := &secretstore.Error{Op: "login", Kind: secretstore.ErrUnreachable, Err: context.DeadlineExceeded}
	for name, loginErr := range map[string]error{
		"success": nil,
		"denied":  &secretstore.Error{Op: "login", Status: 403, Kind: secretstore.ErrDenied},
		"timeout": timeout,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.loginFn = func(context.Context, int) (secret.Value, error) {
				if loginErr != nil {
					return secret.Value{}, loginErr
				}
				return secret.New([]byte(sentinel(1))), nil
			}
			ctx := context.WithValue(t.Context(), ctxKey{}, name)
			_, err := r.sess.Read(ctx, path(t), 0)
			keep(err)
			_, _, obs := r.snapshot()
			if len(obs) != 1 {
				t.Fatalf("observations = %d, want 1", len(obs))
			}
			if obs[0].ctx != ctx || obs[0].ctx.Value(ctxKey{}) != name {
				t.Error("the observation's ctx is not the caller's own")
			}
			if obs[0].ctx.Err() != nil {
				t.Errorf("the observed ctx is done (%v), want it live", obs[0].ctx.Err())
			}
			if loginErr == nil {
				if obs[0].err != nil {
					t.Errorf("observed err = %v, want nil", obs[0].err)
				}
				if _, err := r.sess.Read(ctx, path(t), 0); err != nil {
					t.Fatal(err)
				}
				if _, _, n := r.counts(); n != 1 {
					t.Errorf("observations after a reused token = %d, want still 1", n)
				}
				return
			}
			if !errors.Is(obs[0].err, loginErr) {
				t.Errorf("observed err = %v, want %v", obs[0].err, loginErr)
			}
		})
	}
}

// TC-759-14: New refuses an empty role and each nil collaborator, naming it,
// and a valid New makes no call.
func TestNew_RefusesAnIncompleteConfig(t *testing.T) {
	r := &rig{t: t}
	log, _ := logkittest.New()
	full := storesession.Config{Role: role, Login: r, Store: r, Observer: r, Log: log}
	for field, mutate := range map[string]func(*storesession.Config){
		"Role":     func(c *storesession.Config) { c.Role = "" },
		"Login":    func(c *storesession.Config) { c.Login = nil },
		"Store":    func(c *storesession.Config) { c.Store = nil },
		"Observer": func(c *storesession.Config) { c.Observer = nil },
		"Log":      func(c *storesession.Config) { c.Log = nil },
	} {
		cfg := full
		mutate(&cfg)
		s, err := storesession.New(cfg)
		if err == nil || s != nil || !strings.Contains(err.Error(), "Config."+field) {
			t.Errorf("New without %s = %v, %v; want an error naming it", field, s, err)
		}
	}
	if _, err := storesession.New(full); err != nil {
		t.Fatal(err)
	}
	if logins, kvCalls, obs := r.counts(); logins+kvCalls+obs != 0 {
		t.Errorf("construction made %d logins, %d KV calls and %d observations", logins, kvCalls, obs)
	}
}

// TC-759-13: across the outcomes above, no token appears in the log text, in
// any rendering of a returned error, or in a rendering of the Session.
func TestSession_Redaction(t *testing.T) {
	// The outcome tests run first in file order; run them again here so this
	// test stands alone under -run.
	for _, f := range []func(*testing.T){
		TestSession_LazyLoginReusesTheToken,
		TestSession_RefusedTokenGetsOneReloginAndSucceeds,
		TestSession_WaiterLeavesWhenItsCtxEnds,
		TestSession_RetryRefusedAgainFailsClosed,
		TestSession_FailedReloginFailsClosed,
		TestSession_OneLoginPerCall,
		TestSession_OtherErrorsKeepTheToken,
		TestSession_LoginIsObservedWithTheCallersCtx,
	} {
		f(t)
	}
	r := newRig(t)
	r.warm()
	r.kvFn = func(n int, _ string) error {
		if n == 2 {
			return denied("read")
		}
		return nil
	}
	keep(r.read())
	errsMu.Lock()
	errs := append([]error(nil), seenErrs...)
	errsMu.Unlock()
	if len(errs) == 0 {
		t.Fatal("no errors were collected, so the scan would read nothing")
	}
	var secrets []string
	for n := 1; n <= 4; n++ {
		secrets = append(secrets, sentinel(n))
	}
	logText := seenLogText()
	if !strings.Contains(logText, "secret store login") {
		t.Fatal("the collected logs hold no login record, so the scan would read nothing")
	}
	assertRedacted(t, secrets, logText, errs, r.sess)
}

// assertRedacted fails when any of secrets appears in logText, in %v, %+v,
// %#v or JSON of each error, or in %+v or JSON of sess.
func assertRedacted(t *testing.T, secrets []string, logText string, errs []error, sess *storesession.Session) {
	t.Helper()
	var out []string
	out = append(out, logText)
	for _, err := range errs {
		j, _ := json.Marshal(err)
		out = append(out, fmt.Sprintf("%v|%+v|%#v|%s", err, err, err, j))
	}
	// The Session as a value inside something a caller might marshal: it has
	// no exported field, so this must render it as {} and nothing more.
	sj, err := json.Marshal(map[string]any{"session": sess})
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, fmt.Sprintf("%+v|%#v|%s", sess, sess, sj))
	all := strings.Join(out, "\n")
	for _, s := range secrets {
		if s != "" && strings.Contains(all, s) {
			t.Errorf("a secret (%d bytes) appears in the logs or a rendering", len(s))
		}
	}
}
