package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// countingLogin counts the logins it forwards.
type countingLogin struct {
	inner storesession.Login
	calls atomic.Int32
}

func (c *countingLogin) CertLogin(ctx context.Context, role string) (secret.Value, error) {
	c.calls.Add(1)
	return c.inner.CertLogin(ctx, role)
}

// TC-759-16: the session is wired in every store mode, with no login and no
// store call during wiring. Off reads ErrDisabled with no I/O through
// noAuditObserver; mock round-trips a value; each nil argument is refused.
func TestStoreSessionWiring(t *testing.T) {
	log, _ := logkittest.New()
	js := openJobStore(t)
	ca := ensureStoreCA(t, t.TempDir(), tlscatest.Deps())
	p, err := secretstore.NewKVPath("rasputin-secrets", "apps/wiring")
	if err != nil {
		t.Fatal(err)
	}

	type built struct {
		w     storeWiring
		r     readinessWiring
		login *countingLogin
		store *countingStore
		sess  *storesession.Session
	}
	build := func(t *testing.T, backend string) built {
		t.Helper()
		w, err := wireSecretStore(t.Context(), log, backend, defaultSecretStoreAddr, ca, t.TempDir(), (&recordedRun{}).run, noRestartHook)
		if err != nil {
			t.Fatal(err)
		}
		if w.login == nil {
			t.Fatalf("%q: storeWiring.login is nil", backend)
		}
		store := &countingStore{secretStore: w.store}
		r, err := storeReadinessWiring(backend, w.mode, store, js, time.Now, log)
		if err != nil {
			t.Fatal(err)
		}
		login := &countingLogin{inner: w.login}
		sess, err := storeSessionWiring(login, r.store, r.monitor, log)
		if err != nil || sess == nil {
			t.Fatalf("%q: storeSessionWiring = %v, %v; want a session", backend, sess, err)
		}
		if login.calls.Load() != 0 || store.calls.Load() != 0 {
			t.Fatalf("%q: wiring made %d logins and %d store calls", backend, login.calls.Load(), store.calls.Load())
		}
		return built{w, r, login, store, sess}
	}

	t.Run("off", func(t *testing.T) {
		b := build(t, "")
		if b.r.monitor != nil {
			t.Fatal("nothing requested built a monitor")
		}
		if _, ok := b.w.login.(secretstore.Disabled); !ok {
			t.Errorf("login = %T, want secretstore.Disabled", b.w.login)
		}
		_, err := b.sess.Read(t.Context(), p, 0)
		if !errors.Is(err, secretstore.ErrDisabled) {
			t.Fatalf("Read = %v, want ErrDisabled", err)
		}
		if b.store.calls.Load() != 0 {
			t.Errorf("store calls = %d, want 0", b.store.calls.Load())
		}
	})

	t.Run("a nil monitor never reaches the session", func(t *testing.T) {
		// A successful login is observed, and Monitor.ObserveAudited on a nil
		// *Monitor dereferences it, so this call would panic if the typed nil
		// reached the session's Observer.
		m := secretstore.NewMock(time.Now)
		var monitor *storestate.Monitor
		sess, err := storeSessionWiring(m, m, monitor, log)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sess.Write(t.Context(), p, map[string]secret.Value{"k": secret.New([]byte("v"))}, 0); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("mock", func(t *testing.T) {
		b := build(t, storeModeMock)
		if b.w.login != storesession.Login(b.w.store.(*secretstore.Mock)) {
			t.Errorf("login = %T, want the same Mock as the store", b.w.login)
		}
		if _, err := b.sess.Write(t.Context(), p, map[string]secret.Value{"k": secret.New([]byte("round-trip"))}, 0); err != nil {
			t.Fatal(err)
		}
		kv, err := b.sess.Read(t.Context(), p, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer kv.Destroy()
		if got := string(kv.Data["k"].Reveal()); got != "round-trip" {
			t.Errorf("read %q, want round-trip", got)
		}
		if b.login.calls.Load() != 1 {
			t.Errorf("logins = %d, want 1", b.login.calls.Load())
		}
	})

	t.Run("openbao", func(t *testing.T) {
		b := build(t, storeModeOpenBao)
		if b.w.client == nil || b.w.login != storesession.Login(b.w.client) {
			t.Errorf("login = %T, want the real client", b.w.login)
		}
		if b.r.monitor == nil {
			t.Error("openbao built no monitor")
		}
	})

	t.Run("requested but refused", func(t *testing.T) {
		b := build(t, "vault")
		if b.w.mode != storeModeOff || b.r.monitor == nil {
			t.Fatalf("mode = %q monitor = %v, want off with a monitor", b.w.mode, b.r.monitor)
		}
		if _, err := b.sess.Read(t.Context(), p, 0); !errors.Is(err, secretstore.ErrDisabled) {
			t.Fatalf("Read = %v, want ErrDisabled", err)
		}
	})

	t.Run("nil arguments", func(t *testing.T) {
		m := secretstore.NewMock(time.Now)
		for name, call := range map[string]func() (*storesession.Session, error){
			"login":  func() (*storesession.Session, error) { return storeSessionWiring(nil, m, nil, log) },
			"store":  func() (*storesession.Session, error) { return storeSessionWiring(m, nil, nil, log) },
			"logger": func() (*storesession.Session, error) { return storeSessionWiring(m, m, nil, nil) },
		} {
			if s, err := call(); err == nil || s != nil {
				t.Errorf("nil %s: %v, %v; want an error", name, s, err)
			}
		}
	})
}
