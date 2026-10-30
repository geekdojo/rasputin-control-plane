package main

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// countingStore counts every call to the store it wraps.
type countingStore struct {
	secretStore
	calls atomic.Int32
}

func (c *countingStore) Health(ctx context.Context) (secretstore.Health, error) {
	c.calls.Add(1)
	return c.secretStore.Health(ctx)
}

func (c *countingStore) Read(ctx context.Context, tok secret.Value, p secretstore.KVPath, v int) (secretstore.KV, error) {
	c.calls.Add(1)
	return c.secretStore.Read(ctx, tok, p, v)
}

func (c *countingStore) Write(ctx context.Context, tok secret.Value, p secretstore.KVPath, d map[string]secret.Value, cas int) (int, error) {
	c.calls.Add(1)
	return c.secretStore.Write(ctx, tok, p, d, cas)
}

func (c *countingStore) Versions(ctx context.Context, tok secret.Value, p secretstore.KVPath) (secretstore.Metadata, error) {
	c.calls.Add(1)
	return c.secretStore.Versions(ctx, tok, p)
}

func (c *countingStore) Delete(ctx context.Context, tok secret.Value, p secretstore.KVPath) error {
	c.calls.Add(1)
	return c.secretStore.Delete(ctx, tok, p)
}

// countingSource resolves every compose to the same value and counts calls.
type countingSource struct {
	calls atomic.Int32
}

func (c *countingSource) ResolveCompose(context.Context, string, string) (secret.Value, map[string]secret.Value, error) {
	c.calls.Add(1)
	return secret.New([]byte("resolved")), nil, nil
}

func openJobStore(t *testing.T) *jobs.Store {
	t.Helper()
	js, err := jobs.OpenStore(context.Background(), filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	return js
}

// TC-760-22: the readiness wiring keys on the REQUESTED backend. Nothing
// requested leaves the store and the alerts exactly as before, with no
// monitor; any requested backend, a refused configuration (mode off with a
// Disabled store) included, gets the monitor, the observed store and the
// alert source, and the refused configuration reads unreachable
// (F-760-02). Wiring never calls the store. Whether its deploys refuse is
// TestDeploySourceWiring's.
func TestStoreReadinessWiring(t *testing.T) {
	log, _ := logkittest.New()
	js := openJobStore(t)

	t.Run("nothing requested", func(t *testing.T) {
		store := &countingStore{secretStore: secretstore.Disabled{}}
		w, err := storeReadinessWiring("", false, storeModeOff, store, js, time.Now, notBlank, log)
		if err != nil {
			t.Fatal(err)
		}
		if w.alerts != nil || w.store != secretStore(store) || w.monitor != nil {
			t.Fatalf("wiring = %+v, want the store passed in, no alerts and no monitor", w)
		}
		if n := store.calls.Load(); n != 0 {
			t.Fatalf("wiring called the store %d time(s)", n)
		}
	})

	for _, tc := range []struct {
		name, requested, mode string
		store                 secretStore
		refused               bool
	}{
		{"mock", "mock", storeModeMock, secretstore.NewMock(time.Now), false},
		{"openbao", "openbao", storeModeOpenBao, secretstore.NewMock(time.Now), false},
		{"openbao refused (mode off)", "openbao", storeModeOff, secretstore.Disabled{}, true},
		{"unrecognised (mode off)", "vault", storeModeOff, secretstore.Disabled{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &countingStore{secretStore: tc.store}
			w, err := storeReadinessWiring(tc.requested, false, tc.mode, store, js, time.Now, notBlank, log)
			if err != nil {
				t.Fatal(err)
			}
			if n := store.calls.Load(); n != 0 {
				t.Fatalf("wiring called the store %d time(s)", n)
			}
			if _, ok := w.store.(*storestate.ObservedStore); !ok {
				t.Fatalf("store is %T, want *storestate.ObservedStore", w.store)
			}
			if w.alerts == nil || w.monitor == nil {
				t.Fatal("no alert source or no monitor")
			}
			if !tc.refused {
				return
			}
			alerts := w.alerts(context.Background(), time.Now())
			if len(alerts) != 1 || alerts[0].ID != "secret-store:unreachable" || alerts[0].Severity != proto.AlertCrit {
				t.Fatalf("alerts = %+v, want the unreachable crit", alerts)
			}
		})
	}

	t.Run("nil collaborators", func(t *testing.T) {
		type args struct {
			store secretStore
			js    *jobs.Store
			now   func() time.Time
			blank func(context.Context) (bool, error)
			log   *slog.Logger
		}
		full := args{secretstore.Disabled{}, js, time.Now, notBlank, log}
		for name, clear := range map[string]func(*args){
			"store":  func(a *args) { a.store = nil },
			"jobs":   func(a *args) { a.js = nil },
			"clock":  func(a *args) { a.now = nil },
			"blank":  func(a *args) { a.blank = nil },
			"logger": func(a *args) { a.log = nil },
		} {
			a := full
			clear(&a)
			if _, err := storeReadinessWiring("mock", false, storeModeMock, a.store, a.js, a.now, a.blank, a.log); err == nil {
				t.Errorf("storeReadinessWiring with a nil %s = nil error", name)
			}
		}
	})
}

// TC-762-17 (AC2): the deploy family's source per requested backend. A
// requested backend (ready, or refused and reading unreachable) gives the
// Gate around the store source, and no compose ever reaches the HKDF source:
// the refused one refuses a token compose with secret_store_not_ready and
// raises the unreachable crit. Nothing requested gives the HKDF source
// itself, with no monitor and no alerts. In every row the wiring makes no
// store call and a token-free compose resolves.
func TestDeploySourceWiring(t *testing.T) {
	log, _ := logkittest.New()
	js := openJobStore(t)
	const tokened = "services:\n  web:\n    environment:\n      P: ${secret:db-password}\n"
	const plain = "services:\n  web:\n    image: nginx\n"
	for _, tc := range []struct {
		name, requested, mode string
		store                 secretStore
		// gate: the source is the Gate; refused: its token compose refuses.
		gate, refused bool
	}{
		{"requested, ready", "openbao", storeModeOpenBao, secretstore.NewMock(time.Now), true, false},
		{"requested, refused configuration", "openbao", storeModeOff, secretstore.Disabled{}, true, true},
		{"not requested", "", storeModeOff, secretstore.Disabled{}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &countingStore{secretStore: tc.store}
			r, err := storeReadinessWiring(tc.requested, false, tc.mode, store, js, time.Now, notBlank, log)
			if err != nil {
				t.Fatal(err)
			}
			storeSrc, hkdf := &countingSource{}, &countingSource{}
			src, err := deploySourceWiring(r.monitor, storeSrc, hkdf, log)
			if err != nil {
				t.Fatal(err)
			}
			if n := store.calls.Load(); n != 0 {
				t.Fatalf("wiring called the store %d time(s)", n)
			}
			if _, ok := src.(*storestate.Gate); ok != tc.gate {
				t.Fatalf("source is %T, want the Gate: %v", src, tc.gate)
			}
			if !tc.gate && src != apps.SecretSource(hkdf) {
				t.Fatalf("source is %T, want the HKDF source itself", src)
			}
			if !tc.gate && (r.monitor != nil || r.alerts != nil) {
				t.Fatal("nothing requested, yet a monitor or an alert source")
			}

			_, _, err = src.ResolveCompose(context.Background(), "a", tokened)
			var nr *storestate.NotReadyError
			switch {
			case tc.refused:
				if !errors.As(err, &nr) || nr.Code() != "secret_store_not_ready" {
					t.Fatalf("a tokened resolve = %v, want the coded refusal", err)
				}
				alerts := r.alerts(context.Background(), time.Now())
				if len(alerts) != 1 || alerts[0].ID != "secret-store:unreachable" || alerts[0].Severity != proto.AlertCrit {
					t.Fatalf("alerts = %+v, want the unreachable crit", alerts)
				}
			case err != nil:
				t.Fatalf("a tokened resolve = %v", err)
			}
			if _, _, err := src.ResolveCompose(context.Background(), "a", plain); err != nil {
				t.Fatalf("a token-free resolve = %v", err)
			}
			if tc.gate && hkdf.calls.Load() != 0 {
				t.Fatalf("the HKDF source was called %d time(s) behind a requested store", hkdf.calls.Load())
			}
			if !tc.gate && (hkdf.calls.Load() != 2 || storeSrc.calls.Load() != 0) {
				t.Fatalf("HKDF calls %d, store source calls %d; want 2 and 0", hkdf.calls.Load(), storeSrc.calls.Load())
			}
		})
	}

	t.Run("nil collaborators", func(t *testing.T) {
		s := &countingSource{}
		for name, args := range map[string][3]any{
			"store source": {nil, s, log},
			"hkdf":         {s, nil, log},
			"logger":       {s, s, nil},
		} {
			store, _ := args[0].(apps.SecretSource)
			hkdf, _ := args[1].(apps.SecretSource)
			logger, _ := args[2].(*slog.Logger)
			if src, err := deploySourceWiring(nil, store, hkdf, logger); err == nil || src != nil {
				t.Errorf("deploySourceWiring with a nil %s = %v, %v; want an error", name, src, err)
			}
		}
	})
}

// The quiesce fact reads the job ledger: only a job there and running holds.
func TestJobRunning(t *testing.T) {
	js := openJobStore(t)
	ctx := context.Background()
	running := jobRunning(js)
	if ok, err := running(ctx, "missing"); ok || err != nil {
		t.Fatalf("a job the ledger lacks = (%v, %v), want not running", ok, err)
	}
	j := &jobs.Job{ID: "j1", Kind: "backup", Status: jobs.StatusRunning, CreatedAt: time.Now()}
	if err := js.CreateJob(ctx, j); err != nil {
		t.Fatal(err)
	}
	if ok, err := running(ctx, "j1"); !ok || err != nil {
		t.Fatalf("a running job = (%v, %v), want running", ok, err)
	}
	if err := js.MarkJobSucceeded(ctx, "j1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, err := running(ctx, "j1"); ok || err != nil {
		t.Fatalf("a finished job = (%v, %v), want not running", ok, err)
	}
	_ = js.Close()
	if _, err := running(ctx, "j1"); err == nil {
		t.Fatal("a closed ledger gave no error")
	}
}

// notBlank is a blank verdict that never reads blank.
func notBlank(context.Context) (bool, error) { return false, nil }
