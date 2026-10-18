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

// constSource resolves every compose to the same value.
type constSource struct{}

func (constSource) ResolveCompose(context.Context, string, string) (secret.Value, error) {
	return secret.New([]byte("resolved")), nil
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
// requested leaves the inner source, the store and the alerts exactly as
// before; any requested backend, a refused configuration (mode off with a
// Disabled store) included, gets the Gate, the observed store and the alert
// source, and the refused configuration reads unreachable and refuses a
// secret-bearing deploy (F-760-02). Wiring never calls the store.
func TestStoreReadinessWiring(t *testing.T) {
	log, _ := logkittest.New()
	js := openJobStore(t)
	inner := constSource{}
	const tokened = "services:\n  web:\n    environment:\n      P: ${secret:db-password}\n"

	t.Run("nothing requested", func(t *testing.T) {
		store := &countingStore{secretStore: secretstore.Disabled{}}
		w, err := storeReadinessWiring("", storeModeOff, store, inner, js, time.Now, log)
		if err != nil {
			t.Fatal(err)
		}
		if w.source != apps.SecretSource(inner) || w.alerts != nil || w.store != secretStore(store) || w.monitor != nil {
			t.Fatalf("wiring = %+v, want the inner source, the store passed in, no alerts and no monitor", w)
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
			w, err := storeReadinessWiring(tc.requested, tc.mode, store, inner, js, time.Now, log)
			if err != nil {
				t.Fatal(err)
			}
			if n := store.calls.Load(); n != 0 {
				t.Fatalf("wiring called the store %d time(s)", n)
			}
			if _, ok := w.source.(*storestate.Gate); !ok {
				t.Fatalf("source is %T, want *storestate.Gate", w.source)
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
			_, err = w.source.ResolveCompose(context.Background(), "a", tokened)
			var nr *storestate.NotReadyError
			if !errors.As(err, &nr) || nr.Code() != "secret_store_not_ready" {
				t.Fatalf("a tokened resolve = %v, want the coded refusal", err)
			}
		})
	}

	t.Run("nil collaborators", func(t *testing.T) {
		type args struct {
			store secretStore
			inner apps.SecretSource
			js    *jobs.Store
			now   func() time.Time
			log   *slog.Logger
		}
		full := args{secretstore.Disabled{}, inner, js, time.Now, log}
		for name, clear := range map[string]func(*args){
			"store":  func(a *args) { a.store = nil },
			"inner":  func(a *args) { a.inner = nil },
			"jobs":   func(a *args) { a.js = nil },
			"clock":  func(a *args) { a.now = nil },
			"logger": func(a *args) { a.log = nil },
		} {
			a := full
			clear(&a)
			if _, err := storeReadinessWiring("mock", storeModeMock, a.store, a.inner, a.js, a.now, a.log); err == nil {
				t.Errorf("storeReadinessWiring with a nil %s = nil error", name)
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
