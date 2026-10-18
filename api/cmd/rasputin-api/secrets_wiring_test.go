package main

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// wiringAppID is a canonical app ID, as the api mints them.
const wiringAppID = "01JABCDEFGHJKMNPQRSTVWXYZ0"

func openAppsStore(t *testing.T) *apps.Store {
	t.Helper()
	s, err := apps.OpenStore(t.Context(), filepath.Join(t.TempDir(), "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TC-761-21: appTargetNodes reads an app's target node from a real apps
// store, reports a missing row as not found and a closed database as an
// error; secretsWiring builds the service in every store mode with no store
// call, and refuses each nil argument. With the store off, as the previous
// release ran, every operation is ErrDisabled.
func TestSecretsWiring(t *testing.T) {
	log, _ := logkittest.New()
	as := openAppsStore(t)
	now := time.Now()
	if err := as.Create(t.Context(), &apps.App{ID: wiringAppID, Name: "wiring", ComposeYAML: "services: {}\n",
		TargetNode: "node-1", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}

	t.Run("appTargetNodes", func(t *testing.T) {
		a := appTargetNodes{store: as}
		if node, found, err := a.TargetNode(t.Context(), wiringAppID); err != nil || !found || node != "node-1" {
			t.Errorf("existing app = %q, %v, %v; want node-1, true, nil", node, found, err)
		}
		if node, found, err := a.TargetNode(t.Context(), "01JZZZZZZZZZZZZZZZZZZZZZZ1"); err != nil || found || node != "" {
			t.Errorf("missing app = %q, %v, %v; want \"\", false, nil", node, found, err)
		}
		closed := openAppsStore(t)
		if err := closed.Close(); err != nil {
			t.Fatal(err)
		}
		if _, found, err := (appTargetNodes{store: closed}).TargetNode(t.Context(), wiringAppID); err == nil || found {
			t.Errorf("closed database = %v, %v; want an error", found, err)
		}
	})

	js := openJobStore(t)
	ca := ensureStoreCA(t, t.TempDir(), tlscatest.Deps())
	for _, backend := range []string{"", storeModeMock, storeModeOpenBao} {
		t.Run("mode "+backend, func(t *testing.T) {
			w, err := wireSecretStore(t.Context(), log, backend, defaultSecretStoreAddr, ca, t.TempDir(), (&recordedRun{}).run)
			if err != nil {
				t.Fatal(err)
			}
			store := &countingStore{secretStore: w.store}
			r, err := storeReadinessWiring(backend, w.mode, store, js, time.Now, log)
			if err != nil {
				t.Fatal(err)
			}
			login := &countingLogin{inner: w.login}
			sess, err := storeSessionWiring(login, r.store, r.monitor, log)
			if err != nil {
				t.Fatal(err)
			}
			svc, err := secretsWiring(sess, as, log)
			if err != nil || svc == nil {
				t.Fatalf("secretsWiring = %v, %v; want a service", svc, err)
			}
			if login.calls.Load() != 0 || store.calls.Load() != 0 {
				t.Fatalf("wiring made %d logins and %d store calls", login.calls.Load(), store.calls.Load())
			}
			if backend != "" {
				return
			}
			ref, err := secrets.AppSecret(wiringAppID, "db-pass")
			if err != nil {
				t.Fatal(err)
			}
			_, err = svc.Create(t.Context(), secrets.OperatorActor("u1"), ref, secret.New([]byte("v")))
			if !errors.Is(err, secretstore.ErrDisabled) {
				t.Errorf("Create with the store off = %v, want ErrDisabled", err)
			}
		})
	}

	t.Run("nil arguments", func(t *testing.T) {
		m := secretstore.NewMock(time.Now)
		sess, err := storeSessionWiring(m, m, nil, log)
		if err != nil {
			t.Fatal(err)
		}
		if s, err := secretsWiring(nil, as, log); err == nil || s != nil {
			t.Errorf("nil session: %v, %v; want an error", s, err)
		}
		if s, err := secretsWiring(sess, nil, log); err == nil || s != nil {
			t.Errorf("nil apps store: %v, %v; want an error", s, err)
		}
		if s, err := secretsWiring(sess, as, nil); err == nil || s != nil {
			t.Errorf("nil logger: %v, %v; want an error", s, err)
		}
	})
}
