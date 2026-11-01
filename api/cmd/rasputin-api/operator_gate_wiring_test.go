package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// sealedMock is the mock store reporting itself sealed, so the readiness
// monitor reads Sealed.
type sealedMock struct{ *secretstore.Mock }

func (sealedMock) Health(context.Context) (secretstore.Health, error) {
	return secretstore.Health{Initialized: true, Sealed: true}, nil
}

func refusalCode(err error) string {
	var c interface{ Code() string }
	if errors.As(err, &c) {
		return c.Code()
	}
	return ""
}

// TC-780-16: operatorGated gates both sources deploySourceWiring can pick.
// With the store requested and ready, an unset declared secret is refused
// with operator_secret_unset; with the store off, the presence check fails
// through secretstore.Disabled and is refused with secret_store_unavailable.
// Neither the store source nor the HKDF source (each would derive) is
// reached. With the store sealed, the readiness Gate's refusal comes first.
func TestOperatorGated_GatesBothModes(t *testing.T) {
	log, _ := logkittest.New()
	ctx := jobs.ContextWithJobID(t.Context(), "job-780")
	const compose = "services:\n  feeds:\n    environment:\n      K: ${secret:feed-key}\n"
	js := openJobStore(t)
	ca := ensureStoreCA(t, t.TempDir(), tlscatest.Deps())

	for _, tc := range []struct {
		name, backend string
		sealed        bool
		want          string
	}{
		{"store requested, ready", storeModeMock, false, apps.CodeOperatorSecretUnset},
		{"store off", "", false, appsecret.CodeStoreUnavailable},
		{"store requested, sealed", storeModeMock, true, "secret_store_not_ready"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			as := openAppsStore(t)
			now := time.Now()
			if err := as.Create(ctx, &apps.App{ID: wiringAppID, Name: "feeds", ComposeYAML: compose, TargetNode: "node-1",
				OperatorSecrets: []tileschema.OperatorSecret{{Name: "feed-key", Label: "Feed API key"}},
				CreatedAt:       now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			w, err := wireSecretStore(ctx, log, tc.backend, defaultSecretStoreAddr, ca, t.TempDir(), (&recordedRun{}).run, noRestartHook)
			if err != nil {
				t.Fatal(err)
			}
			store := w.store
			if tc.sealed {
				store = sealedMock{w.store.(*secretstore.Mock)}
			}
			r, err := storeReadinessWiring(tc.backend, false, w.mode, store, js, time.Now, notBlank, log)
			if err != nil {
				t.Fatal(err)
			}
			sess, err := storeSessionWiring(w.login, r.store, r.observer, log)
			if err != nil {
				t.Fatal(err)
			}
			svc, err := secretsWiring(sess, as, testSwitch(t), log)
			if err != nil {
				t.Fatal(err)
			}
			storeSrc, hkdf := &countingSource{}, &countingSource{}
			gatedStore, gatedHKDF, err := operatorGated(storeSrc, hkdf, as, svc, log)
			if err != nil {
				t.Fatal(err)
			}
			src, err := deploySourceWiring(r.monitor, gatedStore, gatedHKDF, log)
			if err != nil {
				t.Fatal(err)
			}
			_, env, err := src.ResolveCompose(ctx, wiringAppID, compose)
			if err == nil || env != nil {
				t.Fatal("an unset operator secret resolved")
			}
			if got := refusalCode(err); got != tc.want {
				t.Fatalf("refusal %q (%v), want %q", got, err, tc.want)
			}
			if storeSrc.calls.Load() != 0 || hkdf.calls.Load() != 0 {
				t.Fatalf("a deriving source was reached: store %d, hkdf %d", storeSrc.calls.Load(), hkdf.calls.Load())
			}
		})
	}

	t.Run("nil collaborators", func(t *testing.T) {
		as := openAppsStore(t)
		s := &countingSource{}
		if _, _, err := operatorGated(s, s, nil, nil, log); err == nil {
			t.Error("a nil apps store was accepted")
		}
		if _, _, err := operatorGated(s, s, as, nil, log); err == nil {
			t.Error("a nil secrets service was accepted")
		}
	})
}
