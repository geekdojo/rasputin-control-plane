package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-762-19: a restore, on main's own wiring chain. The restored database
// holds the app and its token compose, the restored trust dir holds the seed,
// and the store a backend is requested for holds no app entries (an archive
// taken before any entry existed, or one whose store members were not
// restored). The first deploy re-creates each entry from the seed at version
// 1, byte-equal to the HKDF value, and the resolved compose is the one the
// previous release sent.
func TestDeploySource_RestoreReCreatesEntriesEqualToHKDF(t *testing.T) {
	log, rec := logkittest.New()
	ctx := jobs.ContextWithJobID(t.Context(), "job-restore")
	const compose = "services:\n  db:\n    environment:\n      PW: ${secret:db-password}\n      KEY: ${secret:session-key}\n"

	as := openAppsStore(t)
	now := time.Now()
	if err := as.Create(ctx, &apps.App{ID: wiringAppID, Name: "restored", ComposeYAML: compose,
		TargetNode: "node-1", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	seed, hkdf := loadAppSecrets(ctx, log, func(code int) { t.Fatalf("loadAppSecrets exited %d", code) }, t.TempDir())

	w, err := wireSecretStore(ctx, log, storeModeMock, defaultSecretStoreAddr,
		ensureStoreCA(t, t.TempDir(), tlscatest.Deps()), t.TempDir(), (&recordedRun{}).run)
	if err != nil {
		t.Fatal(err)
	}
	r, err := storeReadinessWiring(storeModeMock, w.mode, w.store, openJobStore(t), time.Now, log)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := storeSessionWiring(w.login, r.store, r.monitor, log)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := secretsWiring(sess, as, log)
	if err != nil {
		t.Fatal(err)
	}
	storeSource, err := appsecret.NewStoreSource(appsecret.StoreSourceDeps{Secrets: svc, Apps: appTargetNodes{store: as}, Seed: seed, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	src, err := deploySourceWiring(r.monitor, storeSource, hkdf, log)
	if err != nil {
		t.Fatal(err)
	}

	got, err := src.ResolveCompose(ctx, wiringAppID, compose)
	if err != nil {
		t.Fatalf("the first deploy after the restore = %v", err)
	}
	want, err := hkdf.ResolveCompose(ctx, wiringAppID, compose)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Reveal(), want.Reveal()) {
		t.Fatal("the restored cluster resolved a different compose from the previous release's")
	}
	for _, name := range []string{"db-password", "session-key"} {
		ref, err := secrets.AppSecret(wiringAppID, name)
		if err != nil {
			t.Fatal(err)
		}
		p, err := secretstore.NewKVPath(storepolicy.Mount, ref.String())
		if err != nil {
			t.Fatal(err)
		}
		kv, err := w.store.Read(ctx, secret.Value{}, p, 0)
		if err != nil {
			t.Fatalf("%s was not re-created: %v", name, err)
		}
		derived, err := seed.Derive(wiringAppID, name, appsecret.InitialVersion)
		if err != nil {
			t.Fatal(err)
		}
		if kv.Version != 1 || !bytes.Equal(kv.Data["value"].Reveal(), derived.Reveal()) {
			t.Fatalf("%s: version %d, want version 1 holding the HKDF value", name, kv.Version)
		}
		if strings.Contains(rec.Text(), string(derived.Reveal())) {
			t.Fatalf("%s's value reached a log record", name)
		}
		kv.Destroy()
	}
}
