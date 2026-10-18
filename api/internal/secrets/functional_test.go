package secrets_test

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The functional switch and binary are the smoke test's
// (docs/testing-secret-store.md): CI installs the pinned release and sets
// RASPUTIN_SECRETSTORE_FUNCTIONAL=required, so a missing binary fails the
// backend job instead of skipping.
const (
	binEnv    = "RASPUTIN_SECRETSTORE_BIN"
	switchEnv = "RASPUTIN_SECRETSTORE_FUNCTIONAL"
)

// The values the functional test writes. Each is unique, so TC-761-25 can
// search for both.
const (
	funcValue1 = "sentinel-functional-value-one-5b1e"
	funcValue2 = "sentinel-functional-value-two-9c4d"
)

// TC-761-22 to TC-761-25: the secrets service on the real chain (the
// production client, a real Monitor and ObservedStore, the login session, the
// repository and the service) against the pinned OpenBao, logged in as the
// rasputin-api role bound to the shipped policy text.
func TestService_AgainstTheRealStore(t *testing.T) {
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return
	}
	apiPolicy, err := storepolicy.Text(storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	log, rec := logkittest.New()
	logger := slog.New(slog.NewMultiHandler(log.Handler(), slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug})))
	h, err := secretstoretest.New(secretstoretest.Config{
		BinaryPath: bin, TempParent: t.TempDir(), Logger: logger, Now: time.Now, Rand: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.StartWith(t.Context(), secretstoretest.Bootstrap{Mount: storepolicy.Mount, Roles: []secretstoretest.Role{
		{Name: storepolicy.APIPolicy, Policy: storepolicy.APIPolicy, PolicyText: apiPolicy},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// t.Context() is cancelled before Cleanup runs; Background lets the store
	// stop cleanly.
	t.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			t.Errorf("cleanup Close: %v", err)
		}
	})

	sess := realSession(t, s, logger)
	repo, err := secrets.NewRepository(sess)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := secrets.NewService(secrets.Deps{Repo: repo, Apps: fakeApps{nodes: map[string]string{appX: nodeN}}, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	ref := appRef(t, appX, "db-pass")
	p, err := secretstore.NewKVPath(storepolicy.Mount, ref.String())
	if err != nil {
		t.Fatal(err)
	}
	deploy := secrets.DeployActor(appX, nodeN)
	operator := secrets.OperatorActor("u1")
	var errs []error
	keep := func(err error) error {
		if err != nil {
			errs = append(errs, err)
		}
		return err
	}
	readAs := func(t *testing.T, want string, version int) {
		t.Helper()
		got, err := svc.Read(t.Context(), deploy, ref)
		if keep(err) != nil {
			t.Fatalf("deploy Read: %v", err)
		}
		defer got.Value.Destroy()
		if string(got.Value.Reveal()) != want || got.Version != version {
			t.Fatalf("deploy Read = version %d with %d bytes, want version %d with the value written", got.Version, got.Value.Len(), version)
		}
	}

	t.Run("TC-761-22 deploy create, read, create again", func(t *testing.T) {
		if v, err := svc.Create(t.Context(), deploy, ref, secret.New([]byte(funcValue1))); keep(err) != nil || v != 1 {
			t.Fatalf("Create = %d, %v; want version 1", v, err)
		}
		readAs(t, funcValue1, 1)
		if _, err := svc.Create(t.Context(), deploy, ref, secret.New([]byte(funcValue2))); !errors.Is(keep(err), secrets.ErrExists) {
			t.Fatalf("second Create = %v, want ErrExists", err)
		}
	})

	t.Run("TC-761-23 operator replace", func(t *testing.T) {
		if v, err := svc.Replace(t.Context(), operator, ref, secret.New([]byte(funcValue2))); keep(err) != nil || v != 2 {
			t.Fatalf("Replace = %d, %v; want version 2", v, err)
		}
		readAs(t, funcValue2, 2)
	})

	t.Run("TC-761-24 delete removes every version (T62)", func(t *testing.T) {
		if err := svc.Delete(t.Context(), operator, ref); keep(err) != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := svc.Read(t.Context(), deploy, ref); !errors.Is(keep(err), secretstore.ErrNotFound) {
			t.Errorf("service Read after Delete = %v, want ErrNotFound", err)
		}
		for _, version := range []int{1, 2} {
			kv, err := sess.Read(t.Context(), p, version)
			kv.Destroy()
			if !errors.Is(keep(err), secretstore.ErrNotFound) {
				t.Errorf("session Read of version %d after Delete = %v, want ErrNotFound", version, err)
			}
		}
		if _, err := sess.Versions(t.Context(), p); !errors.Is(keep(err), secretstore.ErrNotFound) {
			t.Errorf("Versions after Delete = %v, want ErrNotFound", err)
		}
		if err := svc.Delete(t.Context(), operator, ref); keep(err) != nil {
			t.Errorf("second Delete = %v, want nil", err)
		}
		if v, err := svc.Create(t.Context(), operator, ref, secret.New([]byte(funcValue1))); keep(err) != nil || v != 1 {
			t.Errorf("Create after Delete = %d, %v; want version 1", v, err)
		}
	})

	t.Run("TC-761-25 no value in the api's logs or errors", func(t *testing.T) {
		if len(errs) == 0 {
			t.Fatal("no error was collected, so the scan would read nothing")
		}
		text := rec.Text()
		if len(rec.Records()) == 0 {
			t.Fatal("no log record was captured, so the scan would read nothing")
		}
		for _, v := range []string{funcValue1, funcValue2} {
			if strings.Contains(text, v) {
				t.Errorf("a written value reached a log record")
			}
			for _, err := range errs {
				if strings.Contains(err.Error(), v) {
					t.Errorf("a written value reached an error: %v", err)
				}
			}
		}
	})
}

// realSession is the api's login session over the production client, a real
// readiness Monitor and its ObservedStore, for the rasputin-api role.
func realSession(t *testing.T, s *secretstoretest.Store, logger *slog.Logger) *storesession.Session {
	t.Helper()
	tc, err := s.ClientTLSFor(storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	client, err := secretstore.New(secretstore.Config{Addr: u, TLS: tc, CallTimeout: 10 * time.Second, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	monitor, err := storestate.New(storestate.Deps{
		Store: client, Now: time.Now, Log: logger,
		JobRunning: func(context.Context, string) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := storestate.NewObservedStore(client, monitor)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := storesession.New(storesession.Config{
		Role: storepolicy.APIPolicy, Login: client, Store: observed, Observer: monitor, Log: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}
