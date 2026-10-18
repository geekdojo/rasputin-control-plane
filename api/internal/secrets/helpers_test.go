package secrets_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// sentinel is the value the service tests write. TC-761-16 searches every
// captured record and error string for it.
const sentinel = "sentinel-secret-value-7f3a9c"

// nodeN and nodeM are target nodes.
const (
	nodeN = "node-n"
	nodeM = "node-m"
)

// rig is a Service over a recording repository, with its log recorder and
// every error the test saw.
type rig struct {
	t    *testing.T
	svc  *secrets.Service
	repo *fakeRepo
	rec  *logkittest.Recorder
	errs []error
}

// newRig builds a Service over repo, with appX and appY existing (target
// nodeN) unless apps says otherwise.
func newRig(t *testing.T, repo secrets.Repository, apps secrets.AppTargets) *rig {
	t.Helper()
	if apps == nil {
		apps = fakeApps{nodes: map[string]string{appX: nodeN, appY: nodeN}}
	}
	log, rec := logkittest.New()
	fr := &fakeRepo{inner: repo}
	svc, err := secrets.NewService(secrets.Deps{Repo: fr, Apps: apps, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, svc: svc, repo: fr, rec: rec}
}

// keep records err for the redaction scan and returns it.
func (r *rig) keep(err error) error {
	if err != nil {
		r.errs = append(r.errs, err)
	}
	return err
}

// assertNoSentinel is TC-761-16 for one test: the sentinel is in no captured
// record and no error string.
func (r *rig) assertNoSentinel() {
	r.t.Helper()
	if strings.Contains(r.rec.Text(), sentinel) {
		r.t.Error("the sentinel value reached a log record")
	}
	for _, err := range r.errs {
		if strings.Contains(err.Error(), sentinel) {
			r.t.Errorf("the sentinel value reached an error: %v", err)
		}
	}
}

// nopObserver discards the session's login outcomes.
type nopObserver struct{}

func (nopObserver) ObserveAudited(context.Context, error) {}

// sessionOver is the real login session over a store that is also its login
// (Mock or Disabled), logging to a logger of its own so the service's records
// are the only ones the rig sees.
func sessionOver(t *testing.T, s interface {
	storesession.Login
	storesession.Store
}) *storesession.Session {
	t.Helper()
	sess, err := storesession.New(storesession.Config{
		Role: "rasputin-api", Login: s, Store: s, Observer: nopObserver{},
		Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

// mockRepo is the real repository over a session over a Mock.
func mockRepo(t *testing.T) (*secrets.KVRepository, *secretstore.Mock) {
	t.Helper()
	m := secretstore.NewMock(time.Now)
	repo, err := secrets.NewRepository(sessionOver(t, m))
	if err != nil {
		t.Fatal(err)
	}
	return repo, m
}

// mockPath is r's path in the Mock.
func mockPath(t *testing.T, r secrets.Ref) secretstore.KVPath {
	t.Helper()
	p, err := secretstore.NewKVPath("rasputin-secrets", r.String())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// readMock is the Mock's value of p at version, and its version.
func readMock(t *testing.T, m *secretstore.Mock, p secretstore.KVPath, version int) (string, int, error) {
	t.Helper()
	kv, err := m.Read(t.Context(), secret.Value{}, p, version)
	if err != nil {
		return "", 0, err
	}
	defer kv.Destroy()
	return string(kv.Data["value"].Reveal()), kv.Version, nil
}

// attrs is every field of rec as text.
func attrs(rec slog.Record) map[string]string {
	out := map[string]string{}
	rec.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value.Resolve().String()
		return true
	})
	return out
}
