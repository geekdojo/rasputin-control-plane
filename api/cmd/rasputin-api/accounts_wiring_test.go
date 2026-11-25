package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

type refusingAdmin struct{}

func (refusingAdmin) Admin(context.Context, string, string, any, any) (idclient.Response, error) {
	return idclient.Response{}, idclient.ErrDisabled
}

type nullConsole struct{}

func (nullConsole) EndBySub(context.Context, string) (int64, error) { return 0, nil }

type registered struct{ kinds map[string]jobs.Workflow }

func (r *registered) Register(w jobs.Workflow) { r.kinds[w.Kind] = w }

func accountsFixture(t *testing.T, dbPath string) (accountsDeps, *logkittest.Recorder) {
	t.Helper()
	mac, err := credmac.New(secret.New([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatal(err)
	}
	store, err := auth.OpenStore(t.Context(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log, rec := logkittest.New()
	kinds, err := authz.NewKindPolicy(noAppFacts{})
	if err != nil {
		t.Fatal(err)
	}
	return accountsDeps{mode: identityModeKeycloak, admin: refusingAdmin{}, dbPath: dbPath, mac: mac,
		console: nullConsole{}, moved: store, kinds: kinds, runner: refusingRunner{}, listDir: t.TempDir(), log: log}, rec
}

type noAppFacts struct{}

func (noAppFacts) AppFacts(context.Context, string, string) (authz.AppFacts, error) {
	return authz.AppFacts{}, authz.ErrNoApp
}

// refusingRunner is a runner no case here submits to.
type refusingRunner struct{}

func (refusingRunner) SubmitFor(context.Context, authz.Submitter, string, any, func(string) error) (*jobs.Job, error) {
	return nil, errors.New("not here")
}

// Outside keycloak nothing is built, nothing registers and no alert rises;
// under keycloak identity.revoke registers as a System kind, and the list
// opens with no record and no alert.
func TestWireAccounts_ByMode(t *testing.T) {
	d, rec := accountsFixture(t, filepath.Join(t.TempDir(), "rasputin.db"))
	for _, mode := range []string{identityModeOff, identityModeMock} {
		d.mode = mode
		w, err := wireAccounts(t.Context(), d)
		r := &registered{kinds: map[string]jobs.Workflow{}}
		w.register(r)
		if err != nil || len(r.kinds) != 0 || w.alerts(t.Context(), time.Now()) != nil {
			t.Errorf("mode %s: %v, %v", mode, err, r.kinds)
		}
	}
	d.mode = identityModeKeycloak
	w, err := wireAccounts(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	r := &registered{kinds: map[string]jobs.Workflow{}}
	w.register(r)
	if wf, ok := r.kinds[accounts.Kind]; !ok || !wf.System {
		t.Errorf("identity.revoke registered %v, System %v", ok, wf.System)
	}
	// #992: the reset registers, its action is the fresh sign-in's, and
	// its check and #991's ender are there for the server and the returns.
	if wf, ok := r.kinds[accounts.ResetKind]; !ok || wf.Steps[0].Name != accounts.StepSetTemporary || wf.OnTerminal == nil {
		t.Errorf("accounts.reset_password registered %v", ok)
	}
	if w.actions()[accounts.ResetKind] == nil || w.resetter == nil || w.sessions.Admin == nil {
		t.Error("the reset's action, check or the session ender is missing")
	}
	if w.access == nil {
		t.Error("no access grant")
	}
	if a := w.alerts(t.Context(), time.Now()); len(a) != 0 {
		t.Errorf("alerts %+v", a)
	}
	if len(rec.Records()) != 0 {
		t.Errorf("records:\n%s", rec.Text())
	}
	d.moved = nil
	if _, err := wireAccounts(t.Context(), d); err == nil {
		t.Error("a nil collaborator was accepted")
	}
	off, _ := wireAccounts(t.Context(), accountsDeps{mode: identityModeOff})
	if off.actions() != nil {
		t.Error("actions outside keycloak")
	}
}

// A list that doesn't open is one ERROR record with configfault=false and
// component=accounts; Unavailable stands in, so the api starts, sign-up
// pauses and the warning rises.
func TestWireAccounts_ListThatDoesNotOpen(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	d, rec := accountsFixture(t, filepath.Join(notADir, "rasputin.db"))
	w, err := wireAccounts(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	errs := rec.Matching(slog.LevelError, "")
	if len(errs) != 1 {
		t.Fatalf("records:\n%s", rec.Text())
	}
	for k, want := range map[string]string{"configfault": "false", "component": "accounts"} {
		if v, _ := logkittest.Attr(errs[0], k); v != want {
			t.Errorf("%s = %q", k, v)
		}
	}
	if _, ok := w.removed.(removednames.Unavailable); !ok {
		t.Errorf("removed is %T, want Unavailable", w.removed)
	}
	if a := w.alerts(t.Context(), time.Now()); len(a) != 1 || a[0].ID != removednames.AlertID {
		t.Errorf("alerts %+v", a)
	}
	if w.revoker == nil {
		t.Error("no revoker")
	}
}
