package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	apipkg "github.com/geekdojo/rasputin-control-plane/api/internal/api"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
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

func (nullConsole) EndBySub(context.Context, string) (int64, error)               { return 0, nil }
func (nullConsole) EndBySubExcept(context.Context, string, string) (int64, error) { return 0, nil }

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
	designations, err := accounts.OpenDesignations(t.Context(), filepath.Join(t.TempDir(), "rasputin.db"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = designations.Close() })
	lock := &sync.Mutex{}
	mw, err := markers.New(markers.Deps{Admin: refusingAdmin{}, Realm: identityRealm,
		DoorOf: func(string) (flows.Door, bool) { return "", false }, Lock: lock, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return accountsDeps{mode: identityModeKeycloak, admin: refusingAdmin{}, dbPath: dbPath, mac: mac,
		console: nullConsole{}, moved: store, kinds: kinds, runner: refusingRunner{}, listDir: t.TempDir(),
		designations: designations, markers: mw, lock: lock, log: log}, rec
}

// waitingSink counts SetWaiting calls.
type waitingSink struct{ n int }

func (s *waitingSink) SetWaiting(apipkg.WaitingCounter) { s.n++ }

// store is a fresh auth store.
func store(t *testing.T) *auth.Store {
	t.Helper()
	st, err := auth.OpenStore(t.Context(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
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

func (refusingRunner) Submit(context.Context, string, any, string) (*jobs.Job, error) {
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
	// #994: the accounts are under main's one lock, the marker writer's.
	if w.lock != d.lock {
		t.Error("the accounts lock is not the one main handed over")
	}
	// TC-990-28: the designated-role grant registers as a System kind, and
	// the claim's first account, the count, the email check and the
	// observer are there for the sign-in, the door and the server.
	if wf, ok := r.kinds[accounts.GrantKind]; !ok || !wf.System || len(wf.Steps) != 3 {
		t.Errorf("accounts.grant_designated_role registered %v", ok)
	}
	if w.claimer() == nil || w.signInObserver() == nil || w.doorWaiting() == nil || w.doorEmails() == nil {
		t.Error("the first account, the observer, the count or the email check is missing")
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
	d.moved = store(t)
	lock := d.lock
	d.lock = nil
	if _, err := wireAccounts(t.Context(), d); err == nil {
		t.Error("no accounts lock was accepted under keycloak")
	}
	d.lock = lock
	d.designations = nil
	if _, err := wireAccounts(t.Context(), d); err == nil {
		t.Error("no designations was accepted under keycloak")
	}
	off, _ := wireAccounts(t.Context(), accountsDeps{mode: identityModeOff})
	if off.actions() != nil {
		t.Error("actions outside keycloak")
	}
	if off.claimer() != nil || off.signInObserver() != nil || off.doorWaiting() != nil || off.doorEmails() != nil {
		t.Error("the #990 collaborators exist outside keycloak")
	}
	srv := &waitingSink{}
	off.installWaiting(srv)
	w.installWaiting(srv)
	if srv.n != 1 {
		t.Errorf("SetWaiting called %d times, want once (keycloak only)", srv.n)
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

// requestsSink counts SetAccountRequests calls.
type requestsSink struct{ n int }

func (s *requestsSink) SetAccountRequests(apipkg.AccountRequester) { s.n++ }

// geekdojo/geekdojo-brain#994 (wiring part of TC-994-31): under keycloak
// every account change registers as a person's kind, each fresh-gated kind
// has the fresh action, the api gets the requests, and the observer joins
// the drain's user sinks; outside keycloak none of it.
func TestWireAccounts_TC994_AccountChanges(t *testing.T) {
	d, _ := accountsFixture(t, filepath.Join(t.TempDir(), "rasputin.db"))
	d.mode = identityModeOff
	off, err := wireAccounts(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	var none requestsSink
	off.installRequests(&none)
	if none.n != 0 || len(off.userSinks(convergeSinks{}).user) != 0 || off.actions() != nil {
		t.Error("outside keycloak the account changes were wired")
	}
	d.mode = identityModeKeycloak
	w, err := wireAccounts(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	r := &registered{kinds: map[string]jobs.Workflow{}}
	w.register(r)
	for _, k := range []string{accounts.KindSetRoles, accounts.KindGrantAccess, accounts.KindRevokeAccess, accounts.KindSetNetwork,
		accounts.KindDisable, accounts.KindEnable, accounts.KindDelete, accounts.KindDecline, accounts.KindUnlock,
		accounts.KindSignOut, accounts.KindSetEmail, accounts.KindConfirmEmail, accounts.KindSetDisplayName,
		accounts.KindRemoveSecondSteps, accounts.KindRemoveCredential, accounts.KindRenameCredential} {
		wf, ok := r.kinds[k]
		if !ok || wf.System || wf.OnTerminal == nil || !authz.Known(k) {
			t.Errorf("%s registered %v, System %v", k, ok, wf.System)
		}
	}
	for _, k := range accounts.FreshKinds {
		if w.actions()[k] == nil {
			t.Errorf("%s has no fresh-sign-in action", k)
		}
	}
	var got requestsSink
	w.installRequests(&got)
	if got.n != 1 {
		t.Errorf("SetAccountRequests called %d times", got.n)
	}
	if s := w.userSinks(convergeSinks{}); len(s.user) != 1 || s.user[0] != w.observer {
		t.Errorf("user sinks %v, want the observer", s.user)
	}
}
