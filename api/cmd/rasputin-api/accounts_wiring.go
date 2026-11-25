package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/pwpolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/sessions"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The accounts' wiring (geekdojo/geekdojo-brain#991, Identity 4.9): the
// identity.revoke job, the app-access grant, and the removed-name list the
// home door's registration filter reads, under keycloak only, as
// identity.recover_admin is. Identity 4.10 (#992) adds the administrator's
// password reset: its policy pre-check, its held passwords, its check, its
// fresh-sign-in action and its job.

// accountsStepTimeout bounds one identity.revoke step: it marks work gone
// far outside normal and decides nothing else.
const accountsStepTimeout = 5 * time.Minute

// removedList is the removed-name list as the door and the alerts read it:
// *removednames.Store, or removednames.Unavailable when it didn't open.
type removedList interface {
	Removed(ctx context.Context, name, email string) (bool, error)
	Record(ctx context.Context, name, email string) error
	Alerts(ctx context.Context, now time.Time) []proto.Alert
}

// accessFacts is the app-access fact: removednames.AccessFacts, or
// removednames.UnavailableFacts.
type accessFacts interface {
	Record(ctx context.Context, sub string) error
	Held(ctx context.Context, sub string) (bool, error)
}

// accountsDeps are wireAccounts' collaborators.
type accountsDeps struct {
	mode    string
	admin   accounts.Admin
	dbPath  string
	mac     removednames.MAC
	console accounts.ConsoleSessions
	moved   *auth.Store
	// kinds is the kind table, the reset's dry run; runner submits the
	// reset; listDir holds the password deny list (#992).
	kinds   accounts.ResetAuthorizer
	runner  accounts.Submitter
	listDir string
	log     *slog.Logger
}

// accountsWiring is what wireAccounts built: nothing outside keycloak.
type accountsWiring struct {
	revoker *accounts.Revoker
	// access is the app-access grant, for Identity 4.8's and 4.12's jobs.
	access  *accounts.Access
	removed removedList
	// sessions is #991's session ender, which the reset returns use too.
	sessions sessions.Ender
	// resetter decides an administrator's reset request; resetAction
	// submits it after the fresh sign-in; reset is its job (#992).
	resetter    *accounts.Resetter
	resetAction *accounts.ResetAction
	reset       jobs.Workflow
}

// wireAccounts builds the accounts under keycloak. A removed-name list that
// doesn't open is one ERROR record, and Unavailable stands in: sign-up
// pauses with its alert, a held-access delete fails before it deletes, and
// the api starts. Any other error is a programming error, fatal to main.
func wireAccounts(ctx context.Context, d accountsDeps) (accountsWiring, error) {
	if d.mode != identityModeKeycloak {
		return accountsWiring{}, nil
	}
	if d.admin == nil || d.mac == nil || d.console == nil || d.moved == nil || d.kinds == nil || d.runner == nil || d.log == nil ||
		d.dbPath == "" || d.listDir == "" {
		return accountsWiring{}, errors.New("accounts: a collaborator is nil under keycloak")
	}
	var removed removedList
	var facts accessFacts
	store, err := removednames.OpenStore(ctx, d.dbPath, d.mac, d.log)
	if err != nil {
		d.log.ErrorContext(ctx, "The removed-name list didn't open, so sign-up is paused.",
			"configfault", false, "component", "accounts", "event", "accounts.removed_names.open_failed", "err", err.Error())
		u := removednames.Unavailable{Err: err}
		removed, facts = u, u.Facts()
	} else {
		removed, facts = store, store.Facts()
	}
	users, err := accounts.NewUsers(accounts.UsersDeps{Admin: d.admin, Realm: identityRealm, ConsoleClient: flows.ConsoleClient})
	if err != nil {
		return accountsWiring{}, err
	}
	roleAccounts, err := accounts.NewRoleAccounts(users)
	if err != nil {
		return accountsWiring{}, err
	}
	// The one accounts lock: the guard, the revoker and the grant share it.
	lock := &sync.Mutex{}
	guard, err := authz.NewRoleGuard(roleAccounts, lock)
	if err != nil {
		return accountsWiring{}, err
	}
	ender := sessions.Ender{Admin: d.admin}
	rev, err := accounts.NewRevoker(accounts.RevokerDeps{
		Sessions: ender, Users: users, Guard: guard, Lock: lock, Console: d.console, Moved: d.moved,
		Removed: removed, Facts: facts,
		// Identity 8.2, 7.5 and 9.5 each replace one of these.
		Devices: accounts.NoHook{What: "devices"}, Apps: accounts.NoHook{What: "apps"}, Network: accounts.NoHook{What: "network"},
		Log: d.log, StepTimeout: accountsStepTimeout,
	})
	if err != nil {
		return accountsWiring{}, err
	}
	access, err := accounts.NewAccess(accounts.AccessDeps{Users: users, Sessions: ender, Facts: facts, Lock: lock})
	if err != nil {
		return accountsWiring{}, err
	}
	checker, err := pwpolicy.New(d.listDir, flows.PasswordPolicy)
	if err != nil {
		return accountsWiring{}, err
	}
	held := accounts.NewHeld()
	reset, err := accounts.ResetPasswordWorkflow(accounts.ResetDeps{Users: users, Held: held, Checker: checker, Revoker: rev,
		Log: d.log, StepTimeout: accountsStepTimeout})
	if err != nil {
		return accountsWiring{}, err
	}
	resetter, err := accounts.NewResetter(accounts.ResetterDeps{Authorizer: d.kinds, Users: users, Checker: checker, Log: d.log})
	if err != nil {
		return accountsWiring{}, err
	}
	action, err := accounts.NewResetAction(d.runner, held)
	if err != nil {
		return accountsWiring{}, err
	}
	return accountsWiring{revoker: rev, access: access, removed: removed, sessions: ender,
		resetter: resetter, resetAction: action, reset: reset}, nil
}

// register registers identity.revoke and accounts.reset_password, under
// keycloak only.
func (w accountsWiring) register(r interface{ Register(jobs.Workflow) }) {
	if w.revoker != nil {
		r.Register(w.revoker.Workflow())
		r.Register(w.reset)
	}
}

// actions are the fresh-sign-in actions the accounts own, by kind; none
// outside keycloak.
func (w accountsWiring) actions() map[string]auth.Action {
	if w.resetAction == nil {
		return nil
	}
	return map[string]auth.Action{accounts.ResetKind: w.resetAction}
}

// alerts is the removed-name list's warning; none outside keycloak.
func (w accountsWiring) alerts(ctx context.Context, now time.Time) []proto.Alert {
	if w.removed == nil {
		return nil
	}
	return w.removed.Alerts(ctx, now)
}
