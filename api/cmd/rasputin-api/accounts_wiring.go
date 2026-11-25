package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	apipkg "github.com/geekdojo/rasputin-control-plane/api/internal/api"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
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
// fresh-sign-in action and its job. Identity 4.8 (#990) adds the first-run
// claim's first account, the waiting count, the in-use email check, and the
// designated-role grant with its observer, over the one Designations main
// opened before the console sessions. Identity 4.12 (#994) adds every
// account change: the request seam, the fresh-sign-in action of the
// fresh-gated kinds, and their workflows, all under the one accounts lock;
// and the observer as a sink of the sign-in history drain.

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
	console accounts.RevokeConsole
	moved   *auth.Store
	// kinds is the kind table, the reset's dry run; runner submits the
	// reset; listDir holds the password deny list (#992).
	kinds   accounts.ResetAuthorizer
	runner  accountsRunner
	listDir string
	// designations is main's one Designations (#990); markers is the one
	// second-step marker writer (markerWriter).
	designations *accounts.Designations
	markers      *markers.Writer
	// lock is the one accounts lock, main's, which the marker writer's drain
	// sink holds too (#994).
	lock sync.Locker
	log  *slog.Logger
}

// accountsRunner is the job runner as the accounts submit to it
// (*jobs.Runner): a person's job, and the system's designated-role grant.
type accountsRunner interface {
	accounts.Submitter
	accounts.GrantSubmitter
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
	// users is the in-use email check the door reads; first names the
	// first-run claim's account; waiting is the count; observer submits the
	// grant, granter is its job (#990).
	users    *accounts.Users
	first    *accounts.FirstAccount
	waiting  *accounts.Waiting
	observer *accounts.Observer
	granter  *accounts.Granter
	// requests decides every account change; freshAction submits a
	// fresh-gated one after the fresh sign-in; changes are their
	// workflows (#994).
	requests    *accounts.Requests
	freshAction *accounts.FreshAction
	changes     *accounts.Changes
	// grantWaiting is the one-action grant of a waiting entry; lock is the
	// one accounts lock and facts the app-access fact, which the move
	// shares (#1004).
	grantWaiting jobs.Workflow
	lock         sync.Locker
	facts        accessFacts
	// checker is the password policy, which the move's bridge checks a
	// first password against too (#1005).
	checker *pwpolicy.Checker
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
		d.designations == nil || d.markers == nil || d.lock == nil || d.dbPath == "" || d.listDir == "" {
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
	// The one accounts lock: the guard, the revoker, the grant and the marker
	// writer share it.
	lock := d.lock
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
	redesignator, err := accounts.NewRedesignator(accounts.RedesignatorDeps{Facts: roleAccounts, Designations: d.designations, Users: users, Lock: lock})
	if err != nil {
		return accountsWiring{}, err
	}
	reset, err := accounts.ResetPasswordWorkflow(accounts.ResetDeps{Users: users, Held: held, Checker: checker, Revoker: rev,
		Redesignate: redesignator, Lock: lock, Log: d.log, StepTimeout: accountsStepTimeout})
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
	first, err := accounts.NewFirstAccount(users)
	if err != nil {
		return accountsWiring{}, err
	}
	waiting, err := accounts.NewWaiting(users, d.designations)
	if err != nil {
		return accountsWiring{}, err
	}
	granter, err := accounts.NewGranter(accounts.GranterDeps{
		Designations: d.designations, Facts: roleAccounts, Markers: d.markers, Sessions: ender, Roles: users, Users: users,
		Access: access, Console: d.console, Admins: roleAccounts, Lock: lock, Log: d.log, StepTimeout: accountsStepTimeout,
	})
	if err != nil {
		return accountsWiring{}, err
	}
	observer, err := accounts.NewObserver(accounts.ObserverDeps{Designations: d.designations, Facts: roleAccounts, Runner: d.runner, Log: d.log})
	if err != nil {
		return accountsWiring{}, err
	}
	fresh := accounts.NewFresh()
	changes, err := accounts.NewChanges(accounts.ChangesDeps{
		Guard: guard, Users: users, Access: access, Sessions: ender, Markers: d.markers, Designations: d.designations,
		Facts: roleAccounts, Revoker: rev, Removed: removed, Held: held, Fresh: fresh, Lock: lock, Log: d.log,
		StepTimeout: accountsStepTimeout,
	})
	if err != nil {
		return accountsWiring{}, err
	}
	requests, err := accounts.NewRequests(accounts.RequestsDeps{Authorizer: d.kinds, Runner: d.runner, Held: held, Facts: roleAccounts, Log: d.log})
	if err != nil {
		return accountsWiring{}, err
	}
	freshAction, err := accounts.NewFreshAction(d.runner, fresh)
	if err != nil {
		return accountsWiring{}, err
	}
	grantWaiting, err := changes.GrantWaitingWorkflow(d.designations)
	if err != nil {
		return accountsWiring{}, err
	}
	return accountsWiring{revoker: rev, access: access, removed: removed, sessions: ender,
		resetter: resetter, resetAction: action, reset: reset,
		users: users, first: first, waiting: waiting, observer: observer, granter: granter,
		requests: requests, freshAction: freshAction, changes: changes,
		grantWaiting: grantWaiting, lock: lock, facts: facts, checker: checker}, nil
}

// register registers identity.revoke, accounts.reset_password,
// accounts.grant_designated_role and every account change's workflow,
// under keycloak only.
func (w accountsWiring) register(r interface{ Register(jobs.Workflow) }) {
	if w.revoker != nil {
		r.Register(w.revoker.Workflow())
		r.Register(w.reset)
		r.Register(w.granter.Workflow())
		for _, wf := range w.changes.Workflows() {
			r.Register(wf)
		}
		r.Register(w.grantWaiting)
	}
}

// installRequests gives the api the account changes, under keycloak only.
func (w accountsWiring) installRequests(srv interface{ SetAccountRequests(apipkg.AccountRequester) }) {
	if w.requests != nil {
		srv.SetAccountRequests(w.requests)
	}
}

// userSinks adds the designation observer to the drain's user sinks
// (F-994-01), under keycloak only.
func (w accountsWiring) userSinks(sinks convergeSinks) convergeSinks {
	if w.observer != nil {
		sinks.user = append(append([]events.UserSink(nil), sinks.user...), w.observer)
	}
	return sinks
}

// doorWaiting, doorEmails and apiWaiting are the count and the in-use email
// check as the door and the api read them; nil outside keycloak, so the
// door builds none and the waiting route answers unwired.
func (w accountsWiring) doorWaiting() policy.Waiting {
	if w.waiting == nil {
		return nil
	}
	return w.waiting
}

func (w accountsWiring) doorEmails() policy.Emails {
	if w.users == nil {
		return nil
	}
	return w.users
}

// installWaiting gives the api the count, under keycloak only.
func (w accountsWiring) installWaiting(srv interface{ SetWaiting(apipkg.WaitingCounter) }) {
	if w.waiting != nil {
		srv.SetWaiting(w.waiting)
	}
}

// actions are the fresh-sign-in actions the accounts own, by kind: the
// reset's and every fresh-gated account change's; none outside keycloak.
func (w accountsWiring) actions() map[string]auth.Action {
	if w.resetAction == nil {
		return nil
	}
	out := map[string]auth.Action{accounts.ResetKind: w.resetAction}
	for _, k := range accounts.FreshKinds {
		out[k] = w.freshAction
	}
	return out
}

// alerts is the removed-name list's warning; none outside keycloak.
func (w accountsWiring) alerts(ctx context.Context, now time.Time) []proto.Alert {
	if w.removed == nil {
		return nil
	}
	return w.removed.Alerts(ctx, now)
}

// claimer and observer are the first account and the designation observer
// as the console's sign-in takes them; nil outside keycloak, where no
// sign-in is built.
func (w accountsWiring) claimer() auth.Claimer {
	if w.first == nil {
		return nil
	}
	return w.first
}

func (w accountsWiring) signInObserver() auth.Observer {
	if w.observer == nil {
		return nil
	}
	return w.observer
}
