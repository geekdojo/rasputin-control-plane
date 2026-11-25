package accounts

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// AccessUsers is the account calls Access makes (*Users).
type AccessUsers interface {
	Read(ctx context.Context, sub string) (Person, error)
	SetAppRole(ctx context.Context, sub string, level AppLevel) error
	AddOfflineAccess(ctx context.Context, sub string) (bool, error)
}

// FactRecorder records the app-access fact (removednames.AccessFacts).
type FactRecorder interface {
	Record(ctx context.Context, sub string) error
}

// AccessDeps are an Access's collaborators. NewAccess refuses a missing
// one.
type AccessDeps struct {
	Users    AccessUsers
	Sessions Sessions
	Facts    FactRecorder
	// Lock is the one accounts lock, held for the whole grant.
	Lock sync.Locker
}

// Access gives app access: the giving side of C10. Its callers are
// Identity 4.12's accounts.grant_access (geekdojo/geekdojo-brain#994) and
// Identity 4.8's accounts.grant_designated_role
// (geekdojo/geekdojo-brain#990).
type Access struct{ d AccessDeps }

// NewAccess checks d and returns an Access. It does no I/O.
func NewAccess(d AccessDeps) (*Access, error) {
	if d.Users == nil || d.Sessions == nil || d.Facts == nil || d.Lock == nil {
		return nil, errors.New("accounts: NewAccess: a collaborator is nil")
	}
	return &Access{d: d}, nil
}

// Grant gives sub app access at level, under the accounts lock from start
// to end, never calling the guard. In order:
//
//  1. It reads the current level.
//  2. When the level changes to admin, or an access already held changes
//     level (raising or lowering), it ends the identity sessions online
//     and then offline (C23; app-sso.md §7.1), so no session made at the
//     old level carries on. Giving user access to someone with none ends no
//     session.
//  3. It records the app-access fact, before access is given, so a crash
//     never leaves access without the fact.
//  4. It writes rasputin_app_role.
//  5. It gives the offline_access role, unless the account holds it.
//
// Any failure stops the grant there: nothing after a failed session end is
// written. Adding offline_access is a realm role change, so the console's
// role-change sink signs the person out of the console once.
func (a *Access) Grant(ctx context.Context, sub string, level AppLevel) error {
	a.d.Lock.Lock()
	defer a.d.Lock.Unlock()
	return a.grantLocked(ctx, sub, level)
}

// errEndSessions marks a grant that stopped because the identity sessions
// could not be ended, so nothing was written.
var errEndSessions = errors.New("accounts: end sessions")

// grantLocked is Grant for a caller that holds the accounts lock already:
// accounts.grant_access, inside the guard's apply (the lock is not
// re-entrant).
func (a *Access) grantLocked(ctx context.Context, sub string, level AppLevel) error {
	if level != AppUser && level != AppAdmin {
		return fmt.Errorf("accounts: grant access: unknown level %q", level)
	}
	p, err := a.d.Users.Read(ctx, sub)
	if err != nil {
		return fmt.Errorf("accounts: grant access: %w", err)
	}
	if p.AppRole != level && (level == AppAdmin || p.AppRole != "") {
		if err := a.d.Sessions.EndAll(ctx, sub); err != nil {
			return fmt.Errorf("accounts: grant access: %w: online: %w", errEndSessions, err)
		}
		if _, err := a.d.Sessions.EndOffline(ctx, sub); err != nil {
			return fmt.Errorf("accounts: grant access: %w: offline: %w", errEndSessions, err)
		}
	}
	if err := a.d.Facts.Record(ctx, sub); err != nil {
		return fmt.Errorf("accounts: grant access: %w", err)
	}
	if err := a.d.Users.SetAppRole(ctx, sub, level); err != nil {
		return fmt.Errorf("accounts: grant access: %w", err)
	}
	if _, err := a.d.Users.AddOfflineAccess(ctx, sub); err != nil {
		return fmt.Errorf("accounts: grant access: %w", err)
	}
	return nil
}
