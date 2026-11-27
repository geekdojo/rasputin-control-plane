package authz

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// Op is a change to an account's console role or to the account itself.
type Op int

// The changes the guard decides. The zero value is no change and is
// refused.
const (
	// OpSetRole sets the account's one console role, or no role.
	OpSetRole Op = iota + 1
	// OpDisable disables the account.
	OpDisable
	// OpDelete deletes the account.
	OpDelete
	// OpSetAppAccess sets the account's app access to RoleChange.AppRole:
	// user or admin (geekdojo/geekdojo-brain#994).
	OpSetAppAccess
	// OpSetNetwork sets the account's network grants to RoleChange.Network:
	// any of join, gear-read and gear-admin.
	OpSetNetwork
	// OpRemoveSecondSteps removes the account's second steps and demotes
	// it until it adds one again.
	OpRemoveSecondSteps
)

// RoleChange is one requested change: its target account's subject, the
// Op and, for OpSetRole, the new role. Role is empty for no role, because
// the fixed roles are a radio button (iam.md §9). AppRole is
// OpSetAppAccess's level and Network OpSetNetwork's grants. Fresh says the
// change arrived at a fresh sign-in's callback (C24): a change that raises
// privilege is refused without it.
type RoleChange struct {
	Target  string
	Op      Op
	Role    string
	AppRole string
	Network []string
	Fresh   bool
}

// AccountFacts are what the guard reads about one account.
type AccountFacts struct {
	Sub string
	// Name is the display name; Username the sign-in name, used in a
	// sentence when Name is empty.
	Name, Username string
	// Roles are the account's console roles.
	Roles   []string
	Enabled bool
	// HoldsSecondStep is a passkey, security key or authenticator app;
	// HoldsRecoveryCodes is saved recovery codes; RequiredActionPending is
	// a required action the account has not finished (C29).
	HoldsSecondStep, HoldsRecoveryCodes, RequiredActionPending bool
	// AppRole is the app access (rasputin_app_role): "", user or admin.
	// Network is the network grants (rasputin_network).
	AppRole string
	Network []string
}

// Kind is what a Decision does.
type Kind int

// The decisions. The zero value is no decision, which an error returns.
const (
	// Apply makes the change now.
	Apply Kind = iota + 1
	// Designate records the role as a designation that starts once the
	// account completes its setup (C29). The current role stays.
	Designate
)

// Decision is the guard's answer to a change it allows: what to do, the
// role it concerns, and for Designate the sentence for the administrator.
// Raises is RaisesPrivilege for the change on the facts read under the
// lock. Unnamed is Sentence naming "this person", for a record that must
// carry no name, such as a job's step outcome.
type Decision struct {
	Kind     Kind
	Role     string
	Sentence string
	Unnamed  string
	Raises   bool
}

// Refusal is a change the guard refuses: a stable code and the sentence
// the administrator reads.
type Refusal struct {
	Code     string
	Sentence string
}

// Error names the code only. The sentence is for the response.
func (r *Refusal) Error() string { return "authz: role change refused: " + r.Code }

// ErrNoAccount is what RoleAccounts.Facts returns for an account that does
// not exist.
var ErrNoAccount = errors.New("authz: no such account")

// RoleAccounts is what the guard reads accounts through. Identity 4.12
// (geekdojo/geekdojo-brain#994) implements it over the identity service.
type RoleAccounts interface {
	// Facts returns the account sub names, or ErrNoAccount.
	Facts(ctx context.Context, sub string) (AccountFacts, error)
	// EnabledAdmins counts the enabled accounts holding the admin role.
	EnabledAdmins(ctx context.Context) (int, error)
}

// RoleGuard decides role changes, disables and deletes (identity-authz.md
// §3.2) under the one accounts lock.
type RoleGuard struct {
	accounts RoleAccounts
	lock     sync.Locker
}

// NewRoleGuard returns a guard reading accounts through accounts and holding
// lock, the one lock that serializes every account change, while it decides
// and applies. It refuses a nil argument.
func NewRoleGuard(accounts RoleAccounts, lock sync.Locker) (*RoleGuard, error) {
	switch {
	case accounts == nil:
		return nil, errors.New("authz: NewRoleGuard: accounts is nil")
	case lock == nil:
		return nil, errors.New("authz: NewRoleGuard: lock is nil")
	}
	return &RoleGuard{accounts: accounts, lock: lock}, nil
}

// Change decides ch, asked for by the account actorSub, and runs apply with
// the Decision when the change is allowed. It holds the guard's lock while
// it reads the facts, decides and runs apply, so the facts it judged are
// still the facts when apply runs. The lock is not re-entrant: a caller
// must not hold it around Change, and apply must not take it.
//
// The actor's authority is read under the lock from the actor's own facts,
// never taken from the caller. A refused change returns a *Refusal and
// never runs apply. A read error or an apply error is returned wrapped,
// with a zero Decision.
func (g *RoleGuard) Change(ctx context.Context, actorSub string, ch RoleChange, apply func(context.Context, Decision) error) (Decision, error) {
	if apply == nil {
		return Decision{}, errors.New("authz: role change: apply is nil")
	}
	g.lock.Lock()
	defer g.lock.Unlock()
	d, err := g.decide(ctx, actorSub, ch)
	if err != nil {
		return Decision{}, err
	}
	if err := apply(ctx, d); err != nil {
		return Decision{}, fmt.Errorf("authz: role change: apply: %w", err)
	}
	return d, nil
}

func refuse(code, sentence string) *Refusal { return &Refusal{Code: code, Sentence: sentence} }

// ownRefusals are the refusals of a change to one's own account, by op.
var ownRefusals = map[Op]*Refusal{
	OpSetRole:           {Code: "own_role", Sentence: "You can't change your own role."},
	OpDisable:           {Code: "own_account_disable", Sentence: "You can't disable your own account."},
	OpDelete:            {Code: "own_account_delete", Sentence: "You can't delete your own account."},
	OpSetAppAccess:      {Code: "own_app_access", Sentence: "You can't change your own app access."},
	OpSetNetwork:        {Code: "own_network", Sentence: "You can't change your own network access."},
	OpRemoveSecondSteps: {Code: "own_second_steps", Sentence: "You can't remove your own second steps here."},
}

// decide is the guards, in order (identity-authz.md §9.1). Authorization is
// judged before any fact about the target is read, so a caller without iam
// learns nothing about it.
func (g *RoleGuard) decide(ctx context.Context, actorSub string, ch RoleChange) (Decision, error) {
	own, known := ownRefusals[ch.Op]
	if !known {
		return Decision{}, refuse("unknown_change", "That change isn't supported.")
	}
	if ch.Target == actorSub {
		return Decision{}, refuse(own.Code, own.Sentence)
	}
	actor, err := g.accounts.Facts(ctx, actorSub)
	switch {
	case errors.Is(err, ErrNoAccount):
		return Decision{}, notPermitted()
	case err != nil:
		return Decision{}, fmt.Errorf("authz: role change: read facts: %w", err)
	case !actor.Enabled || !For(Subject{Sub: actorSub, Roles: actor.Roles}).Has(IAM):
		return Decision{}, notPermitted()
	}
	if r := unknownValue(ch); r != nil {
		return Decision{}, r
	}
	target, err := g.accounts.Facts(ctx, ch.Target)
	switch {
	case errors.Is(err, ErrNoAccount):
		return Decision{}, refuse("no_account", "That account no longer exists.")
	case err != nil:
		return Decision{}, fmt.Errorf("authz: role change: read facts: %w", err)
	}
	if removesAdmin(target, ch) {
		n, err := g.accounts.EnabledAdmins(ctx)
		if err != nil {
			return Decision{}, fmt.Errorf("authz: role change: read facts: %w", err)
		}
		// With consistent facts nobody reaches this: the actor is an enabled
		// administrator other than the target. It stays as defence in depth.
		if n <= 1 {
			return Decision{}, refuse("last_admin", "Rasputin needs at least one administrator, so this one can't be removed.")
		}
	}
	raises := RaisesPrivilege(target, ch)
	switch {
	case raises && !ch.Fresh:
		return Decision{}, refuse(CodeFreshSignIn, "Giving a privileged role needs you to sign in again first. Start it again from Accounts.")
	case raises && !DesignationComplete(target):
		unnamed := target
		unnamed.Name, unnamed.Username = "", ""
		return Decision{Kind: Designate, Role: ch.Role, Sentence: designationSentence(target), Unnamed: designationSentence(unnamed), Raises: true}, nil
	}
	return Decision{Kind: Apply, Role: ch.Role, Raises: raises}, nil
}

// CodeFreshSignIn is the refusal of a change that raises privilege and did
// not arrive at a fresh sign-in's callback (C24).
const CodeFreshSignIn = "fresh_signin"

// unknownValue refuses a role, a level or a grant the change names that
// does not exist.
func unknownValue(ch RoleChange) *Refusal {
	switch ch.Op {
	case OpSetRole:
		if ch.Role != "" && !known(ch.Role) {
			return refuse("unknown_role", "That role doesn't exist.")
		}
	case OpSetAppAccess:
		if ch.AppRole != AppRoleUser && ch.AppRole != AppRoleAdmin {
			return refuse("unknown_access", "That level of app access doesn't exist.")
		}
	case OpSetNetwork:
		for _, g := range ch.Network {
			if !slices.Contains(NetworkGrants(), g) {
				return refuse("unknown_network", "That network access doesn't exist.")
			}
		}
	}
	return nil
}

func notPermitted() *Refusal {
	return refuse("not_permitted", "Only an administrator can change roles.")
}

// removesAdmin reports whether ch takes the admin role from an enabled
// administrator: a disable, a delete, removing the second steps (which
// demotes), or a role other than admin. App access and network grants
// leave the console role alone.
func removesAdmin(target AccountFacts, ch RoleChange) bool {
	if !target.Enabled || highest(target.Roles) != rank(string(Admin)) {
		return false
	}
	switch ch.Op {
	case OpSetRole:
		return ch.Role != string(Admin)
	case OpDisable, OpDelete, OpRemoveSecondSteps:
		return true
	}
	return false
}

// highest is the rank of the highest console role in roles.
func highest(roles []string) int {
	h := 0
	for _, r := range roles {
		h = max(h, rank(r))
	}
	return h
}

// DesignationComplete reports whether a privileged role can start now on
// the account f describes: it holds a second step and recovery codes and
// has no required action pending (C29). Identity 4.8's
// accounts.grant_designated_role (geekdojo/geekdojo-brain#990) and 4.12's
// app-administrator and gear-administrator grants decide on the same fact.
func DesignationComplete(f AccountFacts) bool {
	return f.HoldsSecondStep && f.HoldsRecoveryCodes && !f.RequiredActionPending
}

// designationSentence says what f must do before its role starts. A
// missing credential takes precedence over a pending action.
func designationSentence(f AccountFacts) string {
	name := f.Name
	if name == "" {
		name = f.Username
	}
	if name == "" {
		name = "this person"
	}
	switch {
	case !f.HoldsSecondStep && !f.HoldsRecoveryCodes:
		return "This role starts after " + name + " adds a passkey, security key or authenticator app and saves recovery codes at the next sign-in."
	case !f.HoldsSecondStep:
		return "This role starts after " + name + " adds a passkey, security key or authenticator app at the next sign-in."
	case !f.HoldsRecoveryCodes:
		return "This role starts after " + name + " saves recovery codes at the next sign-in."
	}
	return "This role starts after " + name + " finishes setting up their account at the next sign-in."
}
