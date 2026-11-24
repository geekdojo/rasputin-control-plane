package accounts

import (
	"context"
	"errors"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
)

// RoleAccounts is authz.RoleAccounts over Users: what the guard reads to
// decide a disable or a delete. Facts carries the subject, the console
// roles and the enabled state only; the designation facts are Identity
// 4.12's (geekdojo/geekdojo-brain#994).
type RoleAccounts struct{ users *Users }

var _ authz.RoleAccounts = RoleAccounts{}

// NewRoleAccounts returns RoleAccounts over users.
func NewRoleAccounts(users *Users) (RoleAccounts, error) {
	if users == nil {
		return RoleAccounts{}, errors.New("accounts: NewRoleAccounts: users is nil")
	}
	return RoleAccounts{users: users}, nil
}

// Facts reads sub's facts, or authz.ErrNoAccount for an account that does
// not exist.
func (a RoleAccounts) Facts(ctx context.Context, sub string) (authz.AccountFacts, error) {
	if sub == "" {
		return authz.AccountFacts{}, authz.ErrNoAccount
	}
	p, err := a.users.Read(ctx, sub)
	if errors.Is(err, idclient.ErrNotFound) {
		return authz.AccountFacts{}, authz.ErrNoAccount
	}
	if err != nil {
		return authz.AccountFacts{}, err
	}
	roles, err := a.users.ConsoleRoles(ctx, sub)
	if err != nil {
		return authz.AccountFacts{}, fmt.Errorf("accounts: facts: %w", err)
	}
	return authz.AccountFacts{Sub: sub, Roles: roles, Enabled: p.Enabled}, nil
}

// EnabledAdmins counts the enabled administrators.
func (a RoleAccounts) EnabledAdmins(ctx context.Context) (int, error) {
	return a.users.EnabledAdmins(ctx)
}
