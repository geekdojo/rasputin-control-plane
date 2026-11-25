package accounts

import (
	"context"
	"errors"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
)

// typeRecoveryCodes is Keycloak 26.8.2's recovery-codes credential type.
const typeRecoveryCodes = "recovery-authn-codes"

// RoleAccounts is authz.RoleAccounts over Users: what the guard reads to
// decide a disable or a delete, and what the designated-role grant reads to
// decide C29. Facts carries the subject, the sign-in name, the console
// roles, the enabled state, and the designation facts: a second step
// (markers.IsSecondStep), recovery codes and a pending required action
// (geekdojo/geekdojo-brain#990), and the app access and network grants
// the privileged levels are read from (geekdojo/geekdojo-brain#994).
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
	creds, err := a.users.Credentials(ctx, sub)
	if err != nil {
		return authz.AccountFacts{}, fmt.Errorf("accounts: facts: %w", err)
	}
	f := authz.AccountFacts{Sub: sub, Username: p.Username, Roles: roles, Enabled: p.Enabled,
		RequiredActionPending: len(p.RequiredActions) > 0, AppRole: string(p.AppRole), Network: p.Network}
	for _, c := range creds {
		f.HoldsSecondStep = f.HoldsSecondStep || markers.IsSecondStep(c)
		f.HoldsRecoveryCodes = f.HoldsRecoveryCodes || c == typeRecoveryCodes
	}
	return f, nil
}

// EnabledAdmins counts the enabled administrators.
func (a RoleAccounts) EnabledAdmins(ctx context.Context) (int, error) {
	return a.users.EnabledAdmins(ctx)
}
