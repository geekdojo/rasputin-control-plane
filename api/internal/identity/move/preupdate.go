package move

import (
	"context"
	"errors"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
)

// The move's local facts as the bridge and the pre-update session read them
// (geekdojo/geekdojo-brain#1005): auth.MovedAccounts.

// AccountRows is the move's record as Accounts reads it (*Store).
type AccountRows interface {
	Account(ctx context.Context, handle []byte) (Row, bool, error)
	Rows(ctx context.Context) ([]Row, error)
	PasswordSet(ctx context.Context, sub string) (bool, error)
}

// OldCredentials reads an old user with its passkeys (*auth.Store).
type OldCredentials interface {
	GetUserByID(ctx context.Context, id []byte) (*auth.User, error)
}

// DesignationReader reads a designation (*accounts.Designations).
type DesignationReader interface {
	Get(ctx context.Context, sub string) (accounts.Designation, bool, error)
}

// PendingMove is whether the move has yet to run (*State).
type PendingMove interface {
	Pending(ctx context.Context) (bool, error)
}

// Accounts is auth.MovedAccounts over the move's record, its password
// facts, the old passkeys and the designations. Every read error is
// returned, never read as a negative (ERR-CLOSED).
type Accounts struct {
	rows         AccountRows
	state        PendingMove
	old          OldCredentials
	designations DesignationReader
}

var _ auth.MovedAccounts = (*Accounts)(nil)

// NewAccounts returns the Accounts. It refuses a nil collaborator and does
// no I/O.
func NewAccounts(rows AccountRows, state PendingMove, old OldCredentials, designations DesignationReader) (*Accounts, error) {
	if rows == nil || state == nil || old == nil || designations == nil {
		return nil, errors.New("move: NewAccounts: a collaborator is nil")
	}
	return &Accounts{rows: rows, state: state, old: old, designations: designations}, nil
}

// Account is the moved account of the old user handle, and false without a
// move row. It is Designated while the account holds a designation; its
// Roles are admin while that designation is the move's administrator one,
// and none otherwise, such as a waiting entry (C25).
func (a *Accounts) Account(ctx context.Context, handle []byte) (auth.MovedAccount, bool, error) {
	r, ok, err := a.rows.Account(ctx, handle)
	if err != nil || !ok {
		return auth.MovedAccount{}, false, err
	}
	set, err := a.rows.PasswordSet(ctx, r.AccountID)
	if err != nil {
		return auth.MovedAccount{}, false, err
	}
	x, designated, err := a.designations.Get(ctx, r.AccountID)
	if err != nil {
		return auth.MovedAccount{}, false, fmt.Errorf("move: read the designation: %w", err)
	}
	m := auth.MovedAccount{Sub: r.AccountID, Name: r.NewName, OldName: r.OldName, Designated: designated, Roles: []string{},
		NeedsPassword: !set}
	if designated && x.Reason == accounts.ReasonMoved && x.ConsoleRole == string(authz.Admin) {
		m.Roles = []string{string(authz.Admin)}
	}
	return m, true, nil
}

// Offered reports whether /login offers the bridge: while the move is
// still pending (its person then gets not_moved, F-1005-04), or while some
// moved account has no password fact and its old user still holds a
// passkey.
func (a *Accounts) Offered(ctx context.Context) (bool, error) {
	pending, err := a.state.Pending(ctx)
	if err != nil || pending {
		return pending, err
	}
	rows, err := a.rows.Rows(ctx)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		set, err := a.rows.PasswordSet(ctx, r.AccountID)
		if err != nil {
			return false, err
		}
		if set {
			continue
		}
		u, err := a.old.GetUserByID(ctx, r.Handle)
		if err != nil {
			return false, fmt.Errorf("move: read an old user: %w", err)
		}
		if u != nil && len(u.WebAuthnCredentials()) > 0 {
			return true, nil
		}
	}
	return false, nil
}
