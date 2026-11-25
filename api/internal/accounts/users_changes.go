package accounts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The account writes Identity 4.12's account changes make
// (geekdojo/geekdojo-brain#994). Each attribute write is read back
// (lifecycle.md §4, "one identity write, then a read-back"): an account
// that does not hold what was written is ErrNotKept.

// ErrNotKept is a write the identity service answered and did not keep.
var ErrNotKept = errors.New("accounts: the identity service did not keep the change")

// ErrNoEmail is confirm_email on an account with no email address.
var ErrNoEmail = errors.New("accounts: the account has no email address")

// readBack reads the account and returns ErrNotKept unless kept holds.
func (u *Users) readBack(ctx context.Context, sub string, kept func(Person) bool) error {
	p, err := u.Read(ctx, sub)
	if err != nil {
		return fmt.Errorf("accounts: read the change back: %w", err)
	}
	if !kept(p) {
		return ErrNotKept
	}
	return nil
}

// directConsoleRoles is the console roles the account holds directly, as
// role representations, and the console client's id.
func (u *Users) directConsoleRoles(ctx context.Context, sub string) ([]map[string]any, string, error) {
	id, err := u.consoleClientID(ctx)
	if err != nil {
		return nil, "", err
	}
	var roles []map[string]any
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, u.userPath(sub)+"/role-mappings/clients/"+url.PathEscape(id), nil, &roles); err != nil {
		return nil, "", fmt.Errorf("accounts: read the account's console roles: %w", err)
	}
	return roles, id, nil
}

// SetConsoleRole makes role the account's one console role, "" for none:
// every other console role it holds directly is removed, then role is
// given when it is not held. It reads the direct roles back.
func (u *Users) SetConsoleRole(ctx context.Context, sub, role string) error {
	if sub == "" {
		return errors.New("accounts: no account id")
	}
	if role != "" && !slices.Contains(authz.RoleNames(), role) {
		return fmt.Errorf("accounts: %q is not a console role", role)
	}
	held, id, err := u.directConsoleRoles(ctx, sub)
	if err != nil {
		return err
	}
	var drop []any
	has := false
	for _, r := range held {
		if r["name"] == role {
			has = true
			continue
		}
		drop = append(drop, r)
	}
	if len(drop) > 0 {
		if _, err := u.d.Admin.Admin(ctx, http.MethodDelete, u.userPath(sub)+"/role-mappings/clients/"+url.PathEscape(id), drop, nil); err != nil {
			return fmt.Errorf("accounts: remove the account's console roles: %w", err)
		}
	}
	if role != "" && !has {
		if err := u.AddConsoleRole(ctx, sub, role); err != nil {
			return err
		}
	}
	after, _, err := u.directConsoleRoles(ctx, sub)
	if err != nil {
		return fmt.Errorf("accounts: read the change back: %w", err)
	}
	if role == "" && len(after) != 0 || role != "" && (len(after) != 1 || after[0]["name"] != role) {
		return ErrNotKept
	}
	return nil
}

// SetNetwork sets the account's network grants to grants, and reads them
// back. No grant removes the attribute.
func (u *Users) SetNetwork(ctx context.Context, sub string, grants []string) error {
	err := u.write(ctx, sub, func(_, attrs map[string]any) {
		if len(grants) == 0 {
			delete(attrs, AttrNetwork)
			return
		}
		vs := make([]any, 0, len(grants))
		for _, g := range grants {
			vs = append(vs, g)
		}
		attrs[AttrNetwork] = vs
	})
	if err != nil {
		return err
	}
	return u.readBack(ctx, sub, func(p Person) bool { return sameSet(p.Network, grants) })
}

// sameSet reports whether a and b hold the same strings.
func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// SetEmail sets the account's email to addr and its confirmed email
// (rasputin_email) to addr when confirmed, or clears it, and reads both
// back. An address another account holds is the Admin API's 409, an error
// wrapping idclient.ErrConflict (register row T275).
func (u *Users) SetEmail(ctx context.Context, sub, addr string, confirmed bool) error {
	err := u.write(ctx, sub, func(body, attrs map[string]any) {
		body["email"] = addr
		if confirmed {
			attrs[flows.AttrConfirmedEmail] = []any{addr}
		} else {
			delete(attrs, flows.AttrConfirmedEmail)
		}
	})
	if err != nil {
		return err
	}
	want := ""
	if confirmed {
		want = addr
	}
	return u.readBack(ctx, sub, func(p Person) bool { return equalFoldEmail(p.Email, addr) && equalFoldEmail(p.ConfirmedEmail, want) })
}

// equalFoldEmail compares two addresses as the identity service stores
// them, lower-cased (register row T252).
func equalFoldEmail(a, b string) bool { return removednames.Normal(a) == removednames.Normal(b) }

// ConfirmEmail copies the account's email into rasputin_email, and reads
// it back. An account with no email is ErrNoEmail, with nothing written.
func (u *Users) ConfirmEmail(ctx context.Context, sub string) error {
	p, err := u.Read(ctx, sub)
	if err != nil {
		return err
	}
	if p.Email == "" {
		return ErrNoEmail
	}
	if p.ConfirmedEmail == p.Email {
		return nil
	}
	if err := u.write(ctx, sub, func(_, attrs map[string]any) { attrs[flows.AttrConfirmedEmail] = []any{p.Email} }); err != nil {
		return err
	}
	return u.readBack(ctx, sub, func(q Person) bool { return q.ConfirmedEmail == p.Email })
}

// SetDisplayName sets the account's name (firstName), and reads it back.
func (u *Users) SetDisplayName(ctx context.Context, sub, name string) error {
	if err := u.write(ctx, sub, func(body, _ map[string]any) { body["firstName"] = name }); err != nil {
		return err
	}
	return u.readBack(ctx, sub, func(p Person) bool { return p.DisplayName == name })
}

// Unlock releases an account the identity service's attack detection holds
// (C19): DELETE /attack-detection/brute-force/users/{id} (register row
// T272).
func (u *Users) Unlock(ctx context.Context, sub string) error {
	if sub == "" {
		return errors.New("accounts: no account id")
	}
	if _, err := u.d.Admin.Admin(ctx, http.MethodDelete, u.realmPath()+"/attack-detection/brute-force/users/"+url.PathEscape(sub), nil, nil); err != nil {
		return fmt.Errorf("accounts: unlock the account: %w", err)
	}
	return nil
}

// AddRequiredAction adds action to the account's pending required actions,
// those it holds as read in the same write, and reads it back. An action
// already pending writes nothing. The caller holds the accounts lock: the
// write is the whole account's (geekdojo/geekdojo-brain#321).
func (u *Users) AddRequiredAction(ctx context.Context, sub, action string) error {
	if action == "" {
		return errors.New("accounts: no required action")
	}
	p, err := u.Read(ctx, sub)
	switch {
	case err != nil:
		return err
	case slices.Contains(p.RequiredActions, action):
		return nil
	}
	err = u.writeFrom(ctx, sub, func(rep, body, _ map[string]any) {
		held, _ := rep["requiredActions"].([]any)
		if !slices.Contains(held, any(action)) {
			held = append(slices.Clone(held), action)
		}
		body["requiredActions"] = held
	})
	if err != nil {
		return err
	}
	return u.readBack(ctx, sub, func(p Person) bool { return slices.Contains(p.RequiredActions, action) })
}

// DeleteCredential removes one of the account's credentials (register row
// T273).
func (u *Users) DeleteCredential(ctx context.Context, sub, credID string) error {
	if sub == "" || credID == "" {
		return errors.New("accounts: no account id or no credential id")
	}
	if _, err := u.d.Admin.Admin(ctx, http.MethodDelete, u.userPath(sub)+"/credentials/"+url.PathEscape(credID), nil, nil); err != nil {
		return fmt.Errorf("accounts: delete the credential: %w", err)
	}
	return nil
}

// RenameCredential sets a credential's label: PUT
// /users/{id}/credentials/{cid}/userLabel, whose body is the label as
// text/plain (register row T271).
func (u *Users) RenameCredential(ctx context.Context, sub, credID string, label secret.Value) error {
	if sub == "" || credID == "" {
		return errors.New("accounts: no account id or no credential id")
	}
	if _, err := u.d.Admin.Admin(ctx, http.MethodPut, u.userPath(sub)+"/credentials/"+url.PathEscape(credID)+"/userLabel",
		idclient.TextBody(label), nil); err != nil {
		return fmt.Errorf("accounts: rename the credential: %w", err)
	}
	return nil
}
