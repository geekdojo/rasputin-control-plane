package accounts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
)

// AttrAppRole is the account attribute that holds a person's app access:
// "user" or "admin".
const AttrAppRole = "rasputin_app_role"

// offlineAccess is the realm role that lets an app keep an offline session.
const offlineAccess = "offline_access"

// adminPage is how many administrators one read asks for. A page that
// comes back full is an error, never a truncated count.
const adminPage = 1000

// profileFields are the profile's own fields a user PUT carries back as
// read (markers.go does the same): a whole representation would also write
// back the required actions as read.
var profileFields = []string{"username", "email", "firstName", "lastName"}

// AppLevel is a level of app access.
type AppLevel string

// The levels of app access.
const (
	AppUser  AppLevel = "user"
	AppAdmin AppLevel = "admin"
)

// Admin is the Admin API session (*idclient.Session).
type Admin interface {
	Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error)
}

// UsersDeps are a Users' collaborators.
type UsersDeps struct {
	Admin Admin
	// Realm is the realm the accounts are in: rasputin.
	Realm string
	// ConsoleClient is the client whose roles are the console roles:
	// rasputin-console.
	ConsoleClient string
}

// Users is one person's account at the identity service.
type Users struct{ d UsersDeps }

// NewUsers checks d and returns Users. It does no I/O.
func NewUsers(d UsersDeps) (*Users, error) {
	switch {
	case d.Admin == nil:
		return nil, errors.New("accounts: UsersDeps.Admin is nil")
	case d.Realm == "" || d.ConsoleClient == "":
		return nil, errors.New("accounts: UsersDeps.Realm or ConsoleClient is empty")
	}
	return &Users{d: d}, nil
}

// Person is what Read returns about an account.
type Person struct {
	Username, Email string
	Enabled         bool
	// AppRole is the rasputin_app_role attribute, "" when absent.
	AppRole AppLevel
}

func (u *Users) realmPath() string { return "/admin/realms/" + url.PathEscape(u.d.Realm) }

func (u *Users) userPath(sub string) string { return u.realmPath() + "/users/" + url.PathEscape(sub) }

// raw reads the account's representation. A missing account is an error
// wrapping idclient.ErrNotFound.
func (u *Users) raw(ctx context.Context, sub string) (map[string]any, error) {
	if sub == "" {
		return nil, errors.New("accounts: no account id")
	}
	var rep map[string]any
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, u.userPath(sub), nil, &rep); err != nil {
		return nil, fmt.Errorf("accounts: read the account: %w", err)
	}
	return rep, nil
}

// Read returns the account's sign-in name, email, enabled state and app
// access.
func (u *Users) Read(ctx context.Context, sub string) (Person, error) {
	rep, err := u.raw(ctx, sub)
	if err != nil {
		return Person{}, err
	}
	p := Person{}
	p.Username, _ = rep["username"].(string)
	p.Email, _ = rep["email"].(string)
	p.Enabled, _ = rep["enabled"].(bool)
	attrs, _ := rep["attributes"].(map[string]any)
	if vs, _ := attrs[AttrAppRole].([]any); len(vs) > 0 {
		s, _ := vs[0].(string)
		p.AppRole = AppLevel(s)
	}
	return p, nil
}

// write re-reads the account and writes back its profile fields and
// attributes as read, changed by edit.
func (u *Users) write(ctx context.Context, sub string, edit func(body, attrs map[string]any)) error {
	rep, err := u.raw(ctx, sub)
	if err != nil {
		return err
	}
	attrs, _ := rep["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	body := map[string]any{}
	for _, k := range profileFields {
		if v, ok := rep[k]; ok {
			body[k] = v
		}
	}
	edit(body, attrs)
	body["attributes"] = attrs
	if _, err := u.d.Admin.Admin(ctx, http.MethodPut, u.userPath(sub), body, nil); err != nil {
		return fmt.Errorf("accounts: write the account: %w", err)
	}
	return nil
}

// SetEnabled enables or disables the account.
func (u *Users) SetEnabled(ctx context.Context, sub string, enabled bool) error {
	return u.write(ctx, sub, func(body, _ map[string]any) { body["enabled"] = enabled })
}

// SetAppRole sets the account's app access to level.
func (u *Users) SetAppRole(ctx context.Context, sub string, level AppLevel) error {
	return u.write(ctx, sub, func(_, attrs map[string]any) { attrs[AttrAppRole] = []any{string(level)} })
}

// RemoveAppRole removes the account's app access attribute.
func (u *Users) RemoveAppRole(ctx context.Context, sub string) error {
	return u.write(ctx, sub, func(_, attrs map[string]any) { delete(attrs, AttrAppRole) })
}

// realmRoles is the account's realm role mappings, by name.
func (u *Users) holdsOffline(ctx context.Context, sub string) (bool, error) {
	var roles []struct {
		Name string `json:"name"`
	}
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, u.userPath(sub)+"/role-mappings/realm", nil, &roles); err != nil {
		return false, fmt.Errorf("accounts: read the account's realm roles: %w", err)
	}
	return slices.ContainsFunc(roles, func(r struct {
		Name string `json:"name"`
	}) bool {
		return r.Name == offlineAccess
	}), nil
}

// offlineRole is the offline_access realm role's representation, read by
// name.
func (u *Users) offlineRole(ctx context.Context) (map[string]any, error) {
	var rep map[string]any
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, u.realmPath()+"/roles/"+offlineAccess, nil, &rep); err != nil {
		return nil, fmt.Errorf("accounts: read the %s role: %w", offlineAccess, err)
	}
	return rep, nil
}

// AddOfflineAccess gives the account the offline_access realm role, unless
// it already holds it. It reports whether it gave it.
func (u *Users) AddOfflineAccess(ctx context.Context, sub string) (bool, error) {
	return u.offline(ctx, sub, true)
}

// RemoveOfflineAccess takes the offline_access realm role from the
// account, when it holds it. It reports whether it took it.
func (u *Users) RemoveOfflineAccess(ctx context.Context, sub string) (bool, error) {
	return u.offline(ctx, sub, false)
}

func (u *Users) offline(ctx context.Context, sub string, add bool) (bool, error) {
	held, err := u.holdsOffline(ctx, sub)
	if err != nil || held == add {
		return false, err
	}
	role, err := u.offlineRole(ctx)
	if err != nil {
		return false, err
	}
	method := http.MethodDelete
	if add {
		method = http.MethodPost
	}
	if _, err := u.d.Admin.Admin(ctx, method, u.userPath(sub)+"/role-mappings/realm", []any{role}, nil); err != nil {
		return false, fmt.Errorf("accounts: change the account's %s role: %w", offlineAccess, err)
	}
	return true, nil
}

// Delete deletes the account. An account already gone counts as deleted.
func (u *Users) Delete(ctx context.Context, sub string) error {
	if sub == "" {
		return errors.New("accounts: no account id")
	}
	if _, err := u.d.Admin.Admin(ctx, http.MethodDelete, u.userPath(sub), nil, nil); err != nil && !errors.Is(err, idclient.ErrNotFound) {
		return fmt.Errorf("accounts: delete the account: %w", err)
	}
	return nil
}

// consoleClientID is the console client's internal id.
func (u *Users) consoleClientID(ctx context.Context) (string, error) {
	var clients []struct {
		ID string `json:"id"`
	}
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, u.realmPath()+"/clients?clientId="+url.QueryEscape(u.d.ConsoleClient), nil, &clients); err != nil {
		return "", fmt.Errorf("accounts: read the console client: %w", err)
	}
	if len(clients) != 1 || clients[0].ID == "" {
		return "", fmt.Errorf("accounts: %d console clients", len(clients))
	}
	return clients[0].ID, nil
}

// ConsoleRoles is the account's console roles, composites included.
func (u *Users) ConsoleRoles(ctx context.Context, sub string) ([]string, error) {
	id, err := u.consoleClientID(ctx)
	if err != nil {
		return nil, err
	}
	var roles []struct {
		Name string `json:"name"`
	}
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, u.userPath(sub)+"/role-mappings/clients/"+url.PathEscape(id)+"/composite", nil, &roles); err != nil {
		return nil, fmt.Errorf("accounts: read the account's console roles: %w", err)
	}
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.Name)
	}
	return out, nil
}

// EnabledAdmins counts the enabled accounts holding the console's admin
// role. A page that comes back full is an error: the count would be short.
func (u *Users) EnabledAdmins(ctx context.Context) (int, error) {
	id, err := u.consoleClientID(ctx)
	if err != nil {
		return 0, err
	}
	var users []struct {
		Enabled bool `json:"enabled"`
	}
	path := u.realmPath() + "/clients/" + url.PathEscape(id) + "/roles/admin/users?briefRepresentation=false&first=0&max=" + strconv.Itoa(adminPage)
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, path, nil, &users); err != nil {
		return 0, fmt.Errorf("accounts: read the administrators: %w", err)
	}
	if len(users) >= adminPage {
		return 0, fmt.Errorf("accounts: the administrators fill a page of %d, so the count would be short", adminPage)
	}
	n := 0
	for _, x := range users {
		if x.Enabled {
			n++
		}
	}
	return n, nil
}
