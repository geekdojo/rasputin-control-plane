package accounts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// The identity-service writes of Identity 4.12's definitions
// (geekdojo/geekdojo-brain#994, PR 2; identity-authz.md §3.4): realm groups
// and their members, and the custom claims an administrator defines, each
// a user-profile attribute claim_<name> and a client scope claim-<name>.
// Every caller holds the one accounts lock.

// groupPage is how many groups one read asks for. A page that comes back
// full is an error, never a short list.
const groupPage = 1000

// claimScopePrefix begins a claim's client scope's name: claim-<name>.
const claimScopePrefix = "claim-"

// Group is one realm group: its id and its name.
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Groups is the realm's top-level groups.
func (u *Users) Groups(ctx context.Context) ([]Group, error) {
	var gs []Group
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, u.realmPath()+"/groups?briefRepresentation=true&first=0&max="+strconv.Itoa(groupPage), nil, &gs); err != nil {
		return nil, fmt.Errorf("accounts: list the groups: %w", err)
	}
	if len(gs) >= groupPage {
		return nil, fmt.Errorf("accounts: the groups fill a page of %d, so the list would be short", groupPage)
	}
	return gs, nil
}

// DefineGroup creates the top-level group name and returns its id, and
// whether it already existed: a name the realm holds is the Admin API's
// 409 (register row T279), and that group is read back.
func (u *Users) DefineGroup(ctx context.Context, name string) (string, bool, error) {
	if name == "" {
		return "", false, errors.New("accounts: no group name")
	}
	resp, err := u.d.Admin.Admin(ctx, http.MethodPost, u.realmPath()+"/groups", map[string]any{"name": name}, nil)
	switch {
	case errors.Is(err, idclient.ErrConflict):
	case err != nil:
		return "", false, fmt.Errorf("accounts: create the group: %w", err)
	case resp.Location != "":
		if l, perr := url.Parse(resp.Location); perr == nil && path.Base(l.Path) != "" && path.Base(l.Path) != "groups" {
			return path.Base(l.Path), false, nil
		}
	}
	gs, lerr := u.Groups(ctx)
	if lerr != nil {
		return "", false, lerr
	}
	for _, g := range gs {
		if g.Name == name && g.ID != "" {
			return g.ID, err != nil, nil
		}
	}
	return "", false, ErrNotKept
}

// DeleteGroup deletes the group. A group already gone counts as deleted.
func (u *Users) DeleteGroup(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("accounts: no group id")
	}
	if _, err := u.d.Admin.Admin(ctx, http.MethodDelete, u.realmPath()+"/groups/"+url.PathEscape(id), nil, nil); err != nil && !errors.Is(err, idclient.ErrNotFound) {
		return fmt.Errorf("accounts: delete the group: %w", err)
	}
	return nil
}

// GroupIDs is the ids of the groups the account is directly a member of.
func (u *Users) GroupIDs(ctx context.Context, sub string) ([]string, error) {
	if sub == "" {
		return nil, errors.New("accounts: no account id")
	}
	var gs []Group
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, u.userPath(sub)+"/groups?briefRepresentation=true&first=0&max="+strconv.Itoa(groupPage), nil, &gs); err != nil {
		return nil, fmt.Errorf("accounts: read the account's groups: %w", err)
	}
	if len(gs) >= groupPage {
		return nil, fmt.Errorf("accounts: the account's groups fill a page of %d", groupPage)
	}
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.ID)
	}
	return out, nil
}

// SetGroups makes want the account's groups: it joins the groups it is not
// in and leaves the ones not in want (PUT and DELETE
// /users/{id}/groups/{gid}, register row T280), touching no other, and
// reads the set back. It returns how many it joined and left.
func (u *Users) SetGroups(ctx context.Context, sub string, want []string) (int, int, error) {
	held, err := u.GroupIDs(ctx, sub)
	if err != nil {
		return 0, 0, err
	}
	joined, left := 0, 0
	for _, g := range want {
		if slices.Contains(held, g) {
			continue
		}
		if _, err := u.d.Admin.Admin(ctx, http.MethodPut, u.userPath(sub)+"/groups/"+url.PathEscape(g), nil, nil); err != nil {
			return joined, left, fmt.Errorf("accounts: add the account to a group: %w", err)
		}
		joined++
	}
	for _, g := range held {
		if slices.Contains(want, g) {
			continue
		}
		if _, err := u.d.Admin.Admin(ctx, http.MethodDelete, u.userPath(sub)+"/groups/"+url.PathEscape(g), nil, nil); err != nil {
			return joined, left, fmt.Errorf("accounts: remove the account from a group: %w", err)
		}
		left++
	}
	after, err := u.GroupIDs(ctx, sub)
	if err != nil {
		return joined, left, fmt.Errorf("accounts: read the change back: %w", err)
	}
	if !sameSet(after, want) {
		return joined, left, ErrNotKept
	}
	return joined, left, nil
}

// ClaimDef is a custom claim as the identity service holds it: its name,
// its kind and the values it allows (none for any).
type ClaimDef struct {
	Name   string
	Kind   string
	Values []string
}

// The kinds of claim (identity-authz.md §3.4).
const (
	ClaimText    = "text"
	ClaimList    = "list"
	ClaimBoolean = "boolean"
	ClaimNumber  = "number"
)

// claimAttr is the user attribute that holds the claim name.
func claimAttr(name string) string { return flows.ClaimPrefix + name }

// profileAttribute is the claim's user-profile attribute: admin-only, many
// values for a list, and the kind's validators: 1 to 255 characters for
// text and a list, true or false for a boolean, a whole number for a
// number, and the allowed values when there are any.
func (d ClaimDef) profileAttribute() map[string]any {
	v := map[string]any{}
	switch d.Kind {
	case ClaimText, ClaimList:
		v["length"] = map[string]any{"min": 1, "max": maxText}
	case ClaimBoolean:
		v["options"] = map[string]any{"options": []any{"true", "false"}}
	case ClaimNumber:
		v["integer"] = map[string]any{}
	}
	if len(d.Values) > 0 {
		opts := make([]any, 0, len(d.Values))
		for _, x := range d.Values {
			opts = append(opts, x)
		}
		v["options"] = map[string]any{"options": opts}
	}
	return map[string]any{"name": claimAttr(d.Name), "displayName": d.Name, "permissions": flows.AdminOnlyPermissions(),
		"multivalued": d.Kind == ClaimList, "validations": v}
}

// fits reports whether vs, one account's values of the claim, pass d's
// validators: one value at most unless d is a list; each true or false for
// a boolean, a whole number for a number, 1 to 255 characters otherwise;
// and each one of d's allowed values when it has any.
func (d ClaimDef) fits(vs []string) bool {
	if len(vs) > 1 && d.Kind != ClaimList {
		return false
	}
	for _, v := range vs {
		ok := true
		switch d.Kind {
		case ClaimBoolean:
			ok = v == "true" || v == "false"
		case ClaimNumber:
			_, err := strconv.ParseInt(v, 10, 64)
			ok = err == nil
		default:
			n := utf8.RuneCountInString(v)
			ok = n >= 1 && n <= maxText
		}
		if !ok || len(d.Values) > 0 && !slices.Contains(d.Values, v) {
			return false
		}
	}
	return true
}

// ErrClaimHeld is a redefinition of a claim whose values some account holds
// that the new definition would refuse (F-994-25).
var ErrClaimHeld = errors.New("accounts: an account holds values the claim's new definition refuses")

// holdersFit returns ErrClaimHeld unless every account's values of the
// claim, when the profile already declares it, fit d. A value the new
// validators refuse would make every later write of that whole account a
// 400.
func (u *Users) holdersFit(ctx context.Context, d ClaimDef) error {
	defined, err := u.Claims(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(defined, d.Name) {
		return nil
	}
	reps, err := u.listed(ctx)
	if err != nil {
		return err
	}
	for _, rep := range reps {
		if !d.fits(attrValues(rep, claimAttr(d.Name))) {
			return ErrClaimHeld
		}
	}
	return nil
}

// mappers are the claim's two protocol mappers: a User Attribute mapper
// putting it in the ID token, the access token and userinfo, and a SAML
// attribute mapper (register row T282).
func (d ClaimDef) mappers() []map[string]any {
	jsonType := "String"
	switch d.Kind {
	case ClaimBoolean:
		jsonType = "boolean"
	case ClaimNumber:
		jsonType = "long"
	}
	attr := claimAttr(d.Name)
	return []map[string]any{
		{"name": "claim " + d.Name, "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
			"consentRequired": false, "config": map[string]any{
				"user.attribute": attr, "claim.name": d.Name, "jsonType.label": jsonType,
				"multivalued": strconv.FormatBool(d.Kind == ClaimList), "id.token.claim": "true", "access.token.claim": "true",
				"userinfo.token.claim": "true", "introspection.token.claim": "true"}},
		{"name": "claim " + d.Name + " saml", "protocol": "saml", "protocolMapper": "saml-user-attribute-mapper",
			"consentRequired": false, "config": map[string]any{
				"user.attribute": attr, "attribute.name": d.Name, "friendly.name": d.Name,
				"attribute.nameformat": "Basic", "aggregate.attrs": "false"}},
	}
}

// profile reads the user profile's configuration (GET /users/profile).
func (u *Users) profile(ctx context.Context) (map[string]any, error) {
	var p map[string]any
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, u.realmPath()+"/users/profile", nil, &p); err != nil {
		return nil, fmt.Errorf("accounts: read the user profile: %w", err)
	}
	if p == nil {
		return nil, errors.New("accounts: the user profile is empty")
	}
	return p, nil
}

// editProfile reads the user profile, gives its attributes to edit, and
// writes it back with everything else as read.
func (u *Users) editProfile(ctx context.Context, edit func(attrs []any) []any) error {
	p, err := u.profile(ctx)
	if err != nil {
		return err
	}
	attrs, _ := p["attributes"].([]any)
	p["attributes"] = edit(attrs)
	if _, err := u.d.Admin.Admin(ctx, http.MethodPut, u.realmPath()+"/users/profile", p, nil); err != nil {
		return fmt.Errorf("accounts: write the user profile: %w", err)
	}
	return nil
}

// withoutAttr is attrs without the attribute name.
func withoutAttr(attrs []any, name string) []any {
	return slices.DeleteFunc(slices.Clone(attrs), func(a any) bool {
		m, _ := a.(map[string]any)
		return m["name"] == name
	})
}

// Claims is the names of the claims the user profile declares.
func (u *Users) Claims(ctx context.Context) ([]string, error) {
	p, err := u.profile(ctx)
	if err != nil {
		return nil, err
	}
	attrs, _ := p["attributes"].([]any)
	var out []string
	for _, a := range attrs {
		m, _ := a.(map[string]any)
		n, _ := m["name"].(string)
		if name, ok := strings.CutPrefix(n, flows.ClaimPrefix); ok && name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

// DefineClaim writes d: the user-profile attribute claim_<name>, replaced
// when the profile holds it, then the client scope claim-<name> (an
// existing one kept) with its two mappers, each replaced when the scope
// holds one of that name. A redefinition some account's values don't fit
// is ErrClaimHeld, and changes nothing.
func (u *Users) DefineClaim(ctx context.Context, d ClaimDef) error {
	if d.Name == "" {
		return errors.New("accounts: no claim name")
	}
	if err := u.holdersFit(ctx, d); err != nil {
		return err
	}
	attr := d.profileAttribute()
	if err := u.editProfile(ctx, func(attrs []any) []any {
		return append(withoutAttr(attrs, claimAttr(d.Name)), attr)
	}); err != nil {
		return err
	}
	scope := map[string]any{"name": claimScopePrefix + d.Name, "protocol": "openid-connect",
		"attributes": map[string]any{"include.in.token.scope": "false", "display.on.consent.screen": "false"}}
	if _, err := u.d.Admin.Admin(ctx, http.MethodPost, u.realmPath()+"/client-scopes", scope, nil); err != nil && !errors.Is(err, idclient.ErrConflict) {
		return fmt.Errorf("accounts: create the claim's client scope: %w", err)
	}
	id, err := u.scopeID(ctx, claimScopePrefix+d.Name)
	switch {
	case err != nil:
		return err
	case id == "":
		return ErrNotKept
	}
	mpath := u.realmPath() + "/client-scopes/" + url.PathEscape(id) + "/protocol-mappers/models"
	var held []map[string]any
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, mpath, nil, &held); err != nil {
		return fmt.Errorf("accounts: read the claim's mappers: %w", err)
	}
	for _, m := range d.mappers() {
		i := slices.IndexFunc(held, func(h map[string]any) bool { return h["name"] == m["name"] })
		if i < 0 {
			if _, err := u.d.Admin.Admin(ctx, http.MethodPost, mpath, m, nil); err != nil {
				return fmt.Errorf("accounts: add a claim mapper: %w", err)
			}
			continue
		}
		mid, _ := held[i]["id"].(string)
		m["id"] = mid
		if _, err := u.d.Admin.Admin(ctx, http.MethodPut, mpath+"/"+url.PathEscape(mid), m, nil); err != nil {
			return fmt.Errorf("accounts: replace a claim mapper: %w", err)
		}
	}
	return nil
}

// scopeID is the id of the client scope name, "" when the realm has none.
func (u *Users) scopeID(ctx context.Context, name string) (string, error) {
	var scopes []struct{ ID, Name string }
	if _, err := u.d.Admin.Admin(ctx, http.MethodGet, u.realmPath()+"/client-scopes", nil, &scopes); err != nil {
		return "", fmt.Errorf("accounts: list the client scopes: %w", err)
	}
	for _, s := range scopes {
		if s.Name == name {
			return s.ID, nil
		}
	}
	return "", nil
}

// DeleteClaim removes the claim name and returns how many accounts held a
// value of it: first its client scope, so no token carries it; then each
// account's value, while the profile still declares the attribute; then
// the attribute. Each part already gone counts as removed.
func (u *Users) DeleteClaim(ctx context.Context, name string) (int, error) {
	if name == "" {
		return 0, errors.New("accounts: no claim name")
	}
	id, err := u.scopeID(ctx, claimScopePrefix+name)
	if err != nil {
		return 0, err
	}
	if id != "" {
		if _, err := u.d.Admin.Admin(ctx, http.MethodDelete, u.realmPath()+"/client-scopes/"+url.PathEscape(id), nil, nil); err != nil &&
			!errors.Is(err, idclient.ErrNotFound) {
			return 0, fmt.Errorf("accounts: delete the claim's client scope: %w", err)
		}
	}
	reps, err := u.listed(ctx)
	if err != nil {
		return 0, err
	}
	attr := claimAttr(name)
	n := 0
	for _, rep := range reps {
		if len(attrValues(rep, attr)) == 0 {
			continue
		}
		sub, _ := rep["id"].(string)
		if err := u.write(ctx, sub, func(_, attrs map[string]any) { delete(attrs, attr) }); err != nil {
			return n, err
		}
		n++
	}
	if err := u.editProfile(ctx, func(attrs []any) []any { return withoutAttr(attrs, attr) }); err != nil {
		return n, err
	}
	return n, nil
}

// SetClaims sets each of the account's claims in values to its values, an
// empty list removing it, leaves every other attribute as read, and reads
// them back. A value the claim's validators refuse is the Admin API's 400
// (register row T281).
func (u *Users) SetClaims(ctx context.Context, sub string, values map[string][]string) error {
	err := u.write(ctx, sub, func(_, attrs map[string]any) {
		for name, vs := range values {
			if len(vs) == 0 {
				delete(attrs, claimAttr(name))
				continue
			}
			out := make([]any, 0, len(vs))
			for _, v := range vs {
				out = append(out, v)
			}
			attrs[claimAttr(name)] = out
		}
	})
	if err != nil {
		return err
	}
	rep, err := u.raw(ctx, sub)
	if err != nil {
		return fmt.Errorf("accounts: read the change back: %w", err)
	}
	for name, vs := range values {
		if !sameSet(attrValues(rep, claimAttr(name)), vs) {
			return ErrNotKept
		}
	}
	return nil
}
