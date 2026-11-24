package auth

import (
	"context"
	"slices"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
)

// SessionRef names the console session a request was authenticated by: the
// identity service's session id it was signed in under, and when it began.
type SessionRef struct {
	SID       string
	CreatedAt time.Time
}

// Principal is the person a console request acts for, as RequireSession
// resolved it from the console session (geekdojo/geekdojo-brain#989). The
// services authorize from Roles; nothing authorizes from Name.
type Principal struct {
	// Sub is the identity service's subject: the account's stable id.
	Sub string
	// Name is the account's preferred_username at sign-in, for display and
	// for audit records ("installed by") only. It never authorizes and is
	// never sent to another service.
	Name string
	// Roles are the console roles (rasputin_roles) the ID token carried at
	// sign-in. A change to them ends the session (rolechange.go).
	Roles []string
	// Session is the console session the request carried.
	Session SessionRef
}

// HasRole reports whether p holds role.
func (p Principal) HasRole(role string) bool { return slices.Contains(p.Roles, role) }

// Capabilities is what p may do, computed from its Sub and Roles by
// authz.For, the one capability function. A console session carries no
// grant.
func (p Principal) Capabilities() authz.Set {
	return authz.For(authz.Subject{Sub: p.Sub, Roles: p.Roles})
}

type principalKey struct{}

// PrincipalFrom returns the Principal RequireSession attached.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// WithPrincipal returns a context carrying p as if RequireSession had
// resolved it. It is for tests that drive a handler directly; production
// code goes through RequireSession.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}
