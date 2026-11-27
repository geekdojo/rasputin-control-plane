package auth

import (
	"context"
	"fmt"
	"time"
)

// The pre-update session (geekdojo/geekdojo-brain#1005; register row E3): a
// browser signed in to the console before the update carries the old
// rasputin-session cookie, whose row is in the old sessions table. Until it
// ends, it resolves to its moved account while that account holds a
// designation: administrator while its moved designation stands, otherwise
// no console role (C25). It never writes the old tables; it is ended by
// sign-out, by a new console sign-in clearing its cookie, by C15's deletion
// of the old rows on disable, removal or demotion, and at sessionLifetime.

// legacySessionCookieName is the pre-update api's session cookie.
const legacySessionCookieName = "rasputin-session"

// preUpdate resolves a pre-update session.
type preUpdate struct {
	store    *Store
	accounts MovedAccounts
	now      func() time.Time
}

// resolve returns the Principal of the old session token names, and false
// when it names none, it has expired (its own expires_at, or
// sessionLifetime after it began), or its user has no designated moved
// account. Nothing is written: last_active_at is left as it is.
func (p *preUpdate) resolve(ctx context.Context, token string) (Principal, bool, error) {
	sess, err := p.store.GetSession(ctx, token)
	if err != nil {
		return Principal{}, false, fmt.Errorf("auth: read a pre-update session: %w", err)
	}
	if sess == nil {
		return Principal{}, false, nil
	}
	now := p.now().UTC()
	if !now.Before(sess.ExpiresAt) || !now.Before(sess.CreatedAt.Add(sessionLifetime)) {
		return Principal{}, false, nil
	}
	acct, ok, err := p.accounts.Account(ctx, sess.UserID)
	if err != nil {
		return Principal{}, false, fmt.Errorf("auth: read a pre-update session's account: %w", err)
	}
	if !ok || !acct.Designated {
		return Principal{}, false, nil
	}
	return Principal{Sub: acct.Sub, Name: acct.Name, Roles: acct.Roles,
		Session: SessionRef{CreatedAt: sess.CreatedAt, PreUpdate: true, NeedsPassword: acct.NeedsPassword}}, true, nil
}
