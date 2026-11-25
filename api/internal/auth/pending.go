package auth

import (
	"crypto/subtle"
	"time"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// signinPendingLifetime bounds a sign-in the browser began and never brought
// back (register row C73, timer-audit row L60). A sign-in is consumed by its
// callback, or replaced by a newer one from the same browser, which are the
// facts that end it; one abandoned at the identity service's page produces
// no fact the api could observe, so this bound is what frees its memory. It
// is at least the realm's login and login-action page timeouts
// (accessCodeLifespanLogin and accessCodeLifespanUserAction, flows.Render),
// so a person who takes the page's whole allowance still comes back to a
// live record.
const signinPendingLifetime = 30 * time.Minute

// maxSigninPending caps the in-memory map: /api/auth/signin is open, so
// without a cap it grows with every request. At the cap the expired records
// go first, then the one closest to expiry (the precedent of maxPending).
const maxSigninPending = 1024

// pendingSignin is one sign-in in flight: the values its callback must
// match, and when it began.
type pendingSignin struct {
	state, nonce string
	verifier     secret.Value
	// begin is when the sign-in began, on the injected clock. The ID
	// token's auth_time must not be before it (truncated to the second), so
	// a sign-in the identity service did not re-authenticate is refused.
	begin   time.Time
	expires time.Time
	// action, when set, is the fresh sign-in an action asked for: the return
	// runs the action and mints no session.
	action *pendingAction
	// prepared marks a record PrepareAction stored and StartAction has not
	// begun yet: it has no state, nonce or verifier, so no callback can
	// complete it.
	prepared bool
}

// pendingAction is a fresh sign-in's action: prepared by PrepareAction,
// begun by StartAction.
type pendingAction struct {
	kind string
	sub  string
	// payload is the value the action runs with, held only here until the
	// callback hands it to the action (geekdojo/geekdojo-brain#992); nil
	// when the action needs none.
	payload ActionPayload
	// method and kcAction are a sign-in method's (PrepareMethod,
	// geekdojo/geekdojo-brain#1150): the method, and the one kc_action its
	// fresh sign-in carries. Both are empty for every other action.
	method   Method
	kcAction string
	// forwarded marks that the doors forwarded kcAction once (forward).
	forwarded bool
}

// destroy destroys everything rec holds: the PKCE verifier and the
// action's payload. Every way a record leaves the map but the callback's
// hand-off calls it: take, replacement, eviction and prune.
func (rec *pendingSignin) destroy() {
	rec.verifier.Destroy()
	if rec.action != nil && rec.action.payload != nil {
		rec.action.payload.Destroy()
	}
}

// pendingSignins is the map of sign-ins in flight, keyed by the pending
// cookie's value: an expiring map (expiring.go) capped at maxSigninPending,
// each record expiring signinPendingLifetime after it began. It is safe for
// concurrent use.
type pendingSignins struct {
	*expiring[*pendingSignin]
}

func newPendingSignins(now func() time.Time) *pendingSignins {
	return &pendingSignins{newExpiring(now, maxSigninPending,
		func(rec *pendingSignin) time.Time { return rec.expires },
		func(rec *pendingSignin) { rec.destroy() })}
}

// put stores rec under key, replacing any record there, with its expiry set
// signinPendingLifetime after its begin.
func (p *pendingSignins) put(key string, rec *pendingSignin) {
	rec.expires = rec.begin.Add(signinPendingLifetime)
	p.expiring.put(key, rec)
}

// take removes and returns the record under key, or nil when there is none
// or it has expired. The caller destroys it.
func (p *pendingSignins) take(key string) *pendingSignin {
	rec, ok := p.expiring.take(key)
	if !ok {
		return nil
	}
	return rec
}

// forward reports whether the doors may forward kcAction under state: true
// once, for the live record that has begun (not only been prepared), whose
// state matches and that carries exactly kcAction; it marks that record so
// no later request forwards it again. Anything else is false and marks
// nothing: an empty state or action, and a record carrying no kc_action.
func (p *pendingSignins) forward(state, kcAction string) bool {
	if state == "" || kcAction == "" {
		return false
	}
	ok := false
	p.each(func(rec *pendingSignin) bool {
		if rec.prepared || rec.action == nil || rec.action.kcAction == "" {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(rec.state), []byte(state)) != 1 {
			return false
		}
		if !rec.action.forwarded && rec.action.kcAction == kcAction {
			rec.action.forwarded = true
			ok = true
		}
		return true
	})
	return ok
}
