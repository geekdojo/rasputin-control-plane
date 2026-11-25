package auth

import (
	"sync"
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
// cookie's value. It is safe for concurrent use.
type pendingSignins struct {
	mu  sync.Mutex
	m   map[string]*pendingSignin
	now func() time.Time
}

func newPendingSignins(now func() time.Time) *pendingSignins {
	return &pendingSignins{m: map[string]*pendingSignin{}, now: now}
}

// live reports whether key names a record that has not expired.
func (p *pendingSignins) live(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.m[key]
	return ok && p.now().Before(rec.expires)
}

// put stores rec under key, replacing any record there, with its expiry set
// signinPendingLifetime after its begin.
func (p *pendingSignins) put(key string, rec *pendingSignin) {
	rec.expires = rec.begin.Add(signinPendingLifetime)
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.m[key]; ok {
		old.destroy()
	} else if len(p.m) >= maxSigninPending {
		p.evictLocked()
	}
	p.m[key] = rec
}

// evictLocked makes room for one record: every expired one goes, and when
// none had expired, the one closest to expiry. The caller holds p.mu.
func (p *pendingSignins) evictLocked() {
	now := p.now()
	var (
		oldest    string
		oldestExp time.Time
		pruned    bool
	)
	for k, rec := range p.m {
		if !now.Before(rec.expires) {
			rec.destroy()
			delete(p.m, k)
			pruned = true
			continue
		}
		if oldest == "" || rec.expires.Before(oldestExp) {
			oldest, oldestExp = k, rec.expires
		}
	}
	if !pruned && oldest != "" {
		p.m[oldest].destroy()
		delete(p.m, oldest)
	}
}

// take removes and returns the record under key, or nil when there is none
// or it has expired. The caller destroys it.
func (p *pendingSignins) take(key string) *pendingSignin {
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.m[key]
	if !ok {
		return nil
	}
	delete(p.m, key)
	if !p.now().Before(rec.expires) {
		rec.destroy()
		return nil
	}
	return rec
}

// prune drops every expired record (the janitor's sweep).
func (p *pendingSignins) prune() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for k, rec := range p.m {
		if !now.Before(rec.expires) {
			rec.destroy()
			delete(p.m, k)
		}
	}
}

// size is the number of records held.
func (p *pendingSignins) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}
