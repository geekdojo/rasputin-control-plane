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
}

// pendingAction is a fresh sign-in begun by StartAction.
type pendingAction struct {
	kind string
	sub  string
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
		old.verifier.Destroy()
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
			rec.verifier.Destroy()
			delete(p.m, k)
			pruned = true
			continue
		}
		if oldest == "" || rec.expires.Before(oldestExp) {
			oldest, oldestExp = k, rec.expires
		}
	}
	if !pruned && oldest != "" {
		p.m[oldest].verifier.Destroy()
		delete(p.m, oldest)
	}
}

// take removes and returns the record under key, or nil when there is none
// or it has expired. The caller destroys its verifier.
func (p *pendingSignins) take(key string) *pendingSignin {
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.m[key]
	if !ok {
		return nil
	}
	delete(p.m, key)
	if !p.now().Before(rec.expires) {
		rec.verifier.Destroy()
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
			rec.verifier.Destroy()
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
