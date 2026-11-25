package auth

import (
	"sync"
	"time"
)

// expiring is a map of records, each with its own expiry, bounded by a
// record cap: the in-memory store of the pending sign-ins (pending.go) and
// the bridge's ceremonies and grants (bridge.go). Both sit behind open
// routes, so without the cap each would grow with every request. A record
// that has expired answers as absent and is dropped by take, by eviction at
// the cap and by prune (the janitor's sweep). It is safe for concurrent use.
type expiring[V any] struct {
	mu  sync.Mutex
	m   map[string]V
	now func() time.Time
	max int
	// expires is a record's expiry; destroy releases whatever it holds.
	// Every way a record leaves the map but take calls destroy.
	expires func(V) time.Time
	destroy func(V)
}

func newExpiring[V any](now func() time.Time, max int, expires func(V) time.Time, destroy func(V)) *expiring[V] {
	return &expiring[V]{m: map[string]V{}, now: now, max: max, expires: expires, destroy: destroy}
}

// liveLocked reports whether v has not expired. The caller holds e.mu.
func (e *expiring[V]) liveLocked(v V) bool { return e.now().Before(e.expires(v)) }

// live reports whether key names a record that has not expired.
func (e *expiring[V]) live(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.m[key]
	return ok && e.liveLocked(v)
}

// peek returns the live record under key without removing it.
func (e *expiring[V]) peek(key string) (V, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.m[key]
	if !ok || !e.liveLocked(v) {
		var zero V
		return zero, false
	}
	return v, true
}

// put stores v under key, replacing (and destroying) any record there. At
// the cap it first makes room (evictLocked).
func (e *expiring[V]) put(key string, v V) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if old, ok := e.m[key]; ok {
		e.destroy(old)
	} else if len(e.m) >= e.max {
		e.evictLocked()
	}
	e.m[key] = v
}

// evictLocked makes room for one record: every expired one goes, and when
// none had expired, the one closest to expiry. The caller holds e.mu.
func (e *expiring[V]) evictLocked() {
	var (
		oldest    string
		oldestExp time.Time
		found     bool
		pruned    bool
	)
	for k, v := range e.m {
		if !e.liveLocked(v) {
			e.destroy(v)
			delete(e.m, k)
			pruned = true
			continue
		}
		if exp := e.expires(v); !found || exp.Before(oldestExp) {
			oldest, oldestExp, found = k, exp, true
		}
	}
	if !pruned && found {
		e.destroy(e.m[oldest])
		delete(e.m, oldest)
	}
}

// take removes and returns the record under key, and false when there is
// none or it has expired (an expired one is destroyed). The caller owns
// what it returns.
func (e *expiring[V]) take(key string) (V, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var zero V
	v, ok := e.m[key]
	if !ok {
		return zero, false
	}
	delete(e.m, key)
	if !e.liveLocked(v) {
		e.destroy(v)
		return zero, false
	}
	return v, true
}

// each calls fn on every live record under the lock, until fn returns
// true. fn must not call back into e.
func (e *expiring[V]) each(fn func(v V) bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, v := range e.m {
		if e.liveLocked(v) && fn(v) {
			return
		}
	}
}

// prune drops every expired record (the janitor's sweep).
func (e *expiring[V]) prune() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, v := range e.m {
		if !e.liveLocked(v) {
			e.destroy(v)
			delete(e.m, k)
		}
	}
}

// size is the number of records held.
func (e *expiring[V]) size() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.m)
}
