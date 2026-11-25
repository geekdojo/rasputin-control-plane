package accounts

import (
	"sync"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Held is the temporary passwords of accounts.reset_password jobs, by job
// id, beside the jobs and never in their specs (a spec is persisted and
// shown on the Tasks page). It lives in memory only, so a restart drops
// every one, and the job then fails with sentenceNotHeld. It is safe for
// concurrent use.
type Held struct {
	mu sync.Mutex
	m  map[string]secret.Value
}

// NewHeld returns an empty Held.
func NewHeld() *Held { return &Held{m: map[string]secret.Value{}} }

// Put holds v for jobID, which then owns it; a value already there is
// destroyed.
func (h *Held) Put(jobID string, v secret.Value) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old, ok := h.m[jobID]; ok {
		old.Destroy()
	}
	h.m[jobID] = v
}

// Take removes and returns jobID's value; the caller destroys it.
func (h *Held) Take(jobID string) (secret.Value, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, ok := h.m[jobID]
	delete(h.m, jobID)
	return v, ok
}

// Drop destroys jobID's value, if one is held.
func (h *Held) Drop(jobID string) {
	if v, ok := h.Take(jobID); ok {
		v.Destroy()
	}
}

// size is how many values are held.
func (h *Held) size() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.m)
}
