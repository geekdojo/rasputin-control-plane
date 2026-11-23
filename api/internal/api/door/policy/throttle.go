package policy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
)

// The per-source guessing bounds, ratified by Bryce on 2026-11-02 (D22;
// register row N9): a source's first guessFreeFailures failed sign-ins set no
// wait; each one after that makes the source wait
// sourceWaitMinLifetime·2^(n−4), at most sourceWaitMaxLifetime, from the
// failure's time; and the count restarts only when a failure arrives more
// than sourceFailureWindowLifetime after the source's previous one, D22's
// 12-hour backstop window (realm-baseline.json maxDeltaTimeSeconds 43200).
// Nothing else ends a wait or a count: not a sign-in that succeeds, not an
// administrator's UNLOCK (C19, F-985-01).
const (
	guessFreeFailures           = 3
	sourceWaitMinLifetime       = 60 * time.Second
	sourceWaitMaxLifetime       = 900 * time.Second
	sourceFailureWindowLifetime = 12 * time.Hour
)

// maxSources caps the sources held; seenPerSource the event ids each keeps
// so a re-delivered event counts once.
const (
	maxSources    = 4096
	seenPerSource = 64
)

// The events that count against a source: a wrong password or code, or an
// unknown user, at Keycloak 26.8.2 (capability row K-EVENTS).
const (
	countedType = "LOGIN_ERROR"
)

var countedErrors = []string{"invalid_user_credentials", "user_not_found"}

// The throttle's sentences (ERR-MESSAGE).
const sentenceNoSource = "This device's address couldn't be read, so the sign-in was refused. Try again, or sign in from another device."

// Key is one source at one door: an IPv4 address, or an IPv6 /64, with an
// IPv4-mapped address read as its IPv4 address.
type Key struct {
	Door   Kind
	Source netip.Prefix
}

// keyOf is addr's key at door; false for an address that did not parse.
func keyOf(door Kind, addr netip.Addr) (Key, bool) {
	if !addr.IsValid() {
		return Key{}, false
	}
	a := addr.Unmap()
	bits := 32
	if a.Is6() {
		bits = 64
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return Key{}, false
	}
	return Key{Door: door, Source: p}, true
}

// Admission is Admit's answer. A refusal is either Busy (a credential post
// from the source is still being checked) or a wait of RetryAfter.
type Admission struct {
	OK         bool
	Busy       bool
	RetryAfter time.Duration
	Sentence   string
	Key        Key
}

// source is one key's record.
type source struct {
	failures  int
	last      time.Time
	waitUntil time.Time
	seen      []string
	// inflight is the source's one credential post slot. It is released by
	// the first drain pass that started after the post was answered.
	inflight   bool
	answered   bool
	answeredAt uint64
}

// ThrottleDeps are the throttle's collaborators.
type ThrottleDeps struct {
	// Table decides an event's door: a client of the home door counts there,
	// every other client at the app door (F-985-10).
	Table doors.Table
	// Now dates an event's age against the window when it arrives.
	Now func() time.Time
}

// Throttle is the per-source throttle on credential posts. It is fed by the
// drain (events.UserSink and events.PassSink) and consulted by Check. It has
// no method that clears a source.
type Throttle struct {
	home []string
	now  func() time.Time

	mu      sync.Mutex
	sources map[Key]*source
	// started is the newest drain pass that has started.
	started uint64
}

var (
	_ events.UserSink = (*Throttle)(nil)
	_ events.PassSink = (*Throttle)(nil)
	_ Throttler       = (*Throttle)(nil)
)

// NewThrottle checks d and returns an empty throttle.
func NewThrottle(d ThrottleDeps) (*Throttle, error) {
	switch {
	case len(d.Table.Home.Clients) == 0:
		return nil, errors.New("policy: ThrottleDeps.Table has no home door clients")
	case d.Now == nil:
		return nil, errors.New("policy: ThrottleDeps.Now is nil")
	}
	return &Throttle{home: d.Table.Home.Clients, now: d.Now, sources: map[Key]*source{}}, nil
}

// Admit takes addr's credential post slot at door, unless the source is
// waiting or its slot is held.
func (t *Throttle) Admit(door Kind, addr netip.Addr, now time.Time) Admission {
	k, ok := keyOf(door, addr)
	if !ok {
		return Admission{Sentence: sentenceNoSource}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sources[k]
	switch {
	case s != nil && s.waitUntil.After(now):
		left := s.waitUntil.Sub(now)
		return Admission{RetryAfter: left, Sentence: waitSentence(left), Key: k}
	case s != nil && s.inflight:
		return Admission{Busy: true, Key: k}
	case s == nil:
		if s = t.insert(k, now); s == nil {
			return Admission{Busy: true, Key: k}
		}
	}
	s.inflight, s.answered = true, false
	return Admission{OK: true, Key: k}
}

// Answered records that the identity service has answered k's held post: the
// slot is released by the first drain pass that starts after now.
func (t *Throttle) Answered(k Key) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.sources[k]; s != nil && s.inflight {
		s.answered, s.answeredAt = true, t.started
	}
}

// PassStarted records the drain pass that started.
func (t *Throttle) PassStarted(_ context.Context, pass uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.started = max(t.started, pass)
}

// PassEnded releases every slot whose post was answered before this pass
// started: the pass has read that post's event. A pass that failed still
// ends, so posts stay one at a time while the drain is failing (F-985-11).
func (t *Throttle) PassEnded(_ context.Context, pass uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sources {
		if s.inflight && s.answered && pass > s.answeredAt {
			s.inflight, s.answered = false, false
		}
	}
}

// UserEvent counts a failed sign-in against its source and door.
func (t *Throttle) UserEvent(_ context.Context, e events.UserEvent) {
	if e.Type != countedType || !slices.Contains(countedErrors, e.Error) {
		return
	}
	door := App
	if slices.Contains(t.home, e.ClientID) {
		door = Home
	}
	k, ok := keyOf(door, e.IP)
	if !ok {
		return
	}
	now := t.now()
	if now.Sub(e.Time) > sourceFailureWindowLifetime {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sources[k]
	if s == nil {
		if s = t.insert(k, now); s == nil {
			return
		}
	}
	if slices.Contains(s.seen, e.ID) {
		return
	}
	if len(s.seen) == seenPerSource {
		s.seen = s.seen[1:]
	}
	s.seen = append(s.seen, e.ID)
	if s.failures > 0 && e.Time.Sub(s.last) > sourceFailureWindowLifetime {
		s.failures = 0
	}
	s.failures++
	if e.Time.After(s.last) {
		s.last = e.Time
	}
	if s.failures > guessFreeFailures {
		if until := e.Time.Add(waitFor(s.failures)); until.After(s.waitUntil) {
			s.waitUntil = until
		}
	}
}

// Wait is how long addr waits at door from now; 0 when it does not.
func (t *Throttle) Wait(door Kind, addr netip.Addr, now time.Time) time.Duration {
	k, ok := keyOf(door, addr)
	if !ok {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.sources[k]; s != nil && s.waitUntil.After(now) {
		return s.waitUntil.Sub(now)
	}
	return 0
}

// Waiting is the number of sources waiting at door now:
// rasputin_signin_throttled_sources{door}.
func (t *Throttle) Waiting(door Kind, now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for k, s := range t.sources {
		if k.Door == door && s.waitUntil.After(now) {
			n++
		}
	}
	return n
}

// waitFor is the wait the nth failure sets: 60, 120, 240, 480, then 900 s.
func waitFor(n int) time.Duration {
	shift := n - guessFreeFailures - 1
	if shift >= 5 {
		return sourceWaitMaxLifetime
	}
	return min(sourceWaitMinLifetime<<shift, sourceWaitMaxLifetime)
}

// insert adds an empty record for k. At the cap it first evicts every
// expired record (no slot held, no wait running, window passed), then the
// idle record whose last failure is oldest. It returns nil only when every
// record holds a slot. The caller holds mu.
func (t *Throttle) insert(k Key, now time.Time) *source {
	if len(t.sources) >= maxSources {
		for kk, s := range t.sources {
			if !s.inflight && !s.waitUntil.After(now) && now.Sub(s.last) > sourceFailureWindowLifetime {
				delete(t.sources, kk)
			}
		}
	}
	if len(t.sources) >= maxSources {
		var oldest *Key
		var at time.Time
		for kk, s := range t.sources {
			if s.inflight {
				continue
			}
			if oldest == nil || s.last.Before(at) {
				kk := kk
				oldest, at = &kk, s.last
			}
		}
		if oldest == nil {
			return nil
		}
		delete(t.sources, *oldest)
	}
	s := &source{}
	t.sources[k] = s
	return s
}

// waitSentence is the wait refusal's sentence, in whole minutes rounded up.
func waitSentence(left time.Duration) string {
	minutes := int((left + time.Minute - 1) / time.Minute)
	unit := "minutes"
	if minutes == 1 {
		unit = "minute"
	}
	return fmt.Sprintf("Too many sign-in attempts came from this device. Try again in %d %s, or sign in from another device.", minutes, unit)
}
