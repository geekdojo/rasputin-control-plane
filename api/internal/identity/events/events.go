// Package events is the sign-in history drain (geekdojo/geekdojo-brain#985,
// Identity 4.3; signin-origin.md §5.2, lifecycle.md §5.4): it pages the
// identity service's stored user and admin events from a stored high-water
// mark and hands each new one, once, to its sinks.
//
// It runs on facts only (ARCH-FACTS). A pass runs when the dirty signal is
// marked: a forwarded request that produces events, an Admin API write that
// completed, the api's start, and the identity service becoming ready. Marks
// made while a pass runs coalesce into one more pass. There is no ticker; the
// only bounds are the identity client's per-call ones.
//
// A pass reads the stream oldest first from its mark's floor, by time and
// never by offset (the service's order has no tie-breaker), and reads every
// page before it delivers anything, then delivers each event it has not
// delivered before, oldest first, then stores the new mark. The floor never
// passes the start of a request still open (Signal), so an event committed
// after a later-stamped one is still read. A failure on any page delivers
// nothing and leaves the mark where it was, and the next pass delivers each
// missed event once. A failed pass sets the history-behind fact, with one WARN per
// outage; a good pass clears it.
//
// Nothing here logs an event's body, a user id or an address.
package events

import (
	"context"
	"net/netip"
	"sync"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
)

// UserEvent is one stored user event, as the drain reads it.
type UserEvent struct {
	ID       string
	Time     time.Time
	Type     string
	ClientID string
	UserID   string
	Error    string
	// IP is the event's ipAddress: the address the door wrote in
	// X-Forwarded-For. It is the zero Addr when the event carries none, or
	// one that does not parse.
	IP netip.Addr
	// CredentialType is the event's credential_type detail, "" when it has
	// none: a credential event's type (otp, webauthn, ...).
	CredentialType string
}

// AdminEvent is one stored admin event. It has no sink until #323.
type AdminEvent struct {
	ID            string
	Time          time.Time
	OperationType string
	ResourceType  string
}

// UserSink takes each new user event once, oldest first.
type UserSink interface {
	UserEvent(ctx context.Context, e UserEvent)
}

// AdminSink takes each new admin event once, oldest first.
type AdminSink interface {
	AdminEvent(ctx context.Context, e AdminEvent)
}

// PassSink hears each pass start and end, by its number. A pass that failed
// still ends.
type PassSink interface {
	PassStarted(ctx context.Context, pass uint64)
	PassEnded(ctx context.Context, pass uint64)
}

// Admin is the one Admin API call the drain makes: *idclient.Session's.
type Admin interface {
	Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error)
}

// Marks stores the two high-water marks: *setup.Store.
type Marks interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// The settings keys of the two marks.
const (
	UserMarkKey  = "identity.events.user_mark"
	AdminMarkKey = "identity.events.admin_mark"
)

// Signal is the drain's fact source. Its dirty half is a capacity-one
// channel, so any number of marks while a pass runs make exactly one more
// pass. Its open half counts the requests that can store an event and have
// not been answered yet, with the time each began: a request's events are
// committed before its answer completes (Keycloak 26.8.2's CloseSessionFilter
// commits the request's transaction before the response is closed, and an
// error event is stored in a transaction of its own before that), but each
// is stamped with its time before it commits, so two requests can commit out
// of time order. A pass therefore never moves its mark past the start of the
// oldest request still open (horizon). It is built before the identity
// client is wired, so the Admin API decorator can use it, and it is safe for
// concurrent use.
type Signal struct {
	ch  chan struct{}
	now func() time.Time

	mu   sync.Mutex
	open map[uint64]int64
	next uint64
}

// NewSignal returns an unmarked signal with no request open. now is the
// clock request starts are read from: the host clock the identity service
// stamps its events with.
func NewSignal(now func() time.Time) *Signal {
	return &Signal{ch: make(chan struct{}, 1), now: now, open: map[uint64]int64{}}
}

// MarkDirty records that new events may be stored. It never blocks.
func (s *Signal) MarkDirty() {
	select {
	case s.ch <- struct{}{}:
	default:
	}
}

// Begin records that a request that can store an event is about to be sent.
// The caller calls end once the request's answer has completed (or failed),
// before it marks the signal dirty; end may be called more than once.
func (s *Signal) Begin() (end func()) {
	s.mu.Lock()
	s.next++
	id := s.next
	s.open[id] = s.now().UnixMilli()
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.open, id)
		s.mu.Unlock()
	}
}

// horizon is the time, in milliseconds, before which every event is already
// visible: the start of the oldest open request, or now when none is open.
// An event is stamped no earlier than its request began, and every request
// that began earlier has been answered, so its events are committed.
func (s *Signal) horizon() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.now().UnixMilli()
	for _, start := range s.open {
		h = min(h, start)
	}
	return h
}
