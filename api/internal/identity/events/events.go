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
// A pass reads every page before it delivers anything, then delivers oldest
// first, then stores the new mark. So a failure on any page delivers nothing
// and leaves the mark where it was, and the next pass delivers each missed
// event once. A failed pass sets the history-behind fact, with one WARN per
// outage; a good pass clears it.
//
// Nothing here logs an event's body, a user id or an address.
package events

import (
	"context"
	"net/netip"
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

// Signal is the dirty signal: a capacity-one channel, so any number of marks
// while a pass runs make exactly one more pass. It is built before the
// identity client is wired, so the Admin API decorator can mark it, and it is
// safe for concurrent use.
type Signal struct{ ch chan struct{} }

// NewSignal returns an unmarked signal.
func NewSignal() *Signal { return &Signal{ch: make(chan struct{}, 1)} }

// MarkDirty records that new events may be stored. It never blocks.
func (s *Signal) MarkDirty() {
	select {
	case s.ch <- struct{}{}:
	default:
	}
}
