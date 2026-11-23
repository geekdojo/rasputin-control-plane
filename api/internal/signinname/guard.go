package signinname

import (
	"net/netip"
	"time"
)

// State is the guard's verdict on the name.
type State string

// The three states (the metric's {state} label values).
const (
	// StateOK: probing finished, the responder is answering, and no other
	// host's record for the name is live.
	StateOK State = "ok"
	// StateConflict: another host's record for the name, with data that is not
	// ours, is live. Nothing is answered.
	StateConflict State = "conflict"
	// StateUnpublished: anything else. Cause says why.
	StateUnpublished State = "unpublished"
)

// Cause is why the name is unpublished.
type Cause string

// The causes of StateUnpublished.
const (
	// CauseNone is the cause of every state but StateUnpublished.
	CauseNone Cause = ""
	// CauseNoAddress: the control plane has no usable LAN address.
	CauseNoAddress Cause = "no-lan-address"
	// CauseOpenFailed: the socket on the LAN link could not be opened.
	CauseOpenFailed Cause = "open-failed"
	// CauseStopped: the responder stopped on a panic or a read error. It does
	// not restart itself.
	CauseStopped Cause = "stopped"
	// CauseRefused: the cluster id cannot carry a sign-in name.
	CauseRefused Cause = "refused"
	// CauseProbing: probing is under way, or about to start again.
	CauseProbing Cause = "probing"
)

// Status is the guard's answer at one moment.
type Status struct {
	State State
	Cause Cause
	// Owner is the address another host's record claims for the name, in
	// StateConflict.
	Owner netip.Addr
	// Since is when the state began.
	Since time.Time
}

// ownerRecord is another host's record for our name, tracked while we concede
// it. The zero value is no record.
type ownerRecord struct {
	// addr is the address the record claims for the name.
	addr netip.Addr
	// src is the host that sent it.
	src netip.Addr
	// ttl is the lifetime it announced, capped at maxOwnerTTL.
	ttl time.Duration
	// heard is when the record was last heard: its lifetime runs from here.
	heard time.Time
	// since is when the conflict began.
	since time.Time
	// queries is how many §5.2 maintenance queries were sent since heard.
	queries int
}

// expires is when the record is gone if it is not heard again.
func (o ownerRecord) expires() time.Time { return o.heard.Add(o.ttl) }

// live reports whether the record is still believed at now.
func (o ownerRecord) live(now time.Time) bool {
	return o.addr.IsValid() && now.Before(o.expires())
}

// facts are what the guard decides on.
type facts struct {
	// fault is the responder's own failure, or CauseNone.
	fault Cause
	// answering is set once probing has won, and cleared by a conflict, an
	// address loss or a fault.
	answering bool
	// since is when fault, answering or probing last changed.
	since time.Time
	// owner is the record we concede to, or the zero value.
	owner ownerRecord
}

// classify is the guard: a pure function of the facts and the time. Like the
// agent's nameguard, it decides on facts and never on a timer; the only time it
// reads is the owner record's own announced lifetime.
func classify(f facts, now time.Time) Status {
	switch {
	case f.fault != CauseNone:
		return Status{State: StateUnpublished, Cause: f.fault, Since: f.since}
	case f.owner.live(now):
		return Status{State: StateConflict, Owner: f.owner.addr, Since: f.owner.since}
	case f.answering:
		return Status{State: StateOK, Since: f.since}
	}
	since := f.since
	if f.owner.addr.IsValid() && f.owner.expires().After(since) {
		// The owner's record has run out and the loop has not re-probed yet.
		since = f.owner.expires()
	}
	return Status{State: StateUnpublished, Cause: CauseProbing, Since: since}
}
