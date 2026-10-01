package busauth

import (
	"fmt"

	"github.com/nats-io/nats.go"
)

// AdmissionBus is what StartAdmission needs of the bus: the api's in-process
// connection the responder subscribes on, and the server-side disconnect a
// revoke uses. *bus.Server is one.
type AdmissionBus interface {
	Disconnector
	Conn() *nats.Conn
}

// StartAdmission starts admitting agents to the bus: it records every
// connection the callout admits so a revoke can close it, then starts the
// auth-callout responder. Until it returns, no agent can join.
//
// Call it AFTER every start-up subscriber of agent-published subjects
// (rasputin.node.*: heartbeats, registrations, metrics, IDS events, the BMC
// reconcile and status seed) is subscribed, on the same connection. The server
// applies one connection's subscriptions in order, so every one of them is in
// place before the callout subscription that admits the first agent, and no
// registration an agent sends on joining is dropped for want of a listener
// (geekdojo/geekdojo-brain#623). Admission is the last bus step of start-up.
//
// With enforce false it starts nothing and returns a stop that does nothing:
// with bus auth off the server admits at bus start, before any subscriber can
// exist.
//
// A responder that cannot subscribe is an error the caller must treat as
// fatal: no node can join. stop ends admission; call it before any subscriber
// goes away.
func StartAdmission(enforce bool, b AdmissionBus, issuer *Issuer, tokens *Store) (stop func(), err error) {
	if !enforce {
		return func() {}, nil
	}
	tokens.TrackSessions(b)
	responder := NewResponder(b.Conn(), issuer, tokens)
	if err := responder.Start(); err != nil {
		return nil, fmt.Errorf("bus admission: %w", err)
	}
	return responder.Stop, nil
}
