package busauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// Real embedded server + real callout responder: revoke must close a live
// connection, including one whose authentication is still in flight. The
// HTTP-level functional test (API revoke, removal cascade, other nodes and the
// controlplane's own agent unaffected) is api/internal/api/bus_revoke_test.go.

// busWaitLimit bounds every single wait for an event; each wait fails naming
// what never happened.
const busWaitLimit = 10 * time.Second

// TestRevokeDuringInFlightCallout: the callout has validated the token and not
// yet answered the server when the revoke arrives. The connection must not
// end up usable: the revoke waits for the admission, then closes the
// connection by id — mid-authentication or just after it — and a reconnect
// with the revoked token is refused.
func TestRevokeDuringInFlightCallout(t *testing.T) {
	ctx := context.Background()
	eb := startEnforcedBus(t, "127.0.0.1")
	store := eb.tokens
	tok, id, err := store.MintBound(ctx, "a", "node-a", "compute")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}

	inFlight := make(chan struct{})
	release := make(chan struct{})
	store.sess.afterValidate = func() {
		store.sess.afterValidate = nil // only the first admission; runs under the session lock
		close(inFlight)
		<-release
	}

	type dialResult struct {
		nc  *nats.Conn
		err error
	}
	closed := make(chan struct{})
	dialed := make(chan dialResult, 1)
	go func() {
		nc, err := connect(eb.url, "node-a", tok,
			nats.Timeout(busWaitLimit),
			nats.ClosedHandler(func(*nats.Conn) { close(closed) }))
		dialed <- dialResult{nc, err}
	}()

	select {
	case <-inFlight:
	case <-time.After(busWaitLimit):
		t.Fatalf("the auth callout never reached token validation within %s", busWaitLimit)
	}

	type revokeResult struct {
		n   int
		err error
	}
	revoked := make(chan revokeResult, 1)
	go func() {
		n, err := store.Revoke(ctx, id)
		revoked <- revokeResult{n, err}
	}()
	close(release)

	var r revokeResult
	select {
	case r = <-revoked:
	case <-time.After(busWaitLimit):
		t.Fatalf("Revoke did not return within %s", busWaitLimit)
	}
	if r.err != nil {
		t.Fatalf("Revoke: %v", r.err)
	}
	if r.n != 1 {
		t.Fatalf("Revoke disconnected %d connections, want 1: the in-flight connection was not closed", r.n)
	}

	var d dialResult
	select {
	case d = <-dialed:
	case <-time.After(busWaitLimit):
		t.Fatalf("the client's connect did not return within %s", busWaitLimit)
	}
	if d.err == nil {
		// The kick landed after the server finished authenticating: the
		// connection may have opened, but it must be closed now.
		t.Cleanup(d.nc.Close)
		select {
		case <-closed:
		case <-time.After(busWaitLimit):
			t.Fatalf("connection authenticated concurrently with the revoke is still open after %s (status %v)",
				busWaitLimit, d.nc.Status())
		}
	} else {
		t.Logf("in-flight connection refused at connect: %v", d.err)
	}

	// And the revoked token cannot authenticate again.
	nc, err := connect(eb.url, "node-a", tok)
	if err == nil {
		nc.Close()
		t.Fatal("reconnect with the revoked token was accepted")
	}
	if !errors.Is(err, nats.ErrAuthorization) {
		t.Fatalf("reconnect with the revoked token failed with %v, want an authorization violation", err)
	}
}
