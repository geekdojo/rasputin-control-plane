package busauth

// The real embedded server, auth enforced, the real callout responder: the
// two halves of geekdojo/geekdojo-brain#500 on the wire.
//
//   - A node's credential cannot publish on its OWN command lane, while the
//     api's connection still can and the node still receives commands there.
//   - A second connection presenting the same join token takes the session:
//     the newest wins, the older is disconnected, and the survivor works.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// TestBus_ANodeCannotPublishOnItsOwnCommandLane: the node subscribes to its
// cmd lane (as the agent does) and the api publishes there (as the api does),
// both of which must keep working. The node publishing there is refused by the
// broker, and the message never reaches the api.
func TestBus_ANodeCannotPublishOnItsOwnCommandLane(t *testing.T) {
	ctx := context.Background()
	eb := startEnforcedBus(t, "127.0.0.1")
	api := eb.srv.Conn()

	tok, _, err := eb.tokens.MintBound(ctx, "compute", "compute-1", "compute")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}

	// Permission violations arrive asynchronously; capture them.
	violations := make(chan error, 4)
	node, err := connect(eb.url, "compute-1", tok,
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			select {
			case violations <- err:
			default:
			}
		}))
	if err != nil {
		t.Fatalf("compute-1 connect: %v", err)
	}
	defer node.Close()

	// What the agent legitimately does still works, in both directions.
	assertNodeRoundTrip(t, api, node, "compute-1")

	// The api watches the whole cmd lane; nothing the node publishes there may
	// arrive.
	watch, err := api.SubscribeSync("rasputin.node.compute-1.cmd.>")
	if err != nil {
		t.Fatalf("api subscribe: %v", err)
	}
	defer func() { _ = watch.Unsubscribe() }()
	if err := api.Flush(); err != nil {
		t.Fatalf("api flush: %v", err)
	}

	for _, subj := range []string{
		"rasputin.node.compute-1.cmd.system.reboot",
		"rasputin.node.compute-1.cmd.storage.claim",
		"rasputin.node.compute-1.cmd.update.install",
	} {
		if err := node.Publish(subj, []byte(`{}`)); err != nil {
			t.Fatalf("publish %s: %v", subj, err)
		}
		if err := node.Flush(); err != nil {
			t.Fatalf("flush after %s: %v", subj, err)
		}
		select {
		case err := <-violations:
			if !strings.Contains(strings.ToLower(err.Error()), "permissions violation") {
				t.Fatalf("publishing %s reported %v, want a permissions violation", subj, err)
			}
		case <-time.After(busWaitLimit):
			t.Fatalf("publishing %s raised no permissions violation within %s", subj, busWaitLimit)
		}
		if msg, err := watch.NextMsg(200 * time.Millisecond); err == nil {
			t.Fatalf("the api received %q from the node on its own command lane", msg.Subject)
		}
	}

	// The refusals cost the node nothing it may do.
	assertNodeRoundTrip(t, api, node, "compute-1")
}

// TestBus_ASecondPresenterTakesTheSession: a token holds one live session.
// Both connections here come from loopback, so this pins the eviction, not the
// two-presenter alert — telling presenters apart needs two addresses, which
// takeover_test.go drives directly.
func TestBus_ASecondPresenterTakesTheSession(t *testing.T) {
	ctx := context.Background()
	eb := startEnforcedBus(t, "127.0.0.1")
	api := eb.srv.Conn()

	tok, _, err := eb.tokens.MintBound(ctx, "compute", "compute-1", "compute")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	otherTok, _, err := eb.tokens.MintBound(ctx, "compute", "compute-2", "compute")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}

	closed := make(chan struct{})
	first, err := connect(eb.url, "compute-1", tok,
		nats.ClosedHandler(func(*nats.Conn) { close(closed) }))
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	defer first.Close()
	assertNodeRoundTrip(t, api, first, "compute-1")

	// A bystander, to prove an eviction reaches only the token it belongs to.
	bystander, err := connect(eb.url, "compute-2", otherTok)
	if err != nil {
		t.Fatalf("compute-2 connect: %v", err)
	}
	defer bystander.Close()

	second, err := connect(eb.url, "compute-1", tok)
	if err != nil {
		t.Fatalf("the second presenter was refused: %v — the newest session must win, never be turned away", err)
	}
	defer second.Close()

	select {
	case <-closed:
	case <-time.After(busWaitLimit):
		t.Fatalf("the first session was still open %s after a second connection presented the same token (status %v)",
			busWaitLimit, first.Status())
	}

	// The survivor is fully on the bus, and the bystander was untouched.
	assertNodeRoundTrip(t, api, second, "compute-1")
	if !bystander.IsConnected() {
		t.Error("another node's session was closed by a takeover that was not its")
	}
}
