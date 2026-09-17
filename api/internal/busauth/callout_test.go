package busauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// TestResponder_Authorize exercises the trust matrix directly: a valid node id
// and a live token bound to it are both required, for every connection. There
// is no source-address input any more: loopback earned a tokenless pass until
// geekdojo-brain#140, and authorize cannot be handed an address to exempt.
func TestResponder_Authorize(t *testing.T) {
	ctx := context.Background()
	store := newTokenStore(t)
	good, _, err := store.MintBound(ctx, "test", "fw-1")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	revoked, revID, _ := store.MintBound(ctx, "revoked", "fw-1")
	if _, err := store.Revoke(ctx, revID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	bound, _, err := store.MintBound(ctx, "bound", "fw-1")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	legacy, _ := insertLegacyUnbound(t, store, "legacy")

	r := &Responder{tokens: store}

	cases := []struct {
		name           string
		nodeID, token  string
		wantAuthorized bool
	}{
		{"empty node id denied", "", good, false},
		{"empty node id and no token denied", "", "", false},
		{"no token denied (the controlplane's own id earns nothing)", "node-cp", "", false},
		{"valid token", "fw-1", good, true},
		{"no token denied", "fw-1", "", false},
		{"bad token denied", "fw-1", "garbage", false},
		{"revoked token denied", "fw-1", revoked, false},
		{"bound token as its node", "fw-1", bound, true},
		{"bound token as a different node denied", "fw-2", bound, false},
		{"legacy unbound token denied", "fw-1", legacy, false},
		{"legacy unbound token denied as another node", "fw-2", legacy, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := r.authorize("test-server", 1, tc.nodeID, tc.token)
			if ok != tc.wantAuthorized {
				t.Errorf("authorize(%q, token) = %v (%q); want %v",
					tc.nodeID, ok, reason, tc.wantAuthorized)
			}
		})
	}
}

// TestCallout_EndToEnd brings up the real embedded server with AuthEnforce and
// the responder, then drives a client through it: a valid-token connection
// works and is subject-scoped; a connection with no node id is rejected.
func TestCallout_EndToEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	issuer, err := EnsureIssuer(filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatalf("EnsureIssuer: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nats"), 0o755); err != nil {
		t.Fatalf("mkdir nats: %v", err)
	}
	tokens, err := OpenStore(ctx, filepath.Join(dir, "bus.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = tokens.Close() })
	token, _, err := tokens.MintBound(ctx, "fw", "fw-1")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}

	srv, err := bus.Start(ctx, bus.Config{
		Host: "127.0.0.1", Port: -1, // -1 = ephemeral port
		StoreDir:        filepath.Join(dir, "nats"),
		AuthEnforce:     true,
		IssuerPublicKey: issuer.PublicKey(),
		APIUser:         "rasputin-api",
		APIPass:         "test-secret",
	})
	if err != nil {
		t.Fatalf("bus.Start: %v", err)
	}
	t.Cleanup(srv.Stop)

	resp := NewResponder(srv.Conn(), issuer, tokens)
	if err := resp.Start(); err != nil {
		t.Fatalf("responder.Start: %v", err)
	}
	t.Cleanup(resp.Stop)

	url := srv.ClientURL()

	// 1. Valid token → connects, and is scoped: it can round-trip on its own
	//    node subject but a publish to a foreign node raises a permissions
	//    violation.
	permErr := make(chan error, 4)
	nc, err := nats.Connect(url,
		nats.UserInfo("fw-1", token),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { permErr <- e }),
	)
	if err != nil {
		t.Fatalf("valid-token connect: %v", err)
	}
	defer nc.Close()

	sub, err := nc.SubscribeSync("rasputin.node.fw-1.cmd.test")
	if err != nil {
		t.Fatalf("subscribe own scope: %v", err)
	}
	if err := nc.Publish("rasputin.node.fw-1.evt.hello", []byte("hi")); err != nil {
		t.Fatalf("publish own scope: %v", err)
	}
	_ = nc.Flush()
	_ = sub

	// Foreign-subject publish must be denied (permissions violation).
	if err := nc.Publish("rasputin.node.other.evt.x", []byte("nope")); err != nil {
		t.Fatalf("publish call itself shouldn't error synchronously: %v", err)
	}
	_ = nc.Flush()
	select {
	case e := <-permErr:
		if e == nil {
			t.Fatal("expected a permissions violation error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a permissions violation for a foreign-subject publish; none arrived")
	}

	// 2. No node id (no username) → rejected at connect.
	bad, err := nats.Connect(url, nats.Token("whatever"), nats.MaxReconnects(0), nats.Timeout(2*time.Second))
	if err == nil {
		bad.Close()
		t.Fatal("connection with no node id should be rejected")
	}
	// The exact rejection wording varies (authorization violation / timeout);
	// any connect error is a denial. Log it for clarity.
	t.Logf("no-node-id connection rejected as expected: %v", err)
}

// TestMintedJWTBoundsTheReplyGrantExplicitly is the unit test that would have
// caught the bug on its own. Both fields of the response permission have a
// nats-server default that is substituted when we leave the field at zero
// (validateResponsePermissions, server/auth.go), and both defaults are wrong
// for us — so "unset" is never an acceptable answer for either.
//
// Expires is the one that shipped as zero, which the server read as two
// minutes: shorter than every agent work budget, so a slow handler lost the
// right to answer mid-flight and the failure was invisible on both sides.
// MaxMsgs is asserted alongside it because the obvious way to break the fix is
// to rewrite the literal and drop the -1, reintroducing the default of 1.
func TestMintedJWTBoundsTheReplyGrantExplicitly(t *testing.T) {
	issuer, err := EnsureIssuer(t.TempDir())
	if err != nil {
		t.Fatalf("EnsureIssuer: %v", err)
	}
	ukp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	upub, err := ukp.PublicKey()
	if err != nil {
		t.Fatalf("user public key: %v", err)
	}

	r := NewResponder(nil, issuer, nil)
	token, err := r.mintUserJWT(upub, "fw-1")
	if err != nil {
		t.Fatalf("mintUserJWT: %v", err)
	}
	uc, err := jwt.DecodeUserClaims(token)
	if err != nil {
		t.Fatalf("DecodeUserClaims: %v", err)
	}

	if uc.Permissions.Resp == nil {
		t.Fatal("minted credential has no response permission — the agent could not " +
			"reply to any request, since _INBOX is not in Pub.Allow")
	}
	if uc.Permissions.Resp.Expires == 0 {
		t.Fatal("minted credential leaves ResponsePermission.Expires at zero — " +
			"nats-server substitutes 2 minutes, which is shorter than every agent " +
			"work budget, so any handler past 120s is denied its reply")
	}
	if got, want := uc.Permissions.Resp.Expires, proto.BusReplyGrantTTL; got != want {
		t.Errorf("ResponsePermission.Expires = %s, want proto.BusReplyGrantTTL (%s)", got, want)
	}
	if got := uc.Permissions.Resp.MaxMsgs; got != -1 {
		t.Errorf("ResponsePermission.MaxMsgs = %d, want -1 (unlimited); the server's "+
			"default for zero is 1, so a handler that answers twice is denied", got)
	}

	// The fix is a LIFETIME change, not a widening. The subject space must be
	// exactly what it was: this node's own scope, and nothing else. An _INBOX
	// entry here would let a compromised node forge acks for requests the api
	// addressed to a different node.
	for _, subject := range uc.Permissions.Pub.Allow {
		if subject != "rasputin.node.fw-1.>" {
			t.Errorf("Pub.Allow contains %q; the only publishable scope is this node's own. "+
				"Widening it (notably to _INBOX.>) defeats the per-node scoping entirely", subject)
		}
	}
}

// TestReplyGrantExpires is the integration test: the real embedded server, the
// real callout responder, and a fake agent connected as a node with a real
// token. It asserts the actual enforced behaviour rather than the contents of
// a JWT — a reply inside the grant's lifetime lands, a reply after it is
// refused by the bus with a permissions violation while the agent's own
// Msg.Respond reports success.
//
// The TTL is injected at ~200ms so this runs in milliseconds. The production
// value is asserted separately, in TestMintedJWTBoundsTheReplyGrantExplicitly:
// this test proves the mechanism, that one proves the number.
//
// # Why there are no guessed sleeps
//
// nats-server offers no clock to inject: it stamps the grant with time.Now()
// when it delivers the command to the agent, and denies the reply when
// time.Since(stamp) > Expires at the moment it processes the publish
// (client.go deliverMsg / responseAllowed). So every timing claim here is
// derived by bracketing those two server readings with the test's own
// monotonic clock, in the same process:
//
//   - a reading taken BEFORE the api publishes the command is <= the stamp;
//   - a reading taken AFTER the command reaches the agent is >= the stamp;
//   - a reading taken after agent.Flush() returns is >= the server's check,
//     because the server answers the agent's PING only after it has processed
//     (and, if denied, sent -ERR for) every publish ahead of it.
//
// That turns "was this reply inside the grant?" into a checkable fact instead
// of a hope that a loaded machine stays fast. Every wait for something to
// arrive is bounded by waitLimit and fails naming what never came true.
func TestReplyGrantExpires(t *testing.T) {
	const (
		injectedTTL = 200 * time.Millisecond
		// waitLimit bounds each single wait for a message, error or PONG.
		waitLimit = 10 * time.Second
		// controlLimit bounds the whole control: how long we keep trying to get
		// one round trip that provably completes inside the grant.
		controlLimit = 60 * time.Second
	)

	ctx := context.Background()
	dir := t.TempDir()

	issuer, err := EnsureIssuer(filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatalf("EnsureIssuer: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nats"), 0o755); err != nil {
		t.Fatalf("mkdir nats: %v", err)
	}
	tokens, err := OpenStore(ctx, filepath.Join(dir, "bus.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = tokens.Close() })
	token, _, err := tokens.MintBound(ctx, "fw", "fw-1")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}

	srv, err := bus.Start(ctx, bus.Config{
		Host: "127.0.0.1", Port: -1,
		StoreDir:        filepath.Join(dir, "nats"),
		AuthEnforce:     true,
		IssuerPublicKey: issuer.PublicKey(),
		APIUser:         "rasputin-api",
		APIPass:         "test-secret",
	})
	if err != nil {
		t.Fatalf("bus.Start: %v", err)
	}
	t.Cleanup(srv.Stop)

	resp := NewResponder(srv.Conn(), issuer, tokens)
	resp.replyTTL = injectedTTL
	if err := resp.Start(); err != nil {
		t.Fatalf("responder.Start: %v", err)
	}
	t.Cleanup(resp.Stop)

	// The fake agent: connects as a node, and hands every command it receives
	// to the test so the test controls when the reply goes out.
	asyncErr := make(chan error, 64)
	agent, err := nats.Connect(srv.ClientURL(),
		nats.UserInfo("fw-1", token),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) {
			select {
			case asyncErr <- e:
			default: // never block the client's callback goroutine
			}
		}),
	)
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	defer agent.Close()

	commands := make(chan *nats.Msg, 4)
	if _, err := agent.Subscribe("rasputin.node.fw-1.cmd.slow", func(m *nats.Msg) {
		commands <- m
	}); err != nil {
		t.Fatalf("agent subscribe: %v", err)
	}
	if err := agent.Flush(); err != nil {
		t.Fatalf("agent flush: %v", err)
	}

	// The api watches a subject the agent may always publish to. The server
	// routes one connection's publishes in order and the client queues them in
	// order, so once a sentinel the agent sent AFTER its reply reaches the api,
	// the reply — had it been routed — is already sitting in the api's queue.
	const sentinelSubject = "rasputin.node.fw-1.evt.sentinel"
	sentinels, err := srv.Conn().SubscribeSync(sentinelSubject)
	if err != nil {
		t.Fatalf("api subscribe sentinel: %v", err)
	}
	if err := srv.Conn().Flush(); err != nil {
		t.Fatalf("api flush: %v", err)
	}

	// request sends one command from the api's own (fully privileged)
	// connection and returns the command as the agent saw it, the subscription
	// the reply would land on, and a clock reading taken before the send (so it
	// is no later than the server's grant stamp).
	request := func(t *testing.T) (*nats.Msg, *nats.Subscription, time.Time) {
		t.Helper()
		inbox := nats.NewInbox()
		replies, err := srv.Conn().SubscribeSync(inbox)
		if err != nil {
			t.Fatalf("api subscribe inbox: %v", err)
		}
		t.Cleanup(func() { _ = replies.Unsubscribe() })
		if err := srv.Conn().Flush(); err != nil {
			t.Fatalf("api flush: %v", err)
		}
		sent := time.Now()
		if err := srv.Conn().PublishRequest("rasputin.node.fw-1.cmd.slow", inbox, []byte("work")); err != nil {
			t.Fatalf("api request: %v", err)
		}
		if err := srv.Conn().Flush(); err != nil {
			t.Fatalf("api flush: %v", err)
		}
		select {
		case m := <-commands:
			return m, replies, sent
		case <-time.After(waitLimit):
			t.Fatalf("agent never received the command within %s", waitLimit)
			return nil, nil, time.Time{}
		}
	}

	// deniedReply reports whether the server refused the agent's publish to
	// reply. It must be called right after agent.Flush() has returned: the
	// client records a -ERR as its last error while reading, before it can see
	// the PONG that unblocks Flush. The violation text names the subject, and
	// every request uses a fresh inbox, so an older denial cannot match.
	deniedReply := func(reply string) error {
		if e := agent.LastError(); e != nil &&
			errors.Is(e, nats.ErrPermissionViolation) && strings.Contains(e.Error(), reply) {
			return e
		}
		return nil
	}

	// 1. A handler that replies inside the grant must be delivered.
	//    This is the control: it proves the denial below is about the clock and
	//    not about the subject space.
	//
	//    The assertion is on attempts that PROVABLY finished inside the grant:
	//    if the server denied a reply whose whole round trip, measured around
	//    both server clock readings, took no longer than the TTL, that is a real
	//    bug and fails immediately. A denied attempt that took longer than the
	//    TTL is correct behaviour on a stalled machine and proves nothing either
	//    way, so it is repeated — until one attempt is delivered or controlLimit
	//    passes, which fails naming that no attempt ever landed.
	t.Run("reply inside the grant is delivered", func(t *testing.T) {
		deadline := time.Now().Add(controlLimit)
		for attempt := 1; ; attempt++ {
			cmd, replies, sent := request(t)
			// Answer late in the grant, not instantly: a grant that lapses early
			// (say, a unit slip turning 200ms into 1ms) would still pass a reply
			// sent within a millisecond. This is the handler's simulated work,
			// not a wait for anything; the verdict below does not depend on it.
			time.Sleep(injectedTTL / 2)
			if err := cmd.Respond([]byte("done")); err != nil {
				t.Fatalf("agent Respond: %v", err)
			}
			if err := agent.FlushTimeout(waitLimit); err != nil {
				t.Fatalf("agent flush after Respond: %v", err)
			}
			roundTrip := time.Since(sent) // >= server's check - server's stamp

			if denial := deniedReply(cmd.Reply); denial != nil {
				if roundTrip <= injectedTTL {
					t.Fatalf("reply denied although the whole round trip took %s, inside the %s grant: "+
						"the grant is being refused while still live: %v", roundTrip, injectedTTL, denial)
				}
				if time.Now().After(deadline) {
					t.Fatalf("after %d attempts over %s, no reply round trip completed inside the %s grant "+
						"(last took %s and was correctly denied), so the control never ran",
						attempt, controlLimit, injectedTTL, roundTrip)
				}
				t.Logf("attempt %d: round trip took %s, longer than the %s grant, and was correctly "+
					"denied; inconclusive for the control, retrying", attempt, roundTrip, injectedTTL)
				continue
			}

			reply, err := replies.NextMsg(waitLimit)
			if err != nil {
				t.Fatalf("server accepted the reply but the api never got it within %s: %v", waitLimit, err)
			}
			if string(reply.Data) != "done" {
				t.Errorf("reply = %q, want %q", reply.Data, "done")
			}
			return
		}
	})

	// 2. A handler slower than the grant is REFUSED — and refused silently from
	//    its own point of view. This is the shipped bug, in miniature: the
	//    agent's work finished and it had a real answer, the bus dropped it, and
	//    the api saw nothing but its own deadline expiring.
	t.Run("reply after the grant expires is denied", func(t *testing.T) {
		cmd, replies, _ := request(t)
		// The command is in hand, so the server's stamp is at or before now.
		// Holding the reply until strictly more than the TTL has passed on this
		// clock guarantees more than the TTL has passed on the server's by the
		// time it checks. This wait IS the fact under test — the grant's
		// lifetime running out — not a margin for slowness.
		received := time.Now()
		for time.Since(received) <= injectedTTL {
			time.Sleep(injectedTTL - time.Since(received) + time.Millisecond)
		}

		// Msg.Respond is an async publish: it reports success even when the
		// server is about to refuse the message. That nil is exactly why the
		// failure was invisible on the agent, and why bus.Connect now installs
		// an ErrorHandler.
		if err := cmd.Respond([]byte("done, but too late")); err != nil {
			t.Fatalf("agent Respond returned an error; expected the async path: %v", err)
		}
		if err := agent.Publish(sentinelSubject, []byte(cmd.Reply)); err != nil {
			t.Fatalf("agent publish sentinel: %v", err)
		}
		if err := agent.FlushTimeout(waitLimit); err != nil {
			t.Fatalf("agent flush after Respond: %v", err)
		}

		if deniedReply(cmd.Reply) == nil {
			t.Fatalf("server processed the reply without a permissions violation (last error: %v): "+
				"the reply grant did not expire, so this test is not exercising the bug", agent.LastError())
		}

		// Nothing reached the api: the sentinel sent after the reply has
		// arrived, so a routed reply would already be queued ahead of it.
		for {
			s, err := sentinels.NextMsg(waitLimit)
			if err != nil {
				t.Fatalf("the agent's sentinel never reached the api within %s: %v", waitLimit, err)
			}
			if string(s.Data) == cmd.Reply {
				break
			}
		}
		if n, _, err := replies.Pending(); err != nil {
			t.Fatalf("reply subscription pending: %v", err)
		} else if n != 0 {
			reply, _ := replies.NextMsg(waitLimit)
			t.Fatalf("api received %q after the grant expired: the reply grant did not "+
				"expire, so this test is not exercising the bug", reply.Data)
		}

		// And the denial reached the agent's error handler, the path bus.Connect
		// relies on to make it visible.
		timeout := time.After(waitLimit)
		for {
			select {
			case e := <-asyncErr:
				if e == nil {
					t.Fatal("expected a permissions violation, got a nil error")
				}
				if !strings.Contains(e.Error(), cmd.Reply) {
					continue // an earlier, correctly denied control attempt
				}
				if !errors.Is(e, nats.ErrPermissionViolation) &&
					!strings.Contains(strings.ToLower(e.Error()), "permissions violation") {
					t.Errorf("expected a permissions violation, got %v", e)
				}
				t.Logf("expired reply grant denied as expected: %v", e)
				return
			case <-timeout:
				t.Fatalf("no permissions violation for %s reached the agent's error handler within %s",
					cmd.Reply, waitLimit)
			}
		}
	})
}
