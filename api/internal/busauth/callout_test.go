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

// TestResponder_Authorize exercises the trust matrix directly: node-id always
// required; loopback trusted without a token; everyone else needs a live token.
func TestResponder_Authorize(t *testing.T) {
	ctx := context.Background()
	store := newTokenStore(t)
	good, _, err := store.Mint(ctx, "test")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	revoked, revID, _ := store.Mint(ctx, "revoked")
	if err := store.Revoke(ctx, revID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	bound, _, err := store.MintBound(ctx, "bound", "fw-1")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}

	r := &Responder{tokens: store}

	cases := []struct {
		name           string
		nodeID, token  string
		host           string
		wantAuthorized bool
	}{
		{"empty node id denied", "", good, "192.168.1.50", false},
		{"loopback no token trusted", "node-cp", "", "127.0.0.1", true},
		{"loopback ipv6 trusted", "node-cp", "", "::1", true},
		{"remote valid token", "fw-1", good, "192.168.1.50", true},
		{"remote no token denied", "fw-1", "", "192.168.1.50", false},
		{"remote bad token denied", "fw-1", "garbage", "192.168.1.50", false},
		{"remote revoked token denied", "fw-1", revoked, "192.168.1.50", false},
		{"empty node id even on loopback denied", "", "", "127.0.0.1", false},
		{"bound token as its node", "fw-1", bound, "192.168.1.50", true},
		{"bound token as a different node denied", "fw-2", bound, "192.168.1.50", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := r.authorize(tc.nodeID, tc.token, tc.host)
			if ok != tc.wantAuthorized {
				t.Errorf("authorize(%q,token,%q) = %v (%q); want %v",
					tc.nodeID, tc.host, ok, reason, tc.wantAuthorized)
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
	token, _, err := tokens.Mint(ctx, "fw")
	if err != nil {
		t.Fatalf("Mint: %v", err)
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
func TestReplyGrantExpires(t *testing.T) {
	const injectedTTL = 200 * time.Millisecond

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
	token, _, err := tokens.Mint(ctx, "fw")
	if err != nil {
		t.Fatalf("Mint: %v", err)
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
	asyncErr := make(chan error, 8)
	agent, err := nats.Connect(srv.ClientURL(),
		nats.UserInfo("fw-1", token),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { asyncErr <- e }),
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

	// request sends one command from the api's own (fully privileged)
	// connection and returns the command as the agent saw it, plus the
	// subscription the reply would land on.
	request := func(t *testing.T) (*nats.Msg, *nats.Subscription) {
		t.Helper()
		inbox := nats.NewInbox()
		replies, err := srv.Conn().SubscribeSync(inbox)
		if err != nil {
			t.Fatalf("api subscribe inbox: %v", err)
		}
		if err := srv.Conn().PublishRequest("rasputin.node.fw-1.cmd.slow", inbox, []byte("work")); err != nil {
			t.Fatalf("api request: %v", err)
		}
		if err := srv.Conn().Flush(); err != nil {
			t.Fatalf("api flush: %v", err)
		}
		select {
		case m := <-commands:
			return m, replies
		case <-time.After(5 * time.Second):
			t.Fatal("agent never received the command")
			return nil, nil
		}
	}

	drain := func() {
		for {
			select {
			case <-asyncErr:
			default:
				return
			}
		}
	}

	// 1. A fast handler — replies well inside the grant — must be delivered.
	//    This is the control: it proves the denial below is about the clock and
	//    not about the subject space.
	t.Run("reply inside the grant is delivered", func(t *testing.T) {
		drain()
		cmd, replies := request(t)
		if err := cmd.Respond([]byte("done")); err != nil {
			t.Fatalf("agent Respond: %v", err)
		}
		reply, err := replies.NextMsg(2 * time.Second)
		if err != nil {
			t.Fatalf("api never got the reply: %v", err)
		}
		if string(reply.Data) != "done" {
			t.Errorf("reply = %q, want %q", reply.Data, "done")
		}
		select {
		case e := <-asyncErr:
			t.Errorf("unexpected async error on a reply inside the grant: %v", e)
		case <-time.After(200 * time.Millisecond):
		}
	})

	// 2. A handler slower than the grant is REFUSED — and refused silently from
	//    its own point of view. This is the shipped bug, in miniature: the
	//    agent's work finished and it had a real answer, the bus dropped it, and
	//    the api saw nothing but its own deadline expiring.
	t.Run("reply after the grant expires is denied", func(t *testing.T) {
		drain()
		cmd, replies := request(t)

		time.Sleep(injectedTTL * 3)

		// Msg.Respond is an async publish: it reports success even when the
		// server is about to refuse the message. That nil is exactly why the
		// failure was invisible on the agent, and why bus.Connect now installs
		// an ErrorHandler.
		if err := cmd.Respond([]byte("done, but too late")); err != nil {
			t.Fatalf("agent Respond returned an error; expected the async path: %v", err)
		}

		if reply, err := replies.NextMsg(2 * time.Second); err == nil {
			t.Fatalf("api received %q after the grant expired: the reply grant did not "+
				"expire, so this test is not exercising the bug", reply.Data)
		}

		select {
		case e := <-asyncErr:
			if e == nil {
				t.Fatal("expected a permissions violation, got a nil error")
			}
			if !errors.Is(e, nats.ErrPermissionViolation) &&
				!strings.Contains(strings.ToLower(e.Error()), "permissions violation") {
				t.Errorf("expected a permissions violation, got %v", e)
			}
			t.Logf("expired reply grant denied as expected: %v", e)
		case <-time.After(3 * time.Second):
			t.Fatal("no permissions violation reached the agent's error handler")
		}
	})
}
