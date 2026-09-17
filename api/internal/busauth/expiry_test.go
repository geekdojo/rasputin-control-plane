package busauth

// The auth callout mints every connection a user JWT that expires mintedTTL
// (24h) after it is minted (geekdojo/geekdojo-brain#107). Revoke's
// force-disconnect is the control against a stolen join token; this lifetime
// is its backstop, and it is only a backstop if nats-server really closes a
// connection whose JWT has expired, and the client can only get back on by
// authenticating through the callout again. These tests pin both halves: the
// number the credential carries, and what the server does when it runs out.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// mintWithinOneSecond mints a user JWT and returns its claims with a clock
// reading taken just before the mint. JWT times are whole Unix seconds, so
// when the readings on both sides of the mint fall in the same second, the
// second the minter read is known exactly and the expiry can be asserted with
// equality rather than a tolerance. A mint that straddles a second boundary is
// retried; the loop is bounded and fails naming what never happened.
func mintWithinOneSecond(t *testing.T, r *Responder, userNkey string) (*jwt.UserClaims, time.Time) {
	t.Helper()
	deadline := time.Now().Add(busWaitLimit)
	for {
		before := time.Now()
		token, err := r.mintUserJWT(userNkey, "fw-1")
		after := time.Now()
		if err != nil {
			t.Fatalf("mintUserJWT: %v", err)
		}
		if before.Unix() == after.Unix() {
			uc, err := jwt.DecodeUserClaims(token)
			if err != nil {
				t.Fatalf("DecodeUserClaims: %v", err)
			}
			return uc, before
		}
		if time.Now().After(deadline) {
			t.Fatalf("no mint completed within a single wall-clock second in %s", busWaitLimit)
		}
	}
}

// TestMintedUserJWTExpiresTTLAfterMint proves the number: the credential the
// callout mints expires exactly 24h after the second it was minted in, from
// the production constructor and from a zero-value Responder alike (a zero
// Expires would be read by nats-server as "never"), and the lifetime the
// integration test below injects is the lifetime the credential carries.
//
// The want values are literals, not mintedTTL: changing the constant is a
// decision this test should make someone notice.
func TestMintedUserJWTExpiresTTLAfterMint(t *testing.T) {
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

	injected := NewResponder(nil, issuer, nil)
	injected.userTTL = 90 * time.Second

	cases := []struct {
		name string
		r    *Responder
		want time.Duration
	}{
		{"production constructor mints 24h", NewResponder(nil, issuer, nil), 24 * time.Hour},
		{"zero-value responder still mints 24h", &Responder{issuer: issuer}, 24 * time.Hour},
		{"injected lifetime is the lifetime minted", injected, 90 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uc, minted := mintWithinOneSecond(t, tc.r, upub)
			if uc.Expires == 0 {
				t.Fatal("minted user JWT has no expiry: nats-server would never close the connection")
			}
			if got, want := uc.Expires, minted.Add(tc.want).Unix(); got != want {
				t.Errorf("Expires = %d, want %d (mint second %d + %s)", got, want, minted.Unix(), tc.want)
			}
			if got, want := uc.Expires-uc.IssuedAt, int64(tc.want/time.Second); got != want {
				t.Errorf("Expires - IssuedAt = %ds, want %ds", got, want)
			}
		})
	}
}

// admission is one token connection the callout admitted.
type admission struct {
	cid    uint64
	nodeID string
	at     time.Time // taken after the token validated, so before the JWT was minted
}

// admitRecorder passes every call to the real validator and reports each
// admitted connection, so the test can see a reconnect go through the callout.
type admitRecorder struct {
	inner  Validator
	admits chan<- admission
}

func (a admitRecorder) Admit(ctx context.Context, serverID string, cid uint64, plaintext, presentedNodeID string) (bool, error) {
	ok, err := a.inner.Admit(ctx, serverID, cid, plaintext, presentedNodeID)
	if ok && err == nil {
		select {
		case a.admits <- admission{cid: cid, nodeID: presentedNodeID, at: time.Now()}:
		default: // never block the callout; a dropped admission fails the wait for it
		}
	}
	return ok, err
}

// clientEvent is one callback from the node's connection, in delivery order
// (nats.go runs every async callback on one dispatcher, in the order queued).
type clientEvent struct {
	kind string // "error", "disconnected" or "reconnected"
	err  error
}

// TestExpiredUserJWT_ServerDisconnects_ReconnectReauthenticates proves the
// behaviour, against the real embedded nats-server with enforced auth and the
// real callout responder: when a callout-minted user JWT expires, the SERVER
// closes the connection and tells the client its authentication expired, and
// the client's reconnect is admitted only by authenticating through the
// callout again — as a new connection with a freshly minted, again-bounded
// credential. Two cycles run, so the re-minted credential is shown to expire
// too.
//
// The lifetime is injected at 2s (production's 24h is asserted above). There
// are no sleeps: every step waits on an event — the server's own disconnect
// advisory, the client's callbacks, the callout's admission — each bounded by
// a hard deadline that fails naming what never happened.
//
// # The lower bound on when the server closed
//
// JWT expiry is whole Unix seconds. The minter stamps
// Expires = floor(mint + TTL); the server, on accepting the credential at s,
// arms a timer for Expires - floor(s) seconds. Since s >= mint, the timer fires
// more than TTL - 1s after the mint, and the admission is recorded before the
// mint. So a close observed less than TTL - 1s after the admission was not the
// expiry, whatever the client was told.
func TestExpiredUserJWT_ServerDisconnects_ReconnectReauthenticates(t *testing.T) {
	const (
		injectedTTL = 2 * time.Second
		cycles      = 2
		node        = "node-exp"
	)
	waitLimit := injectedTTL + busWaitLimit

	admits := make(chan admission, 64)
	// Loopback: every connection goes through the token check and so through
	// the admission observed here (geekdojo-brain#140).
	eb := startEnforcedBus(t, "127.0.0.1", func(r *Responder) {
		r.userTTL = injectedTTL
		r.tokens = admitRecorder{inner: r.tokens, admits: admits}
	})
	token, _, err := eb.tokens.MintBound(context.Background(), "expiry", node)
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}

	serverClosed := make(chan uint64, 64)
	if err := eb.srv.OnClientDisconnect(func(cid uint64) {
		select {
		case serverClosed <- cid:
		default: // never block the api's connection; a dropped close fails the wait for it
		}
	}); err != nil {
		t.Fatalf("OnClientDisconnect: %v", err)
	}

	events := make(chan clientEvent, 64)
	push := func(e clientEvent) {
		select {
		case events <- e:
		default: // never block the client's dispatcher; a dropped event fails the wait for it
		}
	}
	// Configured as the agent configures its own connection
	// (agent/internal/bus/client.go): reconnect forever, including through
	// auth errors.
	nc, err := nats.Connect(eb.url,
		nats.Name("rasputin-agent/"+node),
		nats.UserInfo(node, token),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(50*time.Millisecond),
		nats.IgnoreAuthErrorAbort(),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			push(clientEvent{kind: "error", err: err})
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			push(clientEvent{kind: "disconnected", err: err})
		}),
		nats.ReconnectHandler(func(*nats.Conn) {
			push(clientEvent{kind: "reconnected"})
		}),
	)
	if err != nil {
		t.Fatalf("node connect: %v", err)
	}
	t.Cleanup(nc.Close)

	nextAdmission := func(what string) admission {
		t.Helper()
		select {
		case a := <-admits:
			if a.nodeID != node {
				t.Fatalf("%s: callout admitted node %q, want %q", what, a.nodeID, node)
			}
			return a
		case <-time.After(waitLimit):
			t.Fatalf("%s: the callout admitted no connection within %s", what, waitLimit)
			return admission{}
		}
	}
	nextClientEvent := func(want, what string) clientEvent {
		t.Helper()
		select {
		case e := <-events:
			if e.kind != want {
				t.Fatalf("%s: client saw %s (%v), want %s", what, e.kind, e.err, want)
			}
			return e
		case <-time.After(waitLimit):
			t.Fatalf("%s: client saw no %s within %s", what, want, waitLimit)
			return clientEvent{}
		}
	}

	admitted := nextAdmission("initial connect")
	for cycle := 1; cycle <= cycles; cycle++ {
		// 1. The server closes the connection it authenticated, by itself.
		deadline := time.After(waitLimit)
	closed:
		for {
			select {
			case cid := <-serverClosed:
				if cid == admitted.cid {
					break closed
				}
				t.Logf("cycle %d: server closed unrelated connection %d", cycle, cid)
			case <-deadline:
				t.Fatalf("cycle %d: server did not close connection %d within %s of its admission: "+
					"an expired callout-minted user JWT does not end the session", cycle, admitted.cid, waitLimit)
			}
		}
		if lived := time.Since(admitted.at); lived <= injectedTTL-time.Second {
			t.Fatalf("cycle %d: server closed connection %d %s after admission, before its %s JWT could have expired",
				cycle, admitted.cid, lived, injectedTTL)
		}

		// 2. It told the client why: the credential expired, nothing else.
		if e := nextClientEvent("error", "cycle expiry reason"); !errors.Is(e.err, nats.ErrAuthExpired) {
			t.Fatalf("cycle %d: client was told %v, want %v", cycle, e.err, nats.ErrAuthExpired)
		}
		nextClientEvent("disconnected", "client observing the expiry disconnect")

		// 3. Getting back on means authenticating through the callout again:
		//    a new connection, admitted by the token check, then connected.
		next := nextAdmission("reconnect after expiry")
		if next.cid == admitted.cid {
			t.Fatalf("cycle %d: reconnect admitted under the expired connection's id %d", cycle, next.cid)
		}
		nextClientEvent("reconnected", "client reconnecting after expiry")
		t.Logf("cycle %d: connection %d expired and closed by the server; reconnect re-authenticated as %d",
			cycle, admitted.cid, next.cid)
		admitted = next
	}
}
