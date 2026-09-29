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

func (a admitRecorder) Admit(ctx context.Context, conn Conn, plaintext, presentedNodeID string) (bool, error) {
	ok, err := a.inner.Admit(ctx, conn, plaintext, presentedNodeID)
	if ok && err == nil {
		select {
		case a.admits <- admission{cid: conn.CID, nodeID: presentedNodeID, at: time.Now()}:
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
	// cid is the server-assigned id of the connection the client is on after
	// a reconnect, read inside the reconnect handler (GetClientID). Set only
	// on "reconnected".
	cid uint64
	// at is when the callback ran.
	at time.Time
}

// TC-517-24 (F-517-04): TestExpiredUserJWT_ServerDisconnects_ReconnectReauthenticates proves the
// behaviour, against the real embedded nats-server with enforced auth and the
// real callout responder: when a callout-minted user JWT expires, the SERVER
// closes the connection and tells the client its authentication expired, and
// the client's reconnect is admitted only by authenticating through the
// callout again — as a new connection with a freshly minted, again-bounded
// credential. Two cycles run, so the re-minted credential is shown to expire
// too.
//
// The lifetime is injected at 2s (production's 24h is asserted above). There
// are no sleeps: every step waits on an event — the client's callbacks and the
// callout's admission — each bounded by a hard deadline that fails naming what
// never happened.
//
// # Why the client's own events prove the SERVER closed the connection
//
// nats-server ends an expired credential's session in one place:
// client.authExpired sends "-ERR 'User Authentication Expired'" and then closes
// the connection (nats-server v2.14.6 server/client.go:2500-2503). The client
// receives that error as nats.ErrAuthExpired. Under IgnoreAuthErrorAbort — set
// below, as the agent sets it — nats.go does not close the connection itself on
// an auth error: processAuthError answers "do not abort" (nats.go v1.53.1
// nats.go:4077-4091), so processErr takes the reconnect path rather than
// nc.close (nats.go:4327, 4336). The "disconnected" the client then observes
// is therefore the server's close, not its own. The id of the connection that
// expired is the one the client was on: it is read in the connect and
// reconnect handlers only (GetClientID in an error callback can already return
// the next connection's id), carried in event order, and must equal the
// connection the callout admitted.
//
// # The lower bound on when the server closed
//
// JWT expiry is whole Unix seconds. The minter stamps
// Expires = floor(mint + TTL); the server, on accepting the credential at s,
// arms a timer for Expires - floor(s) seconds. Since s >= mint, the timer fires
// more than TTL - 1s after the mint, and the admission is recorded before the
// mint. So an expiry the client observed less than TTL - 1s after the
// admission was not the expiry, whatever it was told; observing it later than
// the server sent it only makes the interval longer.
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
	token, _, err := eb.tokens.MintBound(context.Background(), "expiry", node, "compute")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}

	events := make(chan clientEvent, 64)
	push := func(e clientEvent) {
		e.at = time.Now()
		select {
		case events <- e:
		default: // never block the client's dispatcher; a dropped event fails the wait for it
		}
	}
	// Configured as the agent configures its own connection
	// (agent/internal/bus/client.go): reconnect forever, including through
	// auth errors.
	nc, err := nats.Connect(eb.url, busKit.Option,
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
		nats.ReconnectHandler(func(c *nats.Conn) {
			cid, _ := c.GetClientID() // 0 when unknown, which matches no admission
			push(clientEvent{kind: "reconnected", cid: cid})
		}),
	)
	if err != nil {
		t.Fatalf("node connect: %v", err)
	}
	t.Cleanup(nc.Close)
	// The connection the client is on, read at connect and, from the event
	// stream, at every reconnect.
	current, err := nc.GetClientID()
	if err != nil {
		t.Fatalf("client id at connect: %v", err)
	}

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
	if current != admitted.cid {
		t.Fatalf("the client is on connection %d, the callout admitted %d", current, admitted.cid)
	}
	for cycle := 1; cycle <= cycles; cycle++ {
		// 1. The server tells the client its credential expired, on the
		//    connection the callout admitted, and not before it could have.
		e := nextClientEvent("error", "cycle expiry reason")
		if !errors.Is(e.err, nats.ErrAuthExpired) {
			t.Fatalf("cycle %d: client was told %v, want %v", cycle, e.err, nats.ErrAuthExpired)
		}
		if current != admitted.cid {
			t.Fatalf("cycle %d: the expiry arrived on connection %d, the callout admitted %d", cycle, current, admitted.cid)
		}
		if lived := e.at.Sub(admitted.at); lived <= injectedTTL-time.Second {
			t.Fatalf("cycle %d: connection %d expired %s after admission, before its %s JWT could have expired",
				cycle, admitted.cid, lived, injectedTTL)
		}

		// 2. The server closed it: under IgnoreAuthErrorAbort the client does
		//    not close itself on an auth error (see the doc comment).
		nextClientEvent("disconnected", "client observing the expiry disconnect")

		// 3. Getting back on means authenticating through the callout again:
		//    a new connection, admitted by the token check, then connected.
		next := nextAdmission("reconnect after expiry")
		if next.cid == admitted.cid {
			t.Fatalf("cycle %d: reconnect admitted under the expired connection's id %d", cycle, next.cid)
		}
		back := nextClientEvent("reconnected", "client reconnecting after expiry")
		if back.cid != next.cid {
			t.Fatalf("cycle %d: the client reconnected as %d, the callout admitted %d", cycle, back.cid, next.cid)
		}
		current = back.cid
		t.Logf("cycle %d: connection %d expired and closed by the server; reconnect re-authenticated as %d",
			cycle, admitted.cid, next.cid)
		admitted = next
	}
}
