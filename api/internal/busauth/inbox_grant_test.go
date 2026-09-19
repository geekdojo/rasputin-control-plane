package busauth

// A node's minted credential must not let it subscribe to the inbox space
// (geekdojo/geekdojo-brain#451). The api makes every request to every node on
// its one connection with nats.go's default _INBOX. prefix, so a node that may
// subscribe to _INBOX.> receives every other node's replies to the api. The
// agent needs no inbox subscription: it never makes a request, it only answers
// them, through the dynamic response (Resp) grant.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// inboxSpace is the subject space nats.go's default inbox prefix puts every
// reply in.
const inboxSpace = "_INBOX.>"

// TestMintedCredentialHasNoInboxSubscribe decodes a minted credential and
// checks its subscribe grants: no allow that overlaps the inbox space (by
// subject matching, so a wider wildcard such as ">" is caught too), and the
// grants the agent does need still present — its own command lane and the
// response permission it answers through.
func TestMintedCredentialHasNoInboxSubscribe(t *testing.T) {
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

	tok, err := NewResponder(nil, issuer, nil).mintUserJWT(upub, "fw-1")
	if err != nil {
		t.Fatalf("mintUserJWT: %v", err)
	}
	uc, err := jwt.DecodeUserClaims(tok)
	if err != nil {
		t.Fatalf("DecodeUserClaims: %v", err)
	}

	for _, s := range uc.Permissions.Sub.Allow {
		if server.SubjectsCollide(s, inboxSpace) {
			t.Errorf("Sub.Allow contains %q, which overlaps %s: the node can read replies "+
				"the api receives from every other node", s, inboxSpace)
		}
	}
	for _, s := range uc.Permissions.Pub.Allow {
		if server.SubjectsCollide(s, inboxSpace) {
			t.Errorf("Pub.Allow contains %q, which overlaps %s: the node can forge replies "+
				"to requests the api sent to other nodes", s, inboxSpace)
		}
	}

	if got, want := []string(uc.Permissions.Sub.Allow), []string{"rasputin.node.fw-1.cmd.>"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Sub.Allow = %q, want exactly %q: the node's own command lane and nothing else", got, want)
	}
	if uc.Permissions.Resp == nil {
		t.Error("minted credential has no response permission: the agent could not answer any request")
	}
}

// TestBus_NodeCannotReadOtherNodesReplies drives the real embedded server with
// auth enforced and the real callout responder. Node A tries to subscribe to
// the inbox space; node B, connected with the agent's own client options,
// answers a real command the api requests. It pins, on the bus itself:
//
//   - A's SUBSCRIBE _INBOX.> is refused with a permissions violation;
//   - the api's request to B completes with B's reply;
//   - A receives nothing on the inbox space;
//   - A still cannot publish to the api's live inbox (the forge stays closed).
//
// Both nodes present bound join tokens, and the bus checks them: it listens on
// loopback, which earns a connection nothing (geekdojo-brain#140).
//
// No sleeps: every "nothing arrived" is made a fact by flushing the connection
// whose publish would have been routed, then the one that would have received
// it — a PONG is queued behind every message routed to that connection before
// it. Every wait is bounded by busWaitLimit and fails naming what never came.
func TestBus_NodeCannotReadOtherNodesReplies(t *testing.T) {
	ctx := context.Background()
	eb := startEnforcedBus(t, "127.0.0.1")
	api := eb.srv.Conn()

	tokenA, _, err := eb.tokens.MintBound(ctx, "node a", "nodea", "compute")
	if err != nil {
		t.Fatalf("MintBound(nodea): %v", err)
	}
	tokenB, _, err := eb.tokens.MintBound(ctx, "node b", "nodeb", "compute")
	if err != nil {
		t.Fatalf("MintBound(nodeb): %v", err)
	}

	// Node B: the agent's connection options (agent/internal/bus/client.go,
	// less its mDNS dialer, which only changes how the address resolves),
	// answering diag.ping the way handlePing does — Msg.Respond, nothing else.
	errsB := make(chan error, 16)
	nodeB, err := nats.Connect(eb.url, agentShapedOptions("nodeb", tokenB, errsB)...)
	if err != nil {
		t.Fatalf("node B (agent-shaped) connect: %v", err)
	}
	t.Cleanup(nodeB.Close)

	const replyB = `{"nodeId":"nodeb","detail":"reply for the api only"}`
	var holdReply atomic.Bool // set by the test once B has answered the first request
	held := make(chan *nats.Msg, 1)
	answered := make(chan string, 4)
	pingB := proto.NodeCmdSubject("nodeb", "diag.ping")
	if _, err := nodeB.Subscribe(pingB, func(m *nats.Msg) {
		if holdReply.Load() {
			held <- m
			return
		}
		if err := m.Respond([]byte(replyB)); err != nil {
			t.Errorf("node B Respond: %v", err)
		}
		answered <- m.Reply
	}); err != nil {
		t.Fatalf("node B subscribe %s: %v", pingB, err)
	}
	if err := nodeB.FlushTimeout(busWaitLimit); err != nil {
		t.Fatalf("node B flush: %v", err)
	}

	// Node A: tries to read the inbox space.
	errsA := make(chan error, 16)
	nodeA, err := connect(eb.url, "nodea", tokenA,
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) {
			select {
			case errsA <- e:
			default: // never block the client's callback goroutine
			}
		}))
	if err != nil {
		t.Fatalf("node A connect: %v", err)
	}
	t.Cleanup(nodeA.Close)

	leaked := make(chan *nats.Msg, 64)
	if _, err := nodeA.ChanSubscribe(inboxSpace, leaked); err != nil {
		t.Fatalf("node A subscribe call itself errored (the server decides, asynchronously): %v", err)
	}
	// The server answers A's PING only after processing the SUB, and the client
	// records a -ERR as its last error before it reads the PONG.
	if err := nodeA.FlushTimeout(busWaitLimit); err != nil {
		t.Fatalf("node A flush: %v", err)
	}
	if !isPermissionViolation(nodeA.LastError(), "Subscription", inboxSpace) {
		t.Errorf("node A's SUBSCRIBE %s was not refused (last error: %v): the minted credential "+
			"lets a node read every other node's replies to the api", inboxSpace, nodeA.LastError())
	} else if err := waitForViolation(errsA, "Subscription", inboxSpace); err != nil {
		t.Errorf("the refused subscribe never reached node A's error handler: %v", err)
	}

	// The api requests node B on its real command subject and gets B's reply.
	reply, err := api.Request(pingB, []byte(`{}`), busWaitLimit)
	if err != nil {
		t.Fatalf("api request to node B on %s: %v — a node must still be able to answer the api", pingB, err)
	}
	if string(reply.Data) != replyB {
		t.Fatalf("api got %q from node B, want %q", reply.Data, replyB)
	}
	var replySubject string
	select {
	case replySubject = <-answered:
	case <-time.After(busWaitLimit):
		t.Fatalf("node B's handler never recorded its answer within %s", busWaitLimit)
	}
	if !strings.HasPrefix(replySubject, "_INBOX.") {
		t.Fatalf("the api's reply subject is %q, not in %s: this test no longer models the api's requests",
			replySubject, inboxSpace)
	}

	// Nothing reached node A. B's flush returns once the server has routed B's
	// reply to every matching subscriber; A's flush then returns only after
	// anything routed to A has been handed to its channel.
	if err := nodeB.FlushTimeout(busWaitLimit); err != nil {
		t.Fatalf("node B flush: %v", err)
	}
	if err := nodeA.FlushTimeout(busWaitLimit); err != nil {
		t.Fatalf("node A flush: %v", err)
	}
	if n := len(leaked); n != 0 {
		m := <-leaked
		t.Errorf("node A received %d message(s) on %s, including %q on %q — node B's reply to the api",
			n, inboxSpace, m.Data, m.Subject)
	}

	// The forge stays closed: A publishes a reply to the api's LIVE inbox while
	// B holds its genuine answer, then B answers. Had the server routed A's
	// publish, the api would have it queued ahead of B's reply and return it.
	holdReply.Store(true)
	type result struct {
		msg *nats.Msg
		err error
	}
	pending := make(chan result, 1)
	go func() {
		m, err := api.Request(pingB, []byte(`{}`), busWaitLimit)
		pending <- result{m, err}
	}()
	var cmd *nats.Msg
	select {
	case cmd = <-held:
	case <-time.After(busWaitLimit):
		t.Fatalf("node B never received the api's second request within %s", busWaitLimit)
	}
	if err := nodeA.Publish(cmd.Reply, []byte(`{"forged":true}`)); err != nil {
		t.Fatalf("node A publish call itself errored (the server decides, asynchronously): %v", err)
	}
	if err := nodeA.FlushTimeout(busWaitLimit); err != nil {
		t.Fatalf("node A flush: %v", err)
	}
	if !isPermissionViolation(nodeA.LastError(), "Publish", cmd.Reply) {
		t.Errorf("node A's publish to the api's inbox %q was not refused (last error: %v)", cmd.Reply, nodeA.LastError())
	}
	if err := cmd.Respond([]byte(replyB)); err != nil {
		t.Fatalf("node B Respond: %v", err)
	}
	select {
	case r := <-pending:
		if r.err != nil {
			t.Fatalf("api's second request to node B: %v", r.err)
		}
		if string(r.msg.Data) != replyB {
			t.Errorf("api's request returned %q, want node B's reply %q: node A's forged reply reached the api",
				r.msg.Data, replyB)
		}
	case <-time.After(2 * busWaitLimit):
		t.Fatalf("api's second request never returned within %s", 2*busWaitLimit)
	}

	// Node B, answering through its Resp grant, was never refused anything.
	select {
	case e := <-errsB:
		t.Errorf("node B (agent-shaped) got an async error: %v", e)
	default:
	}
}

// agentShapedOptions are the connection options the agent's bus client dials
// with (agent/internal/bus/client.go), so a test node behaves on the bus as a
// real agent does. The agent's mDNS dialer is left out: it only resolves
// *.local names, and this test dials an IP.
func agentShapedOptions(nodeID, token string, errs chan<- error) []nats.Option {
	return []nats.Option{
		nats.Name(fmt.Sprintf("rasputin-agent/%s", nodeID)),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.PingInterval(20 * time.Second),
		nats.MaxPingsOutstanding(3),
		nats.IgnoreAuthErrorAbort(),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) {
			select {
			case errs <- e:
			default: // never block the client's callback goroutine
			}
		}),
		nats.UserInfo(nodeID, token),
	}
}

// isPermissionViolation reports whether err is the server refusing op
// ("Subscription" or "Publish") on exactly subject.
func isPermissionViolation(err error, op, subject string) bool {
	return err != nil && errors.Is(err, nats.ErrPermissionViolation) &&
		strings.Contains(err.Error(), fmt.Sprintf("for %s to %q", op, subject))
}

// waitForViolation waits, bounded, for the refusal of op on subject to reach an
// error handler feeding errs.
func waitForViolation(errs <-chan error, op, subject string) error {
	timeout := time.After(busWaitLimit)
	for {
		select {
		case e := <-errs:
			if isPermissionViolation(e, op, subject) {
				return nil
			}
		case <-timeout:
			return fmt.Errorf("no permissions violation for %s to %q within %s", op, subject, busWaitLimit)
		}
	}
}
