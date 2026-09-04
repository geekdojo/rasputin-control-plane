package bus

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// TestDial_ReturnsErrorOnUnreachableURL covers the error path: dialing a URL
// that nobody is listening on must fail quickly and return a wrapped error.
// nats.DefaultURL is :4222 — we point at a port nothing would be on.
//
// We bound the wall-clock so a busy CI doesn't see this as flaky if the
// resolver decides to retry. The contract we're testing is: Dial returns
// *some* error here, not silently blocks forever.
func TestDial_ReturnsErrorOnUnreachableURL(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		done <- New("nats://127.0.0.1:1", "node-x", "", nil, nil).Dial()
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Errorf("expected a connect error against unreachable port")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Dial blocked for > 5s on unreachable URL")
	}
}

// TestNew_EmptyURLAttemptsDefault: when url == "" New substitutes
// nats.DefaultURL. Dial must not reject an empty url with some kind of
// "missing url" error — instead it attempts to dial. On a dev box where
// nothing is listening on :4222 the attempt fails fast; on a dev box where
// the dev NATS happens to be running it succeeds. Either way we never want
// "empty url" as a synchronous error here.
func TestNew_EmptyURLAttemptsDefault(t *testing.T) {
	c := New("", "node-x", "", nil, nil)
	if c.url != nats.DefaultURL {
		t.Fatalf("url = %q, want nats.DefaultURL %q", c.url, nats.DefaultURL)
	}
	done := make(chan error, 1)
	go func() {
		err := c.Dial()
		c.Close()
		done <- err
	}()
	select {
	case <-done:
		// Either outcome is fine; what matters is that Dial returned.
	case <-time.After(5 * time.Second):
		t.Fatal("Dial blocked for > 5s with empty URL")
	}
}

// TestDial_NonEmptyURLIsNotReplacedWithDefault pins that a caller-supplied,
// non-empty URL is dialed as-is — the empty-URL default substitution
// (client.go: `if url == ""`) must NOT fire for it. The error Dial wraps
// names the URL it actually dialed, so a distinctive unreachable port that is
// NOT the default (4222) proves which URL was used.
func TestDial_NonEmptyURLIsNotReplacedWithDefault(t *testing.T) {
	const url = "nats://127.0.0.1:1" // unreachable, and deliberately not :4222
	done := make(chan error, 1)
	go func() {
		done <- New(url, "node-x", "", nil, nil).Dial()
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a connect error against an unreachable port")
		}
		if !strings.Contains(err.Error(), "127.0.0.1:1") {
			t.Errorf("error %q does not name the URL we passed (%s) — the non-empty URL must be dialed as-is, not swapped for the default", err.Error(), url)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Dial blocked for > 5s on unreachable URL")
	}
}

// --- the closed state ------------------------------------------------------

const (
	testNode = "node-x"
	testSubj = "rasputin.node.node-x.cmd.diag.ping"
)

// startServer runs an in-process nats-server that requires user/password
// auth. port -1 picks a free port; a fixed port restarts "the same" server
// with different credentials, which is what a rebuilt controlplane looks
// like from a node.
func startServer(t *testing.T, port int, user, pass string) *natsserver.Server {
	t.Helper()
	s, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: port, Username: user, Password: pass, NoLog: true, NoSigs: true,
	})
	if err != nil {
		t.Fatalf("nats server: %v", err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(func() {
		s.Shutdown()
		s.WaitForShutdown()
	})
	return s
}

func stopServer(s *natsserver.Server) {
	s.Shutdown()
	s.WaitForShutdown()
}

func portOf(t *testing.T, s *natsserver.Server) int {
	t.Helper()
	addr, ok := s.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("server addr %v is not TCP", s.Addr())
	}
	return addr.Port
}

// testClient is a Client wired the way the agent wires it — a handler
// subscription in onConn, a registration in onConnected — with the timers
// shrunk so the closed path plays out in well under a second.
type testClient struct {
	*Client
	conns     atomic.Int32 // onConn calls: one per NEW conn
	connected atomic.Int32 // onConnected calls: initial + reconnects + re-dials
}

func newTestClient(t *testing.T, url, token string, opts ...nats.Option) *testClient {
	t.Helper()
	tc := &testClient{}
	tc.Client = New(url, testNode, token,
		func(nc *nats.Conn) error {
			tc.conns.Add(1)
			_, err := nc.Subscribe(testSubj, func(m *nats.Msg) { _ = m.Respond([]byte("pong")) })
			return err
		},
		func(*nats.Conn) { tc.connected.Add(1) },
	)
	tc.reconnectWait = 50 * time.Millisecond
	tc.backoff = Backoff{Min: 50 * time.Millisecond, Max: 200 * time.Millisecond}
	tc.extraOpts = opts
	t.Cleanup(tc.Close)
	return tc
}

// natsDefaultAuthAbort puts nats.go back into its stock behaviour — close the
// conn on the second identical auth error — so a test can drive the Client
// into the closed state with real authorization violations, the way the
// bench did.
func natsDefaultAuthAbort() nats.Option {
	return func(o *nats.Options) error {
		o.IgnoreAuthErrorAbort = false
		return nil
	}
}

// ping asks the agent's handler for a reply through a separate client
// connection to s, proving the subscription is live on the CURRENT server.
func ping(t *testing.T, s *natsserver.Server, pass string) {
	t.Helper()
	probe, err := nats.Connect(s.ClientURL(), nats.UserInfo(testNode, pass))
	if err != nil {
		t.Fatalf("probe connect: %v", err)
	}
	defer probe.Close()
	reply, err := probe.Request(testSubj, nil, 2*time.Second)
	if err != nil {
		t.Fatalf("request %s: %v (the handler is not subscribed on the current connection)", testSubj, err)
	}
	if string(reply.Data) != "pong" {
		t.Fatalf("reply = %q, want pong", reply.Data)
	}
}

func waitFor(t *testing.T, what string, deadline time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", deadline, what)
}

// TestClient_RedialsFromClosedAfterAuthAbort is the e3bench failure of
// 2026-09-04, end to end, against nats.go's stock auth-abort behaviour:
//
//  1. the agent is connected with a valid token and its handler answers;
//  2. the server comes back accepting the SAME user with a DIFFERENT
//     password — a rebuilt controlplane before its token store is seeded —
//     and nats.go, rejected twice, CLOSES the conn for good;
//  3. the server comes back with the ORIGINAL password, and the Client must
//     re-dial a new conn, re-run onConn (the handler is subscribed again),
//     re-run onConnected (the registration goes out again), and the handler
//     must answer a request on the new connection.
//
// Before the fix step 3 never happened: the ClosedHandler logged one line
// and the node stayed off the bus until a human restarted the process.
func TestClient_RedialsFromClosedAfterAuthAbort(t *testing.T) {
	s1 := startServer(t, -1, testNode, "tok-A")
	port := portOf(t, s1)

	tc := newTestClient(t, s1.ClientURL(), "tok-A", natsDefaultAuthAbort())
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	ping(t, s1, "tok-A")
	if got := tc.conns.Load(); got != 1 {
		t.Fatalf("onConn calls after first dial = %d, want 1", got)
	}

	// Step 2: same server, wrong credentials for this node.
	stopServer(s1)
	s2 := startServer(t, port, testNode, "tok-B")
	waitFor(t, "nats.go to close the conn on repeated auth errors", 10*time.Second, first.IsClosed)
	if tc.Redials() != 0 {
		t.Fatalf("re-dialed %d time(s) while the credentials were still rejected; the re-dial must not succeed before the server accepts them", tc.Redials())
	}

	// Step 3: credentials accepted again.
	stopServer(s2)
	s3 := startServer(t, port, testNode, "tok-A")
	waitFor(t, "the Client to re-dial", 10*time.Second, func() bool {
		nc := tc.Conn()
		return tc.Redials() >= 1 && nc != first && nc.IsConnected()
	})
	if got := tc.conns.Load(); got != 2 {
		t.Errorf("onConn calls = %d, want 2 (one per new conn: first dial + re-dial)", got)
	}
	if got := tc.connected.Load(); got < 2 {
		t.Errorf("onConnected calls = %d, want >= 2 (the re-dial must re-publish the registration)", got)
	}
	ping(t, s3, "tok-A")
}

// TestClient_KeepsReconnectingThroughAuthErrors is the same server sequence
// with the Client's REAL options: nats.IgnoreAuthErrorAbort means the stock
// "close on the second identical auth error" never fires, the ORIGINAL conn
// survives the rejected period and reconnects on its own once the
// credentials are accepted again, with its subscriptions intact. This is the
// first line of defence; the re-dial above is the second.
func TestClient_KeepsReconnectingThroughAuthErrors(t *testing.T) {
	s1 := startServer(t, -1, testNode, "tok-A")
	port := portOf(t, s1)

	tc := newTestClient(t, s1.ClientURL(), "tok-A")
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	ping(t, s1, "tok-A")

	stopServer(s1)
	s2 := startServer(t, port, testNode, "tok-B")
	// Give nats.go several reconnect rounds against the rejecting server —
	// more than the two it needs to abort by default.
	time.Sleep(600 * time.Millisecond)
	if first.IsClosed() {
		t.Fatal("nats.go closed the conn on repeated auth errors; IgnoreAuthErrorAbort is not in effect")
	}

	stopServer(s2)
	s3 := startServer(t, port, testNode, "tok-A")
	waitFor(t, "the original conn to reconnect", 10*time.Second, first.IsConnected)
	if tc.Conn() != first {
		t.Fatal("the Client replaced a conn that nats.go never closed")
	}
	if got := tc.Redials(); got != 0 {
		t.Errorf("Redials = %d, want 0: recovery here is a nats-level reconnect, not a re-dial", got)
	}
	if got := tc.conns.Load(); got != 1 {
		t.Errorf("onConn calls = %d, want 1: subscriptions survive a nats-level reconnect and must not be duplicated", got)
	}
	waitFor(t, "onConnected to fire for the reconnect", 5*time.Second, func() bool { return tc.connected.Load() >= 2 })
	ping(t, s3, "tok-A")
}

// TestClient_RedialsWhenConnClosedByAnyRoute: closed is closed, whatever
// reached it. A conn closed under the Client (here directly, standing in for
// any fatal error nats.go treats as final) is re-dialed, and the handler
// answers on the replacement.
func TestClient_RedialsWhenConnClosedByAnyRoute(t *testing.T) {
	s := startServer(t, -1, testNode, "tok-A")
	tc := newTestClient(t, s.ClientURL(), "tok-A")
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	first.Close()
	waitFor(t, "the Client to re-dial", 10*time.Second, func() bool {
		nc := tc.Conn()
		return nc != first && nc.IsConnected()
	})
	if got := tc.Redials(); got != 1 {
		t.Errorf("Redials = %d, want 1", got)
	}
	ping(t, s, "tok-A")
}

// TestClient_RedialRetriesWithBackoffUntilServerReturns: while nothing is
// listening, the re-dial loop keeps failing and keeps trying; it succeeds as
// soon as a server is back. Also pins that Close stops the loop.
func TestClient_RedialRetriesWithBackoffUntilServerReturns(t *testing.T) {
	s1 := startServer(t, -1, testNode, "tok-A")
	port := portOf(t, s1)
	tc := newTestClient(t, s1.ClientURL(), "tok-A")
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	stopServer(s1)
	first.Close()
	// Nothing to dial: several backoff rounds go by with no success.
	time.Sleep(500 * time.Millisecond)
	if tc.Redials() != 0 {
		t.Fatalf("re-dialed with no server listening")
	}
	s2 := startServer(t, port, testNode, "tok-A")
	waitFor(t, "the Client to re-dial once the server is back", 10*time.Second, func() bool {
		nc := tc.Conn()
		return nc != first && nc.IsConnected()
	})
	ping(t, s2, "tok-A")
	// Close returns promptly (the loop is not running); the drain it starts
	// closes the conn shortly after.
	done := make(chan struct{})
	go func() { tc.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked")
	}
	waitFor(t, "the drained conn to close", 5*time.Second, tc.Conn().IsClosed)
}

// TestClient_CloseDoesNotRedial: the agent's own shutdown reaches the same
// ClosedHandler; it must not spawn a re-dial loop against a process that is
// exiting.
func TestClient_CloseDoesNotRedial(t *testing.T) {
	s := startServer(t, -1, testNode, "tok-A")
	tc := newTestClient(t, s.ClientURL(), "tok-A")
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	tc.Close()
	waitFor(t, "the drained conn to close", 5*time.Second, first.IsClosed)
	time.Sleep(300 * time.Millisecond) // long enough for a re-dial to have happened if one were coming
	if tc.Redials() != 0 || tc.Conn() != first {
		t.Fatalf("Close re-dialed (redials=%d)", tc.Redials())
	}
}

// TestClient_RejectsConnWhoseSetupFails: a conn onConn cannot subscribe on is
// not a connection; Dial fails and the conn is closed rather than kept
// half-wired.
func TestClient_RejectsConnWhoseSetupFails(t *testing.T) {
	s := startServer(t, -1, testNode, "tok-A")
	var seen *nats.Conn
	c := New(s.ClientURL(), testNode, "tok-A",
		func(nc *nats.Conn) error {
			seen = nc
			_, err := nc.Subscribe("bad subject with spaces", func(*nats.Msg) {})
			return err
		}, nil)
	t.Cleanup(c.Close)
	if err := c.Dial(); err == nil {
		t.Fatal("Dial succeeded with a failing onConn")
	}
	if c.Conn() != nil {
		t.Error("a rejected conn was installed as current")
	}
	if seen == nil || !seen.IsClosed() {
		t.Error("the rejected conn was not closed")
	}
}

func TestClient_PublishBeforeDial(t *testing.T) {
	c := New("nats://127.0.0.1:1", testNode, "", nil, nil)
	if err := c.Publish("x", nil); err != ErrNotConnected {
		t.Fatalf("Publish before Dial = %v, want ErrNotConnected", err)
	}
	if got := c.ConnectedAddr(); got != "" {
		t.Fatalf("ConnectedAddr before Dial = %q, want empty", got)
	}
}
