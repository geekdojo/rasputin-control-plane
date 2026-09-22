package bus

import (
	"errors"
	"log"
	"net"
	"strings"
	"sync"
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

// connHolder is the Client under test as ping needs it — bare, or wrapped in
// a testClient.
type connHolder interface{ Conn() *nats.Conn }

// ping asks the agent's handler for a reply through a separate client
// connection to s, proving the subscription is live on the CURRENT server.
//
// It flushes the Client's own connection first, and that is the whole reason
// this probe is reliable. nats.go does not put a SUB on the wire when
// Subscribe returns: Conn.subscribe appends the protocol to a buffer and
// kicks a flusher goroutine, and a nats-level reconnect re-sends the
// subscriptions the same buffered way. So neither "Dial returned" nor
// "onConn ran" nor "the reconnect callback fired" says the SERVER has
// registered the subscription. The probe below is a SEPARATE connection, so
// nothing orders its request after that SUB — on a contended runner the
// request wins the race and the server answers "no responders available",
// which is a test bug, not a broken Client. Flush is a PING/PONG on the
// agent's own connection: when its PONG comes back the server has parsed
// everything written on that connection before it, the SUB included.
func ping(t *testing.T, c connHolder, s *natsserver.Server, pass string) {
	t.Helper()
	nc := c.Conn()
	if nc == nil {
		t.Fatal("the Client has no connection: nothing could be subscribed")
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush the agent's connection: %v (its subscriptions never reached the server)", err)
	}
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

// connAttempts is how many client connections s has accepted since it
// started, connections it went on to reject included: the server bumps the
// counter when it creates the client, before authentication. It is the
// observable for "nats.go has tried again", which a sleep can only guess at.
func connAttempts(t *testing.T, s *natsserver.Server) uint64 {
	t.Helper()
	v, err := s.Varz(nil)
	if err != nil {
		t.Fatalf("varz: %v", err)
	}
	return v.TotalConnections
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
	ping(t, tc, s1, "tok-A")
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
	// install() installs the conn and bumps the re-dial counter BEFORE it
	// runs onConnected, so the wait above can be satisfied in the window
	// between the two. Wait for the hook itself rather than assume the
	// ordering — what is asserted is unchanged, only when it is read.
	waitFor(t, "onConnected to fire for the re-dial (the registration must be re-published)", 5*time.Second,
		func() bool { return tc.connected.Load() >= 2 })
	ping(t, tc, s3, "tok-A")
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
	ping(t, tc, s1, "tok-A")

	stopServer(s1)
	s2 := startServer(t, port, testNode, "tok-B")
	// Give nats.go more reconnect rounds against the rejecting server than
	// the two it needs to abort by default. Waiting on the server's own
	// count of accepted connections, not on a clock: a sleep that is too
	// short on a contended runner turns the assertion below into a vacuous
	// pass, because a conn that was never retried cannot have been aborted.
	waitFor(t, "nats.go to be rejected by the rebuilt server at least 3 times", 10*time.Second,
		func() bool { return connAttempts(t, s2) >= 3 || first.IsClosed() })
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
	ping(t, tc, s3, "tok-A")
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
	ping(t, tc, s, "tok-A")
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
	ping(t, tc, s2, "tok-A")
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

// TestNew_DefaultsReconnectWaitAndBackoff pins the connection-recovery timers
// New wires in: a 2s nats-level ReconnectWait and the DefaultBackoff re-dial
// schedule. Nothing else asserted these constructor values, so an arithmetic
// slip that zeroed reconnectWait (2 * time.Second → 2 / time.Second) went
// unnoticed — a zero wait would hammer a rebuilt controlplane with no pause.
func TestNew_DefaultsReconnectWaitAndBackoff(t *testing.T) {
	c := New("nats://127.0.0.1:1", testNode, "", nil, nil)
	if c.reconnectWait != 2*time.Second {
		t.Errorf("reconnectWait = %s, want 2s", c.reconnectWait)
	}
	if c.backoff != DefaultBackoff {
		t.Errorf("backoff = %+v, want DefaultBackoff %+v", c.backoff, DefaultBackoff)
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

// TestClient_OnLostFiresWhenTheServerGoesAwayAndNotOnClose: the hook runs
// when the connection is lost under the Client, and stays quiet for the
// Client's own shutdown, which drains through the same nats handlers.
func TestClient_OnLostFiresWhenTheServerGoesAwayAndNotOnClose(t *testing.T) {
	s := startServer(t, -1, testNode, "tok-A")
	tc := newTestClient(t, s.ClientURL(), "tok-A")
	var lost atomic.Int32
	tc.OnLost(func() { lost.Add(1) })
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if lost.Load() != 0 {
		t.Fatalf("OnLost fired %d time(s) on a healthy connect", lost.Load())
	}
	stopServer(s)
	waitFor(t, "OnLost after the server went away", 10*time.Second, func() bool { return lost.Load() >= 1 })

	before := lost.Load()
	done := make(chan struct{})
	go func() { tc.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked")
	}
	time.Sleep(200 * time.Millisecond) // long enough for the drain's handlers to have run
	if got := lost.Load(); got != before {
		t.Errorf("OnLost fired %d more time(s) for the Client's own Close", got-before)
	}
}

// --- the dialer gets a NAME, not an address --------------------------------

// recordingDialer stands in for mdnsDialer and records every address nats.go
// asks it to dial. It always fails the dial, so the connect attempt returns
// immediately and the test never needs a server.
type recordingDialer struct {
	mu   sync.Mutex
	seen []string
}

func (d *recordingDialer) Dial(network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.seen = append(d.seen, address)
	d.mu.Unlock()
	return nil, errors.New("recordingDialer: dial refused by the test")
}

func (d *recordingDialer) addrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.seen...)
}

// TestDial_CustomDialerReceivesHostnameNotResolvedIP is the regression guard
// for geekdojo-brain#547: the custom dialer must be handed the hostname from
// the URL, not an address nats.go resolved on its own behalf.
//
// It matters because mdnsDialer decides whether to consult mDNS by looking at
// the address it is given (`strings.HasSuffix(host, ".local")`). nats.go's
// createConn resolves the URL's hostname through the OS resolver BEFORE
// calling the dialer and passes the A record it gets back, so without
// nats.SkipHostLookup() the dialer sees an IP literal, the guard never
// matches, and mDNS is never consulted — the agent can then never re-find a
// control plane whose DHCP lease moved, because the only answer it has is the
// stale one its own dnsmasq is serving.
//
// The URL deliberately uses "localhost" rather than a .local name. The
// assertion is that no OS lookup happened, and a name that does NOT resolve
// cannot show that: nats.go falls back to the raw URL host when a lookup
// returns nothing, so the dialer would receive the name either way and the
// test could not fail. "localhost" is the one name every machine that can run
// this suite resolves, which is what gives the assertion teeth.
// TestMDNSDialer_LocalNameEntersMDNSPath covers the second half — that a
// .local name reaching this dialer does send the agent down the mDNS path.
func TestDial_CustomDialerReceivesHostnameNotResolvedIP(t *testing.T) {
	const host = "localhost"
	if addrs, err := net.LookupHost(host); err != nil || len(addrs) == 0 {
		t.Skipf("this machine does not resolve %q (%v) — the assertion would pass vacuously", host, err)
	}
	rec := &recordingDialer{}
	c := New("nats://"+host+":4222", testNode, "", nil, nil)
	// extraOpts are appended after the client's own options, so this replaces
	// the mdnsDialer while leaving every other option — SkipHostLookup among
	// them — exactly as the agent sets it.
	c.extraOpts = []nats.Option{nats.SetCustomDialer(rec)}
	if err := c.Dial(); err == nil {
		t.Fatal("Dial succeeded against a dialer that always fails")
	}
	c.Close()

	got := rec.addrs()
	if len(got) == 0 {
		t.Fatal("the custom dialer was never called — nats.go dialed some other way")
	}
	want := net.JoinHostPort(host, "4222")
	for _, addr := range got {
		if addr == want {
			continue
		}
		h, _, err := net.SplitHostPort(addr)
		if err == nil && net.ParseIP(h) != nil {
			t.Fatalf("the custom dialer was handed the resolved address %q; it must be handed %q. "+
				"nats.SkipHostLookup() is missing from the options in dial() — mdnsDialer's "+
				".local guard cannot match an IP literal, so mDNS is never consulted and a "+
				"control plane that changed address is unreachable forever.", addr, want)
		}
		t.Fatalf("the custom dialer was handed %q, want %q", addr, want)
	}
}

// TestMDNSDialer_LocalNameEntersMDNSPath pins the other half of the chain: once
// a .local NAME reaches mdnsDialer, the mDNS path really is entered rather than
// the name being handed straight to the OS resolver.
//
// There is no mDNS responder for this name, so Resolve fails and the dialer
// takes its documented fallback — dialing the unmodified name. The evidence
// that Resolve ran at all is the log line the fallback emits, so the test reads
// the log rather than the return value: a passing dial would prove nothing
// about which path produced the address.
func TestMDNSDialer_LocalNameEntersMDNSPath(t *testing.T) {
	var buf strings.Builder
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	const name = "rasputin-no-such-responder-547.local"
	d := &mdnsDialer{resolveTimeout: 250 * time.Millisecond, dialTimeout: 250 * time.Millisecond}
	if conn, err := d.Dial("tcp", net.JoinHostPort(name, "4222")); err == nil {
		conn.Close()
		t.Fatalf("dialing %q unexpectedly succeeded", name)
	}
	if logged := buf.String(); !strings.Contains(logged, "mDNS resolve "+name) {
		t.Errorf("mdnsDialer did not report an mDNS attempt for a .local name; log was %q. "+
			"The .local guard did not match, so mdns.Resolve was never called.", logged)
	}
}
