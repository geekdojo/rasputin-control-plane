package bus

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"log"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// --- the test bus ----------------------------------------------------------

// testKey is the one bus key every TLS test server in this package serves, so
// a server restarted on the same port is "the same controlplane" to a client
// pinned to testPin — the way the api's bus is across a restart.
var testKey = sync.OnceValue(func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
})

func testPin(t *testing.T) string {
	t.Helper()
	return mustPin(t, testKey())
}

// capture is a slog.Handler that keeps every record, so a test can assert
// what the Client logged and with which fields.
type capture struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r.Clone())
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

// records returns the captured records whose message contains msg.
func (c *capture) records(msg string) []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []slog.Record
	for _, r := range c.recs {
		if strings.Contains(r.Message, msg) {
			out = append(out, r)
		}
	}
	return out
}

// attr returns the value of key on r, and whether it is there.
func attr(r slog.Record, key string) (slog.Value, bool) {
	var v slog.Value
	found := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			v, found = a.Value, true
			return false
		}
		return true
	})
	return v, found
}

func newCapture() (*capture, *slog.Logger) {
	c := &capture{}
	return c, slog.New(c)
}

// discard is a logger for tests that do not read what the Client logs.
func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// mustNew builds a Client or fails the test.
func mustNew(t *testing.T, cfg Config) *Client {
	t.Helper()
	if cfg.Log == nil {
		cfg.Log = discard()
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// --- New -------------------------------------------------------------------

// sentinelListener proves New opens no socket: after New returns, the test
// dials the listener itself, and the first connection it accepts must be that
// sentinel — anything New had dialed would be queued ahead of it.
func assertNothingDialed(t *testing.T, l net.Listener) {
	t.Helper()
	sentinel, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sentinel.Close()
	got, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if got.RemoteAddr().String() != sentinel.LocalAddr().String() {
		t.Fatalf("the listener's first connection came from %s, not the sentinel %s: New dialed", got.RemoteAddr(), sentinel.LocalAddr())
	}
}

func stubListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// TC-517-01: New refuses an empty pin and opens no socket.
func TestNew_RefusesAnEmptyPin(t *testing.T) {
	l := stubListener(t)
	c, err := New(Config{URL: "nats://" + l.Addr().String(), NodeID: testNode, Pin: "", Log: discard()})
	if err == nil || c != nil {
		t.Fatalf("New with no pin = (%v, %v), want an error and no Client", c, err)
	}
	if !errors.Is(err, proto.ErrBusPinFormat) {
		t.Errorf("error %v does not wrap ErrBusPinFormat", err)
	}
	assertNothingDialed(t, l)
}

// TC-517-02: every malformed pin is refused with ErrBusPinFormat.
func TestNew_RefusesAMalformedPin(t *testing.T) {
	good := testPin(t)
	body := strings.TrimPrefix(good, proto.BusPinPrefix)
	for name, pin := range map[string]string{
		"short":           "sha256/short",
		"no prefix":       body,
		"43-char body":    proto.BusPinPrefix + body[:43],
		"curl's sha256//": "sha256//" + body,
	} {
		t.Run(name, func(t *testing.T) {
			c, err := New(Config{URL: "nats://127.0.0.1:1", NodeID: testNode, Pin: pin, Log: discard()})
			if c != nil || !errors.Is(err, proto.ErrBusPinFormat) {
				t.Fatalf("New(%q) = (%v, %v), want no Client and ErrBusPinFormat", pin, c, err)
			}
		})
	}
}

// TC-517-56: New refuses a nil logger and opens no socket.
func TestNew_RefusesANilLogger(t *testing.T) {
	l := stubListener(t)
	c, err := New(Config{URL: "nats://" + l.Addr().String(), NodeID: testNode, Pin: testPin(t)})
	if err == nil || c != nil {
		t.Fatalf("New with no logger = (%v, %v), want an error and no Client", c, err)
	}
	assertNothingDialed(t, l)
}

// TC-517-46: zero Backoff and ReconnectWait take the defaults; explicit values
// are what the Client actually uses — ReconnectWait on the nats connection,
// Backoff in the re-dial schedule it logs.
func TestNew_ConfigDefaultsAndOverrides(t *testing.T) {
	c := mustNew(t, Config{URL: "nats://127.0.0.1:1", NodeID: testNode, Pin: testPin(t)})
	if c.reconnectWait != 2*time.Second {
		t.Errorf("default reconnectWait = %s, want 2s", c.reconnectWait)
	}
	if c.backoff != DefaultBackoff {
		t.Errorf("default backoff = %+v, want DefaultBackoff %+v", c.backoff, DefaultBackoff)
	}

	s := startBus(t, -1, testNode, "tok-A")
	cp, logger := newCapture()
	want := Backoff{Min: 30 * time.Millisecond, Max: 30 * time.Millisecond}
	c = mustNew(t, Config{
		URL: natsURL(t, s), NodeID: testNode, Pin: testPin(t), Token: StaticToken("tok-A"),
		Backoff: want, ReconnectWait: 70 * time.Millisecond, Log: logger,
	})
	t.Cleanup(c.Close)
	if err := c.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if got := c.Conn().Opts.ReconnectWait; got != 70*time.Millisecond {
		t.Errorf("the connection's ReconnectWait = %s, want the configured 70ms", got)
	}
	// Close the conn with no server to re-dial to: the re-dial loop logs each
	// failed attempt with the delay the configured Backoff gave it.
	stopServer(s)
	c.Conn().Close()
	waitFor(t, "a failed re-dial attempt to be logged", 10*time.Second, func() bool {
		return len(cp.records("re-dial attempt failed")) > 0
	})
	next, ok := attr(cp.records("re-dial attempt failed")[0], "next")
	if !ok || next.Duration() != 30*time.Millisecond {
		t.Fatalf("the first re-dial waited %v, want the configured 30ms", next)
	}
}

// TC-517-45: a nil Token presents no password, and the bus refuses it; the
// Client falls back to nothing else.
func TestNew_NilTokenPresentsNoPassword(t *testing.T) {
	seen := &recordingAuth{}
	s := startBusWith(t, &natsserver.Options{CustomClientAuthentication: seen})
	c := mustNew(t, Config{URL: natsURL(t, s), NodeID: testNode, Pin: testPin(t)})
	t.Cleanup(c.Close)
	err := c.Dial()
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "authorization") {
		t.Fatalf("Dial with no token = %v, want an authorization violation", err)
	}
	user, pass, n := seen.last()
	if n == 0 {
		t.Fatal("the bus never saw a CONNECT")
	}
	if user != testNode || pass != "" {
		t.Fatalf("CONNECT presented (%q, %q), want (%q, \"\")", user, pass, testNode)
	}
	if c.Conn() != nil {
		t.Fatal("a refused connection was installed")
	}
}

// recordingAuth is a nats-server authenticator that records what each CONNECT
// presented and admits only the password "tok-A".
type recordingAuth struct {
	mu         sync.Mutex
	user, pass string
	n          int
}

func (a *recordingAuth) Check(c natsserver.ClientAuthentication) bool {
	o := c.GetOpts()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.user, a.pass, a.n = o.Username, o.Password, a.n+1
	return o.Password == "tok-A"
}

func (a *recordingAuth) last() (string, string, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.user, a.pass, a.n
}

// TestDial_ReturnsErrorOnUnreachableURL covers the error path: dialing a URL
// that nobody is listening on must fail quickly and return a wrapped error.
func TestDial_ReturnsErrorOnUnreachableURL(t *testing.T) {
	done := make(chan error, 1)
	c := mustNew(t, Config{URL: "nats://127.0.0.1:1", NodeID: testNode, Pin: testPin(t)})
	go func() { done <- c.Dial() }()
	select {
	case err := <-done:
		if err == nil {
			t.Errorf("expected a connect error against unreachable port")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Dial blocked for > 5s on unreachable URL")
	}
}

// TestNew_EmptyURLAttemptsDefault: when URL == "" New substitutes
// nats.DefaultURL, and Dial attempts it rather than rejecting the empty url.
func TestNew_EmptyURLAttemptsDefault(t *testing.T) {
	c := mustNew(t, Config{NodeID: testNode, Pin: testPin(t)})
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
// non-empty URL is dialed as-is. The error Dial wraps names the URL it
// actually dialed, so a distinctive unreachable port that is NOT the default
// (4222) proves which URL was used.
func TestDial_NonEmptyURLIsNotReplacedWithDefault(t *testing.T) {
	const url = "nats://127.0.0.1:1" // unreachable, and deliberately not :4222
	c := mustNew(t, Config{URL: url, NodeID: testNode, Pin: testPin(t)})
	done := make(chan error, 1)
	go func() { done <- c.Dial() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a connect error against an unreachable port")
		}
		if !strings.Contains(err.Error(), "127.0.0.1:1") {
			t.Errorf("error %q does not name the URL we passed (%s)", err.Error(), url)
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

// startServer runs a PLAINTEXT nats-server that requires user/password auth.
// No Client can connect to it (see TC-517-03); it stands in for a server that
// offers no TLS, and for tests of code that does not dial through the Client.
func startServer(t *testing.T, port int, user, pass string) *natsserver.Server {
	t.Helper()
	return runServer(t, &natsserver.Options{Host: "127.0.0.1", Port: port, Username: user, Password: pass})
}

// startBus runs a TLS-required nats-server with user/password auth, serving
// testKey — the shape of the api's bus. port -1 picks a free port; a fixed
// port restarts "the same" bus with different credentials, which is what a
// rebuilt controlplane looks like from a node.
func startBus(t *testing.T, port int, user, pass string) *natsserver.Server {
	t.Helper()
	return startBusWith(t, &natsserver.Options{Port: port, Username: user, Password: pass})
}

// startBusWith runs a TLS-required bus serving testKey with the given auth
// options.
func startBusWith(t *testing.T, o *natsserver.Options) *natsserver.Server {
	t.Helper()
	if o.Port == 0 {
		o.Port = -1
	}
	o.Host = "127.0.0.1"
	o.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{alwaysValid(t, testKey())}}
	o.TLSTimeout = 5
	return runServer(t, o)
}

func runServer(t *testing.T, o *natsserver.Options) *natsserver.Server {
	t.Helper()
	o.NoLog, o.NoSigs = true, true
	s, err := natsserver.NewServer(o)
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

// natsURL is the server's address as a nats:// URL. A TLS server's ClientURL
// says tls://, and nats.go turns TLS on for that scheme by itself — which is
// not how a node dials (seeds carry nats://), so it would hide exactly the
// behaviour under test.
func natsURL(t *testing.T, s *natsserver.Server) string {
	t.Helper()
	return "nats://" + s.Addr().String()
}

// testClient is a Client wired the way the agent wires it — a handler
// subscription in onConn, a registration in onConnected — with the timers
// shrunk so the closed path plays out in well under a second.
type testClient struct {
	*Client
	conns     atomic.Int32 // onConn calls: one per NEW conn
	connected atomic.Int32 // onConnected calls: initial + reconnects + re-dials
	lost      atomic.Int32 // onLost calls
	logs      *capture
}

func newTestClient(t *testing.T, url, token string, opts ...nats.Option) *testClient {
	t.Helper()
	tc := &testClient{}
	var logger *slog.Logger
	tc.logs, logger = newCapture()
	tc.Client = mustNew(t, Config{
		URL: url, NodeID: testNode, Pin: testPin(t), Token: StaticToken(token),
		OnConn: func(nc *nats.Conn) error {
			tc.conns.Add(1)
			_, err := nc.Subscribe(testSubj, func(m *nats.Msg) { _ = m.Respond([]byte("pong")) })
			return err
		},
		OnConnected:   func(*nats.Conn) { tc.connected.Add(1) },
		OnLost:        func() { tc.lost.Add(1) },
		Backoff:       Backoff{Min: 50 * time.Millisecond, Max: 200 * time.Millisecond},
		ReconnectWait: 50 * time.Millisecond,
		Log:           logger,
	})
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

// probeTLS is how a test's own probe connection reaches a test bus: TLS,
// verified by the same pin the Client uses.
func probeTLS(t *testing.T) nats.Option {
	t.Helper()
	return nats.Secure(pinnedTLSConfig(pinDigest(t, testKey())))
}

// ping asks the agent's handler for a reply through a separate client
// connection to s, proving the subscription is live on the CURRENT server.
//
// It flushes the Client's own connection first, and that is the whole reason
// this probe is reliable: nats.go buffers SUB and writes it from another
// goroutine, so a probe on a second connection can reach the server before
// the handler's subscription does and be answered "no responders". Flush is a
// PING/PONG on the agent's own connection: when its PONG comes back the server
// has parsed everything written on that connection before it, the SUB
// included.
func ping(t *testing.T, c connHolder, s *natsserver.Server, pass string) {
	t.Helper()
	nc := c.Conn()
	if nc == nil {
		t.Fatal("the Client has no connection: nothing could be subscribed")
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush the agent's connection: %v (its subscriptions never reached the server)", err)
	}
	probe, err := nats.Connect(natsURL(t, s), nats.UserInfo(testNode, pass), probeTLS(t))
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
// started, connections it went on to reject included. It is the observable
// for "nats.go has tried again", which a sleep can only guess at.
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
//     re-dial a new conn, re-run onConn, re-run onConnected, and the handler
//     must answer a request on the new connection.
func TestClient_RedialsFromClosedAfterAuthAbort(t *testing.T) {
	s1 := startBus(t, -1, testNode, "tok-A")
	port := portOf(t, s1)

	tc := newTestClient(t, natsURL(t, s1), "tok-A", natsDefaultAuthAbort())
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
	s2 := startBus(t, port, testNode, "tok-B")
	waitFor(t, "nats.go to close the conn on repeated auth errors", 10*time.Second, first.IsClosed)
	if tc.Redials() != 0 {
		t.Fatalf("re-dialed %d time(s) while the credentials were still rejected", tc.Redials())
	}

	// Step 3: credentials accepted again.
	stopServer(s2)
	s3 := startBus(t, port, testNode, "tok-A")
	waitFor(t, "the Client to re-dial", 10*time.Second, func() bool {
		nc := tc.Conn()
		return tc.Redials() >= 1 && nc != first && nc.IsConnected()
	})
	if got := tc.conns.Load(); got != 2 {
		t.Errorf("onConn calls = %d, want 2 (one per new conn: first dial + re-dial)", got)
	}
	// install() installs the conn and bumps the re-dial counter BEFORE it
	// runs onConnected, so wait for the hook itself.
	waitFor(t, "onConnected to fire for the re-dial (the registration must be re-published)", 5*time.Second,
		func() bool { return tc.connected.Load() >= 2 })
	ping(t, tc, s3, "tok-A")
}

// TestClient_KeepsReconnectingThroughAuthErrors is the same server sequence
// with the Client's REAL options: nats.IgnoreAuthErrorAbort means the stock
// "close on the second identical auth error" never fires, and the ORIGINAL
// conn survives the rejected period and reconnects on its own.
func TestClient_KeepsReconnectingThroughAuthErrors(t *testing.T) {
	s1 := startBus(t, -1, testNode, "tok-A")
	port := portOf(t, s1)

	tc := newTestClient(t, natsURL(t, s1), "tok-A")
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	ping(t, tc, s1, "tok-A")

	stopServer(s1)
	s2 := startBus(t, port, testNode, "tok-B")
	// More reconnect rounds against the rejecting server than the two nats.go
	// needs to abort by default, counted on the server, not on a clock.
	waitFor(t, "nats.go to be rejected by the rebuilt server at least 3 times", 10*time.Second,
		func() bool { return connAttempts(t, s2) >= 3 || first.IsClosed() })
	if first.IsClosed() {
		t.Fatal("nats.go closed the conn on repeated auth errors; IgnoreAuthErrorAbort is not in effect")
	}

	stopServer(s2)
	s3 := startBus(t, port, testNode, "tok-A")
	waitFor(t, "the original conn to reconnect", 10*time.Second, first.IsConnected)
	if tc.Conn() != first {
		t.Fatal("the Client replaced a conn that nats.go never closed")
	}
	if got := tc.Redials(); got != 0 {
		t.Errorf("Redials = %d, want 0: recovery here is a nats-level reconnect, not a re-dial", got)
	}
	if got := tc.conns.Load(); got != 1 {
		t.Errorf("onConn calls = %d, want 1: subscriptions survive a nats-level reconnect", got)
	}
	waitFor(t, "onConnected to fire for the reconnect", 5*time.Second, func() bool { return tc.connected.Load() >= 2 })
	ping(t, tc, s3, "tok-A")
}

// TC-517-06: every new connection is TLS and pin-verified — after a
// nats-level reconnect to a restarted server, and after a re-dial from the
// closed state.
func TestClient_TLSOnEveryReconnectAndRedial(t *testing.T) {
	s1 := startBus(t, -1, testNode, "tok-A")
	port := portOf(t, s1)
	tc := newTestClient(t, natsURL(t, s1), "tok-A")
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	if _, err := first.TLSConnectionState(); err != nil {
		t.Fatalf("first connection is not TLS: %v", err)
	}

	// A nats-level reconnect: the server restarts, the same conn comes back.
	stopServer(s1)
	s2 := startBus(t, port, testNode, "tok-A")
	waitFor(t, "the conn to reconnect", 10*time.Second, func() bool {
		return first.IsConnected() && tc.connected.Load() >= 2
	})
	if _, err := first.TLSConnectionState(); err != nil {
		t.Fatalf("the reconnected connection is not TLS: %v", err)
	}
	ping(t, tc, s2, "tok-A")

	// A re-dial from the closed state: a brand new conn.
	first.Close()
	waitFor(t, "the Client to re-dial", 10*time.Second, func() bool {
		nc := tc.Conn()
		return nc != first && nc.IsConnected()
	})
	if got := tc.Redials(); got != 1 {
		t.Fatalf("Redials = %d, want 1", got)
	}
	if _, err := tc.Conn().TLSConnectionState(); err != nil {
		t.Fatalf("the re-dialed connection is not TLS: %v", err)
	}
	ping(t, tc, s2, "tok-A")
}

// TestClient_RedialsWhenConnClosedByAnyRoute: closed is closed, whatever
// reached it. A conn closed under the Client is re-dialed, and the handler
// answers on the replacement.
func TestClient_RedialsWhenConnClosedByAnyRoute(t *testing.T) {
	s := startBus(t, -1, testNode, "tok-A")
	tc := newTestClient(t, natsURL(t, s), "tok-A")
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
	s1 := startBus(t, -1, testNode, "tok-A")
	port := portOf(t, s1)
	tc := newTestClient(t, natsURL(t, s1), "tok-A")
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	stopServer(s1)
	first.Close()
	// Nothing to dial: wait for several failed attempts, counted in the log.
	waitFor(t, "three failed re-dial attempts", 10*time.Second, func() bool {
		return len(tc.logs.records("re-dial attempt failed")) >= 3
	})
	if tc.Redials() != 0 {
		t.Fatalf("re-dialed with no server listening")
	}
	s2 := startBus(t, port, testNode, "tok-A")
	waitFor(t, "the Client to re-dial once the server is back", 10*time.Second, func() bool {
		nc := tc.Conn()
		return nc != first && nc.IsConnected()
	})
	ping(t, tc, s2, "tok-A")
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
	s := startBus(t, -1, testNode, "tok-A")
	tc := newTestClient(t, natsURL(t, s), "tok-A")
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
	s := startBus(t, -1, testNode, "tok-A")
	var seen *nats.Conn
	c := mustNew(t, Config{
		URL: natsURL(t, s), NodeID: testNode, Pin: testPin(t), Token: StaticToken("tok-A"),
		OnConn: func(nc *nats.Conn) error {
			seen = nc
			_, err := nc.Subscribe("bad subject with spaces", func(*nats.Msg) {})
			return err
		},
	})
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
	c := mustNew(t, Config{URL: "nats://127.0.0.1:1", NodeID: testNode, Pin: testPin(t)})
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
	s := startBus(t, -1, testNode, "tok-A")
	tc := newTestClient(t, natsURL(t, s), "tok-A")
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if tc.lost.Load() != 0 {
		t.Fatalf("OnLost fired %d time(s) on a healthy connect", tc.lost.Load())
	}
	stopServer(s)
	waitFor(t, "OnLost after the server went away", 10*time.Second, func() bool { return tc.lost.Load() >= 1 })

	before := tc.lost.Load()
	done := make(chan struct{})
	go func() { tc.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked")
	}
	time.Sleep(200 * time.Millisecond) // long enough for the drain's handlers to have run
	if got := tc.lost.Load(); got != before {
		t.Errorf("OnLost fired %d more time(s) for the Client's own Close", got-before)
	}
}

// TC-517-51: the Client writes nothing through the global log. Connect, loss
// and re-dial each arrive as a captured record carrying node_id and url.
func TestClient_LogsOnlyThroughTheInjectedLogger(t *testing.T) {
	var global strings.Builder
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&global)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	s1 := startBus(t, -1, testNode, "tok-A")
	port := portOf(t, s1)
	tc := newTestClient(t, natsURL(t, s1), "tok-A")
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	stopServer(s1)
	waitFor(t, "the disconnect to be logged", 10*time.Second, func() bool {
		return len(tc.logs.records("agent/bus: disconnected")) > 0
	})
	first.Close()
	startBus(t, port, testNode, "tok-A")
	waitFor(t, "the re-dial to be logged", 10*time.Second, func() bool {
		return len(tc.logs.records("agent/bus: re-dialed")) > 0
	})

	for _, msg := range []string{"agent/bus: connected", "agent/bus: re-dialed"} {
		recs := tc.logs.records(msg)
		if len(recs) == 0 {
			t.Fatalf("no %q record", msg)
		}
		if v, ok := attr(recs[0], "node_id"); !ok || v.String() != testNode {
			t.Errorf("%q node_id = %v, want %s", msg, v, testNode)
		}
		if v, ok := attr(recs[0], "url"); !ok || v.String() == "" {
			t.Errorf("%q has no url", msg)
		}
		if recs[0].Level != slog.LevelInfo {
			t.Errorf("%q at %s, want INFO", msg, recs[0].Level)
		}
	}
	disc := tc.logs.records("agent/bus: disconnected")
	if v, ok := attr(disc[0], "node_id"); !ok || v.String() != testNode || disc[0].Level != slog.LevelWarn {
		t.Errorf("disconnected record = %s %v, want WARN with node_id", disc[0].Level, v)
	}
	if global.Len() != 0 {
		t.Fatalf("the Client wrote to the global log: %q", global.String())
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
// mdnsDialer decides whether to consult mDNS by looking at the address it is
// given (`strings.HasSuffix(host, ".local")`). Without nats.SkipHostLookup()
// nats.go resolves the name first, the dialer sees an IP literal, and mDNS is
// never consulted.
//
// The URL deliberately uses "localhost": the assertion is that no OS lookup
// happened, and only a name that DOES resolve can show that.
func TestDial_CustomDialerReceivesHostnameNotResolvedIP(t *testing.T) {
	const host = "localhost"
	if addrs, err := net.LookupHost(host); err != nil || len(addrs) == 0 {
		t.Skipf("this machine does not resolve %q (%v) — the assertion would pass vacuously", host, err)
	}
	rec := &recordingDialer{}
	c := mustNew(t, Config{URL: "nats://" + host + ":4222", NodeID: testNode, Pin: testPin(t)})
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
				"nats.SkipHostLookup() is missing from the options in dial().", addr, want)
		}
		t.Fatalf("the custom dialer was handed %q, want %q", addr, want)
	}
}

// TestMDNSDialer_LocalNameEntersMDNSPath pins the other half of the chain: once
// a .local NAME reaches mdnsDialer, the mDNS path really is entered rather than
// the name being handed straight to the OS resolver (geekdojo-brain#547).
//
// There is no mDNS responder for this name, so Resolve fails and the dialer
// takes its documented fallback. The evidence that Resolve ran at all is the
// WARN record the fallback writes to the dialer's injected logger, naming the
// host (TC-517-51): a passing dial would prove nothing about which path
// produced the address.
func TestMDNSDialer_LocalNameEntersMDNSPath(t *testing.T) {
	cp, logger := newCapture()
	const name = "rasputin-no-such-responder-547.local"
	d := &mdnsDialer{resolveTimeout: 250 * time.Millisecond, dialTimeout: 250 * time.Millisecond, log: logger}
	if conn, err := d.Dial("tcp", net.JoinHostPort(name, "4222")); err == nil {
		conn.Close()
		t.Fatalf("dialing %q unexpectedly succeeded", name)
	}
	recs := cp.records("mDNS resolve failed")
	if len(recs) != 1 {
		t.Fatalf("got %d mDNS-failure records, want exactly 1: the .local guard did not match, so mdns.Resolve was never called", len(recs))
	}
	if recs[0].Level != slog.LevelWarn {
		t.Errorf("level = %s, want WARN", recs[0].Level)
	}
	if host, ok := attr(recs[0], "host"); !ok || host.String() != name {
		t.Fatalf("host = %v, want %q", host, name)
	}
}

// --- a server that offers no TLS -------------------------------------------

// plainStub is a TCP server that speaks just enough NATS to offer no TLS: it
// sends an INFO without tls_required or tls_available, then records every byte
// the client writes.
type plainStub struct {
	l    net.Listener
	mu   sync.Mutex
	got  strings.Builder
	done chan struct{}
}

func startPlainStub(t *testing.T) *plainStub {
	t.Helper()
	p := &plainStub{l: stubListener(t), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		c, err := p.l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte(`INFO {"server_id":"stub","version":"2.14.6","proto":1,"max_payload":1048576,"auth_required":true}` + "\r\n"))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			p.mu.Lock()
			p.got.WriteString(line)
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return p
}

// TC-517-03: a server that offers no TLS is refused before CONNECT, so the
// join token never crosses the wire.
func TestClient_RefusesAServerThatOffersNoTLS(t *testing.T) {
	p := startPlainStub(t)
	c := mustNew(t, Config{URL: "nats://" + p.l.Addr().String(), NodeID: testNode, Pin: testPin(t), Token: StaticToken("tok-SECRET")})
	t.Cleanup(c.Close)
	err := c.Dial()
	if !errors.Is(err, nats.ErrSecureConnWanted) {
		t.Fatalf("Dial = %v, want nats.ErrSecureConnWanted", err)
	}
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the stub never saw the connection end")
	}
	p.mu.Lock()
	got := p.got.String()
	p.mu.Unlock()
	if strings.Contains(got, "CONNECT") || strings.Contains(got, "tok-SECRET") {
		t.Fatalf("the client wrote %q to a server that offered no TLS", got)
	}
}

// A controlplane that comes back with a different bus key — an identity
// restore onto a controlplane that had generated its own — is refused on every
// nats-level reconnect, and the refusal is in the log once, naming the pin
// mismatch, however many attempts fail the same way (TC-517-33's agent half;
// docs/bus-tls-contract.md).
func TestClient_LogsAReconnectPinMismatchOnce(t *testing.T) {
	s1 := startBus(t, -1, testNode, "tok-A")
	port := portOf(t, s1)
	tc := newTestClient(t, natsURL(t, s1), "tok-A")
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	stopServer(s1)

	// Same port, another key.
	s2 := runServer(t, &natsserver.Options{
		Host: "127.0.0.1", Port: port, Username: testNode, Password: "tok-A",
		TLSConfig:  &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{alwaysValid(t, newKey(t))}},
		TLSTimeout: 5,
	})
	waitFor(t, "three refused reconnect attempts", 20*time.Second, func() bool { return connAttempts(t, s2) >= 3 })
	waitFor(t, "the refusal in the log", 10*time.Second, func() bool {
		return len(tc.logs.records("refused the bus server's key")) > 0
	})
	recs := tc.logs.records("refused the bus server's key")
	if len(recs) != 1 {
		t.Fatalf("%d refusal records for one repeated error, want 1", len(recs))
	}
	if v, ok := attr(recs[0], "err"); !ok || !strings.Contains(v.String(), "does not match RASPUTIN_BUS_PIN") {
		t.Fatalf("err = %v, want the pin mismatch", v)
	}
	if recs[0].Level != slog.LevelWarn {
		t.Errorf("level = %s, want WARN", recs[0].Level)
	}
	if first.IsConnected() || tc.Redials() != 0 {
		t.Fatalf("connected=%v redials=%d: a client joined a bus serving another key", first.IsConnected(), tc.Redials())
	}
}
