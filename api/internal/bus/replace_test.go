package bus

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// Replacing the embedded server in-process (SetAllowNonTLS) — the switch to
// TLS-only without restarting the api (geekdojo/geekdojo-brain#448). Every
// wait here is on an event under a deadline.

const replaceWait = 15 * time.Second

// The reason the api replaces the server instead of reloading it: on the
// vendored nats-server, a reload refuses to change AllowNonTLS. This is a
// trip-wire — if a nats-server upgrade makes it reloadable, this fails, and a
// reload should be evaluated again (it would also have to disconnect the
// plaintext clients already connected, which a reload of this option has
// never been shown to do).
func TestReloadCannotChangeAllowNonTLS(t *testing.T) {
	opts := &server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TLSConfig: serverTLS(t), AllowNonTLS: true, TLSTimeout: 5,
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(replaceWait) {
		t.Fatal("server not ready")
	}
	t.Cleanup(func() { ns.Shutdown(); ns.WaitForShutdown() })

	next := *opts
	next.AllowNonTLS = false
	err = ns.ReloadOptions(&next)
	if err == nil || !strings.Contains(err.Error(), "AllowNonTLS") {
		t.Fatalf("ReloadOptions(AllowNonTLS true → false) = %v; want nats-server to refuse it. "+
			"If this nats-server can reload it now, evaluate a reload instead of SetAllowNonTLS's replacement.", err)
	}
}

// replaceBus is a TLS bus that accepts plaintext, as a controlplane in migrate
// runs it, with its test seams reachable.
func replaceBus(t *testing.T, seam func(s *Server)) *Server {
	t.Helper()
	s := &Server{}
	if seam != nil {
		seam(s)
	}
	s, err := start(context.Background(), Config{
		Host: "127.0.0.1", Port: -1, StoreDir: t.TempDir(),
		TLS: serverTLS(t), AllowNonTLS: true,
	}, s)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

// event is a one-shot fact a test waits for.
type event struct {
	once sync.Once
	ch   chan struct{}
}

func newEvent() *event { return &event{ch: make(chan struct{})} }
func (e *event) fire() { e.once.Do(func() { close(e.ch) }) }

func waitFor(t *testing.T, e *event, what string) {
	t.Helper()
	select {
	case <-e.ch:
	case <-time.After(replaceWait):
		t.Fatalf("%s did not happen within %s", what, replaceWait)
	}
}

func tlsClientOpts() nats.Option {
	return nats.Secure(&tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // loopback test client; pin verification is the agent's, tested there
	})
}

// The whole replacement: the api's connection object survives, every
// subscription it held before works on the new server in both directions
// (a message in, a request answered, a message out), a plaintext client that
// was connected is cut off and its reconnect refused, a raw plaintext CONNECT
// is refused on the wire, a TLS client connects, and the JOBS stream is there.
func TestSetAllowNonTLS_RefusesPlaintextAndKeepsTheAPIConnection(t *testing.T) {
	ctx := context.Background()
	s := replaceBus(t, nil)
	api := s.Conn()
	oldID := s.ServerID()

	got := make(chan string, 4)
	if _, err := api.Subscribe("test.in", func(m *nats.Msg) { got <- string(m.Data) }); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Subscribe("test.echo", func(m *nats.Msg) { _ = m.Respond(append([]byte("echo:"), m.Data...)) }); err != nil {
		t.Fatal(err)
	}
	if err := api.Flush(); err != nil {
		t.Fatal(err)
	}

	plainGone := newEvent()
	plain, err := nats.Connect("nats://"+addrOf(s), nats.Name("plain-agent"),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(*nats.Conn, error) { plainGone.fire() }))
	if err != nil {
		t.Fatalf("plaintext connect in migrate: %v", err)
	}
	t.Cleanup(plain.Close)

	if err := s.SetAllowNonTLS(ctx, false); err != nil {
		t.Fatalf("SetAllowNonTLS(false): %v", err)
	}
	if s.Conn() != api || !api.IsConnected() {
		t.Fatalf("the api's connection was replaced or is down (same=%t, status %v)", s.Conn() == api, api.Status())
	}
	if s.AllowsPlaintext() {
		t.Fatal("AllowsPlaintext = true after the replacement")
	}
	if s.ServerID() == oldID || s.ServerID() == "" {
		t.Fatalf("server id %q after the replacement, was %q: not a new server", s.ServerID(), oldID)
	}

	// The plaintext client was cut off (and cannot come back: the next check).
	waitFor(t, plainGone, "the plaintext client's disconnect")
	if plain.IsConnected() {
		t.Fatal("the plaintext client is connected to a TLS-required bus")
	}

	// A raw plaintext CONNECT is refused on the wire.
	assertPlaintextRefusedOnTheWire(t, s)

	// A TLS client connects, and the api's old subscriptions serve it.
	secure, err := nats.Connect("nats://"+addrOf(s), nats.Name("tls-agent"), tlsClientOpts())
	if err != nil {
		t.Fatalf("TLS connect after the replacement: %v", err)
	}
	t.Cleanup(secure.Close)
	if err := secure.Publish("test.in", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-got:
		if m != "hello" {
			t.Fatalf("api received %q, want hello", m)
		}
	case <-time.After(replaceWait):
		t.Fatal("the api's pre-replacement subscription received nothing on the new server")
	}
	reply, err := secure.Request("test.echo", []byte("ping"), replaceWait)
	if err != nil || string(reply.Data) != "echo:ping" {
		t.Fatalf("request to the api's pre-replacement responder = (%v, %v)", reply, err)
	}
	// And the api reaches a client on the new server.
	out := make(chan struct{}, 1)
	if _, err := secure.Subscribe("test.out", func(*nats.Msg) { out <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	if err := secure.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := api.Publish("test.out", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-out:
	case <-time.After(replaceWait):
		t.Fatal("a publish on the api's connection did not reach a client of the new server")
	}

	if _, err := s.js.Stream(ctx, "JOBS"); err != nil {
		t.Fatalf("JOBS stream after the replacement: %v", err)
	}
	// Setting the mode it is already in changes nothing.
	id := s.ServerID()
	if err := s.SetAllowNonTLS(ctx, false); err != nil || s.ServerID() != id {
		t.Fatalf("a no-op SetAllowNonTLS = %v and server %q → %q, want nothing replaced", err, id, s.ServerID())
	}
}

func assertPlaintextRefusedOnTheWire(t *testing.T, s *Server) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addrOf(s), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	info, r := readInfo(t, conn)
	if info["tls_required"] != true {
		t.Fatalf("INFO tls_required = %v, want true", info["tls_required"])
	}
	if _, err := conn.Write([]byte("CONNECT {\"verbose\":false}\r\nPING\r\n")); err != nil {
		t.Fatal(err)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("the server neither answered nor closed a plaintext CONNECT: %v", err)
			}
			return
		}
		if strings.HasPrefix(line, "PONG") {
			t.Fatal("a plaintext client got PONG from a TLS-required bus")
		}
	}
}

// Disconnect advisories keep flowing after a replacement (the new server gets
// the export and import, the subscription is re-sent), and they name
// connections on the running server.
func TestSetAllowNonTLS_DisconnectAdvisoriesSurvive(t *testing.T) {
	s := replaceBus(t, nil)
	closed := make(chan uint64, 16)
	if err := s.OnClientDisconnect(func(cid uint64) { closed <- cid }); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAllowNonTLS(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	secure, err := nats.Connect("nats://"+addrOf(s), nats.Name("leaving"), tlsClientOpts())
	if err != nil {
		t.Fatal(err)
	}
	cid, err := secure.GetClientID()
	if err != nil {
		t.Fatal(err)
	}
	secure.Close()
	deadline := time.After(replaceWait)
	for {
		select {
		case got := <-closed:
			if got == cid {
				return
			}
		case <-deadline:
			t.Fatalf("no disconnect advisory for connection %d on the new server", cid)
		}
	}
}

// The replacement cannot start (a failure injected before the new server is
// built): the previous options run again, the api's connection is back and
// its subscriptions work, plaintext is accepted again, and the error says so.
func TestSetAllowNonTLS_FallsBackWhenTheNewServerDoesNotStart(t *testing.T) {
	s := replaceBus(t, func(s *Server) {
		s.beforeStart = func(opts *server.Options) error {
			if !opts.AllowNonTLS {
				return errors.New("injected: the TLS-required server does not start")
			}
			return nil
		}
	})
	assertFallback(t, s)
}

// The same, with a real failure: the port is taken between the old server
// shutting down and the new one binding it. nats-server's logger would exit
// the process on that; it must come back as an error, and the fallback must
// bind once the port is free again.
func TestSetAllowNonTLS_FallsBackWhenThePortIsTaken(t *testing.T) {
	var squatter net.Listener
	s := replaceBus(t, func(s *Server) {
		s.readyTimeout = 2 * time.Second
		s.beforeStart = func(opts *server.Options) error {
			if s.nc == nil {
				return nil // the first start
			}
			if !opts.AllowNonTLS {
				l, err := net.Listen("tcp", net.JoinHostPort(opts.Host, fmt.Sprint(opts.Port)))
				if err != nil {
					return fmt.Errorf("test could not take the port: %w", err)
				}
				squatter = l
				return nil
			}
			return squatter.Close()
		}
	})
	assertFallback(t, s)
}

func assertFallback(t *testing.T, s *Server) {
	t.Helper()
	api := s.Conn()
	got := make(chan struct{}, 1)
	if _, err := api.Subscribe("test.in", func(*nats.Msg) { got <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	if err := api.Flush(); err != nil {
		t.Fatal(err)
	}
	err := s.SetAllowNonTLS(context.Background(), false)
	if !errors.Is(err, ErrFellBack) {
		t.Fatalf("SetAllowNonTLS = %v, want an error wrapping ErrFellBack", err)
	}
	if !s.AllowsPlaintext() || s.ServerID() == "" || s.Conn() != api || !api.IsConnected() {
		t.Fatalf("after the fallback: plaintext=%t server=%q sameConn=%t connected=%t", s.AllowsPlaintext(), s.ServerID(), s.Conn() == api, api.IsConnected())
	}
	plain, err := nats.Connect("nats://"+addrOf(s), nats.Name("plain-agent"))
	if err != nil {
		t.Fatalf("plaintext connect after the fallback: %v", err)
	}
	defer plain.Close()
	if err := plain.Publish("test.in", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(replaceWait):
		t.Fatal("the api's subscription does not work on the fallback server")
	}
}

// Neither the replacement nor the fallback starts: there is no bus, and the
// error is not ErrFellBack, so the caller cannot mistake it for a working one.
func TestSetAllowNonTLS_NoBusWhenTheFallbackFailsToo(t *testing.T) {
	var started bool
	s := replaceBus(t, func(s *Server) {
		s.beforeStart = func(*server.Options) error {
			if !started {
				started = true
				return nil
			}
			return errors.New("injected: nothing starts")
		}
	})
	err := s.SetAllowNonTLS(context.Background(), false)
	if err == nil || errors.Is(err, ErrFellBack) || !strings.Contains(err.Error(), "NO BUS") {
		t.Fatalf("SetAllowNonTLS = %v, want a NO BUS error that is not ErrFellBack", err)
	}
	if s.ServerID() != "" {
		t.Fatalf("a server is reported running (%q) with none started", s.ServerID())
	}
	if _, err := s.PlaintextClients(); err == nil {
		t.Fatal("PlaintextClients answered with no server running")
	}
	if err := s.SetAllowNonTLS(context.Background(), true); err == nil {
		t.Fatal("a second SetAllowNonTLS on a bus with no server succeeded")
	}
}

// With no TLS configured there is nothing to require.
func TestSetAllowNonTLS_RefusedWithoutTLS(t *testing.T) {
	s, err := Start(context.Background(), Config{Host: "127.0.0.1", Port: -1, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	id := s.ServerID()
	if err := s.SetAllowNonTLS(context.Background(), false); err == nil {
		t.Fatal("SetAllowNonTLS(false) on a bus with no TLS succeeded")
	}
	if s.ServerID() != id {
		t.Fatal("the server was replaced anyway")
	}
}

// A connection id recorded on the replaced server names nothing on the new
// one, even where the new server has a connection with the same id.
func TestClientOpen_OldServerIDsNameNothingAfterReplacement(t *testing.T) {
	s := replaceBus(t, nil)
	plain, err := nats.Connect("nats://"+addrOf(s), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	cid, err := plain.GetClientID()
	if err != nil {
		t.Fatal(err)
	}
	oldID := s.ServerID()
	if !s.ClientOpen(oldID, cid) {
		t.Fatal("ClientOpen is false for a live connection")
	}
	if err := s.SetAllowNonTLS(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	var conns []*nats.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	// Open TLS clients on the new server until one has the old id.
	for i := uint64(0); i <= cid+1; i++ {
		c, err := nats.Connect("nats://"+addrOf(s), tlsClientOpts(), nats.NoReconnect())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		if got, _ := c.GetClientID(); got == cid {
			break
		}
	}
	if s.ClientOpen(oldID, cid) || s.DisconnectClient(oldID, cid) {
		t.Fatal("an id from the replaced server named (or closed) a connection on the new one")
	}
	if !s.ClientOpen(s.ServerID(), cid) {
		t.Skipf("the new server never assigned id %d; the collision this guards against did not occur", cid)
	}
}
