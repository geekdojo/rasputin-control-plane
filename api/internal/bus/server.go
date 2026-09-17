package bus

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Server embeds a NATS server with JetStream into the api process and exposes
// the in-process client connection and JetStream context.
//
// The embedded nats-server can be REPLACED while the api runs
// (SetAllowNonTLS): the old one shuts down and a new one starts on the same
// port and store. The in-process connection (Conn) survives that. It is one
// *nats.Conn for the life of the process, dialed through a provider that
// always hands out a pipe to the current server, so every consumer that holds
// it keeps holding a working connection, and nats.go re-sends every
// subscription on it when it reconnects.
type Server struct {
	cfg Config // Port is the bound port once the first server is up
	nc  *nats.Conn
	js  jetstream.JetStream

	mu sync.Mutex
	// ns is the running server; nil between the old one shutting down and
	// its replacement (or fallback) being installed.
	ns          *server.Server
	allowNonTLS bool
	url         string
	// connServer is the server the in-process connection's current pipe
	// came from, and reconnected is closed (and replaced) every time that
	// connection finishes a reconnect: together, the event a replacement
	// waits on to know the api's own connection is on the new server.
	connServer  *server.Server
	reconnected chan struct{}
	// onDisconnect is OnClientDisconnect's callback, re-wired on every
	// server this Server starts.
	onDisconnect func(cid uint64)

	// swapMu serialises SetAllowNonTLS and Stop.
	swapMu  sync.Mutex
	stopped bool

	// Test seams. beforeStart runs before each server is built, with the
	// options it will get; an error fails that start as if the server had.
	// readyTimeout bounds one server's wait to accept connections.
	beforeStart  func(opts *server.Options) error
	readyTimeout time.Duration
}

// Config controls the embedded NATS server's listen address and storage.
type Config struct {
	Host     string // default 127.0.0.1
	Port     int    // default 4222
	StoreDir string // JetStream storage root; must exist and be writable

	// AuthEnforce turns on NATS auth callout. When false (default) the bus is
	// open exactly as before — zero change to existing behavior. When true,
	// IssuerPublicKey + APIUser + APIPass must be set: external connections are
	// delegated to the in-process busauth responder, while the api's own
	// connection authenticates as the AuthUser and bypasses the callout.
	AuthEnforce     bool
	IssuerPublicKey string // account public key the callout responder signs with
	APIUser         string // AuthUser name for the api's in-process connection
	APIPass         string // AuthUser secret (per-boot random is fine)

	// TLS, when non-nil, is served on the client port: server-auth TLS with
	// the dedicated bus key, which agents trust by pin
	// (geekdojo/geekdojo-brain#448, api/internal/bustls). nil keeps the bus
	// plaintext, exactly as before — which is what every test helper that
	// dials an embedded server still wants.
	TLS *tls.Config
	// AllowNonTLS, with TLS set, accepts plaintext clients beside TLS ones:
	// the migration window, while nodes enrolled before the bus key existed
	// have no pin yet. false with TLS set is TLS-required — the server's INFO
	// says so, and a client that does not upgrade is refused before it can
	// send its CONNECT, so its join token never crosses the wire.
	//
	// nats-server cannot change this on reload ("config reload not supported
	// for AllowNonTLS", proven by TestReloadCannotChangeAllowNonTLS), so
	// SetAllowNonTLS replaces the server inside this process instead.
	AllowNonTLS bool
}

// defaultReadyTimeout bounds one embedded server's start: the wait for it to
// accept connections.
const defaultReadyTimeout = 10 * time.Second

// defaultRejoinTimeout bounds a replacement's wait for the api's in-process
// connection to be back on the new server, when the caller set no deadline.
// The connection is a pipe inside this process: this is a bound on one local
// reconnect and round trip, never a wait for something outside to happen.
const defaultRejoinTimeout = 30 * time.Second

// Start brings up the embedded NATS server, opens an in-process client,
// initializes JetStream, and creates the streams the architecture relies on.
func Start(ctx context.Context, cfg Config) (*Server, error) {
	return start(ctx, cfg, nil)
}

// start is Start with a Server whose test seams are already set.
func start(ctx context.Context, cfg Config, s *Server) (*Server, error) {
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if cfg.Port == 0 {
		cfg.Port = 4222
	}
	if cfg.StoreDir == "" {
		return nil, fmt.Errorf("bus: StoreDir is required")
	}
	if cfg.AuthEnforce && (cfg.IssuerPublicKey == "" || cfg.APIUser == "" || cfg.APIPass == "") {
		return nil, fmt.Errorf("bus: AuthEnforce requires IssuerPublicKey, APIUser, APIPass")
	}
	if s == nil {
		s = &Server{}
	}
	s.cfg = cfg
	s.reconnected = make(chan struct{})

	ns, err := s.startServer(s.options(cfg.AllowNonTLS))
	if err != nil {
		return nil, err
	}
	// A random port (-1, tests) is resolved once: a replacement binds the
	// same port, because that is the address every node dials.
	if addr, ok := ns.Addr().(*net.TCPAddr); ok {
		s.cfg.Port = addr.Port
	}
	s.ns, s.allowNonTLS, s.url = ns, cfg.AllowNonTLS, ns.ClientURL()

	inProcOpts := []nats.Option{
		nats.InProcessServer(inProcessProvider{s}),
		nats.Name(InProcessClientName),
		// Never give up: the connection is replaced under a running process
		// (SetAllowNonTLS), and a closed one cannot be reopened — every
		// consumer holds this exact *nats.Conn.
		nats.MaxReconnects(-1),
		nats.ReconnectHandler(func(*nats.Conn) { s.noteReconnected() }),
	}
	if cfg.AuthEnforce {
		inProcOpts = append(inProcOpts, nats.UserInfo(cfg.APIUser, cfg.APIPass))
	}
	nc, err := nats.Connect("", inProcOpts...)
	if err != nil {
		ns.Shutdown()
		ns.WaitForShutdown()
		return nil, fmt.Errorf("bus: in-process connect: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		ns.Shutdown()
		ns.WaitForShutdown()
		return nil, fmt.Errorf("bus: jetstream: %w", err)
	}

	s.nc, s.js = nc, js
	if err := s.setupStreams(ctx); err != nil {
		s.Stop()
		return nil, err
	}
	return s, nil
}

// options builds the nats-server options for this Server with plaintext
// allowed or not. Every server this Server starts — the first, a replacement,
// a fallback — is built here, so they differ in AllowNonTLS alone.
func (s *Server) options(allowNonTLS bool) *server.Options {
	cfg := s.cfg
	opts := &server.Options{
		ServerName: "rasputin-api",
		Host:       cfg.Host,
		Port:       cfg.Port,
		JetStream:  true,
		StoreDir:   cfg.StoreDir,
		NoSigs:     true,
	}
	if cfg.TLS != nil {
		opts.TLSConfig = cfg.TLS
		opts.AllowNonTLS = allowNonTLS
		// A few seconds, not the 0.5s default: a Pi 4 has no AES or SHA
		// extensions and a boot-time handshake competes with everything
		// else coming up.
		opts.TLSTimeout = 5
	}
	if cfg.AuthEnforce {
		// The api's own connection authenticates as this AuthUser and bypasses
		// the callout (full perms on $G); every other connection is delegated
		// to the busauth responder. See busauth/callout.go.
		opts.Users = []*server.User{{Username: cfg.APIUser, Password: cfg.APIPass}}
		opts.AuthCallout = &server.AuthCallout{
			Issuer:    cfg.IssuerPublicKey,
			AuthUsers: []string{cfg.APIUser},
		}
	}
	return opts
}

// startServer builds, starts and waits for one embedded server, and wires the
// server-side state this Server keeps (the disconnect advisory import). On
// error nothing it started is left running.
func (s *Server) startServer(opts *server.Options) (*server.Server, error) {
	if s.beforeStart != nil {
		if err := s.beforeStart(opts); err != nil {
			return nil, fmt.Errorf("bus: new server: %w", err)
		}
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		return nil, fmt.Errorf("bus: new server: %w", err)
	}
	// Without this the embedded server has NO logger and says nothing, ever —
	// including about its own authorization decisions. A permissions violation
	// is logged server-side with the user, the subject and the connection id,
	// which is the only place both halves of a denied reply appear together;
	// with logging off, a node silently losing the right to answer left no
	// trace anywhere in the controlplane journal. Info level: no Debug, no
	// Trace, so this is startup lines plus errors, not per-message noise.
	ns.ConfigureLogger()
	// nats-server's logger exits the PROCESS on a fatal error, and a port it
	// cannot bind is one. That is a failed start this package reports and
	// recovers from (SetAllowNonTLS falls back), not a reason to kill the api.
	fatal := &nonFatalLogger{}
	if l := ns.Logger(); l != nil {
		fatal.Logger = l
		ns.SetLoggerV2(fatal, opts.Debug, opts.Trace, opts.TraceVerbose)
	}
	go ns.Start()
	timeout := s.readyTimeout
	if timeout <= 0 {
		timeout = defaultReadyTimeout
	}
	if !ns.ReadyForConnections(timeout) {
		ns.Shutdown()
		ns.WaitForShutdown()
		if why := fatal.last(); why != "" {
			return nil, fmt.Errorf("bus: nats server did not start: %s", why)
		}
		return nil, fmt.Errorf("bus: nats server not ready in %s", timeout)
	}
	s.mu.Lock()
	onDisconnect := s.onDisconnect
	s.mu.Unlock()
	if onDisconnect != nil {
		if err := importDisconnectAdvisory(ns); err != nil {
			// The advisory only makes a decision prompter; losing it is
			// logged, not fatal (see OnClientDisconnect).
			log.Printf("bus: %v", err)
		}
	}
	return ns, nil
}

func (s *Server) setupStreams(ctx context.Context) error {
	_, err := s.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      "JOBS",
		Subjects:  []string{"rasputin.job.>"},
		Retention: jetstream.LimitsPolicy,
		MaxAge:    30 * 24 * time.Hour,
		Storage:   jetstream.FileStorage,
	})
	if err != nil {
		return fmt.Errorf("bus: create JOBS stream: %w", err)
	}
	return nil
}

// Stop drains the client connection and shuts down the embedded server.
func (s *Server) Stop() {
	s.swapMu.Lock()
	defer s.swapMu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	if s.nc != nil {
		_ = s.nc.Drain()
	}
	s.mu.Lock()
	ns := s.ns
	s.ns = nil
	s.mu.Unlock()
	if ns != nil {
		ns.Shutdown()
		ns.WaitForShutdown()
	}
}

// ErrFellBack is wrapped by SetAllowNonTLS's error when the replacement server
// did not start and the previous options are running again: the bus works,
// just not in the mode that was asked for.
var ErrFellBack = errors.New("bus: the replacement server did not start; the bus is running again with its previous options")

// errReplacing is what a server-side read answers between the old server
// shutting down and its replacement being installed.
var errReplacing = errors.New("bus: the embedded server is being replaced")

// SetAllowNonTLS makes the bus accept plaintext clients or refuse them, while
// the api keeps running. nats-server cannot reload that option, so this
// replaces the embedded server:
//
//  1. the old server shuts down, which closes every client connection — the
//     api's in-process one included;
//  2. a new server starts with the same options except AllowNonTLS, on the
//     same port and JetStream store, and gets the same server-side wiring
//     (the disconnect advisory import);
//  3. the api's in-process connection is sent to it at once (a forced
//     reconnect, not the client's reconnect back-off), nats.go re-sends every
//     subscription on it, and a round trip proves the server has them;
//  4. the JOBS stream is ensured again.
//
// Remote clients (the agents) reconnect by themselves on their own reconnect
// loops. Nothing here waits on a clock: the new server's start and the
// in-process round trip are each bounded, the latter by ctx.
//
// A nil error means the new server is up in the mode asked for and the api's
// own connection works on it. An error wrapping ErrFellBack means the new
// server did not start and one with the PREVIOUS options is running again,
// with the in-process connection back on it. Any other error means there is
// no working bus: neither server could be brought up, or the api's own
// connection did not rejoin within ctx. The api cannot run like that.
func (s *Server) SetAllowNonTLS(ctx context.Context, allow bool) error {
	s.swapMu.Lock()
	defer s.swapMu.Unlock()
	if s.stopped {
		return errors.New("bus: stopped")
	}
	if s.cfg.TLS == nil {
		return errors.New("bus: no TLS is configured, so plaintext cannot be refused")
	}
	s.mu.Lock()
	prev, old := s.allowNonTLS, s.ns
	if old == nil {
		s.mu.Unlock()
		return errors.New("bus: NO BUS: no embedded server is running (an earlier replacement failed)")
	}
	if prev == allow {
		s.mu.Unlock()
		return nil
	}
	s.ns = nil
	s.mu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultRejoinTimeout)
		defer cancel()
	}

	log.Printf("bus: replacing the embedded server in-process: plaintext %s → %s", allowedWord(prev), allowedWord(allow))
	old.Shutdown()
	old.WaitForShutdown()

	next, startErr := s.startServer(s.options(allow))
	if startErr != nil {
		log.Printf("bus: the replacement server did not start (%v); starting one with the previous options (plaintext %s)", startErr, allowedWord(prev))
		back, backErr := s.startServer(s.options(prev))
		if backErr != nil {
			return fmt.Errorf("bus: NO BUS: the replacement server did not start (%v), and neither did one with the previous options: %w", startErr, backErr)
		}
		if err := s.install(ctx, back, prev); err != nil {
			return fmt.Errorf("bus: NO BUS: a server with the previous options is up, but the api's own connection did not rejoin it: %w", err)
		}
		return fmt.Errorf("%w: %v", ErrFellBack, startErr)
	}
	if err := s.install(ctx, next, allow); err != nil {
		return fmt.Errorf("bus: NO BUS: the replacement server is up, but the api's own connection did not rejoin it: %w", err)
	}
	log.Printf("bus: the embedded server was replaced: plaintext %s; the api's connection and its subscriptions are on the new server", allowedWord(allow))
	return nil
}

// install makes ns the running server and brings the in-process connection
// onto it.
func (s *Server) install(ctx context.Context, ns *server.Server, allow bool) error {
	s.mu.Lock()
	s.ns, s.allowNonTLS = ns, allow
	onIt := s.connServer == ns
	s.mu.Unlock()
	if !onIt {
		// The connection's own reconnect loop would retry after its back-off;
		// the fact that a server is ready is the trigger instead. Forcing it
		// when the loop has just got there on its own costs one extra
		// reconnect, which awaitInProcess rides out.
		if err := s.nc.ForceReconnect(); err != nil {
			return fmt.Errorf("reconnect: %w", err)
		}
	}
	if err := s.awaitInProcess(ctx, ns); err != nil {
		return err
	}
	return s.setupStreams(ctx)
}

// awaitInProcess waits until the in-process connection is connected through a
// pipe from ns and a round trip on it succeeds, re-checking only when a
// reconnect completes. The round trip comes after nats.go has re-sent the
// subscriptions, so the server holds them when it answers.
func (s *Server) awaitInProcess(ctx context.Context, ns *server.Server) error {
	for {
		s.mu.Lock()
		changed, onIt := s.reconnected, s.connServer == ns
		s.mu.Unlock()
		if onIt && s.nc.IsConnected() {
			err := s.nc.FlushWithContext(ctx)
			if err == nil {
				return nil
			}
			if ctx.Err() != nil {
				return err
			}
			// The connection dropped under the round trip (a second
			// reconnect); the next reconnect is the next chance.
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("the api's in-process connection is not back on the new server: %w", ctx.Err())
		}
	}
}

func (s *Server) noteReconnected() {
	s.mu.Lock()
	defer s.mu.Unlock()
	close(s.reconnected)
	s.reconnected = make(chan struct{})
}

// inProcessProvider hands the in-process connection a pipe to whichever
// server is running now, and records which one.
type inProcessProvider struct{ s *Server }

func (p inProcessProvider) InProcessConn() (net.Conn, error) {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()
	if p.s.ns == nil {
		return nil, errReplacing
	}
	conn, err := p.s.ns.InProcessConn()
	if err != nil {
		return nil, err
	}
	p.s.connServer = p.s.ns
	return conn, nil
}

// current is the running server, or nil while one is being replaced.
func (s *Server) current() *server.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ns
}

// AllowsPlaintext reports whether the running server accepts plaintext
// clients: always with no TLS configured, else per its AllowNonTLS.
func (s *Server) AllowsPlaintext() bool {
	if s.cfg.TLS == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowNonTLS
}

// ServerID is the running server's unique id ("" while it is being replaced).
// Every server this process starts has a new one, and connection ids are only
// unique within one server, so the pair names a connection.
func (s *Server) ServerID() string {
	if ns := s.current(); ns != nil {
		return ns.ID()
	}
	return ""
}

func allowedWord(allow bool) string {
	if allow {
		return "allowed"
	}
	return "REFUSED"
}

// nonFatalLogger is the embedded server's logger with Fatalf demoted to an
// error that is remembered, so a server that cannot start reports why instead
// of ending the process.
type nonFatalLogger struct {
	server.Logger
	lastFatal atomic.Pointer[string]
}

func (l *nonFatalLogger) Fatalf(format string, v ...any) {
	msg := fmt.Sprintf(format, v...)
	l.lastFatal.Store(&msg)
	l.Errorf("%s", msg)
}

func (l *nonFatalLogger) last() string {
	if p := l.lastFatal.Load(); p != nil {
		return *p
	}
	return ""
}

// Conn is the in-process NATS client connection. It is the same connection
// for the life of the Server, across SetAllowNonTLS.
func (s *Server) Conn() *nats.Conn { return s.nc }

// ClientURL is the URL external clients (e.g. the agent during dev) can dial.
func (s *Server) ClientURL() string { return s.url }

// InProcessClientName is the NATS client name of the api's own in-process
// connection, so a listing of connections can leave it out: it never crosses
// a network and has no TLS to report.
const InProcessClientName = "rasputin-api (in-process)"

// PlaintextClient is one client connection to the bus that is not using TLS.
type PlaintextClient struct {
	// CID is the server's connection id.
	CID  uint64 `json:"cid"`
	Name string `json:"name,omitempty"`
	// User is the authorised username — the node id an agent presents — when
	// auth is on. Empty with auth off.
	User string `json:"user,omitempty"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// PlaintextClients lists the client connections currently open without TLS,
// the api's own in-process connection excluded. It is the server's view,
// independent of anything an agent reports about itself: the fact that says
// turning plaintext off would cut someone off right now.
//
// Only connections that have completed their CONNECT count. The server lists a
// connection from the moment it accepts the socket, so one still negotiating
// TLS — a pinned agent mid-handshake, or an unpinned one about to be refused —
// is listed with no TLS version yet. It is not a plaintext client: it has not
// spoken the protocol, and nothing would be cut off. A completed CONNECT shows
// as an authorised user (auth on) or a client language (every client library
// sends one).
//
// Connz can wait up to TLSTimeout: in the migration window the server holds a
// new connection's lock while it waits for the first bytes to tell TLS from
// plaintext, and Connz takes that lock. That bounds a status read or an
// evaluation; it never makes one wrong.
func (s *Server) PlaintextClients() ([]PlaintextClient, error) {
	ns := s.current()
	if ns == nil {
		return nil, errReplacing
	}
	cz, err := ns.Connz(&server.ConnzOptions{Limit: 4096})
	if err != nil {
		return nil, fmt.Errorf("bus: connz: %w", err)
	}
	out := []PlaintextClient{}
	for _, c := range cz.Conns {
		if !isPlaintextClient(c) {
			continue
		}
		out = append(out, PlaintextClient{CID: c.Cid, Name: c.Name, User: c.AuthorizedUser, IP: c.IP, Port: c.Port})
	}
	return out, nil
}

// isPlaintextClient is PlaintextClients' rule for one connection.
func isPlaintextClient(c *server.ConnInfo) bool {
	if c.TLSVersion != "" || c.Name == InProcessClientName {
		return false
	}
	// No CONNECT processed yet: not a client, whatever the socket turns into.
	return c.AuthorizedUser != "" || c.Lang != ""
}
