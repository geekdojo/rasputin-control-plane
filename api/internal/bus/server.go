package bus

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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
// The bus accepts only TLS (geekdojo/geekdojo-brain#517): a Server either
// listens with Config.TLS, where a client that does not upgrade is refused
// before it can send its CONNECT, or does not listen at all (Config.NoListen).
// There is no configuration that listens in plaintext.
type Server struct {
	cfg Config
	nc  *nats.Conn
	js  jetstream.JetStream

	mu sync.Mutex
	// ns is the running server; nil once Stop has run.
	ns      *server.Server
	stopped bool
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

	// TLS is served on the client port: server-auth TLS with the dedicated
	// bus key, which agents trust by pin (geekdojo/geekdojo-brain#448,
	// api/internal/bustls). The server requires it: its INFO says so, and a
	// client that does not upgrade is refused before it can send its CONNECT,
	// so its join token never crosses the wire.
	TLS *tls.Config
	// NoListen starts the server with no network listener at all: only the
	// api's own in-process connection reaches it. It is the answer when the
	// bus key or certificate did not load — the api keeps running, and no
	// node, the controlplane's own agent included, can join until the key is
	// fixed. Exactly one of TLS and NoListen is set; Start refuses anything
	// else.
	NoListen bool
}

// defaultReadyTimeout bounds the embedded server's start: the wait for it to
// accept connections.
const defaultReadyTimeout = 10 * time.Second

// ErrNoTLS is returned by Start for a config that would listen in plaintext.
var ErrNoTLS = errors.New("bus: refusing to listen without TLS: set Config.TLS, or Config.NoListen to serve no listener")

// ErrTLSAndNoListen is returned by Start for a config that sets both TLS and
// NoListen, which cannot both be meant.
var ErrTLSAndNoListen = errors.New("bus: Config.TLS and Config.NoListen are mutually exclusive")

// Start brings up the embedded NATS server, opens an in-process client,
// initializes JetStream, and creates the streams the architecture relies on.
func Start(ctx context.Context, cfg Config) (*Server, error) {
	switch {
	case cfg.TLS == nil && !cfg.NoListen:
		return nil, ErrNoTLS
	case cfg.TLS != nil && cfg.NoListen:
		return nil, ErrTLSAndNoListen
	}
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
	s := &Server{cfg: cfg}

	ns, err := startServer(s.options())
	if err != nil {
		return nil, err
	}
	s.ns = ns

	inProcOpts := []nats.Option{
		nats.InProcessServer(ns),
		nats.Name(InProcessClientName),
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

// options builds the nats-server options for this Server.
func (s *Server) options() *server.Options {
	cfg := s.cfg
	opts := &server.Options{
		ServerName: "rasputin-api",
		Host:       cfg.Host,
		Port:       cfg.Port,
		JetStream:  true,
		StoreDir:   cfg.StoreDir,
		NoSigs:     true,
		DontListen: cfg.NoListen,
	}
	if cfg.TLS != nil {
		opts.TLSConfig = cfg.TLS
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

// startServer builds, starts and waits for the embedded server. On error
// nothing it started is left running.
func startServer(opts *server.Options) (*server.Server, error) {
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
	// cannot bind is one. That is a failed start this package reports, with
	// the reason, rather than an exit the caller never sees coming.
	fatal := &nonFatalLogger{}
	if l := ns.Logger(); l != nil {
		fatal.Logger = l
		ns.SetLoggerV2(fatal, opts.Debug, opts.Trace, opts.TraceVerbose)
	}
	go ns.Start()
	if !ns.ReadyForConnections(defaultReadyTimeout) {
		ns.Shutdown()
		ns.WaitForShutdown()
		if why := fatal.last(); why != "" {
			return nil, fmt.Errorf("bus: nats server did not start: %s", why)
		}
		return nil, fmt.Errorf("bus: nats server not ready in %s", defaultReadyTimeout)
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
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	ns := s.ns
	s.ns = nil
	s.mu.Unlock()
	if s.nc != nil {
		_ = s.nc.Drain()
	}
	if ns != nil {
		ns.Shutdown()
		ns.WaitForShutdown()
	}
}

// current is the running server, or nil once the Server has stopped.
func (s *Server) current() *server.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ns
}

// ServerID is the running server's unique id ("" once stopped). Connection
// ids are only unique within one server, so the pair names a connection.
func (s *Server) ServerID() string {
	if ns := s.current(); ns != nil {
		return ns.ID()
	}
	return ""
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

// Conn is the in-process NATS client connection, for the life of the Server.
func (s *Server) Conn() *nats.Conn { return s.nc }

// ClientURL is the URL external clients (the agents) dial, and whether there
// is one. With NoListen there is no listener: listening is false and the url
// is "", which a caller must not dial — nats.Connect("") would reach
// nats.DefaultURL, a different server or none.
func (s *Server) ClientURL() (url string, listening bool) {
	if s.cfg.NoListen {
		return "", false
	}
	ns := s.current()
	if ns == nil {
		return "", false
	}
	return ns.ClientURL(), true
}

// InProcessClientName is the NATS client name of the api's own in-process
// connection: it never crosses a network and has no TLS to report.
const InProcessClientName = "rasputin-api (in-process)"
