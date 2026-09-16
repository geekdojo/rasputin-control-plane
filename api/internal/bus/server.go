package bus

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Server embeds a NATS server with JetStream into the api process and exposes
// the in-process client connection and JetStream context.
type Server struct {
	ns *server.Server
	nc *nats.Conn
	js jetstream.JetStream
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
	// for AllowNonTLS"), so switching modes is a process restart; see
	// bustls.Service.SetMode.
	AllowNonTLS bool
}

// Start brings up the embedded NATS server, opens an in-process client,
// initializes JetStream, and creates the streams the architecture relies on.
func Start(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if cfg.Port == 0 {
		cfg.Port = 4222
	}
	if cfg.StoreDir == "" {
		return nil, fmt.Errorf("bus: StoreDir is required")
	}

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
		opts.AllowNonTLS = cfg.AllowNonTLS
		// A few seconds, not the 0.5s default: a Pi 4 has no AES or SHA
		// extensions and a boot-time handshake competes with everything
		// else coming up.
		opts.TLSTimeout = 5
	}
	if cfg.AuthEnforce {
		if cfg.IssuerPublicKey == "" || cfg.APIUser == "" || cfg.APIPass == "" {
			return nil, fmt.Errorf("bus: AuthEnforce requires IssuerPublicKey, APIUser, APIPass")
		}
		// The api's own connection authenticates as this AuthUser and bypasses
		// the callout (full perms on $G); every other connection is delegated
		// to the busauth responder. See busauth/callout.go.
		opts.Users = []*server.User{{Username: cfg.APIUser, Password: cfg.APIPass}}
		opts.AuthCallout = &server.AuthCallout{
			Issuer:    cfg.IssuerPublicKey,
			AuthUsers: []string{cfg.APIUser},
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
	go ns.Start()
	if !ns.ReadyForConnections(10 * time.Second) {
		return nil, fmt.Errorf("bus: nats server not ready in 10s")
	}

	inProcOpts := []nats.Option{nats.InProcessServer(ns), nats.Name(InProcessClientName)}
	if cfg.AuthEnforce {
		inProcOpts = append(inProcOpts, nats.UserInfo(cfg.APIUser, cfg.APIPass))
	}
	nc, err := nats.Connect("", inProcOpts...)
	if err != nil {
		ns.Shutdown()
		return nil, fmt.Errorf("bus: in-process connect: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		ns.Shutdown()
		return nil, fmt.Errorf("bus: jetstream: %w", err)
	}

	s := &Server{ns: ns, nc: nc, js: js}
	if err := s.setupStreams(ctx); err != nil {
		s.Stop()
		return nil, err
	}
	return s, nil
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
	if s.nc != nil {
		_ = s.nc.Drain()
	}
	if s.ns != nil {
		s.ns.Shutdown()
		s.ns.WaitForShutdown()
	}
}

// Conn is the in-process NATS client connection.
func (s *Server) Conn() *nats.Conn { return s.nc }

// ClientURL is the URL external clients (e.g. the agent during dev) can dial.
func (s *Server) ClientURL() string { return s.ns.ClientURL() }

// InProcessClientName is the NATS client name of the api's own in-process
// connection, so a listing of connections can leave it out: it never crosses
// a network and has no TLS to report.
const InProcessClientName = "rasputin-api (in-process)"

// PlaintextClient is one client connection to the bus that is not using TLS.
type PlaintextClient struct {
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
func (s *Server) PlaintextClients() ([]PlaintextClient, error) {
	cz, err := s.ns.Connz(&server.ConnzOptions{Limit: 4096})
	if err != nil {
		return nil, fmt.Errorf("bus: connz: %w", err)
	}
	out := []PlaintextClient{}
	for _, c := range cz.Conns {
		if c.TLSVersion != "" || c.Name == InProcessClientName {
			continue
		}
		out = append(out, PlaintextClient{Name: c.Name, User: c.AuthorizedUser, IP: c.IP, Port: c.Port})
	}
	return out, nil
}
