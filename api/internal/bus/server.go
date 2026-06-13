package bus

import (
	"context"
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
	go ns.Start()
	if !ns.ReadyForConnections(10 * time.Second) {
		return nil, fmt.Errorf("bus: nats server not ready in 10s")
	}

	inProcOpts := []nats.Option{nats.InProcessServer(ns)}
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

// JS is the JetStream context bound to Conn.
func (s *Server) JS() jetstream.JetStream { return s.js }

// ClientURL is the URL external clients (e.g. the agent during dev) can dial.
func (s *Server) ClientURL() string { return s.ns.ClientURL() }
