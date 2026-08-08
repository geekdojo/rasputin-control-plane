package nameserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/miekg/dns"
)

// ErrNoLANRoute is returned by Start when the control plane has no LAN IPv4 to
// bind — e.g. a dev box with no default route. Callers treat it as "run without
// the nameserver," not a fatal error: a control plane that won't start is worse
// than one without name resolution (the same posture main takes elsewhere).
var ErrNoLANRoute = errors.New("nameserver: no LAN IPv4 to bind")

// Server binds the authoritative responder on the control plane's LAN IP for
// both UDP and TCP. It binds that IP *by value*, never 0.0.0.0:53, so it never
// displaces systemd-resolved's 127.0.0.53:53 stub — which also publishes the
// cluster's mDNS <cluster>.local (ADR-0003), so taking the wildcard would break
// cluster discovery.
type Server struct {
	handler dns.Handler
	ipFn    func() net.IP // the CP's LAN IPv4, re-resolved at Start (it moves per lease)
	port    int           // 53 in production; 0 asks the OS for an ephemeral port (tests)

	mu       sync.Mutex
	udp, tcp *dns.Server
	addr     string // the actual bound host:port (meaningful after Start)
	stopped  bool
}

// NewServer builds a nameserver that binds ipFn()'s address on the given port
// (use 0 for an OS-assigned port in tests). handler is normally a *Responder.
func NewServer(ipFn func() net.IP, port int, handler dns.Handler) *Server {
	return &Server{handler: handler, ipFn: ipFn, port: port}
}

// Start resolves the LAN IP, binds UDP+TCP, and serves until ctx is cancelled
// (or Stop is called). It returns once serving has begun; bind errors are
// returned synchronously. Returns ErrNoLANRoute if there is no LAN IPv4.
func (s *Server) Start(ctx context.Context) error {
	ip := s.ipFn()
	if ip == nil || ip.To4() == nil {
		return ErrNoLANRoute
	}

	// Bind UDP first; when port is 0 the OS assigns one, and we then bind TCP on
	// that same port so a caller has a single address for both transports.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: s.port})
	if err != nil {
		return fmt.Errorf("nameserver: bind udp %s:%d: %w", ip, s.port, err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("nameserver: bind tcp %s: %w", addr, err)
	}

	s.mu.Lock()
	s.udp = &dns.Server{PacketConn: pc, Handler: s.handler}
	s.tcp = &dns.Server{Listener: ln, Handler: s.handler}
	s.addr = addr
	s.mu.Unlock()

	go func() { _ = s.udp.ActivateAndServe() }()
	go func() { _ = s.tcp.ActivateAndServe() }()
	go func() {
		<-ctx.Done()
		_ = s.Stop()
	}()
	return nil
}

// Stop shuts down both listeners. Idempotent and safe to call concurrently with
// the ctx-cancellation path in Start.
func (s *Server) Stop() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	udp, tcp := s.udp, s.tcp
	s.mu.Unlock()

	var errs []error
	if udp != nil {
		if err := udp.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	if tcp != nil {
		if err := tcp.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Addr returns the bound host:port (useful when port 0 was requested). Empty
// until Start has bound successfully.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}
