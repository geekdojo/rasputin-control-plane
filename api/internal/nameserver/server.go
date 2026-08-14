package nameserver

import (
	"context"
	"errors"
	"fmt"
	"net"
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

	mu               sync.Mutex
	udp, tcp         *dns.Server
	udpAddr, tcpAddr string // the actual bound host:port per transport (meaningful after Start)
	stopped          bool
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

	// Each transport binds the requested port itself; neither is ever handed a
	// port number read back off the other. UDP and TCP have independent port
	// spaces, so an ephemeral port the UDP bind lands on may already be held on
	// TCP — deriving one from the other is a TOCTOU that shows up as an
	// intermittent "bind: address already in use" (#125). In production both
	// transports get 53, as DNS requires; at port 0 they may land on different
	// ports, which is why the two addresses are reported separately.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: s.port})
	if err != nil {
		return fmt.Errorf("nameserver: bind udp %s:%d: %w", ip, s.port, err)
	}
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: s.port})
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("nameserver: bind tcp %s:%d: %w", ip, s.port, err)
	}

	s.mu.Lock()
	s.udp = &dns.Server{PacketConn: pc, Handler: s.handler}
	s.tcp = &dns.Server{Listener: ln, Handler: s.handler}
	s.udpAddr = pc.LocalAddr().String()
	s.tcpAddr = ln.Addr().String()
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

// UDPAddr returns the bound UDP host:port (useful when port 0 was requested).
// Empty until Start has bound successfully.
func (s *Server) UDPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpAddr
}

// TCPAddr returns the bound TCP host:port. It equals UDPAddr for any fixed port
// (53 in production) but not necessarily at port 0, where each transport takes
// whatever the OS assigns it — see Start.
func (s *Server) TCPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcpAddr
}
