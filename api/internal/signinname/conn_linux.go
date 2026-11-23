//go:build linux

package signinname

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// sendTimeout bounds one multicast write, a single I/O call.
const sendTimeout = 2 * time.Second

var (
	mdnsGroupIP = [4]byte{224, 0, 0, 251}
	mdnsGroup   = netip.AddrPortFrom(netip.AddrFrom4(mdnsGroupIP), mdnsPort)
)

// GroupOpener returns the production socket opener. Each socket is made by
// hand, as SP-6's stand-in's was: Go's net package rewrites a multicast listen
// address to the wildcard (net/sock_posix.go), which would share
// systemd-resolved's host-unicast datagrams. This one is bound to
// 224.0.0.251:5353 with SO_REUSEADDR, so it co-binds beside resolved in
// either start order and receives only group datagrams; it joins the group on
// ifindex only, with IP_MULTICAST_ALL off so no other link's group traffic
// arrives (F-995-07), sends on that link, and hears its own packets (loop on),
// which the responder drops by source.
func GroupOpener(clock Clock) func(ifindex int) (Conn, error) {
	return func(ifindex int) (Conn, error) { return openGroup(ifindex, clock) }
}

func openGroup(ifindex int, clock Clock) (Conn, error) {
	idx, err := ifindex32(ifindex)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("signinname: socket: %w", err)
	}
	mreq := &unix.IPMreqn{Multiaddr: mdnsGroupIP, Ifindex: idx}
	steps := []struct {
		name string
		fn   func() error
	}{
		{"SO_REUSEADDR", func() error { return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1) }},
		{"bind 224.0.0.251:5353", func() error {
			return unix.Bind(fd, &unix.SockaddrInet4{Port: mdnsPort, Addr: mdnsGroupIP})
		}},
		{"IP_ADD_MEMBERSHIP", func() error {
			return unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, mreq)
		}},
		{"IP_MULTICAST_IF", func() error {
			return unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_IF, mreq)
		}},
		{"IP_MULTICAST_ALL", func() error { return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_ALL, 0) }},
		{"IP_MULTICAST_LOOP", func() error { return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_LOOP, 1) }},
		{"IP_MULTICAST_TTL", func() error { return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, 255) }},
	}
	for _, s := range steps {
		if err := s.fn(); err != nil {
			_ = unix.Close(fd) // the setsockopt error is the one returned
			return nil, fmt.Errorf("signinname: %s on ifindex %d: %w", s.name, ifindex, err)
		}
	}
	f := os.NewFile(uintptr(fd), "signinname-mdns")
	pc, err := net.FilePacketConn(f)
	_ = f.Close() // FilePacketConn holds its own duplicate of fd
	if err != nil {
		return nil, fmt.Errorf("signinname: FilePacketConn: %w", err)
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("signinname: the mDNS socket is not a UDP socket")
	}
	return &groupConn{c: uc, clock: clock}, nil
}

// groupConn is the opened mDNS socket.
type groupConn struct {
	c     *net.UDPConn
	clock Clock
}

func (g *groupConn) Read(b []byte) (int, netip.AddrPort, error) {
	n, src, err := g.c.ReadFromUDPAddrPort(b)
	return n, netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), err
}

func (g *groupConn) Send(b []byte) error {
	if err := g.c.SetWriteDeadline(g.clock.Now().Add(sendTimeout)); err != nil {
		return fmt.Errorf("signinname: write deadline: %w", err)
	}
	_, err := g.c.WriteToUDPAddrPort(b, mdnsGroup)
	return err
}

func (g *groupConn) Close() error { return g.c.Close() }
