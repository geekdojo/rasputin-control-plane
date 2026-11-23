//go:build linux

package signinname

// CI SO-19 (TC-995-20, signin-origin.md SO-19): the responder on a real Linux
// socket, in two network namespaces joined by a veth pair.
//
// What it proves: the group-bound socket co-binds beside a wildcard
// SO_REUSEADDR socket on 5353 (the shape of systemd-resolved's) and receives
// no host-unicast datagram; a querier on the other end of the link sees three
// probes before the first announcement and reads sso-<cid>.local at the
// responder's address; a query for <cid>.local draws nothing; a claimant's
// announcement stops every answer and raises the conflict naming it; its
// goodbye brings probing and the name back with no restart; and stop sends
// the TTL-0 goodbye. What it does not prove: co-binding beside the real
// resolved, or any operating system's resolver (bench IDT-24 and IDT-25).
//
// How to run it: as root on Linux with iproute2's ip,
//
//	go test -c -o /tmp/signinname.test ./api/internal/signinname
//	sudo RASPUTIN_SIGNINNAME_FUNCTIONAL=required /tmp/signinname.test -test.v -test.run '^TestSO19_'
//
// Without root or ip it skips, and with the switch set to required the skip
// is a failure. CI's backend job runs it that way.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/lanaddr"
)

const so19Switch = "RASPUTIN_SIGNINNAME_FUNCTIONAL"

// so19Step is each step's one long deadline: far past the few seconds a step
// takes, it only marks a step dead.
const so19Step = 60 * time.Second

var (
	so19A = netip.MustParseAddr("10.99.19.1")
	so19B = netip.MustParseAddr("10.99.19.2")
)

const (
	so19Name = "sso-so19.local."
	so19CID  = "so19.local."
)

func TestSO19_SigninNameInNamespaces(t *testing.T) {
	if os.Geteuid() != 0 {
		functest.SkipOrFail(t, so19Switch, "SO-19 needs root to create network namespaces")
		return
	}
	if _, err := exec.LookPath("ip"); err != nil {
		functest.SkipOrFail(t, so19Switch, "SO-19 needs the ip tool: %v", err)
		return
	}
	nsA, nsB, idxA := so19Netns(t)

	// In A: a wildcard SO_REUSEADDR socket on 5353 plays the part of resolved.
	var resolved *net.UDPConn
	if err := inNetns(nsA, func() error {
		var err error
		resolved, err = reuseUDP(netip.AddrPortFrom(netip.IPv4Unspecified(), 5353), 0)
		return err
	}); err != nil {
		t.Fatalf("the stand-in for resolved: %v", err)
	}
	defer resolved.Close()
	standIn := make(chan []byte, 64)
	go readLoop(resolved, func(b []byte, _ netip.AddrPort) { standIn <- b })

	// In B: one socket on 5353 joined to the group, the querier and claimant.
	var bConn *net.UDPConn
	if err := inNetns(nsB, func() error {
		ifi, err := net.InterfaceByName("so19b")
		if err != nil {
			return err
		}
		bConn, err = reuseUDP(netip.AddrPortFrom(netip.IPv4Unspecified(), 5353), ifi.Index)
		return err
	}); err != nil {
		t.Fatalf("B's socket: %v", err)
	}
	defer bConn.Close()
	fromA := make(chan *dns.Msg, 256)
	var everA []*dns.Msg
	var everMu sync.Mutex
	go readLoop(bConn, func(b []byte, src netip.AddrPort) {
		if src.Addr().Unmap() != so19A {
			return
		}
		m := new(dns.Msg)
		if m.Unpack(b) == nil {
			everMu.Lock()
			everA = append(everA, m)
			everMu.Unlock()
			fromA <- m
		}
	})
	group := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{224, 0, 0, 251}), 5353))
	sendB := func(m *dns.Msg) {
		t.Helper()
		b, err := m.Pack()
		if err == nil {
			_, err = bConn.WriteTo(b, group)
		}
		if err != nil {
			t.Fatalf("B send: %v", err)
		}
	}

	// The responder in A, on its real socket, counting what it reads from B.
	logs := newLogWatch(t)
	reads := make(chan struct{}, 256)
	var fromB int
	var fromBMu sync.Mutex
	open := func(idx int) (Conn, error) {
		var c Conn
		err := inNetns(nsA, func() error {
			var err error
			c, err = openGroup(idx, SystemClock{})
			return err
		})
		if err != nil {
			return nil, err
		}
		return countingConn{Conn: c, on: func(src netip.AddrPort) {
			if src.Addr() == so19B {
				fromBMu.Lock()
				fromB++
				fromBMu.Unlock()
				reads <- struct{}{}
			}
		}}, nil
	}
	readCount := func() int { fromBMu.Lock(); defer fromBMu.Unlock(); return fromB }
	addrs := &fakeAddrs{s: lanaddr.Snapshot{Usable: []lanaddr.Addr{{IP: net.IP(so19A.AsSlice()), Link: "so19a", Index: idxA}}}}
	r, err := New(Config{Name: so19Name, Addrs: addrs, Open: open, Clock: SystemClock{}, Log: slog.New(logs)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go r.Run(ctx)

	// The steps run in TC-995-20's order but for step 1, which needs the
	// responder's socket open, so it runs once the name is published.

	// (2) B sees three probes before the first announcement.
	t.Run("step 2: probes then publish", func(t *testing.T) {
		probes := 0
		for {
			m := next(t, fromA, "the first announcement")
			if !m.Response && len(m.Ns) > 0 {
				probes++
				continue
			}
			if m.Response {
				break
			}
		}
		if probes != 3 {
			t.Fatalf("%d probes before the first announcement, want 3", probes)
		}
		readName(t, sendB, fromA)
	})

	// (1) A unicast datagram to A on 5353 reaches the stand-in, not the
	// responder: after it, one multicast datagram from B moves the
	// responder's count by exactly one.
	t.Run("step 1: co-binding", func(t *testing.T) {
		before := readCount()
		if _, err := bConn.WriteTo([]byte("so19-unicast"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(so19A, 5353))); err != nil {
			t.Fatal(err)
		}
		deadline := time.After(so19Step)
		for got := false; !got; {
			select {
			case b := <-standIn:
				got = string(b) == "so19-unicast"
			case <-deadline:
				t.Fatal("dead: the stand-in never received the unicast datagram")
			}
		}
		sendB(query("printer.local.", dns.TypeA))
		waitReads(t, reads, readCount, before+1)
		if n := readCount(); n != before+1 {
			t.Fatalf("the responder read %d datagrams from B, want 1: the unicast reached it", n-before)
		}
	})

	// (3) A query for <cid>.local reaches the responder and draws nothing.
	t.Run("step 3: never cid.local", func(t *testing.T) {
		before := readCount()
		sendB(query(so19CID, dns.TypeA))
		sendB(query(so19CID, dns.TypeANY))
		waitReads(t, reads, readCount, before+2)
		readName(t, sendB, fromA) // packets are ordered: anything for cid.local came first
		everMu.Lock()
		defer everMu.Unlock()
		for _, m := range everA {
			for _, n := range namesIn(m) {
				if n == so19CID {
					t.Fatalf("A sent a packet naming %s: %v", so19CID, m)
				}
			}
		}
	})

	// (4) A claimant in B announces the name: conflict, alert, no answer.
	var queryAt int
	t.Run("step 4: conflict", func(t *testing.T) {
		sendB(so19Claim(120))
		logs.wait(t, slog.LevelWarn, "sign-in name conflict")
		a := r.Alerts(time.Now())
		if len(a) != 1 || a[0].ID != AlertConflict || !strings.Contains(a[0].Title, so19B.String()) {
			t.Fatalf("alerts %+v, want the conflict naming %v", a, so19B)
		}
		everMu.Lock()
		queryAt = len(everA)
		everMu.Unlock()
		before := readCount()
		sendB(query(so19Name, dns.TypeA))
		waitReads(t, reads, readCount, before+1)
	})

	// (5) The claimant's goodbye: new probes, then the name again; and the
	// step-4 query, read before the goodbye, drew no answer.
	t.Run("step 5: heal", func(t *testing.T) {
		sendB(so19Claim(0))
		logs.wait(t, slog.LevelInfo, "re-probing")
		probes := 0
		for probes < 3 {
			if m := next(t, fromA, "new probes"); !m.Response && len(m.Ns) > 0 {
				probes++
			}
		}
		everMu.Lock()
		for _, m := range everA[queryAt:] {
			if m.Response {
				everMu.Unlock()
				t.Fatalf("A answered while in conflict: %v", m)
			}
			if !m.Response && len(m.Ns) > 0 {
				break
			}
		}
		everMu.Unlock()
		readName(t, sendB, fromA)
	})

	// (6) Stop sends the TTL-0 goodbye.
	t.Run("step 6: goodbye", func(t *testing.T) {
		cancel()
		r.Wait()
		for {
			m := next(t, fromA, "the goodbye")
			if m.Response && len(m.Answer) > 0 && m.Answer[0].Header().Ttl == 0 {
				return
			}
		}
	})
}

// readName queries for the name from B until A answers with its address. A
// real querier retransmits (RFC 6762 §5.2); so does this one, because the
// responder holds back an answer within a second of its last multicast.
func readName(t *testing.T, sendB func(*dns.Msg), fromA <-chan *dns.Msg) {
	t.Helper()
	deadline := time.After(so19Step)
	for {
		sendB(query(so19Name, dns.TypeA))
		retry := time.After(1500 * time.Millisecond) // one querier retransmission interval
		for waiting := true; waiting; {
			select {
			case m := <-fromA:
				if !m.Response {
					continue
				}
				for _, a := range aAddrs(m.Answer) {
					if a == so19A {
						return
					}
				}
			case <-retry:
				waiting = false
			case <-deadline:
				t.Fatal("dead: B never read the name at A's address")
			}
		}
	}
}

func next(t *testing.T, ch <-chan *dns.Msg, what string) *dns.Msg {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(so19Step):
		t.Fatalf("dead: waiting for %s", what)
		return nil
	}
}

func waitReads(t *testing.T, reads <-chan struct{}, count func() int, n int) {
	t.Helper()
	deadline := time.After(so19Step)
	for count() < n {
		select {
		case <-reads:
		case <-deadline:
			t.Fatalf("dead: the responder read %d datagrams from B, want %d", count(), n)
		}
	}
}

func so19Claim(ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.Response, m.Authoritative = true, true
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: so19Name, Rrtype: dns.TypeA, Class: dns.ClassINET | cacheFlush, Ttl: ttl}, A: so19B.AsSlice()}}
	return m
}

// countingConn reports every datagram read.
type countingConn struct {
	Conn
	on func(netip.AddrPort)
}

func (c countingConn) Read(b []byte) (int, netip.AddrPort, error) {
	n, src, err := c.Conn.Read(b)
	if err == nil {
		c.on(src)
	}
	return n, src, err
}

// so19Netns makes namespaces A and B joined by a veth pair, so19a in A and
// so19b in B, and removes them when the test ends. It returns the
// namespaces' paths and so19a's index in A.
func so19Netns(t *testing.T) (string, string, int) {
	t.Helper()
	suffix := fmt.Sprint(os.Getpid())
	a, b := "so19a-"+suffix, "so19b-"+suffix
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			functest.SkipOrFail(t, so19Switch, "ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	ip("netns", "add", a)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", a).Run() })
	ip("netns", "add", b)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", b).Run() })
	ip("link", "add", "so19a", "netns", a, "type", "veth", "peer", "name", "so19b", "netns", b)
	for _, c := range []struct{ ns, dev, addr string }{{a, "so19a", so19A.String()}, {b, "so19b", so19B.String()}} {
		ip("-n", c.ns, "addr", "add", c.addr+"/24", "dev", c.dev)
		ip("-n", c.ns, "link", "set", c.dev, "up")
		ip("-n", c.ns, "link", "set", "lo", "up")
		ip("-n", c.ns, "route", "add", "224.0.0.0/4", "dev", c.dev)
	}
	nsA, nsB := "/run/netns/"+a, "/run/netns/"+b
	var idx int
	if err := inNetns(nsA, func() error {
		ifi, err := net.InterfaceByName("so19a")
		if err == nil {
			idx = ifi.Index
		}
		return err
	}); err != nil {
		t.Fatalf("so19a: %v", err)
	}
	return nsA, nsB, idx
}

// inNetns runs fn on a thread switched into the namespace at path. A socket
// made there stays in that namespace. If the thread cannot be switched back,
// it is left locked, so the runtime retires it.
func inNetns(path string, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer orig.Close()
		target, err := os.Open(path)
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer target.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("setns %s: %w", path, err)
			return
		}
		ferr := fn()
		if err := unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET); err != nil {
			errc <- errors.Join(ferr, fmt.Errorf("setns back: %w", err))
			return // the thread stays locked and dies with this goroutine
		}
		runtime.UnlockOSThread()
		errc <- ferr
	}()
	return <-errc
}

// reuseUDP binds a SO_REUSEADDR UDP socket at addr, joined to the mDNS group
// on ifindex when it is not 0, sending there and hearing no loop.
func reuseUDP(addr netip.AddrPort, ifindex int) (*net.UDPConn, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: int(addr.Port()), Addr: addr.Addr().As4()}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if ifindex != 0 {
		mreq := &unix.IPMreqn{Multiaddr: [4]byte{224, 0, 0, 251}, Ifindex: int32(ifindex)}
		for _, set := range []func() error{
			func() error { return unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, mreq) },
			func() error { return unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_IF, mreq) },
			func() error { return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, 255) },
		} {
			if err := set(); err != nil {
				unix.Close(fd)
				return nil, err
			}
		}
	}
	f := os.NewFile(uintptr(fd), "so19")
	defer f.Close()
	pc, err := net.FilePacketConn(f)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func readLoop(c *net.UDPConn, fn func([]byte, netip.AddrPort)) {
	buf := make([]byte, maxPacket)
	for {
		n, src, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		fn(append([]byte(nil), buf[:n]...), netip.AddrPortFrom(src.Addr().Unmap(), src.Port()))
	}
}

// logWatch is a slog handler that keeps every record and lets the test wait
// for one.
type logWatch struct {
	t     *testing.T
	mu    sync.Mutex
	recs  []slog.Record
	added chan struct{}
}

func newLogWatch(t *testing.T) *logWatch { return &logWatch{t: t, added: make(chan struct{}, 1024)} }

func (l *logWatch) Enabled(context.Context, slog.Level) bool { return true }
func (l *logWatch) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	l.recs = append(l.recs, r)
	l.mu.Unlock()
	select {
	case l.added <- struct{}{}:
	default:
	}
	return nil
}
func (l *logWatch) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logWatch) WithGroup(string) slog.Handler      { return l }

func (l *logWatch) wait(t *testing.T, level slog.Level, sub string) {
	t.Helper()
	deadline := time.After(so19Step)
	for {
		l.mu.Lock()
		for _, r := range l.recs {
			if r.Level == level && strings.Contains(r.Message, sub) {
				l.mu.Unlock()
				return
			}
		}
		l.mu.Unlock()
		select {
		case <-l.added:
		case <-deadline:
			t.Fatalf("dead: no %s record %q", level, sub)
		}
	}
}
