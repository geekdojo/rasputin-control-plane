package signinname

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/geekdojo/rasputin-control-plane/api/internal/lanaddr"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

const (
	testHost = "sso-bench.local"
	testFQDN = "sso-bench.local."
	cidFQDN  = "bench.local."
)

var (
	t0     = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	lease  = netip.MustParseAddr("192.168.1.20")
	fallbk = netip.MustParseAddr("192.168.1.2")
	other  = netip.MustParseAddr("192.168.1.4")
	// otherSrc is another host sending from the mDNS port.
	otherSrc = netip.AddrPortFrom(other, 5353)
)

// snap is a snapshot with addrs on ifindex idx ("end0"), the first dynamic.
func snap(idx int, addrs ...netip.Addr) lanaddr.Snapshot {
	var in []lanaddr.Addr
	for i, a := range addrs {
		in = append(in, lanaddr.Addr{IP: net.IP(a.AsSlice()), Link: "end0", Index: idx, Dynamic: i == 0})
	}
	return lanaddr.Select(in)
}

// sent is one datagram a fakeConn sent.
type sent struct {
	at  time.Time
	msg *dns.Msg
}

// fakeConn records every send, decoded, and delivers packets pushed on in.
type fakeConn struct {
	mu     sync.Mutex
	now    func() time.Time
	sends  []sent
	sentC  chan struct{}
	in     chan inPkt
	closed chan struct{}
	once   sync.Once
	// readPanic and readErr make Read panic or fail at once.
	readPanic bool
	readErr   error
	// sendPanicAfter makes the send after that many succeeded panic (0: never).
	sendPanicAfter int
	sendErr        error
}

type inPkt struct {
	b   []byte
	src netip.AddrPort
}

func newFakeConn(now func() time.Time) *fakeConn {
	return &fakeConn{now: now, sentC: make(chan struct{}, 1024), in: make(chan inPkt), closed: make(chan struct{})}
}

func (c *fakeConn) Read(b []byte) (int, netip.AddrPort, error) {
	if c.readPanic {
		panic("read exploded")
	}
	if c.readErr != nil {
		return 0, netip.AddrPort{}, c.readErr
	}
	select {
	case p := <-c.in:
		return copy(b, p.b), p.src, nil
	case <-c.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (c *fakeConn) Send(b []byte) error {
	c.mu.Lock()
	if c.sendPanicAfter > 0 && len(c.sends) >= c.sendPanicAfter {
		c.mu.Unlock()
		panic("send exploded")
	}
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		c.mu.Unlock()
		panic("the responder sent a message that does not unpack: " + err.Error())
	}
	c.sends = append(c.sends, sent{at: c.now(), msg: m})
	err := c.sendErr
	c.mu.Unlock()
	c.sentC <- struct{}{}
	return err
}

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *fakeConn) all() []sent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]sent(nil), c.sends...)
}

// since returns the sends from index i on.
func (c *fakeConn) from(i int) []sent {
	a := c.all()
	if i > len(a) {
		return nil
	}
	return a[i:]
}

// waitSends blocks until n sends in total, with a deadline that marks a hang.
func (c *fakeConn) waitSends(t *testing.T, n int) []sent {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		if a := c.all(); len(a) >= n {
			return a
		}
		select {
		case <-c.sentC:
		case <-deadline:
			t.Fatalf("hung: %d sends, want %d", len(c.all()), n)
		}
	}
}

// fakeAddrs is an Addresses that hands the subscriber the snapshot it holds,
// as lanaddr.Watcher.Subscribe does.
type fakeAddrs struct {
	s  lanaddr.Snapshot
	fn func(prev, next lanaddr.Snapshot)
}

func (a *fakeAddrs) Subscribe(fn func(prev, next lanaddr.Snapshot)) {
	a.fn = fn
	fn(lanaddr.Snapshot{}, a.s)
}

// rig drives a Responder's handlers directly, as Run would, on a fake clock:
// each handler is called with the rig's now, and advance fires every
// protocol deadline in order. No goroutine but the reader runs, so every
// assertion sees a settled state.
type rig struct {
	t       *testing.T
	r       *Responder
	now     time.Time
	addrs   *fakeAddrs
	conns   []*fakeConn
	opens   []int
	openErr error
	logs    *logkittest.Recorder
}

func newRig(t *testing.T, s lanaddr.Snapshot) *rig {
	t.Helper()
	g := &rig{t: t, now: t0, addrs: &fakeAddrs{s: s}}
	log, rec := logkittest.New()
	g.logs = rec
	r, err := New(Config{
		Name:  testHost,
		Addrs: g.addrs,
		Open: func(idx int) (Conn, error) {
			g.opens = append(g.opens, idx)
			if g.openErr != nil {
				return nil, g.openErr
			}
			c := newFakeConn(func() time.Time { return g.now })
			g.conns = append(g.conns, c)
			return c, nil
		},
		Clock: fixedClock{g},
		Log:   log,
	})
	if err != nil {
		t.Fatal(err)
	}
	g.r = r
	t.Cleanup(func() { g.r.shutdown(g.now) })
	return g
}

// fixedClock reads the rig's now; the rig never runs Run, so NewTimer is
// unused.
type fixedClock struct{ g *rig }

func (c fixedClock) Now() time.Time               { return c.g.now }
func (c fixedClock) NewTimer(time.Duration) Timer { panic("the rig does not run timers") }

// start delivers the snapshot the subscription stored, as Run's first
// iteration does.
func (g *rig) start() *rig {
	g.r.handleAddrs(g.now, g.r.latestSnapshot())
	return g
}

// setAddrs changes the addresses through the subscription and delivers them.
func (g *rig) setAddrs(s lanaddr.Snapshot) {
	g.addrs.fn(lanaddr.Snapshot{}, s)
	g.r.handleAddrs(g.now, g.r.latestSnapshot())
}

// conn is the current socket.
func (g *rig) conn() *fakeConn {
	g.t.Helper()
	if len(g.conns) == 0 {
		g.t.Fatal("no socket was opened")
	}
	return g.conns[len(g.conns)-1]
}

// advance moves the clock by d, firing every deadline on the way in order.
func (g *rig) advance(d time.Duration) {
	end := g.now.Add(d)
	for i := 0; i < 1000; i++ {
		at, ok := g.r.deadline()
		if !ok || at.After(end) {
			g.now = end
			return
		}
		if at.After(g.now) {
			g.now = at
		}
		g.r.handleDeadline(g.now)
	}
	g.t.Fatal("deadlines did not move forward")
}

// publish runs probing and both announcements.
func (g *rig) publish() {
	g.t.Helper()
	g.advance(probeInterval*3 + announceInterval)
	if st := g.r.State(g.now); st.State != StateOK {
		g.t.Fatalf("not published: %+v", st)
	}
}

// inject delivers msg from src to the responder on the current socket.
func (g *rig) inject(m *dns.Msg, src netip.AddrPort) {
	g.t.Helper()
	b, err := m.Pack()
	if err != nil {
		g.t.Fatal(err)
	}
	g.injectRaw(b, src)
}

func (g *rig) injectRaw(b []byte, src netip.AddrPort) {
	g.r.mu.Lock()
	gen := g.r.gen
	g.r.mu.Unlock()
	g.r.handlePacket(g.now, packet{gen: gen, data: b, src: src})
}

// query is a QM query for name of type qtype.
func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.Question = []dns.Question{{Name: name, Qtype: qtype, Qclass: dns.ClassINET}}
	return m
}

// claim is another host's response claiming testFQDN at addr with ttl.
func claim(addr netip.Addr, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.Response, m.Authoritative = true, true
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: testFQDN, Rrtype: dns.TypeA, Class: dns.ClassINET | cacheFlush, Ttl: ttl}, A: addr.AsSlice()}}
	return m
}

// otherProbe is another host's probe for testFQDN proposing addr.
func otherProbe(addr netip.Addr) *dns.Msg {
	m := query(testFQDN, dns.TypeANY)
	m.Ns = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: testFQDN, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: addr.AsSlice()}}
	return m
}

// kinds of sent message.
func isProbe(m *dns.Msg) bool {
	return !m.Response && len(m.Question) == 1 && m.Question[0].Qtype == dns.TypeANY && len(m.Ns) > 0
}
func isAnswer(m *dns.Msg) bool {
	return m.Response && len(m.Answer) > 0 && m.Answer[0].Header().Ttl > 0
}
func isGoodbye(m *dns.Msg) bool {
	return m.Response && len(m.Answer) > 0 && m.Answer[0].Header().Ttl == 0
}
func isMaintQuery(m *dns.Msg) bool {
	return !m.Response && len(m.Question) == 1 && m.Question[0].Qtype == dns.TypeA && len(m.Ns) == 0
}

func count(ss []sent, pred func(*dns.Msg) bool) int {
	n := 0
	for _, s := range ss {
		if pred(s.msg) {
			n++
		}
	}
	return n
}

// aAddrs are the A records' addresses in rrs, in order.
func aAddrs(rrs []dns.RR) []netip.Addr {
	var out []netip.Addr
	for _, rr := range rrs {
		if a, ok := rr.(*dns.A); ok {
			ad, _ := netip.AddrFromSlice(a.A.To4())
			out = append(out, ad)
		}
	}
	return out
}

// namesIn is every owner name and question name in m, lowercased.
func namesIn(m *dns.Msg) []string {
	var out []string
	for _, q := range m.Question {
		out = append(out, strings.ToLower(q.Name))
	}
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			out = append(out, strings.ToLower(rr.Header().Name))
		}
	}
	return out
}

// runClock is a fake Clock for tests that run Run: each NewTimer is handed
// to the test on armed, and fires only when the test fires it.
type runClock struct {
	mu    sync.Mutex
	now   time.Time
	armed chan *runTimer
}

type runTimer struct {
	at time.Time
	c  chan time.Time
}

func newRunClock() *runClock { return &runClock{now: t0, armed: make(chan *runTimer, 1024)} }

func (c *runClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *runClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *runClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	t := &runTimer{at: c.now.Add(d), c: make(chan time.Time, 1)}
	c.mu.Unlock()
	c.armed <- t
	return t
}

func (t *runTimer) C() <-chan time.Time { return t.c }
func (t *runTimer) Stop() bool          { return true }

// fireNext waits for the loop to arm its next timer, moves the clock to it
// and fires it.
func (c *runClock) fireNext(t *testing.T) {
	t.Helper()
	select {
	case tm := <-c.armed:
		c.mu.Lock()
		if tm.at.After(c.now) {
			c.now = tm.at
		}
		now := c.now
		c.mu.Unlock()
		tm.c <- now
	case <-time.After(10 * time.Second):
		t.Fatal("hung: the loop armed no timer")
	}
}

// waitDone waits for Run to return, with a deadline that marks a hang.
func waitDone(t *testing.T, r *Responder) {
	t.Helper()
	done := make(chan struct{})
	go func() { r.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("hung: Run did not return")
	}
}

var errBoom = errors.New("boom")
