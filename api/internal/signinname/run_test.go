package signinname

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/geekdojo/rasputin-control-plane/api/internal/lanaddr"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fakeSource is a lanaddr.Source the test drives, so a real Watcher runs.
type fakeSource struct {
	mu    sync.Mutex
	addrs []lanaddr.Addr
	ch    chan struct{}
}

func (f *fakeSource) Subscribe(context.Context) (<-chan struct{}, error) { return f.ch, nil }
func (f *fakeSource) List() ([]lanaddr.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]lanaddr.Addr(nil), f.addrs...), nil
}
func (f *fakeSource) set(a ...lanaddr.Addr) {
	f.mu.Lock()
	f.addrs = a
	f.mu.Unlock()
	f.ch <- struct{}{}
}

func lanAddr(a netip.Addr, idx int) lanaddr.Addr {
	return lanaddr.Addr{IP: net.IP(a.AsSlice()), Link: "end0", Index: idx, Dynamic: true}
}

// runRig runs a real Run over a real lanaddr.Watcher, a fake Conn and a fake
// clock whose timers fire only when the test fires them.
type runRig struct {
	r      *Responder
	clk    *runClock
	src    *fakeSource
	w      *lanaddr.Watcher
	conn   *fakeConn
	logs   *logkittest.Recorder
	cancel context.CancelFunc
	second chan lanaddr.Snapshot
}

func newRunRig(t *testing.T, conn func(*fakeConn)) *runRig {
	t.Helper()
	g := &runRig{clk: newRunClock(), src: &fakeSource{ch: make(chan struct{}, 4), addrs: []lanaddr.Addr{lanAddr(lease, 2)}}}
	g.w = lanaddr.NewWatcher(g.src)
	ctx, cancel := context.WithCancel(t.Context())
	g.cancel = cancel
	t.Cleanup(cancel)
	if err := g.w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	g.conn = newFakeConn(g.clk.Now)
	if conn != nil {
		conn(g.conn)
	}
	log, rec := logkittest.New()
	g.logs = rec
	r, err := New(Config{Name: testHost, Addrs: g.w, Open: func(int) (Conn, error) { return g.conn, nil }, Clock: g.clk, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	g.r = r
	// A second subscriber, as the nameserver listeners and the api leaf are.
	g.second = make(chan lanaddr.Snapshot, 16)
	g.w.Subscribe(func(_, next lanaddr.Snapshot) { g.second <- next })
	<-g.second // the replay
	return g
}

func (g *runRig) run(ctx context.Context) { go g.r.Run(ctx) }

// publish fires the loop's timers through probing and announcing.
func (g *runRig) publish(t *testing.T) {
	t.Helper()
	g.conn.waitSends(t, 1)
	for n := 2; n <= probeCount+announceCount; n++ {
		g.clk.fireNext(t)
		g.conn.waitSends(t, n)
	}
}

// assertStopped checks the stopped state, its alert, and that the watcher
// still reaches its other subscriber.
func (g *runRig) assertStopped(t *testing.T) {
	t.Helper()
	waitDone(t, g.r)
	now := g.clk.Now()
	if st := g.r.State(now); st.State != StateUnpublished || st.Cause != CauseStopped {
		t.Errorf("state %+v, want unpublished stopped", st)
	}
	a := g.r.Alerts(now)
	if len(a) != 1 || a[0].ID != AlertUnpublished ||
		a[0].Detail != "The sign-in name responder stopped after an internal error. Restart the control plane to publish the name again." {
		t.Errorf("alerts %+v", a)
	}
	if !g.conn.isClosed() {
		t.Error("the socket was left open")
	}
	// After the stop, an address change still reaches the second subscriber.
	g.src.set(lanAddr(other, 2))
	select {
	case s := <-g.second:
		if s.PrimaryIP().String() != other.String() {
			t.Errorf("second subscriber got %v", s)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("hung: the watcher stalled after the responder stopped")
	}
}

// TC-995-13: a panic in Conn.Read stops the responder; the process lives and
// the watcher keeps serving.
func TestFaultPanicInRead(t *testing.T) {
	g := newRunRig(t, func(c *fakeConn) { c.readPanic = true })
	g.run(t.Context())
	g.assertStopped(t)
	if recs := g.logs.Matching(slog.LevelError, "panic recovered"); len(recs) != 1 {
		t.Errorf("%d panic records:\n%s", len(recs), g.logs.Text())
	} else if v, _ := logkittest.Attr(recs[0], "where"); v != "reader" {
		t.Errorf("where = %q", v)
	}
}

// TC-995-13: a panic in packet handling (the answer's send) stops it.
func TestFaultPanicInPacketHandling(t *testing.T) {
	g := newRunRig(t, func(c *fakeConn) { c.sendPanicAfter = probeCount + announceCount })
	g.run(t.Context())
	g.publish(t)
	g.clk.advance(2 * time.Second)
	q, _ := query(testFQDN, dns.TypeA).Pack()
	g.conn.in <- inPkt{b: q, src: otherSrc}
	g.assertStopped(t)
	if recs := g.logs.Matching(slog.LevelError, "panic recovered"); len(recs) != 1 {
		t.Errorf("%d panic records", len(recs))
	} else if v, _ := logkittest.Attr(recs[0], "where"); v != "run" {
		t.Errorf("where = %q", v)
	}
}

// TC-995-13: a read error that is not our own close stops it.
func TestFaultReadError(t *testing.T) {
	g := newRunRig(t, func(c *fakeConn) { c.readErr = errBoom })
	g.run(t.Context())
	g.assertStopped(t)
	if len(g.logs.Matching(slog.LevelError, "stopped on a read error")) != 1 {
		t.Errorf("no read-error record:\n%s", g.logs.Text())
	}
}

// TC-995-13: subscribing before Run starts does not block, and an unstarted
// responder never stalls the watcher.
func TestSubscribeBeforeRunDoesNotBlock(t *testing.T) {
	g := newRunRig(t, nil) // New subscribed; Run is never started
	for _, a := range []netip.Addr{other, lease, fallbk} {
		g.src.set(lanAddr(a, 2))
		select {
		case <-g.second:
		case <-time.After(10 * time.Second):
			t.Fatal("hung: the watcher stalled on an unstarted responder")
		}
	}
}

// TC-995-13: a panic inside the subscription callback is recovered there, so
// it never reaches the watcher's dispatch path.
func TestSubscribeCallbackRecovers(t *testing.T) {
	log, rec := logkittest.New()
	r, err := New(Config{Name: testHost, Addrs: &fakeAddrs{}, Open: func(int) (Conn, error) { return nil, errBoom }, Clock: newRunClock(), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	close(r.addrSig) // the callback's signal now panics
	r.onAddrs(lanaddr.Snapshot{}, snap(2, lease))
	if recs := rec.Matching(slog.LevelError, "panic recovered"); len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	} else if v, _ := logkittest.Attr(recs[0], "where"); v != "subscribe" {
		t.Errorf("where = %q", v)
	}
	if got := r.latestSnapshot(); got.PrimaryIP().String() != lease.String() {
		t.Errorf("snapshot not stored: %v", got)
	}
}

// TC-995-12 (through Run): cancelling a published responder sends one
// goodbye, closes the socket, and Wait returns.
func TestRunGoodbyeOnCancel(t *testing.T) {
	g := newRunRig(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	g.run(ctx)
	g.publish(t)
	cancel()
	waitDone(t, g.r)
	ss := g.conn.all()
	if len(ss) != probeCount+announceCount+1 || !isGoodbye(ss[len(ss)-1].msg) {
		t.Fatalf("sent %d, last %v; want a goodbye last", len(ss), ss[len(ss)-1].msg)
	}
	if !g.conn.isClosed() {
		t.Error("socket left open")
	}
}
