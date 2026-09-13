package nameserver

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeBound records the order of binds and stops across one Listeners, so the
// stop-before-bind rule is checkable without sockets.
type fakeBound struct {
	ip  string
	log *eventLog
}

func (f *fakeBound) Stop() error     { f.log.add("stop " + f.ip); return nil }
func (f *fakeBound) UDPAddr() string { return f.ip + ":53" }

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (e *eventLog) add(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, s)
}

func (e *eventLog) take() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.events
	e.events = nil
	return out
}

func fakeListeners(ctx context.Context, fail map[string]bool) (*Listeners, *eventLog) {
	log := &eventLog{}
	l := NewListeners(ctx, 53, dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {}))
	l.listen = func(_ context.Context, ip net.IP) (boundListener, error) {
		if fail[ip.String()] {
			log.add("fail " + ip.String())
			return nil, fmt.Errorf("bind %s: address already in use", ip)
		}
		log.add("bind " + ip.String())
		return &fakeBound{ip: ip.String(), log: log}, nil
	}
	return l, log
}

func ips(ss ...string) []net.IP {
	out := make([]net.IP, 0, len(ss))
	for _, s := range ss {
		out = append(out, net.ParseIP(s))
	}
	return out
}

func eq(a, b []string) bool {
	return strings.Join(a, "|") == strings.Join(b, "|")
}

// TestListeners_Lifecycle walks the #431 sequence through Sync: no address, the
// fallback appears, a lease joins it, the fallback is released, the lease moves,
// and the node loses its address.
func TestListeners_Lifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, log := fakeListeners(ctx, nil)

	steps := []struct {
		name       string
		ips        []net.IP
		wantEvents []string
		wantBound  []string
	}{
		{"boot with no usable address", nil, nil, []string{}},
		{"fallback appears: nameserver starts", ips("192.168.1.2"), []string{"bind 192.168.1.2"}, []string{"192.168.1.2:53"}},
		{"same set again: nothing", ips("192.168.1.2"), nil, []string{"192.168.1.2:53"}},
		{"late lease beside it: bind only the new one", ips("192.168.1.226", "192.168.1.2"), []string{"bind 192.168.1.226"}, []string{"192.168.1.226:53", "192.168.1.2:53"}}, // string order
		{"fallback released: stop only it", ips("192.168.1.226"), []string{"stop 192.168.1.2"}, []string{"192.168.1.226:53"}},
		// The rebind: the stale listener goes before the new bind, never after.
		{"lease moves: stop, then bind", ips("192.168.1.227"), []string{"stop 192.168.1.226", "bind 192.168.1.227"}, []string{"192.168.1.227:53"}},
		{"address removed: nameserver stops", nil, []string{"stop 192.168.1.227"}, []string{}},
	}
	for _, st := range steps {
		res, err := l.Sync(st.ips)
		if err != nil {
			t.Fatalf("%s: Sync: %v", st.name, err)
		}
		if got := log.take(); !eq(got, st.wantEvents) {
			t.Fatalf("%s: events = %v, want %v", st.name, got, st.wantEvents)
		}
		if !eq(res.Bound, st.wantBound) || !eq(l.Bound(), st.wantBound) {
			t.Fatalf("%s: bound = %v / %v, want %v", st.name, res.Bound, l.Bound(), st.wantBound)
		}
		if res.Changed() != (len(st.wantEvents) > 0) {
			t.Fatalf("%s: Changed() = %v with events %v", st.name, res.Changed(), st.wantEvents)
		}
	}
}

// A failed bind is reported and left unbound, and the next Sync — the next
// address event — tries it again. No timer retries it in between.
func TestListeners_FailedBindRetriedOnNextSync(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fail := map[string]bool{"192.168.1.2": true}
	l, log := fakeListeners(ctx, fail)

	if _, err := l.Sync(ips("192.168.1.2")); err == nil {
		t.Fatal("expected the bind error")
	}
	if got := log.take(); !eq(got, []string{"fail 192.168.1.2"}) {
		t.Fatalf("events = %v", got)
	}
	if len(l.Bound()) != 0 {
		t.Fatalf("bound after a failed bind: %v", l.Bound())
	}

	delete(fail, "192.168.1.2")
	if _, err := l.Sync(ips("192.168.1.2")); err != nil {
		t.Fatalf("retry Sync: %v", err)
	}
	if got := log.take(); !eq(got, []string{"bind 192.168.1.2"}) {
		t.Fatalf("retry events = %v", got)
	}
}

func TestListeners_NoBindAfterShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l, log := fakeListeners(ctx, nil)
	if _, err := l.Sync(ips("192.168.1.2")); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := l.Sync(ips("192.168.1.226")); err != nil {
		t.Fatal(err)
	}
	if got := log.take(); !eq(got, []string{"bind 192.168.1.2", "stop 192.168.1.2"}) {
		t.Fatalf("events = %v, want no bind once ctx has ended", got)
	}
}

// TestListeners_RealSockets drives real Servers: a listener answers while its
// address is wanted, and once it is dropped the port on that address is free
// again — nothing still holds it.
func TestListeners_RealSockets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp := NewResponder(testZone, NewSelfSource(testZone, testLocal, func() net.IP { return testIP }))
	l := NewListeners(ctx, 0, resp)
	defer l.Close()

	res, err := l.Sync(ips("127.0.0.1"))
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Started) != 1 {
		t.Fatalf("started = %v", res.Started)
	}
	addr := res.Started[0]
	if m := exchange(t, "udp", addr, testZone, dns.TypeA); len(m.Answer) != 1 {
		t.Fatalf("no answer on the bound listener: %v", m)
	}

	if _, err := l.Sync(nil); err != nil {
		t.Fatalf("Sync(nil): %v", err)
	}
	assertPortFree(t, addr)
}

// TestListeners_RealRebind moves the listener between two real addresses and
// checks the old address stops answering and releases its port. It needs a
// second bindable loopback address, which Linux has (all of 127/8) and macOS
// does not by default.
func TestListeners_RealRebind(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs 127.0.0.2, which only Linux binds without configuration")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp := NewResponder(testZone, NewSelfSource(testZone, testLocal, func() net.IP { return testIP }))
	l := NewListeners(ctx, 0, resp)
	defer l.Close()

	first, err := l.Sync(ips("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := l.Sync(ips("127.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	if !eq(second.Stopped, []string{"127.0.0.1"}) || len(second.Started) != 1 {
		t.Fatalf("rebind result = %+v", second)
	}
	if m := exchange(t, "udp", second.Started[0], testZone, dns.TypeA); len(m.Answer) != 1 {
		t.Fatalf("no answer on the new address: %v", m)
	}
	assertPortFree(t, first.Started[0])
}

// TestServer_StopRightAfterStartReleasesPort is the regression for two
// miekg/dns races a rebind walks straight into, because a rebind is exactly a
// Stop close behind a Start on the same port:
//
//   - a Shutdown that lands before the serve loop starts is refused and the
//     socket stays bound forever (fails on the first iteration without Start's
//     wait for NotifyStartedFunc);
//   - Shutdown can return while the serve loop's own Close is still releasing
//     the descriptor (fails a few iterations in ten thousand without Stop's
//     wait for ActivateAndServe to return — caught by CI on this test).
//
// Every iteration must find the port free.
func TestServer_StopRightAfterStartReleasesPort(t *testing.T) {
	loopback := net.IPv4(127, 0, 0, 1)
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	resp := NewResponder(testZone, NewSelfSource(testZone, testLocal, func() net.IP { return testIP }))
	for i := 0; i < 50; i++ {
		srv := NewServer(func() net.IP { return loopback }, port, resp)
		if err := srv.Start(context.Background()); err != nil {
			// The TCP side of a port chosen by a UDP probe can be taken by
			// someone else; that is not this bug, but a leak from the previous
			// iteration would surface here as "address already in use".
			if i > 0 {
				t.Fatalf("iteration %d: Start: %v (previous Stop leaked the bind?)", i, err)
			}
			t.Skipf("port %d not free on TCP: %v", port, err)
		}
		if err := srv.Stop(); err != nil {
			t.Fatalf("iteration %d: Stop: %v", i, err)
		}
	}
}

func assertPortFree(t *testing.T, hostport string) {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("%s still bound after its listener was dropped: %v", hostport, err)
	}
	_ = pc.Close()

	// And nothing answers there: a query to a closed UDP port gets ICMP
	// unreachable or times out, never a DNS answer.
	c := &dns.Client{Net: "udp", Timeout: 300 * time.Millisecond}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(testZone), dns.TypeA)
	if r, _, err := c.Exchange(m, hostport); err == nil && r != nil {
		t.Fatalf("%s still answers after its listener was dropped", hostport)
	}
}
