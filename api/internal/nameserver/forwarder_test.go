package nameserver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// captureWriter is a dns.ResponseWriter that records the reply and reports a
// settable remote address (so tests drive the source-ACL guard).
type captureWriter struct {
	remote net.Addr
	msg    *dns.Msg
}

func (c *captureWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 53}
}
func (c *captureWriter) RemoteAddr() net.Addr        { return c.remote }
func (c *captureWriter) WriteMsg(m *dns.Msg) error   { c.msg = m; return nil }
func (c *captureWriter) Write(b []byte) (int, error) { return len(b), nil }
func (c *captureWriter) Close() error                { return nil }
func (c *captureWriter) TsigStatus() error           { return nil }
func (c *captureWriter) TsigTimersOnly(bool)         {}
func (c *captureWriter) Hijack()                     {}

func udpFrom(ip string) net.Addr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: 5300} }

// startUpstream spins up a real UDP resolver that answers every A query with
// `answer`, returning its address and a stop func.
func startUpstream(t *testing.T, answer net.IP) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	started := make(chan struct{})
	srv := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.RecursionAvailable = true
			if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   answer.To4(),
				})
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not start")
	}
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

func queryA(name string, rd bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = rd
	return m
}

func TestForwarder_ForwardsForPrivateClient(t *testing.T) {
	up, stop := startUpstream(t, net.IPv4(1, 2, 3, 4))
	defer stop()

	f := NewForwarder(ForwarderConfig{Upstream: up})
	w := &captureWriter{remote: udpFrom("192.168.1.50")}

	if !f.tryForward(w, queryA("example.com", true)) {
		t.Fatal("tryForward declined a valid private-client query")
	}
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("expected one forwarded answer, got %+v", w.msg)
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("expected forwarded A 1.2.3.4, got %v", w.msg.Answer[0])
	}
	if !w.msg.RecursionAvailable {
		t.Error("forwarded reply should set RecursionAvailable")
	}
}

func TestForwarder_DeclinesPublicSource(t *testing.T) {
	up, stop := startUpstream(t, net.IPv4(1, 2, 3, 4))
	defer stop()

	f := NewForwarder(ForwarderConfig{Upstream: up})
	w := &captureWriter{remote: udpFrom("8.8.8.8")} // public source

	if f.tryForward(w, queryA("example.com", true)) {
		t.Error("forwarded for a public source; source ACL should have declined")
	}
	if w.msg != nil {
		t.Error("declined path must not write a reply")
	}
}

func TestForwarder_DeclinesWithoutRecursionDesired(t *testing.T) {
	up, stop := startUpstream(t, net.IPv4(1, 2, 3, 4))
	defer stop()

	f := NewForwarder(ForwarderConfig{Upstream: up})
	w := &captureWriter{remote: udpFrom("10.0.0.5")}

	if f.tryForward(w, queryA("example.com", false)) {
		t.Error("forwarded an RD=0 query; should decline")
	}
}

func TestForwarder_DeclinesSelfLoop(t *testing.T) {
	self := net.IPv4(192, 168, 1, 1)
	f := NewForwarder(ForwarderConfig{
		Upstream: "192.168.1.1:53", // == self
		SelfIP:   func() net.IP { return self },
	})
	w := &captureWriter{remote: udpFrom("192.168.1.50")}

	if f.tryForward(w, queryA("example.com", true)) {
		t.Error("forwarded to self; self-loop guard should have declined")
	}
}

func TestForwarder_DisabledWhenNoUpstream(t *testing.T) {
	f := NewForwarder(ForwarderConfig{}) // empty upstream
	w := &captureWriter{remote: udpFrom("192.168.1.50")}

	if f.tryForward(w, queryA("example.com", true)) {
		t.Error("a forwarder with no upstream must decline")
	}
	// And a nil receiver is safe (the responder calls through a nil field).
	var nilF *Forwarder
	if nilF.tryForward(w, queryA("example.com", true)) {
		t.Error("nil forwarder must decline")
	}
}

func TestForwarder_UpstreamFailureIsServfail(t *testing.T) {
	f := NewForwarder(ForwarderConfig{
		Upstream: "127.0.0.1:1", // nothing listening
		Timeout:  150 * time.Millisecond,
	})
	w := &captureWriter{remote: udpFrom("192.168.1.50")}

	if !f.tryForward(w, queryA("example.com", true)) {
		t.Fatal("a forward attempt that reaches the upstream stage should own the response")
	}
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL on upstream failure, got %+v", w.msg)
	}
}

func TestForwarder_RateLimited(t *testing.T) {
	up, stop := startUpstream(t, net.IPv4(1, 2, 3, 4))
	defer stop()

	f := NewForwarder(ForwarderConfig{Upstream: up})
	// One token, no refill: first query forwards, the second is limited.
	f.limiter = &tokenBucket{tokens: 1, max: 1, rate: 0, last: time.Unix(0, 0), now: func() time.Time { return time.Unix(0, 0) }}
	w1 := &captureWriter{remote: udpFrom("192.168.1.50")}
	w2 := &captureWriter{remote: udpFrom("192.168.1.50")}

	if !f.tryForward(w1, queryA("example.com", true)) {
		t.Fatal("first query should pass the rate limit")
	}
	if f.tryForward(w2, queryA("example.com", true)) {
		t.Error("second query should be rate-limited")
	}
}

func TestTokenBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	b := &tokenBucket{tokens: 2, max: 2, rate: 1, last: now, now: func() time.Time { return now }}

	if !b.allow() || !b.allow() {
		t.Fatal("burst of 2 should both pass")
	}
	if b.allow() {
		t.Fatal("third call should be limited (bucket empty)")
	}
	now = now.Add(time.Second) // one token refills
	if !b.allow() {
		t.Fatal("after 1s a token should have refilled")
	}
	if b.allow() {
		t.Fatal("only one token refilled; second should be limited")
	}
}

// TestResponder_ForwarderOnlyForOffZone proves the responder still answers its
// own zone authoritatively with a forwarder attached, and forwards only off-zone.
func TestResponder_ForwarderOnlyForOffZone(t *testing.T) {
	up, stop := startUpstream(t, net.IPv4(1, 2, 3, 4))
	defer stop()

	self := net.IPv4(192, 168, 1, 1)
	src := NewSelfSource("home1.internal.", "home1.local.", func() net.IP { return self })
	r := NewResponder("home1.internal.", src).
		WithForwarder(NewForwarder(ForwarderConfig{Upstream: up, SelfIP: func() net.IP { return self }}))

	// In-zone apex: authoritative self answer, never forwarded.
	inZone := &captureWriter{remote: udpFrom("192.168.1.50")}
	r.ServeDNS(inZone, queryA("home1.internal.", true))
	if !inZone.msg.Authoritative || len(inZone.msg.Answer) != 1 {
		t.Fatalf("in-zone query should be answered authoritatively, got %+v", inZone.msg)
	}
	if a := inZone.msg.Answer[0].(*dns.A); !a.A.Equal(self) {
		t.Fatalf("in-zone A should be the self IP %v, got %v", self, a.A)
	}

	// Off-zone: forwarded to the upstream.
	offZone := &captureWriter{remote: udpFrom("192.168.1.50")}
	r.ServeDNS(offZone, queryA("example.com.", true))
	if offZone.msg.Rcode != dns.RcodeSuccess || len(offZone.msg.Answer) != 1 {
		t.Fatalf("off-zone query should be forwarded, got %+v", offZone.msg)
	}
	if a := offZone.msg.Answer[0].(*dns.A); !a.A.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("off-zone answer should come from upstream, got %v", a.A)
	}
}

// TestResponder_OffZoneRefusedWithoutForwarder pins the default (no forwarder)
// behavior: off-zone still REFUSEs, and the nil-forwarder call path is safe.
func TestResponder_OffZoneRefusedWithoutForwarder(t *testing.T) {
	src := NewSelfSource("home1.internal.", "", func() net.IP { return net.IPv4(192, 168, 1, 1) })
	r := NewResponder("home1.internal.", src)

	w := &captureWriter{remote: udpFrom("192.168.1.50")}
	r.ServeDNS(w, queryA("example.com.", true))
	if w.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("off-zone without a forwarder should REFUSE, got %s", dns.RcodeToString[w.msg.Rcode])
	}
}

// TestNewForwarder_Defaults pins the construction defaults (a zero-config
// forwarder must still be bounded) and that explicit config is honored.
func TestNewForwarder_Defaults(t *testing.T) {
	// Zero-value tuning → documented defaults; a bare upstream gets :53.
	f := NewForwarder(ForwarderConfig{Upstream: "1.1.1.1"})
	if f.upstream != "1.1.1.1:53" {
		t.Errorf("bare upstream should get :53, got %q", f.upstream)
	}
	if f.client.Timeout != 3*time.Second {
		t.Errorf("default timeout = %v, want 3s", f.client.Timeout)
	}
	if f.limiter.rate != 50 || f.limiter.max != 100 {
		t.Errorf("default rate/burst = %v/%v, want 50/100", f.limiter.rate, f.limiter.max)
	}

	// Explicit values are honored; an upstream that already has a port is kept.
	f2 := NewForwarder(ForwarderConfig{Upstream: "9.9.9.9:5353", Timeout: time.Second, QPS: 5, Burst: 7})
	if f2.upstream != "9.9.9.9:5353" {
		t.Errorf("upstream with a port should be preserved, got %q", f2.upstream)
	}
	if f2.client.Timeout != time.Second || f2.limiter.rate != 5 || f2.limiter.max != 7 {
		t.Errorf("explicit config not honored: timeout=%v rate=%v burst=%v", f2.client.Timeout, f2.limiter.rate, f2.limiter.max)
	}
}

// TestResponder_SetForwarderSwapsLive proves the atomic hot-swap: off-zone flips
// between REFUSE and forward as the forwarder is set and cleared, no restart.
func TestResponder_SetForwarderSwapsLive(t *testing.T) {
	up, stop := startUpstream(t, net.IPv4(1, 2, 3, 4))
	defer stop()
	self := net.IPv4(192, 168, 1, 1)
	src := NewSelfSource("home1.internal.", "", func() net.IP { return self })
	r := NewResponder("home1.internal.", src) // no forwarder yet

	refused := func(tag string) {
		w := &captureWriter{remote: udpFrom("192.168.1.50")}
		r.ServeDNS(w, queryA("example.com.", true))
		if w.msg.Rcode != dns.RcodeRefused {
			t.Fatalf("%s: off-zone should REFUSE, got %s", tag, dns.RcodeToString[w.msg.Rcode])
		}
	}

	refused("before")

	r.SetForwarder(NewForwarder(ForwarderConfig{Upstream: up, SelfIP: func() net.IP { return self }}))
	w := &captureWriter{remote: udpFrom("192.168.1.50")}
	r.ServeDNS(w, queryA("example.com.", true))
	if w.msg.Rcode != dns.RcodeSuccess || len(w.msg.Answer) != 1 {
		t.Fatalf("after SetForwarder, off-zone should forward, got %+v", w.msg)
	}

	r.SetForwarder(nil)
	refused("after clear")
}
