package nameserver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestFunctional_EndToEnd is the repeatable functional test mandated by
// ADR-0004 §8: a real Server bound on a loopback ephemeral port, queried end to
// end with a real DNS client over BOTH UDP and TCP, asserting the wire answers.
// It exercises the whole path the unit tests stub — actual sockets, real
// packet encode/decode, transport selection — and is re-runnable on every
// change (plain `go test`). It binds 127.0.0.1 (not :53), so it needs no
// privilege; the real <LAN-IP>:53 bind + resolved coexistence is the separate
// on-image port-53 bench.
func TestFunctional_EndToEnd(t *testing.T) {
	loopback := net.IPv4(127, 0, 0, 1)
	resp := NewResponder(testZone, NewSelfSource(testZone, testLocal, func() net.IP { return testIP }))
	srv := NewServer(func() net.IP { return loopback }, 0, resp)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	// Each transport reports its own bound address: at port 0 the OS assigns
	// them independently, so they need not share a port (Start never derives
	// one bind's port from the other's).
	transports := []struct{ proto, addr string }{
		{"udp", srv.UDPAddr()},
		{"tcp", srv.TCPAddr()},
	}
	for _, tr := range transports {
		if tr.addr == "" {
			t.Fatalf("Server %s address empty after Start", tr.proto)
		}
	}

	for _, tr := range transports {
		proto, addr := tr.proto, tr.addr
		t.Run(proto, func(t *testing.T) {
			// Positive: apex A resolves to the CP IP over the wire.
			m := exchange(t, proto, addr, testZone, dns.TypeA)
			if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
				t.Fatalf("apex A: rcode=%s answers=%d", dns.RcodeToString[m.Rcode], len(m.Answer))
			}
			a, ok := m.Answer[0].(*dns.A)
			if !ok || !a.A.Equal(testIP) {
				t.Fatalf("apex A answer = %v, want %v", m.Answer, testIP)
			}
			if !m.Authoritative {
				t.Errorf("AA bit not set over %s", proto)
			}

			// The <cluster>.local unicast convenience name resolves too.
			ml := exchange(t, proto, addr, testLocal, dns.TypeA)
			if ml.Rcode != dns.RcodeSuccess || len(ml.Answer) != 1 {
				t.Errorf("%s A: rcode=%s answers=%d", testLocal, dns.RcodeToString[ml.Rcode], len(ml.Answer))
			}

			// Negative: NXDOMAIN in-zone, REFUSED off-zone.
			if nx := exchange(t, proto, addr, "ghost."+testZone, dns.TypeA); nx.Rcode != dns.RcodeNameError {
				t.Errorf("in-zone miss: rcode=%s, want NXDOMAIN", dns.RcodeToString[nx.Rcode])
			}
			if ref := exchange(t, proto, addr, "example.com", dns.TypeA); ref.Rcode != dns.RcodeRefused {
				t.Errorf("off-zone: rcode=%s, want REFUSED", dns.RcodeToString[ref.Rcode])
			}
		})
	}
}

// TestFunctional_ReflectsLiveChanges proves the embedding payoff: a record set
// change is visible on the very next query, with no reload — the reconcile-on-
// change property Slice 2's lease/app updates rely on.
func TestFunctional_ReflectsLiveChanges(t *testing.T) {
	loopback := net.IPv4(127, 0, 0, 1)
	// The server reads the IP from a handler goroutine while the test changes it,
	// so the holder must be concurrency-safe — exactly what a real Source must be
	// (production's primaryLanIP shares no state). An atomic models that honestly.
	var current atomic.Pointer[net.IP]
	ip1 := net.ParseIP("192.168.1.10")
	current.Store(&ip1)
	resp := NewResponder(testZone, NewSelfSource(testZone, testLocal, func() net.IP {
		if p := current.Load(); p != nil {
			return *p
		}
		return nil
	}))
	srv := NewServer(func() net.IP { return loopback }, 0, resp)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	first := exchange(t, "udp", srv.UDPAddr(), testZone, dns.TypeA)
	if len(first.Answer) != 1 || !first.Answer[0].(*dns.A).A.Equal(net.ParseIP("192.168.1.10")) {
		t.Fatalf("first answer = %v, want 192.168.1.10", first.Answer)
	}

	// Simulate the CP moving subnets (a new lease); no restart, no reload.
	ip2 := net.ParseIP("10.0.0.5")
	current.Store(&ip2)

	second := exchange(t, "udp", srv.UDPAddr(), testZone, dns.TypeA)
	if len(second.Answer) != 1 || !second.Answer[0].(*dns.A).A.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("second answer = %v, want 10.0.0.5 (change not reflected without reload)", second.Answer)
	}
}

// TestFunctional_ClusterRecords wires a ClusterSource (on the .lan subzone)
// alongside SelfSource and resolves a node name and an app name end to end over
// the wire — the projection proven through real sockets — and confirms the bare
// (tailnet) names NXDOMAIN on the CP nameserver (ADR-0004 §9).
func TestFunctional_ClusterRecords(t *testing.T) {
	loopback := net.IPv4(127, 0, 0, 1)
	nodes := []NodeAddr{{ID: "cp", Hostname: "home1-cp", IP: net.ParseIP("192.168.1.2")}}
	apps := []AppRec{{Name: "jellyfin", TargetNode: "cp", ExposeLAN: true}}
	resp := NewResponder(testZone,
		NewSelfSource(testZone, testLocal, func() net.IP { return testIP }),
		NewClusterSource(testLANZone, func() []NodeAddr { return nodes }, func() []AppRec { return apps }))
	srv := NewServer(func() net.IP { return loopback }, 0, resp)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	// LAN names resolve under .lan.
	node := exchange(t, "udp", srv.UDPAddr(), "home1-cp."+testLANZone, dns.TypeA)
	if len(node.Answer) != 1 || !node.Answer[0].(*dns.A).A.Equal(net.ParseIP("192.168.1.2")) {
		t.Errorf("node .lan record = %v, want 192.168.1.2", node.Answer)
	}
	app := exchange(t, "udp", srv.UDPAddr(), "jellyfin."+testLANZone, dns.TypeA)
	if len(app.Answer) != 1 || !app.Answer[0].(*dns.A).A.Equal(net.ParseIP("192.168.1.2")) {
		t.Errorf("app .lan record = %v, want 192.168.1.2 (target node's IP)", app.Answer)
	}

	// Bare (tailnet) node/app names are NOT served by the CP nameserver — that's
	// MagicDNS's job; the CP nameserver correctly NXDOMAINs them (Decision 9).
	for _, bare := range []string{"home1-cp." + testZone, "jellyfin." + testZone} {
		m := exchange(t, "udp", srv.UDPAddr(), bare, dns.TypeA)
		if m.Rcode != dns.RcodeNameError {
			t.Errorf("bare name %s: rcode = %s, want NXDOMAIN", bare, dns.RcodeToString[m.Rcode])
		}
	}
	// The apex (SelfSource) still resolves alongside the cluster records.
	apex := exchange(t, "udp", srv.UDPAddr(), testZone, dns.TypeA)
	if len(apex.Answer) != 1 || !apex.Answer[0].(*dns.A).A.Equal(testIP) {
		t.Errorf("apex = %v, want %v", apex.Answer, testIP)
	}
}

func exchange(t *testing.T, proto, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Net: proto, Timeout: 3 * time.Second}
	m, _, err := c.Exchange(req, addr)
	if err != nil {
		t.Fatalf("%s exchange for %s: %v", proto, name, err)
	}
	return m
}
