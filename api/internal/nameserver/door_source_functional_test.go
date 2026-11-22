package nameserver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// TC-983-07 (CI SO-15, nameserver half): a real Server on loopback with a
// DoorSource wired answers the app door over UDP and TCP with the zone's TTL,
// gives AAAA NODATA with the SOA in authority, answers NXDOMAIN while the door
// is withheld or there is no LAN IPv4, and follows a new address on the next
// query with no reload. It runs in CI with no skip path.
func TestFunctional_DoorSource(t *testing.T) {
	const door = "signin.home1.internal"
	var withheld atomic.Bool
	var current atomic.Pointer[net.IP]
	ip1 := net.ParseIP("192.168.1.10")
	current.Store(&ip1)
	ipFn := func() net.IP {
		if p := current.Load(); p != nil {
			return *p
		}
		return nil
	}
	resp := NewResponder(testZone,
		NewSelfSource(testZone, testLocal, ipFn),
		NewDoorSource(door, ipFn, withheld.Load))
	srv := NewServer(func() net.IP { return net.IPv4(127, 0, 0, 1) }, 0, resp)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	for _, tr := range []struct{ proto, addr string }{{"udp", srv.UDPAddr()}, {"tcp", srv.TCPAddr()}} {
		t.Run(tr.proto, func(t *testing.T) {
			withheld.Store(false)
			current.Store(&ip1)

			m := exchange(t, tr.proto, tr.addr, door, dns.TypeA)
			if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
				t.Fatalf("A: rcode=%s answers=%d", dns.RcodeToString[m.Rcode], len(m.Answer))
			}
			a := m.Answer[0].(*dns.A)
			if !a.A.Equal(ip1) || a.Hdr.Ttl != uint32(recordTTL.Seconds()) {
				t.Errorf("A = %v ttl %d, want %v ttl %d", a.A, a.Hdr.Ttl, ip1, uint32(recordTTL.Seconds()))
			}

			aaaa := exchange(t, tr.proto, tr.addr, door, dns.TypeAAAA)
			if aaaa.Rcode != dns.RcodeSuccess || len(aaaa.Answer) != 0 || len(aaaa.Ns) != 1 {
				t.Errorf("AAAA: rcode=%s answers=%d ns=%d, want NODATA with the SOA", dns.RcodeToString[aaaa.Rcode], len(aaaa.Answer), len(aaaa.Ns))
			} else if _, ok := aaaa.Ns[0].(*dns.SOA); !ok {
				t.Errorf("AAAA authority = %v, want the SOA", aaaa.Ns[0])
			}

			ip2 := net.ParseIP("10.0.0.5")
			current.Store(&ip2)
			if m := exchange(t, tr.proto, tr.addr, door, dns.TypeA); len(m.Answer) != 1 || !m.Answer[0].(*dns.A).A.Equal(ip2) {
				t.Errorf("after the address moved: %v, want %v", m.Answer, ip2)
			}

			withheld.Store(true)
			if m := exchange(t, tr.proto, tr.addr, door, dns.TypeA); m.Rcode != dns.RcodeNameError {
				t.Errorf("withheld: rcode=%s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
			}
			withheld.Store(false)

			current.Store(nil)
			if m := exchange(t, tr.proto, tr.addr, door, dns.TypeA); m.Rcode != dns.RcodeNameError {
				t.Errorf("no LAN IPv4: rcode=%s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
			}
		})
	}
}

// A nil predicate withholds: the door fails closed.
func TestDoorSource_NilPredicateWithholds(t *testing.T) {
	d := NewDoorSource("signin.home1.internal", func() net.IP { return testIP }, nil)
	if r := d.Records(); r != nil {
		t.Errorf("Records = %v, want nil", r)
	}
	ok := NewDoorSource("SIGNIN.home1.internal", func() net.IP { return testIP }, func() bool { return false })
	if r := ok.Records(); !r["signin.home1.internal."].Equal(testIP) {
		t.Errorf("Records = %v, want the canonical key", r)
	}
}
