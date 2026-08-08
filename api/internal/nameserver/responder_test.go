package nameserver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

const (
	testZone  = "home1.internal"
	testLocal = "home1.local"
)

var testIP = net.ParseIP("192.168.1.10")

// fakeRW is a dns.ResponseWriter that captures the reply and reports a chosen
// transport (so truncation logic, which keys off RemoteAddr().Network(), can be
// exercised without real sockets).
type fakeRW struct {
	msg     *dns.Msg
	network string // "udp" (default) or "tcp"
}

func (f *fakeRW) WriteMsg(m *dns.Msg) error { f.msg = m; return nil }
func (f *fakeRW) LocalAddr() net.Addr       { return &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 53} }
func (f *fakeRW) RemoteAddr() net.Addr {
	if f.network == "tcp" {
		return &net.TCPAddr{IP: net.IPv4(192, 168, 1, 50), Port: 5000}
	}
	return &net.UDPAddr{IP: net.IPv4(192, 168, 1, 50), Port: 5000}
}
func (f *fakeRW) Write([]byte) (int, error) { return 0, nil }
func (f *fakeRW) Close() error              { return nil }
func (f *fakeRW) TsigStatus() error         { return nil }
func (f *fakeRW) TsigTimersOnly(bool)       {}
func (f *fakeRW) Hijack()                   {}

func newTestResponder(ip net.IP) *Responder {
	return NewResponder(testZone, NewSelfSource(testZone, testLocal, func() net.IP { return ip }))
}

// ask runs a single query through the responder and returns the reply.
func ask(r *Responder, name string, qtype uint16, edns bool) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	if edns {
		req.SetEdns0(4096, false)
	}
	rw := &fakeRW{}
	r.ServeDNS(rw, req)
	return rw.msg
}

func TestResponder_PositiveAnswers(t *testing.T) {
	r := newTestResponder(testIP)

	tests := []struct {
		name  string
		qname string
		qtype uint16
	}{
		{"apex A", testZone, dns.TypeA},
		{"local A", testLocal, dns.TypeA},
		{"apex ANY yields A", testZone, dns.TypeANY},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := ask(r, tc.qname, tc.qtype, false)
			if m.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
			}
			if !m.Authoritative {
				t.Errorf("AA bit not set on an authoritative answer")
			}
			if len(m.Answer) != 1 {
				t.Fatalf("got %d answers, want 1", len(m.Answer))
			}
			a, ok := m.Answer[0].(*dns.A)
			if !ok {
				t.Fatalf("answer is %T, want *dns.A", m.Answer[0])
			}
			if !a.A.Equal(testIP) {
				t.Errorf("A = %v, want %v", a.A, testIP)
			}
			if a.Hdr.Ttl != uint32(recordTTL.Seconds()) {
				t.Errorf("TTL = %d, want %d", a.Hdr.Ttl, uint32(recordTTL.Seconds()))
			}
		})
	}
}

func TestResponder_CaseInsensitive(t *testing.T) {
	r := newTestResponder(testIP)
	m := ask(r, "HOME1.INTERNAL", dns.TypeA, false)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("mixed-case query not answered: rcode=%s answers=%d", dns.RcodeToString[m.Rcode], len(m.Answer))
	}
	// The answer must echo the queried name verbatim (case preserved).
	if got := m.Answer[0].Header().Name; got != "HOME1.INTERNAL." {
		t.Errorf("answer name = %q, want %q (case echoed)", got, "HOME1.INTERNAL.")
	}
}

func TestResponder_NXDOMAIN(t *testing.T) {
	r := newTestResponder(testIP)
	m := ask(r, "nope.home1.internal", dns.TypeA, false)
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
	if !m.Authoritative {
		t.Errorf("NXDOMAIN must be authoritative")
	}
	if len(m.Answer) != 0 {
		t.Errorf("NXDOMAIN must have no answers, got %d", len(m.Answer))
	}
	soa := assertSingleSOA(t, m.Ns)
	if soa.Minttl != uint32(negativeTTL.Seconds()) {
		t.Errorf("SOA MINIMUM = %d, want %d (negative-cache TTL)", soa.Minttl, uint32(negativeTTL.Seconds()))
	}
	if soa.Hdr.Ttl != uint32(negativeTTL.Seconds()) {
		t.Errorf("SOA TTL = %d, want %d", soa.Hdr.Ttl, uint32(negativeTTL.Seconds()))
	}
}

func TestResponder_NODATA_AAAA(t *testing.T) {
	// The apex exists (has an A) but has no AAAA — Rasputin is IPv4-only. That's
	// NODATA: NOERROR, no answers, SOA in authority. NOT NXDOMAIN.
	r := newTestResponder(testIP)
	m := ask(r, testZone, dns.TypeAAAA, false)
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR (NODATA)", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Errorf("NODATA must have no answers, got %d", len(m.Answer))
	}
	assertSingleSOA(t, m.Ns)
}

func TestResponder_SOAandNS(t *testing.T) {
	r := newTestResponder(testIP)

	soaMsg := ask(r, testZone, dns.TypeSOA, false)
	if soaMsg.Rcode != dns.RcodeSuccess || len(soaMsg.Answer) != 1 {
		t.Fatalf("SOA query: rcode=%s answers=%d", dns.RcodeToString[soaMsg.Rcode], len(soaMsg.Answer))
	}
	soa, ok := soaMsg.Answer[0].(*dns.SOA)
	if !ok {
		t.Fatalf("answer is %T, want *dns.SOA", soaMsg.Answer[0])
	}
	if soa.Ns != dns.Fqdn(testZone) {
		t.Errorf("SOA MNAME = %q, want %q", soa.Ns, dns.Fqdn(testZone))
	}

	nsMsg := ask(r, testZone, dns.TypeNS, false)
	if nsMsg.Rcode != dns.RcodeSuccess || len(nsMsg.Answer) != 1 {
		t.Fatalf("NS query: rcode=%s answers=%d", dns.RcodeToString[nsMsg.Rcode], len(nsMsg.Answer))
	}
	if _, ok := nsMsg.Answer[0].(*dns.NS); !ok {
		t.Fatalf("answer is %T, want *dns.NS", nsMsg.Answer[0])
	}
}

func TestResponder_RefusedOffZone(t *testing.T) {
	r := newTestResponder(testIP)
	for _, name := range []string{"example.com", "random.local", "notourcluster.internal"} {
		m := ask(r, name, dns.TypeA, false)
		if m.Rcode != dns.RcodeRefused {
			t.Errorf("%s: rcode = %s, want REFUSED", name, dns.RcodeToString[m.Rcode])
		}
		if m.Authoritative {
			t.Errorf("%s: must not claim authority over an off-zone name", name)
		}
	}
}

func TestResponder_EDNS0Echo(t *testing.T) {
	r := newTestResponder(testIP)
	m := ask(r, testZone, dns.TypeA, true)
	if m.IsEdns0() == nil {
		t.Errorf("EDNS0 query got a reply with no OPT record")
	}
	// A non-EDNS0 query must not get an OPT back.
	plain := ask(r, testZone, dns.TypeA, false)
	if plain.IsEdns0() != nil {
		t.Errorf("non-EDNS0 query got an unexpected OPT record")
	}
}

func TestResponder_NoLANIP(t *testing.T) {
	// With no LAN IP the self-source is empty; the apex is in-zone but has no
	// record, so it's an honest NXDOMAIN rather than a bogus answer.
	r := newTestResponder(nil)
	m := ask(r, testZone, dns.TypeA, false)
	if m.Rcode != dns.RcodeNameError {
		t.Errorf("no-IP apex: rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
}

func TestResponder_MalformedRefused(t *testing.T) {
	// A query with no question section is not something we answer.
	req := new(dns.Msg)
	req.Opcode = dns.OpcodeQuery
	rw := &fakeRW{}
	newTestResponder(testIP).ServeDNS(rw, req)
	if rw.msg.Rcode != dns.RcodeRefused {
		t.Errorf("empty-question query: rcode = %s, want REFUSED", dns.RcodeToString[rw.msg.Rcode])
	}
}

func assertSingleSOA(t *testing.T, rrs []dns.RR) *dns.SOA {
	t.Helper()
	if len(rrs) != 1 {
		t.Fatalf("authority section has %d records, want 1 (SOA)", len(rrs))
	}
	soa, ok := rrs[0].(*dns.SOA)
	if !ok {
		t.Fatalf("authority record is %T, want *dns.SOA", rrs[0])
	}
	return soa
}
