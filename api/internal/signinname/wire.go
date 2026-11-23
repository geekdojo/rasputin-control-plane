package signinname

import (
	"net/netip"

	"github.com/miekg/dns"
)

// mdnsPort is the mDNS port. A response that claims our name counts as a
// conflict only when it is sent from it (RFC 6762 §6, §11).
const mdnsPort = 5353

// cacheFlush is the top bit of a resource record's class in mDNS: the record
// set replaces any cached one (RFC 6762 §10.2). In a question, the same bit is
// the unicast-response bit (§5.4).
const cacheFlush = 0x8000

// hostRecord is one A record for our name that another host sent: the address
// it claims for the name, and the TTL it carried, in seconds.
type hostRecord struct {
	addr netip.Addr
	ttl  uint32
}

// observation is what parse found in one datagram. It is the only form in
// which a received packet reaches the rest of the package (SEC-INPUT).
type observation struct {
	// response is the QR bit.
	response bool
	// asksForUs is a query with an A or ANY question in class IN for our name.
	asksForUs bool
	// probe is a query for our name that carries records for our name in its
	// Authority section (RFC 6762 §8.1).
	probe bool
	// records are the A records for our name in a response's Answer and
	// Additional sections.
	records []hostRecord
	// src is the sender.
	src netip.AddrPort
}

// parse reads one received datagram for name, a canonical FQDN
// (dns.CanonicalName). It is the only code that reads raw bytes. It reports
// false for anything that is not a well-formed mDNS message: a packet that does
// not unpack, or one with a non-zero opcode or rcode, which RFC 6762 §18.3 and
// §18.11 say to ignore.
func parse(b []byte, src netip.AddrPort, name string) (observation, bool) {
	var m dns.Msg
	if err := m.Unpack(b); err != nil {
		return observation{}, false
	}
	if m.Opcode != dns.OpcodeQuery || m.Rcode != dns.RcodeSuccess {
		return observation{}, false
	}
	o := observation{response: m.Response, src: src}
	if m.Response {
		for _, rr := range append(append([]dns.RR(nil), m.Answer...), m.Extra...) {
			if rec, ok := ourA(rr, name); ok {
				o.records = append(o.records, rec)
			}
		}
		return o, true
	}
	for _, q := range m.Question {
		if dns.CanonicalName(q.Name) == name && q.Qclass&^cacheFlush == dns.ClassINET &&
			(q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY) {
			o.asksForUs = true
		}
	}
	if o.asksForUs {
		for _, rr := range m.Ns {
			if dns.CanonicalName(rr.Header().Name) == name {
				o.probe = true
			}
		}
	}
	return o, true
}

// ourA returns rr as a hostRecord when it is an A record in class IN for name.
func ourA(rr dns.RR, name string) (hostRecord, bool) {
	a, ok := rr.(*dns.A)
	if !ok || a.Hdr.Class&^cacheFlush != dns.ClassINET || dns.CanonicalName(a.Hdr.Name) != name {
		return hostRecord{}, false
	}
	addr, ok := netip.AddrFromSlice(a.A.To4())
	if !ok {
		return hostRecord{}, false
	}
	return hostRecord{addr: addr, ttl: a.Hdr.Ttl}, true
}

// records are our A records for name, one per address, in class class.
func records(name string, addrs []netip.Addr, ttl uint32, class uint16) []dns.RR {
	out := make([]dns.RR, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: class, Ttl: ttl},
			A:   a.AsSlice(),
		})
	}
	return out
}

// probeMsg is RFC 6762 §8.1's probe: an ANY question for name with the
// unicast-response bit clear, so a defender answers to the group, the only
// destination the socket receives; and our proposed records in Authority.
func probeMsg(name string, addrs []netip.Addr) ([]byte, error) {
	m := new(dns.Msg)
	m.Question = []dns.Question{{Name: name, Qtype: dns.TypeANY, Qclass: dns.ClassINET}}
	m.Ns = records(name, addrs, hostRecordTTL, dns.ClassINET)
	return m.Pack()
}

// answerMsg is an announcement, an answer or, with ttl 0, a goodbye: QR and AA
// set, one A record per address with the cache-flush bit set (§8.3, §10.1).
func answerMsg(name string, addrs []netip.Addr, ttl uint32) ([]byte, error) {
	m := new(dns.Msg)
	m.Response, m.Authoritative = true, true
	m.Answer = records(name, addrs, ttl, dns.ClassINET|cacheFlush)
	return m.Pack()
}

// queryMsg is a cache-maintenance query (§5.2): an A question for name with the
// unicast-response bit clear, so the owner's answer reaches the group.
func queryMsg(name string) ([]byte, error) {
	m := new(dns.Msg)
	m.Question = []dns.Question{{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	return m.Pack()
}
