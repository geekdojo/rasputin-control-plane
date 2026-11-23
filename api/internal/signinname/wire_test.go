package signinname

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func pack(t testing.TB, m *dns.Msg) []byte {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// parse's typed reading of each message shape the responder acts on.
func TestParse(t *testing.T) {
	foreign := claim(other, 120)
	foreign.Answer = append(foreign.Answer, &dns.A{Hdr: dns.RR_Header{Name: "printer.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: lease.AsSlice()})
	bad := query(testFQDN, dns.TypeA)
	bad.Opcode = dns.OpcodeUpdate
	for name, c := range map[string]struct {
		b    []byte
		ok   bool
		want observation
	}{
		"query":     {pack(t, query("SSO-BENCH.local.", dns.TypeA)), true, observation{asksForUs: true}},
		"any":       {pack(t, query(testFQDN, dns.TypeANY)), true, observation{asksForUs: true}},
		"aaaa":      {pack(t, query(testFQDN, dns.TypeAAAA)), true, observation{}},
		"cid":       {pack(t, query(cidFQDN, dns.TypeA)), true, observation{}},
		"probe":     {pack(t, otherProbe(other)), true, observation{asksForUs: true, probe: true}},
		"response":  {pack(t, foreign), true, observation{response: true, records: []hostRecord{{other, 120}}}},
		"goodbye":   {pack(t, claim(other, 0)), true, observation{response: true, records: []hostRecord{{other, 0}}}},
		"opcode":    {pack(t, bad), false, observation{}},
		"truncated": {pack(t, query(testFQDN, dns.TypeA))[:7], false, observation{}},
		"empty":     {nil, false, observation{}},
	} {
		got, ok := parse(c.b, otherSrc, testFQDN)
		c.want.src = otherSrc
		if !c.ok {
			c.want = observation{}
		}
		if ok != c.ok || got.response != c.want.response || got.asksForUs != c.want.asksForUs ||
			got.probe != c.want.probe || len(got.records) != len(c.want.records) {
			t.Errorf("%s: parse = %+v, %v; want %+v, %v", name, got, ok, c.want, c.ok)
			continue
		}
		for i := range got.records {
			if got.records[i] != c.want.records[i] {
				t.Errorf("%s: record %d = %+v", name, i, got.records[i])
			}
		}
	}
}

// TC-995-19: FuzzParse never panics, and never reports a question or record
// for a name other than ours. Its seeds are a valid query, response, probe and
// goodbye, and a truncated, compressed-loop and oversized packet. It is in
// .github/workflows/fuzz.yml's deep-fuzz targets.
func FuzzParse(f *testing.F) {
	addrs := []netip.Addr{lease}
	for _, b := range [][]byte{
		pack(f, query(testFQDN, dns.TypeA)),
		pack(f, claim(other, 120)),
		pack(f, otherProbe(other)),
		pack(f, claim(other, 0)),
		pack(f, query(cidFQDN, dns.TypeANY))[:9],
		// A name whose compression pointer points at itself.
		{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1},
		bytes.Repeat([]byte{0xff}, 9001),
	} {
		f.Add(b)
	}
	for _, build := range []func() ([]byte, error){
		func() ([]byte, error) { return probeMsg(testFQDN, addrs) },
		func() ([]byte, error) { return answerMsg(testFQDN, addrs, 0) },
		func() ([]byte, error) { return queryMsg(testFQDN) },
	} {
		b, err := build()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		o, ok := parse(b, otherSrc, testFQDN)
		if !ok {
			return
		}
		var m dns.Msg
		if err := m.Unpack(b); err != nil {
			t.Fatalf("parse accepted what does not unpack: %v", err)
		}
		if o.asksForUs {
			found := false
			for _, q := range m.Question {
				if dns.CanonicalName(q.Name) == testFQDN {
					found = true
				}
			}
			if !found {
				t.Fatalf("asksForUs for a message with no question for us: %v", m.Question)
			}
		}
		for _, rec := range o.records {
			found := false
			for _, rr := range append(append([]dns.RR(nil), m.Answer...), m.Extra...) {
				if a, isA := rr.(*dns.A); isA && dns.CanonicalName(a.Hdr.Name) == testFQDN && a.A.Equal(rec.addr.AsSlice()) {
					found = true
				}
			}
			if !found {
				t.Fatalf("record %v is not an A record for our name", rec)
			}
		}
	})
}
