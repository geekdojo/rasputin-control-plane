package nameserver

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Response TTLs. The zone is dynamic — node/app IPs churn on reboot (no DHCP
// MAC reservations, ADR-0004 §8) — so answers are short-lived to bound how long
// a stale IP or a not-yet-existent name can be cached. A control-plane reboot
// pausing app-name resolution is TTL-bounded by exactly these (ADR-0004
// Consequences).
const (
	recordTTL   = 60 * time.Second // positive A answers
	negativeTTL = 30 * time.Second // SOA MINIMUM → NXDOMAIN/NODATA caching
)

// ednsUDPSize is the UDP payload size we advertise in our EDNS0 OPT. 1232 is the
// DNS-flag-day default — large enough to avoid TCP for our small answers, small
// enough to dodge IPv6 fragmentation. Answers over the requester's advertised
// size get the TC bit and a TCP retry.
const ednsUDPSize = 1232

// Responder is the authoritative miekg/dns handler for the internal zone. It
// answers A (IPv4-only), SOA, and NS from its Sources and applies proper
// authoritative semantics for everything else: NODATA for an existing name of
// the wrong type, NXDOMAIN for a name that does not exist in-zone, and REFUSED
// for anything off-zone (we are authoritative, never recursive).
type Responder struct {
	zone    string // canonical apex, e.g. "home1.internal."
	mname   string // primary nameserver / SOA MNAME — we are it
	rname   string // SOA RNAME (hostmaster.<zone>), '@' encoded as a label dot
	sources []Source
	// forwarder, when set, proxies off-zone queries to an upstream instead of
	// REFUSEing them (AA-11 forwarding stub, ADR-0004 §10). Held atomically so the
	// api can hot-swap it when the operator toggles forwarding — a nil (unset)
	// value keeps the pure authoritative posture. See WithForwarder / SetForwarder.
	forwarder atomic.Pointer[Forwarder]
}

// NewResponder builds a responder authoritative for zone (any case / trailing
// dot accepted), reading records from the given Sources (merged; later sources
// win on key collision). Slice 1 passes one SelfSource.
func NewResponder(zone string, sources ...Source) *Responder {
	z := canonical(zone)
	return &Responder{
		zone:    z,
		mname:   z,
		rname:   "hostmaster." + z,
		sources: sources,
	}
}

// WithForwarder attaches an optional off-zone forwarding stub (AA-11) and
// returns the responder for chaining. Passing nil is a no-op that keeps the
// pure authoritative (REFUSE off-zone) behavior.
func (r *Responder) WithForwarder(f *Forwarder) *Responder {
	r.forwarder.Store(f)
	return r
}

// SetForwarder atomically swaps the off-zone forwarder — the reconcile path when
// the operator toggles DNS forwarding or changes the upstream (AA-11 slice 2). A
// nil f disables forwarding (off-zone reverts to REFUSE) with no restart.
func (r *Responder) SetForwarder(f *Forwarder) {
	r.forwarder.Store(f)
}

// ServeDNS implements dns.Handler.
func (r *Responder) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = false

	// Honor the requester's UDP payload size for truncation, and echo an OPT so
	// an EDNS0 querier knows we speak it.
	udpSize := uint16(dns.MinMsgSize) // 512, the pre-EDNS0 UDP limit
	if opt := req.IsEdns0(); opt != nil {
		m.SetEdns0(ednsUDPSize, false)
		if sz := opt.UDPSize(); sz > udpSize {
			udpSize = sz
		}
	}

	// We answer standard queries with exactly one question. Anything else
	// (NOTIFY, UPDATE, a malformed multi-question packet) is not ours to answer.
	if req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 {
		m.Authoritative = false
		m.Rcode = dns.RcodeRefused
		r.write(w, m, udpSize)
		return
	}

	q := req.Question[0]
	qname := dns.CanonicalName(q.Name)
	ip, hasRec := r.records()[qname]
	if hasRec && ip.To4() == nil {
		hasRec = false // defensive: never serve a non-IPv4 value as an A record
	}
	inZone := qname == r.zone || dns.IsSubDomain(r.zone, qname)

	// Positive answers.
	switch q.Qtype {
	case dns.TypeA, dns.TypeANY:
		if hasRec {
			m.Answer = append(m.Answer, r.a(q.Name, ip))
			r.write(w, m, udpSize)
			return
		}
	case dns.TypeSOA:
		if qname == r.zone {
			m.Answer = append(m.Answer, r.soa())
			r.write(w, m, udpSize)
			return
		}
	case dns.TypeNS:
		if qname == r.zone {
			m.Answer = append(m.Answer, r.ns())
			r.write(w, m, udpSize)
			return
		}
	}

	// No positive answer. Classify the negative response.
	switch {
	case !inZone && !hasRec:
		// Not in our zone, and not one of the extra unicast names we serve.
		// The !hasRec half is load-bearing: the extra unicast names (e.g.
		// <cluster>.local) are deliberately NOT subdomains of the zone apex, so
		// they fail inZone. Testing !inZone alone REFUSEd every non-A query for
		// them — including AAAA, which on an IPv4-only cluster is the single
		// most common query a resolver makes. tailscaled treats that REFUSE as
		// a failed lookup for its control URL and falls back to Tailscale's
		// public bootstrap DNS, which can never resolve a .local name; nodes
		// then never rejoin the mesh (geekdojo/geekdojo-brain#202). A name we
		// serve an A for exists, so a different qtype is NODATA, not REFUSED.
		// With the optional AA-11
		// forwarding stub attached, proxy the query to the upstream so the CP can
		// serve as a client's whole-network resolver (ADR-0004 §10); the
		// forwarder self-guards (source ACL, self-loop, rate limit) and returns
		// false when it declines. Absent a forwarder, or on decline, we are not
		// authoritative for the name — REFUSE rather than assert a false NXDOMAIN
		// (the correct answer for, e.g., an arbitrary *.local other than
		// <cluster>.local).
		if r.forwarder.Load().tryForward(w, req) {
			return
		}
		m.Authoritative = false
		m.Rcode = dns.RcodeRefused
	case hasRec:
		// The name exists (it has an A) but not of the requested type: NODATA —
		// NOERROR with an empty answer section and the SOA in authority so
		// resolvers cache the negative for MINIMUM. (AAAA lands here: Rasputin
		// is IPv4-only, LOCKED decision #9.) This covers both in-zone names and
		// the extra unicast names, which are equally ours to answer for.
		m.Ns = append(m.Ns, r.soa())
	default:
		// In-zone name with no records at all: NXDOMAIN, SOA in authority.
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, r.soa())
	}
	r.write(w, m, udpSize)
}

// write sends the reply, truncating on UDP so an oversized answer sets TC and
// prompts a TCP retry. TCP (64 KiB) is never truncated.
func (r *Responder) write(w dns.ResponseWriter, m *dns.Msg, udpSize uint16) {
	if w.RemoteAddr().Network() != "tcp" {
		m.Truncate(int(udpSize))
	}
	_ = w.WriteMsg(m)
}

// records merges every Source's current view. Called once per query — cheap,
// and the reason to embed: a change is visible on the next lookup, no reload.
func (r *Responder) records() map[string]net.IP {
	if len(r.sources) == 1 {
		return r.sources[0].Records()
	}
	out := map[string]net.IP{}
	for _, s := range r.sources {
		for k, v := range s.Records() {
			out[k] = v
		}
	}
	return out
}

func (r *Responder) a(name string, ip net.IP) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   name, // echo the queried name (and its case) verbatim
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    uint32(recordTTL.Seconds()),
		},
		A: ip.To4(),
	}
}

func (r *Responder) ns() *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: r.zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: uint32(recordTTL.Seconds())},
		Ns:  r.mname,
	}
}

// soa returns the zone SOA. Serial is a constant 1: the zone has no secondaries
// yet (AXFR/IXFR is the ADR-0004 §8 flip condition, not v1), so serial — which
// governs zone transfer, not negative caching — is cosmetic. MINIMUM carries the
// negative-cache TTL and is the field that matters here.
func (r *Responder) soa() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: r.zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: uint32(negativeTTL.Seconds())},
		Ns:      r.mname,
		Mbox:    r.rname,
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  uint32(negativeTTL.Seconds()),
	}
}
