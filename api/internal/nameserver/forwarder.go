package nameserver

import (
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Forwarder is the optional AA-11 DNS forwarding stub (ADR-0004 §10). The
// responder is authoritative for one internal zone and REFUSEs everything else;
// with a Forwarder attached, off-zone queries are instead proxied to a single
// upstream resolver. That lets an operator point their whole network's DNS at
// the control plane and have both `<cluster>.internal` names and the public
// internet resolve from one box — the Mode-B "point your router at Rasputin"
// path, where there is no firewall in the DHCP/DNS chain to do the forwarding.
//
// It is OFF by default: a nil *Forwarder (or one with no upstream) leaves the
// REFUSE behavior unchanged. When on it is deliberately guarded — this is a
// resolver other hosts query, so it must not become an open resolver or a query
// loop:
//
//   - source ACL — forwards only for RFC1918 / loopback clients, never a public
//     source. The server already binds the LAN interface (server.go); this is
//     the defense-in-depth second check. 100.64/10 (CGNAT/tailnet) is *not*
//     private here — a tailnet peer is not a LAN client.
//   - recursion-desired — only forwards when the client set RD; an RD=0 off-zone
//     query still REFUSEs (we are not volunteering recursion nobody asked for).
//   - self-loop — never forwards to the control plane's own address. The
//     router↔CP loop (operator points their router at the CP, the CP forwards
//     back to that router) is prevented at the config layer, where the operator
//     picks the upstream (AA-11 slice 2); this catches the direct self case.
//   - rate limit — a global token bucket bounds query volume (anti-abuse /
//     anti-amplification, E7).
//
// Queries are proxied transparently (any qtype): what a client resolves for the
// public internet is the client's business, not something we filter. IPv4-only
// (LOCKED decision #9) applies to the *transport* — the upstream is dialed over
// v4 — not to which record types a client may look up through us.
type Forwarder struct {
	upstream string        // upstream resolver "ip:port"; "" disables forwarding
	self     func() net.IP // the CP's own LAN IP — never forward here (self-loop)
	client   *dns.Client   // reused; carries the per-query timeout
	limiter  *tokenBucket
}

// ForwarderConfig configures a Forwarder. Upstream is required; a bare "ip" gets
// the default :53. Zero-value tuning fields fall back to sane defaults.
type ForwarderConfig struct {
	// Upstream is the resolver to forward off-zone queries to ("ip" or "ip:port").
	Upstream string
	// SelfIP returns the CP's current LAN IP, used for self-loop detection. It is
	// read per query (the box moves subnets); nil is treated as "unknown", which
	// only disables the self-loop guard, never forwarding itself.
	SelfIP func() net.IP
	// Timeout bounds each upstream exchange (default 3s) so a slow upstream can't
	// stall the handler goroutine.
	Timeout time.Duration
	// QPS / Burst size the global token bucket (defaults 50 / 100).
	QPS   float64
	Burst float64
}

// NewForwarder builds a Forwarder from cfg. An empty Upstream yields a disabled
// forwarder (tryForward always declines), which is a valid "off" state.
func NewForwarder(cfg ForwarderConfig) *Forwarder {
	up := cfg.Upstream
	if up != "" {
		if _, _, err := net.SplitHostPort(up); err != nil {
			up = net.JoinHostPort(up, "53") // bare ip -> ip:53
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	qps := cfg.QPS
	if qps <= 0 {
		qps = 50
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = 100
	}
	self := cfg.SelfIP
	if self == nil {
		self = func() net.IP { return nil }
	}
	return &Forwarder{
		upstream: up,
		self:     self,
		client:   &dns.Client{Net: "udp", Timeout: timeout},
		limiter:  newTokenBucket(qps, burst),
	}
}

// tryForward proxies an off-zone query to the upstream when every guard passes.
// It returns true when it has produced a response for the client (the upstream's
// answer, or SERVFAIL if the upstream failed) and false when a guard declined,
// in which case the caller keeps the authoritative REFUSE. Safe to call on a nil
// receiver (the disabled case).
func (f *Forwarder) tryForward(w dns.ResponseWriter, req *dns.Msg) bool {
	if f == nil || f.upstream == "" {
		return false
	}
	if !req.RecursionDesired {
		return false
	}
	if src := clientIP(w.RemoteAddr()); src == nil || !isPrivateV4(src) {
		return false
	}
	if self := f.self(); self != nil && upstreamIsSelf(f.upstream, self) {
		return false // direct self-loop — refuse rather than spin
	}
	if !f.limiter.allow() {
		return false
	}

	// Dial the upstream over the same transport the client used, so a client's
	// TCP retry (after a truncated UDP answer) forwards over TCP too.
	c := *f.client
	if w.RemoteAddr().Network() == "tcp" {
		c.Net = "tcp"
	}
	resp, _, err := c.Exchange(req, f.upstream)
	if err != nil || resp == nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		m.RecursionAvailable = true
		_ = w.WriteMsg(m)
		return true
	}
	resp.RecursionAvailable = true
	_ = w.WriteMsg(resp)
	return true
}

// clientIP extracts the source IP from a dns.ResponseWriter's remote address.
func clientIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	}
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// isPrivateV4 reports whether ip is an IPv4 address we will forward for: RFC1918
// or loopback (a same-host query to the LAN-bound socket is trusted). It is
// deliberately NOT true for 100.64/10 (CGNAT/tailnet) — a tailnet peer is not a
// LAN client — nor any public address.
func isPrivateV4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	switch {
	case ip4[0] == 10:
		return true
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return true
	case ip4[0] == 192 && ip4[1] == 168:
		return true
	case ip4[0] == 127:
		return true
	default:
		return false
	}
}

// upstreamIsSelf reports whether the upstream "ip:port" resolves to self's IP —
// forwarding there would loop straight back into this responder.
func upstreamIsSelf(upstream string, self net.IP) bool {
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		host = upstream
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.Equal(self)
}

// tokenBucket is a minimal global rate limiter: `rate` tokens/sec accrue up to
// `max`, each allow() spends one. now is a field so tests drive it
// deterministically; production uses time.Now.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	rate   float64
	last   time.Time
	now    func() time.Time
}

func newTokenBucket(ratePerSec, burst float64) *tokenBucket {
	return &tokenBucket{tokens: burst, max: burst, rate: ratePerSec, last: time.Now(), now: time.Now}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	b.tokens += t.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.last = t
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
