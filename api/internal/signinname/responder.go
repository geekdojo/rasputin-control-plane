package signinname

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/geekdojo/rasputin-control-plane/api/internal/lanaddr"
)

// RFC 6762's protocol constants. Each is the protocol's own definition of the
// fact it waits for ("nobody objected within the listening window"), not a
// guess at how long something takes (ARCH-FACTS; timer-audit.tsv).
const (
	// probeInterval is the gap between probes, and the wait after the third
	// before the name is ours (§8.1).
	probeInterval = 250 * time.Millisecond
	probeCount    = 3
	// announceInterval is the gap between the two announcements (§8.3).
	announceInterval = time.Second
	announceCount    = 2
	// multicastMinGap is the least time between two multicasts of the same
	// answer (§6.2). It also caps what a LAN host can make the api send.
	multicastMinGap = time.Second
	// probeAnswerMinGap is §6.2's one exception: an answer to a probe may
	// follow the last multicast after 250 ms.
	probeAnswerMinGap = 250 * time.Millisecond
	// hostRecordTTL is the lifetime, in seconds, of the A records we publish:
	// RFC 6762 §10's host-record TTL.
	hostRecordTTL uint32 = 120
	// maxOwnerTTL caps how long we believe another host's record before we
	// re-confirm it: the same §10 host-record lifetime. A live owner still
	// answers the maintenance queries, so the cap only shortens the wait for
	// one that has gone (F-995-03).
	maxOwnerTTL = 120 * time.Second
)

// maintenancePoints are the fractions of the owner record's lifetime at which
// a §5.2 cache-maintenance query is sent. At 100 % the record is gone.
var maintenancePoints = [...]float64{0.80, 0.85, 0.90, 0.95}

// maxPacket is the read buffer: the largest mDNS message (§17).
const maxPacket = 9000

// Addresses is where the responder learns the LAN link's addresses.
// *lanaddr.Watcher satisfies it.
type Addresses interface {
	Subscribe(fn func(prev, next lanaddr.Snapshot))
}

// Conn is the mDNS socket on one link. Read returns one datagram and its
// sender; Send multicasts one datagram to 224.0.0.251:5353.
type Conn interface {
	Read(b []byte) (int, netip.AddrPort, error)
	Send(b []byte) error
	Close() error
}

// Timer is a one-shot timer.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
}

// Clock is the responder's time source.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
}

// Config is New's input. Every field is required.
type Config struct {
	// Name is the one name published: the door table's Home.Host.
	Name string
	// Addrs supplies the LAN link: its primary's interface and LinkIPs.
	Addrs Addresses
	// Open opens the mDNS socket on an interface index.
	Open  func(ifindex int) (Conn, error)
	Clock Clock
	Log   *slog.Logger
}

// phase is where the protocol is.
type phase int

const (
	// phaseIdle: no socket (no address, open failed, stopped or refused).
	phaseIdle phase = iota
	phaseProbing
	// phaseAnswering: probing won; announcing, then answering.
	phaseAnswering
	// phaseConceded: another host's record is live; nothing is answered.
	phaseConceded
)

// packet is one received datagram, tagged with the socket generation it was
// read on so a packet from a closed socket is dropped.
type packet struct {
	gen  uint64
	data []byte
	src  netip.AddrPort
}

// fault is the reader goroutine's report that it stopped.
type fault struct {
	gen      uint64
	err      error
	panicked bool
}

// Responder publishes one name. Build it with New and start it with Run, or
// build a refused one with NewRefused.
type Responder struct {
	name  string // canonical FQDN, "sso-bench.local."
	host  string // as people read it, "sso-bench.local"
	open  func(ifindex int) (Conn, error)
	clock Clock
	log   *slog.Logger

	// The lanaddr hand-off: the callback stores the latest snapshot and
	// signals; the loop reads the latest when signalled.
	addrMu  sync.Mutex
	latest  lanaddr.Snapshot
	addrSig chan struct{}

	pkts   chan packet
	faults chan fault
	done   chan struct{}

	// Refused responders only.
	refused   bool
	clusterID string
	reason    error

	// mu guards everything below. Every handler holds it for its duration,
	// and State reads under it.
	mu         sync.Mutex
	f          facts
	ph         phase
	conn       Conn
	gen        uint64
	readerStop chan struct{}
	link       int
	addrs      []netip.Addr
	step       int       // probes or announcements sent in this phase
	next       time.Time // the next probe or announcement; zero for none
	lastMcast  time.Time // the last multicast of our answer
}

// New builds a responder for cfg.Name and subscribes it to cfg.Addrs. The
// subscription callback never blocks, so New is safe before Run. Run starts
// it.
func New(cfg Config) (*Responder, error) {
	switch {
	case strings.TrimSpace(cfg.Name) == "":
		return nil, errors.New("signinname: the name is empty")
	case cfg.Addrs == nil:
		return nil, errors.New("signinname: the address source is nil")
	case cfg.Open == nil:
		return nil, errors.New("signinname: the socket opener is nil")
	case cfg.Clock == nil:
		return nil, errors.New("signinname: the clock is nil")
	case cfg.Log == nil:
		return nil, errors.New("signinname: the logger is nil")
	}
	host := strings.TrimSuffix(cfg.Name, ".")
	r := &Responder{
		name:    dns.CanonicalName(cfg.Name),
		host:    host,
		open:    cfg.Open,
		clock:   cfg.Clock,
		log:     cfg.Log.With("component", "signinname", "name", host),
		addrSig: make(chan struct{}, 1),
		pkts:    make(chan packet),
		faults:  make(chan fault, 1),
		done:    make(chan struct{}),
	}
	r.f.since = cfg.Clock.Now()
	cfg.Addrs.Subscribe(r.onAddrs)
	return r, nil
}

// NewRefused builds a responder for a cluster id that cannot carry a sign-in
// name. It opens nothing; its state is unpublished, "refused", and its only
// alert is the refused alert, titled for reason. Wait returns at once.
func NewRefused(clusterID string, reason error, clock Clock) *Responder {
	done := make(chan struct{})
	close(done)
	r := &Responder{refused: true, clusterID: clusterID, reason: reason, clock: clock, done: done}
	r.f = facts{fault: CauseRefused, since: clock.Now()}
	return r
}

// onAddrs is the lanaddr subscription callback. It runs on the watcher's
// dispatch path, so it stores the snapshot, signals without blocking and
// returns; a panic in it is recovered here and never reaches the watcher
// (F-995-01).
func (r *Responder) onAddrs(_, next lanaddr.Snapshot) {
	defer func() {
		if v := recover(); v != nil {
			r.logPanic("subscribe", v)
		}
	}()
	r.storeLatest(next)
	select {
	case r.addrSig <- struct{}{}:
	default:
		// A signal is already pending; the loop reads the latest snapshot.
	}
}

func (r *Responder) storeLatest(s lanaddr.Snapshot) {
	r.addrMu.Lock()
	defer r.addrMu.Unlock()
	r.latest = s
}

func (r *Responder) latestSnapshot() lanaddr.Snapshot {
	r.addrMu.Lock()
	defer r.addrMu.Unlock()
	return r.latest
}

// Run is the responder's one event loop. It returns when ctx ends (after a
// goodbye, when the name is published) or when the responder stops on a
// fault. A panic anywhere in the loop is recovered here: the state becomes
// unpublished, "stopped", the socket is closed, and Run returns. It never
// restarts itself, because a deterministic fault would loop.
func (r *Responder) Run(ctx context.Context) {
	if r.refused {
		return
	}
	defer close(r.done)
	defer func() {
		if v := recover(); v != nil {
			r.logPanic("run", v)
			r.stop(r.clock.Now())
		}
	}()
	for {
		var (
			t      Timer
			timerC <-chan time.Time
		)
		if at, ok := r.deadline(); ok {
			t = r.clock.NewTimer(at.Sub(r.clock.Now()))
			timerC = t.C()
		}
		select {
		case <-ctx.Done():
			stopTimer(t)
			r.shutdown(r.clock.Now())
			return
		case p := <-r.pkts:
			r.handlePacket(r.clock.Now(), p)
		case <-r.addrSig:
			r.handleAddrs(r.clock.Now(), r.latestSnapshot())
		case fl := <-r.faults:
			if r.handleFault(r.clock.Now(), fl) {
				stopTimer(t)
				return
			}
		case <-timerC:
			r.handleDeadline(r.clock.Now())
		}
		stopTimer(t)
	}
}

func stopTimer(t Timer) {
	if t != nil {
		t.Stop()
	}
}

// Wait returns once Run has returned. It is safe on a nil Responder, which
// is what the composition root holds when there is no cluster id.
func (r *Responder) Wait() {
	if r == nil {
		return
	}
	<-r.done
}

func (r *Responder) logPanic(where string, v any) {
	if r.log == nil {
		return
	}
	r.log.Error("signinname: panic recovered; the sign-in name is not published", "where", where, "panic", fmt.Sprint(v))
	r.log.Debug("signinname: panic stack", "where", where, "stack", string(debug.Stack()))
}

// read is the reader goroutine for one socket. It recovers its own panics.
// A read error after stop is closed is our own close; any other error, and
// any panic, is one non-blocking fault report, and the goroutine exits.
func (r *Responder) read(conn Conn, gen uint64, stop <-chan struct{}) {
	defer func() {
		if v := recover(); v != nil {
			r.logPanic("reader", v)
			r.reportFault(fault{gen: gen, err: fmt.Errorf("panic in the reader: %v", v), panicked: true})
		}
	}()
	buf := make([]byte, maxPacket)
	for {
		n, src, err := conn.Read(buf)
		if err != nil {
			select {
			case <-stop:
				return
			default:
			}
			r.reportFault(fault{gen: gen, err: err})
			return
		}
		p := packet{gen: gen, data: bytes.Clone(buf[:n]), src: src}
		select {
		case r.pkts <- p:
		case <-stop:
			return
		}
	}
}

func (r *Responder) reportFault(fl fault) {
	select {
	case r.faults <- fl:
	default:
		r.log.Debug("signinname: a second fault dropped", "err", fl.err.Error())
	}
}

// deadline is the next protocol deadline, if any.
func (r *Responder) deadline() (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.ph {
	case phaseProbing, phaseAnswering:
		return r.next, !r.next.IsZero()
	case phaseConceded:
		o := r.f.owner
		if o.queries < len(maintenancePoints) {
			return o.heard.Add(time.Duration(float64(o.ttl) * maintenancePoints[o.queries])), true
		}
		return o.expires(), true
	}
	return time.Time{}, false
}

// handleDeadline acts on the deadline that has come due at now.
func (r *Responder) handleDeadline(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.ph {
	case phaseProbing:
		if now.Before(r.next) {
			return
		}
		if r.step < probeCount {
			r.sendProbe(now)
			return
		}
		// 250 ms after the third probe with no conflicting response.
		r.ph, r.step = phaseAnswering, 0
		r.f.answering, r.f.since = true, now
		r.announce(now)
		r.log.Info("sign-in name published", "addresses", addrList(r.addrs), "link", r.link)
	case phaseAnswering:
		if !r.next.IsZero() && !now.Before(r.next) {
			r.announce(now)
		}
	case phaseConceded:
		o := &r.f.owner
		if !o.live(now) {
			r.log.Info("re-probing: the other device's record is gone", "owner", o.addr.String(), "how", "expired")
			r.f.owner = ownerRecord{}
			r.reprobeIfUnpublished(now)
			return
		}
		if o.queries < len(maintenancePoints) {
			r.send("maintenance query", queryMsg)
			o.queries++
		}
	}
}

// handlePacket acts on one received datagram.
func (r *Responder) handlePacket(now time.Time, p packet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.gen != r.gen || r.conn == nil {
		return
	}
	src := p.src.Addr().Unmap()
	if slices.Contains(r.addrs, src) {
		return // our own packet, looped back
	}
	o, ok := parse(p.data, p.src, r.name)
	if !ok {
		r.log.Debug("signinname: malformed packet ignored", "src", p.src.String())
		return
	}
	if o.response {
		r.handleResponse(now, src, o)
		return
	}
	if !o.asksForUs || r.ph != phaseAnswering {
		return
	}
	gap := multicastMinGap
	if o.probe {
		gap = probeAnswerMinGap
	}
	if !r.lastMcast.IsZero() && now.Sub(r.lastMcast) < gap {
		return // §6.2: the same answer went out too recently
	}
	r.sendAnswer(now, hostRecordTTL)
}

// handleResponse checks a response's records for our name against ours.
func (r *Responder) handleResponse(now time.Time, src netip.Addr, o observation) {
	if r.ph == phaseIdle {
		return
	}
	for _, rec := range o.records {
		if slices.Contains(r.addrs, rec.addr) {
			continue // identical data is not a conflict (§9)
		}
		if o.src.Port() != mdnsPort {
			r.log.Debug("signinname: a record for our name from a port other than 5353 ignored", "src", o.src.String())
			continue
		}
		if rec.ttl == 0 {
			if r.ph == phaseConceded && rec.addr == r.f.owner.addr {
				r.log.Info("re-probing: the other device's record is gone", "owner", rec.addr.String(), "how", "goodbye")
				r.f.owner = ownerRecord{}
				r.reprobeIfUnpublished(now)
				return
			}
			continue
		}
		ttl := min(time.Duration(rec.ttl)*time.Second, maxOwnerTTL)
		if r.ph == phaseConceded {
			r.f.owner.addr, r.f.owner.src = rec.addr, src
			r.f.owner.ttl, r.f.owner.heard, r.f.owner.queries = ttl, now, 0
			continue
		}
		r.ph, r.step, r.next = phaseConceded, 0, time.Time{}
		r.f.answering, r.f.since = false, now
		r.f.owner = ownerRecord{addr: rec.addr, src: src, ttl: ttl, heard: now, since: now}
		r.log.Warn("sign-in name conflict", "owner", rec.addr.String(), "source", o.src.String(), "event", "signinname.conflict")
	}
}

// reprobeIfUnpublished is the way back from a conflict: once the guard reads
// the owner's record as gone, the loop probes again.
func (r *Responder) reprobeIfUnpublished(now time.Time) {
	if r.ph == phaseConceded && classify(r.f, now).State == StateUnpublished {
		r.startProbing(now)
	}
}

// handleAddrs follows the LAN link (§8.4).
func (r *Responder) handleAddrs(now time.Time, s lanaddr.Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f.fault == CauseStopped {
		return
	}
	p, ok := s.Primary()
	if !ok {
		r.closeConn()
		r.link, r.addrs = 0, nil
		if r.f.fault != CauseNoAddress {
			r.setFault(now, CauseNoAddress)
			r.log.Warn("not published: no LAN address")
		}
		return
	}
	addrs := toAddrs(s.LinkIPs())
	if r.conn != nil && p.Index == r.link {
		if slices.Equal(addrs, r.addrs) {
			return
		}
		r.addrs = addrs
		if r.ph == phaseAnswering {
			r.step = 0
			r.announce(now)
			r.log.Info("address change: announced again", "addresses", addrList(addrs))
		}
		return
	}
	r.closeConn()
	r.link, r.addrs = p.Index, addrs
	conn, err := r.open(p.Index)
	if err != nil {
		r.setFault(now, CauseOpenFailed)
		r.log.Error("signinname: the mDNS socket could not be opened; the sign-in name is not published", "link", p.Link, "ifindex", p.Index, "err", err.Error())
		return
	}
	r.gen++
	r.conn, r.readerStop = conn, make(chan struct{})
	go r.read(conn, r.gen, r.readerStop)
	r.f.fault, r.f.owner = CauseNone, ownerRecord{}
	r.startProbing(now)
}

// handleFault stops the responder on a reader fault from the current socket.
// It reports whether Run should return.
func (r *Responder) handleFault(now time.Time, fl fault) bool {
	r.mu.Lock()
	stale := fl.gen != r.gen
	r.mu.Unlock()
	if stale {
		return false
	}
	if !fl.panicked {
		r.log.Error("signinname: the responder stopped on a read error; the sign-in name is not published", "err", fl.err.Error())
	}
	r.stop(now)
	return true
}

// stop is the terminal fault state: unpublished, "stopped", socket closed.
func (r *Responder) stop(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeConn()
	r.setFault(now, CauseStopped)
}

// shutdown sends one goodbye when the name is published, then closes the
// socket.
func (r *Responder) shutdown(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ph == phaseAnswering && r.conn != nil {
		if err := r.sendRaw(answerMsg(r.name, r.addrs, 0)); err != nil {
			r.log.Warn("goodbye not sent", "err", err.Error())
		} else {
			r.log.Info("goodbye sent")
		}
	}
	r.closeConn()
	r.ph = phaseIdle
	r.f.answering = false
}

func (r *Responder) setFault(now time.Time, c Cause) {
	r.ph, r.step, r.next = phaseIdle, 0, time.Time{}
	r.f = facts{fault: c, since: now}
}

func (r *Responder) closeConn() {
	if r.conn == nil {
		return
	}
	close(r.readerStop)
	if err := r.conn.Close(); err != nil {
		r.log.Debug("signinname: closing the socket", "err", err.Error())
	}
	r.conn, r.readerStop = nil, nil
}

func (r *Responder) startProbing(now time.Time) {
	r.ph, r.step = phaseProbing, 0
	r.f.answering, r.f.since = false, now
	r.sendProbe(now)
}

func (r *Responder) sendProbe(now time.Time) {
	r.send("probe", func(name string) ([]byte, error) { return probeMsg(name, r.addrs) })
	r.step++
	r.next = now.Add(probeInterval)
}

// announce sends one announcement and schedules the next.
func (r *Responder) announce(now time.Time) {
	r.sendAnswer(now, hostRecordTTL)
	r.step++
	r.next = time.Time{}
	if r.step < announceCount {
		r.next = now.Add(announceInterval)
	}
}

func (r *Responder) sendAnswer(now time.Time, ttl uint32) {
	r.send("answer", func(name string) ([]byte, error) { return answerMsg(name, r.addrs, ttl) })
	r.lastMcast = now
}

// send builds and multicasts one message. A failed send is logged and the
// protocol carries on: the next deadline or query sends again.
func (r *Responder) send(what string, build func(name string) ([]byte, error)) {
	if r.conn == nil {
		return
	}
	if err := r.sendRaw(build(r.name)); err != nil {
		r.log.Warn("signinname: send failed", "what", what, "err", err.Error())
	}
}

func (r *Responder) sendRaw(b []byte, err error) error {
	if err != nil {
		return fmt.Errorf("signinname: build: %w", err)
	}
	return r.conn.Send(b)
}

func toAddrs(ips []net.IP) []netip.Addr {
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip.To4()); ok {
			out = append(out, a)
		}
	}
	return out
}

func addrList(addrs []netip.Addr) string {
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ",")
}
