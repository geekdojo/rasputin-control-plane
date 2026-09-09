package clusterdns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ---- an in-process nameserver ------------------------------------------
//
// The probe's verdict is what every keep and every withdrawal rests on, so
// these tests do not stub it. They run the production query (queryA) against
// a nameserver that speaks DNS on loopback and vary what it says: an answer
// for the cluster's apex, NXDOMAIN, SERVFAIL, an empty NOERROR, a port that
// listens and never replies, a truncated UDP reply, or nothing listening at
// all. Each of those is a fact on the wire, and the test asserts what the
// package does with it.

type nsMode int

const (
	nsAnswers   nsMode = iota // authoritative: an A record for its zone apex
	nsNXDomain                // listens, answers NXDOMAIN to everything
	nsServFail                // listens, answers SERVFAIL
	nsEmpty                   // NOERROR with nothing in the answer section
	nsSilent                  // holds the port and never replies
	nsTruncates               // over UDP: TC set and no answer; over TCP: the answer
)

// fakeNS is a nameserver authoritative for one cluster's internal apex,
// bound UDP and TCP on the same loopback port, whose behaviour a test can
// switch while it runs.
type fakeNS struct {
	t    *testing.T
	udp  *net.UDPConn
	tcp  net.Listener
	addr string // "127.0.0.1:<port>" — one port, both transports
	zone string // canonical apex it holds, e.g. "rasputin.internal."

	mu    sync.Mutex
	mode  nsMode
	asked []string // every name queried, in order, as the wire carried it
}

func startNS(t *testing.T, clusterID string) *fakeNS {
	t.Helper()
	ns := &fakeNS{t: t, zone: clusterID + ".internal."}
	// One port for both transports, as a real nameserver has: bind UDP on an
	// ephemeral port, then TCP on the same one; retry if TCP loses the race.
	for try := 0; ; try++ {
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		tcp, err := net.Listen("tcp", udp.LocalAddr().String())
		if err == nil {
			ns.udp, ns.tcp, ns.addr = udp, tcp, udp.LocalAddr().String()
			break
		}
		_ = udp.Close()
		if try == 10 {
			t.Fatalf("no port free on both udp and tcp: %v", err)
		}
	}
	t.Cleanup(func() { _ = ns.udp.Close(); _ = ns.tcp.Close() })
	go ns.serveUDP()
	go ns.serveTCP()
	return ns
}

func (ns *fakeNS) set(m nsMode) { ns.mu.Lock(); ns.mode = m; ns.mu.Unlock() }

func (ns *fakeNS) queries() []string {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return append([]string(nil), ns.asked...)
}

func (ns *fakeNS) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, peer, err := ns.udp.ReadFromUDP(buf)
		if err != nil {
			return // closed by Cleanup
		}
		if reply := ns.reply(buf[:n], false); reply != nil {
			_, _ = ns.udp.WriteToUDP(reply, peer)
		}
	}
}

func (ns *fakeNS) serveTCP() {
	for {
		c, err := ns.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			var hdr [2]byte
			if _, err := io.ReadFull(c, hdr[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(hdr[:]))
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			reply := ns.reply(q, true)
			if reply == nil || len(reply) > 0xffff {
				return
			}
			framed := make([]byte, 2+len(reply))
			binary.BigEndian.PutUint16(framed, uint16(len(reply)))
			copy(framed[2:], reply)
			_, _ = c.Write(framed)
		}()
	}
}

// reply is the nameserver's answer to one query under the current mode, or
// nil for no reply at all.
func (ns *fakeNS) reply(query []byte, overTCP bool) []byte {
	var p dnsmessage.Parser
	qh, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	ns.mu.Lock()
	mode := ns.mode
	ns.asked = append(ns.asked, q.Name.String())
	ns.mu.Unlock()

	holds := strings.EqualFold(q.Name.String(), ns.zone) && q.Type == dnsmessage.TypeA && q.Class == dnsmessage.ClassINET
	h := dnsmessage.Header{ID: qh.ID, Response: true, Authoritative: true, RecursionDesired: qh.RecursionDesired}
	answer := false
	switch mode {
	case nsSilent:
		return nil
	case nsNXDomain:
		h.RCode = dnsmessage.RCodeNameError
	case nsServFail:
		h.RCode = dnsmessage.RCodeServerFailure
	case nsEmpty:
	case nsTruncates:
		if overTCP {
			answer = holds
		} else {
			h.Truncated = true
		}
	case nsAnswers:
		if holds {
			answer = true
		} else {
			h.RCode = dnsmessage.RCodeNameError // authoritative, and this is not its name
		}
	}
	b := dnsmessage.NewBuilder(nil, h)
	must := func(err error) {
		if err != nil {
			ns.t.Errorf("fake nameserver building a reply: %v", err)
		}
	}
	must(b.StartQuestions())
	must(b.Question(q))
	must(b.StartAnswers())
	if answer {
		must(b.AResource(
			dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
			dnsmessage.AResource{A: [4]byte{192, 168, 1, 181}}))
	}
	msg, err := b.Finish()
	must(err)
	return msg
}

// directory stands in for port 53, which a test cannot bind: it maps the
// address the bus or the drop-in names to the loopback port of the fake
// serving as that control plane. Everything from the query onward is the
// production path (queryA); only the port is substituted. An address with no
// fake behind it is dialed at a loopback port nothing listens on, so a gone
// server fails the way it fails on the wire — refused — not by a stub's
// say-so.
type directory struct {
	mu   sync.Mutex
	at   map[string]*fakeNS
	dead string
}

func newDirectory(t *testing.T) *directory {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	dead := l.LocalAddr().String()
	_ = l.Close()
	return &directory{at: map[string]*fakeNS{}, dead: dead}
}

func (d *directory) serve(t *testing.T, ip, clusterID string) *fakeNS {
	ns := startNS(t, clusterID)
	d.mu.Lock()
	d.at[ip] = ns
	d.mu.Unlock()
	return ns
}

func (d *directory) gone(ip string) { d.mu.Lock(); delete(d.at, ip); d.mu.Unlock() }

func (d *directory) probe(ctx context.Context, ip, name string) error {
	d.mu.Lock()
	addr := d.dead
	if ns, ok := d.at[ip]; ok {
		addr = ns.addr
	}
	d.mu.Unlock()
	return queryA(ctx, addr, name)
}

// harness is one node under test: the config Apply and Run see, the bus
// address as the client would report it, the nameservers behind each
// address, and how many times resolved was restarted. Guarded for -race,
// since Run-level tests change it while Run is looking.
type harness struct {
	t       *testing.T
	cfg     Config
	servers *directory

	mu      sync.Mutex
	addr    string
	reloads int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, servers: newDirectory(t)}
	h.cfg = Config{
		ClusterID: "rasputin",
		ServerIP:  h.serverIP,
		probe:     h.servers.probe,
		Dir:       filepath.Join(t.TempDir(), "resolved.conf.d"),
		reload:    h.reload,
	}
	return h
}

// serve starts a nameserver for this cluster behind ip.
func (h *harness) serve(ip string) *fakeNS { return h.servers.serve(h.t, ip, h.cfg.ClusterID) }

// bus sets what the bus client reports as the control plane's address; ""
// is not connected.
func (h *harness) bus(ip string) { h.mu.Lock(); h.addr = ip; h.mu.Unlock() }

func (h *harness) serverIP() string { h.mu.Lock(); defer h.mu.Unlock(); return h.addr }
func (h *harness) reload(context.Context) error {
	h.mu.Lock()
	h.reloads++
	h.mu.Unlock()
	return nil
}
func (h *harness) reloaded() int { h.mu.Lock(); defer h.mu.Unlock(); return h.reloads }
func (h *harness) path() string  { return filepath.Join(h.cfg.Dir, fileName) }

// run starts Run with a Trigger and a tick that cannot fire unless the test
// set one, so anything that happens happened because of a trigger.
func (h *harness) run(ctx context.Context) <-chan struct{} {
	if h.cfg.Interval == 0 {
		h.cfg.Interval = time.Hour
	}
	if h.cfg.Trigger == nil {
		h.cfg.Trigger = NewTrigger()
	}
	done := make(chan struct{})
	go func() { Run(ctx, h.cfg); close(done) }()
	return done
}

// connected is the common starting point: a control plane at ip whose
// nameserver answers, and the bus connected to it.
func connected(t *testing.T, ip string) (*harness, *fakeNS) {
	t.Helper()
	h := newHarness(t)
	ns := h.serve(ip)
	h.bus(ip)
	return h, ns
}

// answering is a probe that says yes without asking anything, for the tests
// of config validation, where the probe is not what is under test.
func answering(context.Context, string, string) error { return nil }

// at makes a static address source.
func at(ip string) func() string { return func() string { return ip } }

func TestDomainsAreRoutingOnly(t *testing.T) {
	// The "~" prefix is the whole safety argument: without it this would make
	// the control plane the node's resolver for everything, and the CP
	// nameserver REFUSEs off-zone names — general DNS on the node would break.
	for _, d := range Domains("rasputin") {
		if !strings.HasPrefix(d, "~") {
			t.Errorf("domain %q is not routing-only; it would capture all DNS", d)
		}
	}
	want := []string{"~rasputin.local", "~rasputin.internal"}
	got := Domains("rasputin")
	if len(got) != len(want) {
		t.Fatalf("Domains() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Domains()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// The name the probe asks for must be one the drop-in routes at the pinned
// server — otherwise the probe would be proving something the pin does not
// assert. Canonical, so it goes on the wire as-is.
func TestProbeNameIsARoutedDomain(t *testing.T) {
	name := probeName("rasputin")
	if name != "rasputin.internal." {
		t.Fatalf("probeName = %q, want the internal apex, canonical", name)
	}
	routed := false
	for _, d := range Domains("rasputin") {
		if d == "~"+strings.TrimSuffix(name, ".") {
			routed = true
		}
	}
	if !routed {
		t.Errorf("%q is not among the routed domains %v", name, Domains("rasputin"))
	}
}

func TestRenderContainsDNSAndDomains(t *testing.T) {
	body := Render("home1", "10.0.0.5")
	for _, want := range []string{
		"[Resolve]",
		"DNS=10.0.0.5",
		"Domains=~home1.local ~home1.internal",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered config missing %q:\n%s", want, body)
		}
	}
}

func TestApplyWritesAndReloads(t *testing.T) {
	h, _ := connected(t, "192.168.197.224")

	changed, err := Apply(context.Background(), h.cfg, TriggerTick)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !changed {
		t.Error("first Apply reported no change")
	}
	if h.reloaded() != 1 {
		t.Errorf("reloads = %d, want 1", h.reloaded())
	}

	body, err := os.ReadFile(h.path())
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(body) != Render(h.cfg.ClusterID, "192.168.197.224") {
		t.Errorf("written body does not match Render():\n%s", body)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	// The steady-state call must not restart systemd-resolved. A restart
	// flushes the DNS cache, so an unconditional rewrite on a 5-minute ticker
	// would be a self-inflicted cache flush forever.
	h, _ := connected(t, "192.168.197.224")

	if _, err := Apply(context.Background(), h.cfg, TriggerTick); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	changed, err := Apply(context.Background(), h.cfg, TriggerTick)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if changed {
		t.Error("second Apply reported a change with identical config")
	}
	if h.reloaded() != 1 {
		t.Errorf("reloads = %d after two identical Applies, want 1", h.reloaded())
	}
}

func TestApplyRequiresClusterAndServer(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no cluster id", Config{ServerIP: at("10.0.0.1"), probe: answering, Dir: t.TempDir()}},
		{"no address source", Config{ClusterID: "rasputin", Dir: t.TempDir(), probe: answering}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Apply(context.Background(), tc.cfg, TriggerTick); err == nil {
				t.Error("Apply succeeded with incomplete config")
			}
		})
	}
}

func TestApplyReportsReloadFailureButKeepsFile(t *testing.T) {
	// A failed reload still leaves correct config on disk — it takes effect at
	// the next resolved restart. Removing it would be strictly worse.
	h, _ := connected(t, "192.168.197.224")
	h.cfg.reload = func(context.Context) error { return errors.New("boom") }

	changed, err := Apply(context.Background(), h.cfg, TriggerTick)
	if err == nil {
		t.Error("Apply hid a reload failure")
	}
	if !changed {
		t.Error("Apply reported no change despite writing the file")
	}
	if _, serr := os.Stat(h.path()); serr != nil {
		t.Errorf("drop-in was removed after a failed reload: %v", serr)
	}
}

func TestRunStopsWhenResolvedIsAbsent(t *testing.T) {
	// The OpenWrt firewall and dev boxes have no systemd-resolved. Run must
	// notice and return rather than spin writing files nothing will read.
	cfg := Config{
		ClusterID: "rasputin",
		ServerIP:  at("10.0.0.1"), probe: answering,
		Dir:    filepath.Join(t.TempDir(), "definitely", "absent", "resolved.conf.d"),
		reload: func(context.Context) error { t.Error("reloaded on a host with no resolved"); return nil },
	}
	done := make(chan struct{})
	go func() { Run(context.Background(), cfg); close(done) }()
	<-done // Run returning at all is the assertion; it would block otherwise.
}

func TestApplyDefaultsInterval(t *testing.T) {
	// The re-check period must never end up zero or negative: time.NewTicker
	// panics on a non-positive duration, so a caller that left Interval unset
	// would take the agent down at startup rather than degrade.
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"unset", 0, DefaultInterval},
		{"negative", -time.Second, DefaultInterval},
		{"positive is preserved", 90 * time.Second, 90 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{ClusterID: "rasputin", ServerIP: at("10.0.0.1"), probe: answering, Interval: tc.in}
			cfg.applyDefaults()
			if cfg.Interval != tc.want {
				t.Errorf("Interval = %s, want %s", cfg.Interval, tc.want)
			}
		})
	}
}

func TestApplyDefaultsDirReloadAndProbe(t *testing.T) {
	cfg := Config{ClusterID: "rasputin", ServerIP: at("10.0.0.1")}
	cfg.applyDefaults()
	if cfg.Dir != DefaultDir {
		t.Errorf("Dir = %q, want %q", cfg.Dir, DefaultDir)
	}
	if cfg.reload == nil {
		t.Error("applyDefaults left reload nil; Apply would panic")
	}
	if cfg.probe == nil {
		t.Error("applyDefaults left probe nil; Apply would panic")
	}
}

func TestRunRefusesIncompleteConfig(t *testing.T) {
	// Run must return, not spin, when it has nothing usable. Each field is
	// checked separately so a mutation that drops one half of the guard is
	// caught: with only a both-empty case, either half alone still passes.
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no cluster id", Config{ServerIP: at("10.0.0.1"), probe: answering}},
		{"no server ip", Config{ClusterID: "rasputin"}},
		{"neither", Config{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			// A real dir, so the absent-resolved guard cannot be what stops it.
			cfg.Dir = filepath.Join(t.TempDir(), "resolved.conf.d")
			cfg.reload = func(context.Context) error {
				t.Error("Run acted on an incomplete config")
				return nil
			}
			done := make(chan struct{})
			go func() { Run(context.Background(), cfg); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return on an incomplete config")
			}
		})
	}
}

func TestRunAppliesThenHonoursContext(t *testing.T) {
	// One pass through the loop body — including the error branch — then a
	// clean exit when the context ends.
	h, _ := connected(t, "192.168.197.224")
	reloads := 0
	h.cfg.reload = func(context.Context) error {
		reloads++
		return errors.New("reload unavailable")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := h.run(ctx)

	// The drop-in should appear even though the reload failed.
	waitFor(t, "the drop-in", func() bool { _, err := os.Stat(h.path()); return err == nil })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run ignored context cancellation")
	}
	if reloads == 0 {
		t.Error("Run never attempted a reload")
	}
}

// ---- the control plane moves -------------------------------------------
//
// These are the regression for the worst bug this package has had. The address
// used to be captured once at startup. A rollout reboots the control plane
// LAST, it comes back on a new DHCP lease, and every node this package had just
// repaired was left pinned to where the control plane used to be. Because the
// domains are routing-only that is not a degraded state, it is a dead one: the
// cluster's own names stop resolving entirely, where without any drop-in mDNS
// would still have answered. Five nodes at once on e3bench, 2026-08-30.

func TestApply_FollowsTheControlPlaneWhenItMoves(t *testing.T) {
	h, _ := connected(t, "192.168.1.182")

	if _, err := Apply(context.Background(), h.cfg, TriggerTick); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if pinnedIP(h.path()) != "192.168.1.182" {
		t.Fatalf("initial pin wrong: %q", pinnedIP(h.path()))
	}

	// The control plane reboots and comes back elsewhere; its nameserver
	// answers from the new address, and the bus re-dialed it.
	h.serve("192.168.1.183")
	h.servers.gone("192.168.1.182")
	h.bus("192.168.1.183")
	changed, err := Apply(context.Background(), h.cfg, TriggerConnected)
	if err != nil {
		t.Fatalf("Apply after the CP moved: %v", err)
	}
	if !changed {
		t.Error("Apply did not react to the control plane moving")
	}
	if pinnedIP(h.path()) != "192.168.1.183" {
		t.Errorf("still pinned to the old address: %q", pinnedIP(h.path()))
	}
	if h.reloaded() != 2 {
		t.Errorf("reloads = %d, want 2", h.reloaded())
	}
}

// ---- what "answers" means ----------------------------------------------
//
// The pin asserts that the cluster's names, sent to this address, come back
// answered. A server that merely listens on :53 does not satisfy that — a
// stub, a forwarder, a half-started api all accept a connection — and the
// previous probe, a TCP connect, could not tell them from the real thing. The
// probe now asks the actual question, on the wire, and these are its verdicts.

// The probe asks the pinned server for the cluster's internal apex, and for
// nothing else.
func TestApply_ProbeAsksForTheClusterApex(t *testing.T) {
	h, ns := connected(t, "192.168.1.181")
	if _, err := Apply(context.Background(), h.cfg, TriggerConnected); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := ns.queries(); len(got) != 1 || got[0] != "rasputin.internal." {
		t.Errorf("the nameserver was asked %v, want exactly [rasputin.internal.]", got)
	}
}

// Every way a server can fail to answer, from an address the bus vouches
// for: the pin is withdrawn, and the reason is in the line.
func TestApply_WithdrawsWhenTheServerDoesNotAnswer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(h *harness, ns *fakeNS)
		reason  string
	}{
		{"nothing listening", func(h *harness, _ *fakeNS) { h.servers.gone("192.168.1.181") }, "connection refused"},
		{"NXDOMAIN", func(_ *harness, ns *fakeNS) { ns.set(nsNXDomain) }, "NXDOMAIN"},
		{"SERVFAIL", func(_ *harness, ns *fakeNS) { ns.set(nsServFail) }, "SERVFAIL"},
		{"NOERROR with no answer", func(_ *harness, ns *fakeNS) { ns.set(nsEmpty) }, "no address in the answer"},
		// A nameserver — a real, answering one — for a DIFFERENT cluster: it
		// listens, it speaks DNS, and it does not hold this cluster's name.
		// The old TCP-connect probe would have kept this pin.
		{"another cluster's nameserver", func(h *harness, _ *fakeNS) { h.servers.serve(h.t, "192.168.1.181", "other") }, "NXDOMAIN"},
		// Holds the port and never replies. This one costs the full
		// probeTimeout, which is the bound's reason to exist.
		{"listens but never replies", func(_ *harness, ns *fakeNS) { ns.set(nsSilent) }, "i/o timeout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, ns := connected(t, "192.168.1.181")
			if _, err := Apply(context.Background(), h.cfg, TriggerConnected); err != nil {
				t.Fatalf("seed pin: %v", err)
			}
			tc.arrange(h, ns)

			changed, err := Apply(context.Background(), h.cfg, TriggerTick)
			if !changed {
				t.Error("Apply left a pin whose server does not answer")
			}
			if err == nil {
				t.Fatal("withdrawing must be reported, not silent")
			}
			if !strings.Contains(err.Error(), "192.168.1.181 does not answer rasputin.internal.") || !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("withdrawal must name the address, the name and the reason (%s):\n%v", tc.reason, err)
			}
			if _, serr := os.Stat(h.path()); !os.IsNotExist(serr) {
				t.Error("drop-in still present after the server stopped answering")
			}
			if h.reloaded() != 2 {
				t.Errorf("reloads = %d, want 2 (pin, withdrawal)", h.reloaded())
			}
		})
	}
}

// Never write a pin we have not verified. Writing first and checking later
// would black-hole the cluster name for a whole tick.
func TestApply_DoesNotWriteAnUnverifiedPin(t *testing.T) {
	h, ns := connected(t, "192.168.1.181")
	ns.set(nsNXDomain)

	changed, err := Apply(context.Background(), h.cfg, TriggerConnected)
	if changed || err != nil {
		// Nothing was pinned, so there is nothing to withdraw and nothing to say.
		t.Errorf("changed=%v err=%v, want a quiet no-op", changed, err)
	}
	if _, err := os.Stat(h.path()); !os.IsNotExist(err) {
		t.Error("wrote a drop-in pointing at a server that never answered")
	}
	if h.reloaded() != 0 {
		t.Errorf("resolved restarted %d time(s) for a pin that was never written", h.reloaded())
	}
}

// A UDP reply cut short is asked again over TCP, under the same bound, and
// the answer that arrives there counts.
func TestQueryA_RetriesOverTCPWhenTruncated(t *testing.T) {
	ns := startNS(t, "rasputin")
	ns.set(nsTruncates)
	if err := queryA(context.Background(), ns.addr, "rasputin.internal."); err != nil {
		t.Fatalf("truncated over UDP, answered over TCP, yet: %v", err)
	}
	if got := ns.queries(); len(got) != 2 {
		t.Errorf("queries = %v, want the UDP ask and the TCP retry", got)
	}
}

// An address that is not on the network does not answer, and the probe says
// so within its bound rather than waiting on the kernel.
func TestQueryA_UnroutableSaysNoWithinTheBound(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed not routable.
	start := time.Now()
	err := queryA(context.Background(), "192.0.2.1:53", "rasputin.internal.")
	if err == nil {
		t.Fatal("probe said an unreachable address answered the cluster name")
	}
	if took := time.Since(start); took > probeTimeout+time.Second {
		t.Errorf("probe took %s, want within probeTimeout (%s)", took, probeTimeout)
	}
}

// A query name that cannot go on the wire is an error, not a pass.
func TestQueryA_RejectsANonCanonicalName(t *testing.T) {
	ns := startNS(t, "rasputin")
	if err := queryA(context.Background(), ns.addr, "rasputin.internal"); err == nil {
		t.Error("a name without its trailing dot was sent, or worse, counted as answered")
	}
	if got := ns.queries(); len(got) != 0 {
		t.Errorf("queries = %v, want none", got)
	}
}

// ---- the address is unknown ---------------------------------------------
//
// ServerIP returns "" whenever the bus is not connected — the seconds between
// the agent starting and its first dial (Run starts before the dial), and
// every loss after that. The first version withdrew on sight, and the next
// look was the five-minute tick: every agent restart took the node off the
// mesh for up to five minutes (e3bench 2026-09-09,
// geekdojo/geekdojo-brain#403). The revision after that kept the pin for a
// 20 s grace and withdrew on the clock — which would have withdrawn during an
// ordinary control-plane reboot, and was ruled out: "we keep relying on
// timeouts to do work and those keep biting us."
//
// Now there is no clock. An existing pin is read back and its server ASKED
// for the cluster's name; it answers, the pin stays; it does not, the pin
// goes. The bus state is not an input and neither is elapsed time.

func seedPin(t *testing.T, cfg Config, ip string) string {
	t.Helper()
	path := filepath.Join(cfg.Dir, fileName)
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(Render(cfg.ClusterID, ip)), 0o644); err != nil {
		t.Fatalf("seed pin: %v", err)
	}
	return path
}

// Start with the previous process's pin on disk and the bus not yet dialed:
// the PINNED server — read back out of the drop-in, not any other — is asked
// for the cluster's name, answers, and the pin is kept: no write, no resolved
// restart.
func TestApply_StartWithUnknownAddressKeepsAnAnsweringPin(t *testing.T) {
	h := newHarness(t)
	pinned := h.serve("192.168.1.181")
	other := h.serve("192.168.1.182") // also a live nameserver; must not be the one asked
	path := seedPin(t, h.cfg, "192.168.1.181")

	changed, err := Apply(context.Background(), h.cfg, TriggerStart)
	if changed || err != nil {
		t.Fatalf("start with an unknown address touched the pin: changed=%v err=%v", changed, err)
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Fatal("the pin the previous process left was withdrawn on start")
	}
	if got := pinned.queries(); len(got) != 1 || got[0] != "rasputin.internal." {
		t.Errorf("the pinned server was asked %v, want exactly [rasputin.internal.] — the pin is kept because it ANSWERED, not because it exists", got)
	}
	if got := other.queries(); len(got) != 0 {
		t.Errorf("a server that is not the pinned one was asked %v", got)
	}
	if h.reloaded() != 0 {
		t.Errorf("resolved restarted %d time(s) while nothing changed", h.reloaded())
	}
}

// The bus dropped and the pinned server still answers: kept. Looked at again
// and again — every look is a tick or a bus event while the bus stays down —
// and still kept. Nothing about how many looks or how long withdraws a pin
// whose server answers.
func TestApply_LostBusKeepsAnAnsweringPinOnEveryLook(t *testing.T) {
	h := newHarness(t)
	ns := h.serve("192.168.1.181")
	path := seedPin(t, h.cfg, "192.168.1.181")

	looks := []string{TriggerLost, TriggerTick, TriggerTick, TriggerLost, TriggerTick}
	for i, trigger := range looks {
		changed, err := Apply(context.Background(), h.cfg, trigger)
		if changed || err != nil {
			t.Fatalf("look %d [%s] withdrew an answering pin: changed=%v err=%v", i, trigger, changed, err)
		}
	}
	if pinnedIP(path) != "192.168.1.181" {
		t.Error("pin gone or changed with the bus down and the server answering")
	}
	if got := ns.queries(); len(got) != len(looks) {
		t.Errorf("the server was asked %d time(s) over %d looks — every look must ask, none may assume", len(got), len(looks))
	}
	if h.reloaded() != 0 {
		t.Errorf("resolved restarted %d time(s) while nothing changed", h.reloaded())
	}
}

// The bus dropped and the pinned server does NOT answer the cluster's name:
// withdrawn, at once, naming the dead address and why. Gone from the network
// and still listening but not serving the zone are the same fact here.
func TestApply_LostBusWithdrawsAPinWhoseServerDoesNotAnswer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(h *harness, ns *fakeNS)
		reason  string
	}{
		{"server gone", func(h *harness, _ *fakeNS) { h.servers.gone("192.168.1.181") }, "connection refused"},
		{"server up but not serving the zone", func(_ *harness, ns *fakeNS) { ns.set(nsNXDomain) }, "NXDOMAIN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ns := h.serve("192.168.1.181")
			path := seedPin(t, h.cfg, "192.168.1.181")
			tc.arrange(h, ns)

			changed, err := Apply(context.Background(), h.cfg, TriggerLost)
			if !changed || err == nil {
				t.Fatalf("a dead pin survived the bus dropping: changed=%v err=%v", changed, err)
			}
			for _, want := range []string{"pinned 192.168.1.181 does not answer rasputin.internal.", tc.reason, "[" + TriggerLost + "]"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("withdrawal must say %q:\n%v", want, err)
				}
			}
			if _, serr := os.Stat(path); !os.IsNotExist(serr) {
				t.Error("dead pin still present")
			}
			if h.reloaded() != 1 {
				t.Errorf("reloads = %d, want 1 (the withdrawal)", h.reloaded())
			}
		})
	}
}

// A drop-in with no DNS= line cannot be probed and is not one this package
// wrote; withdrawn rather than kept on faith.
func TestApply_UnknownAddressWithdrawsADropInThatNamesNoServer(t *testing.T) {
	h := newHarness(t)
	h.cfg.probe = func(context.Context, string, string) error {
		t.Error("probed with no address to probe")
		return nil
	}
	if err := os.MkdirAll(h.cfg.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.path(), []byte("[Resolve]\nDomains=~rasputin.local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := Apply(context.Background(), h.cfg, TriggerStart)
	if !changed || err == nil || !strings.Contains(err.Error(), "names no server") {
		t.Fatalf("changed=%v err=%v, want a reported withdrawal", changed, err)
	}
	if _, serr := os.Stat(h.path()); !os.IsNotExist(serr) {
		t.Error("unverifiable drop-in still present")
	}
}

func TestPinnedIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	if got := pinnedIP(path); got != "" {
		t.Errorf("missing file: pinnedIP = %q, want empty", got)
	}
	if err := os.WriteFile(path, []byte(Render("e3bench", "192.168.1.181")), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := pinnedIP(path); got != "192.168.1.181" {
		t.Errorf("pinnedIP = %q, want 192.168.1.181", got)
	}
	if err := os.WriteFile(path, []byte("[Resolve]\nDomains=~x.local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := pinnedIP(path); got != "" {
		t.Errorf("no DNS= line: pinnedIP = %q, want empty", got)
	}
}

// Nothing pinned and no address is the boot case: nothing to keep, nothing to
// withdraw, and nothing to ask.
func TestApply_UnknownAddressWithNothingPinnedIsQuiet(t *testing.T) {
	h := newHarness(t)
	h.cfg.probe = func(context.Context, string, string) error {
		t.Error("probed with nothing pinned")
		return nil
	}
	changed, err := Apply(context.Background(), h.cfg, TriggerStart)
	if changed || err != nil {
		t.Errorf("changed=%v err=%v, want a silent no-op", changed, err)
	}
}

// Withdrawing when there is nothing pinned is a no-op, not an error — otherwise
// every tick on a node that never had a drop-in would log a failure.
func TestApply_WithdrawIsQuietWhenNothingIsPinned(t *testing.T) {
	h, ns := connected(t, "192.168.1.181")
	ns.set(nsServFail)
	changed, err := Apply(context.Background(), h.cfg, TriggerTick)
	if changed || err != nil {
		t.Errorf("no pin to withdraw should be silent; changed=%v err=%v", changed, err)
	}
}

// The withdrawal message must distinguish a clean withdrawal from one whose
// reload failed — they need different operator responses, and both return an
// error so only the text tells them apart.
func TestWithdraw_ReloadFailureIsDistinguishable(t *testing.T) {
	h, ns := connected(t, "192.168.1.181")
	if _, err := Apply(context.Background(), h.cfg, TriggerTick); err != nil {
		t.Fatalf("seed Apply: %v", err)
	}
	ns.set(nsNXDomain)
	h.cfg.reload = func(context.Context) error { return errors.New("resolved is not running") }

	changed, err := Apply(context.Background(), h.cfg, TriggerTick)
	if !changed || err == nil {
		t.Fatalf("expected a reported withdrawal; changed=%v err=%v", changed, err)
	}
	if !strings.Contains(err.Error(), "reload failed") {
		t.Errorf("a failed reload must say so — the file is gone but resolved still has it loaded:\n%v", err)
	}
	if strings.Contains(err.Error(), "falls back to mDNS until this resolves") {
		t.Errorf("reported a clean withdrawal when the reload actually failed:\n%v", err)
	}
}

// ---- Run follows the bus, not the tick -----------------------------------

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for !cond() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func absent(path string) bool { _, err := os.Stat(path); return os.IsNotExist(err) }

// The bench timeline this exists for: agent up, bus connected seconds later,
// pin written five MINUTES later on the tick. With the trigger the pin follows
// the connection.
func TestRun_PinsOnBusConnectWithoutWaitingForATick(t *testing.T) {
	h := newHarness(t)
	ns := h.serve("192.168.1.181")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := h.run(ctx)

	// Boot case: nothing pinned, address unknown, and Run must not have
	// invented one — nor asked anyone, since there is no address to ask.
	time.Sleep(50 * time.Millisecond)
	if !absent(h.path()) {
		t.Fatal("Run wrote a pin before the bus had an address")
	}
	if got := ns.queries(); len(got) != 0 {
		t.Fatalf("Run asked %v before the bus had an address", got)
	}

	// The bus connects: onConnected fires the trigger. A change ends with
	// the reload, so that is what the test waits on; the file is then
	// settled and can be read.
	h.bus("192.168.1.181")
	h.cfg.Trigger.Fire()
	waitFor(t, "the pin after the bus connected", func() bool { return h.reloaded() == 1 })
	if pinnedIP(h.path()) != "192.168.1.181" {
		t.Errorf("pinned %q, want 192.168.1.181", pinnedIP(h.path()))
	}
	if got := ns.queries(); len(got) != 1 || got[0] != "rasputin.internal." {
		t.Errorf("the pin was written on %v, want one ask for rasputin.internal.", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run ignored context cancellation")
	}
}

// A re-dial that lands on a control plane that moved re-pins to where it is
// now; a re-fire with the same address does not restart resolved.
func TestRun_RepinsOnRedialToANewAddressAndIsQuietWhenUnchanged(t *testing.T) {
	h, _ := connected(t, "192.168.1.181")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.run(ctx)
	waitFor(t, "the first pin", func() bool { return h.reloaded() == 1 })
	if pinnedIP(h.path()) != "192.168.1.181" {
		t.Fatalf("pinned %q, want 192.168.1.181", pinnedIP(h.path()))
	}

	// nats reconnect to the same server: onConnected fires again.
	h.cfg.Trigger.Fire()
	time.Sleep(100 * time.Millisecond)
	if got := h.reloaded(); got != 1 {
		t.Errorf("an unchanged re-fire restarted resolved: reloads = %d, want 1", got)
	}
	// The control plane rebooted on a new lease; the client re-dialed it.
	h.serve("192.168.1.183")
	h.servers.gone("192.168.1.181")
	h.bus("192.168.1.183")
	h.cfg.Trigger.Fire()
	waitFor(t, "the re-pin to the new address", func() bool { return h.reloaded() == 2 })
	if pinnedIP(h.path()) != "192.168.1.183" {
		t.Errorf("pinned %q, want 192.168.1.183", pinnedIP(h.path()))
	}
}

// Agent restart: the previous process's pin is under /run, the bus has not
// dialed yet. Run's start pass asks the pinned server, it answers, and the
// pin stays — the node never leaves the mesh. Then the bus connects to the
// same address and nothing is rewritten.
func TestRun_StartKeepsTheAnsweringPinUntilTheBusConfirmsIt(t *testing.T) {
	h := newHarness(t)
	ns := h.serve("192.168.1.181")
	seedPin(t, h.cfg, "192.168.1.181")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.run(ctx)

	waitFor(t, "the start pass to ask the pinned server", func() bool { return len(ns.queries()) >= 1 })
	if pinnedIP(h.path()) != "192.168.1.181" {
		t.Fatal("pin withdrawn at start although its server answers")
	}
	h.bus("192.168.1.181")
	h.cfg.Trigger.Fire()
	waitFor(t, "the connect pass to ask again", func() bool { return len(ns.queries()) >= 2 })
	if pinnedIP(h.path()) != "192.168.1.181" {
		t.Error("pin changed when the bus connected to the address already pinned")
	}
	if got := h.reloaded(); got != 0 {
		t.Errorf("resolved restarted %d time(s) although nothing changed", got)
	}
}

// The control plane reboots: the bus drops, and for longer than any grace
// would have allowed. The pinned server keeps answering (a reboot is not a
// move, and the nameserver is back long before the bus is), so through the
// loss and every tick that goes by inside it, the pin stays. No clock is
// consulted, so there is no duration after which this test would fail — the
// ticks here are the proof: looks happen, each one asks, and none withdraws.
func TestRun_LostBusKeepsAnAnsweringPinThroughAnyNumberOfTicks(t *testing.T) {
	h, ns := connected(t, "192.168.1.181")
	h.cfg.Interval = 20 * time.Millisecond // many looks in a short test

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.run(ctx)
	waitFor(t, "the first pin", func() bool { return h.reloaded() == 1 })

	// The bus drops; the server still answers.
	h.bus("")
	h.cfg.Trigger.Lost()
	// Dozens of ticks with the bus down.
	time.Sleep(400 * time.Millisecond)
	if pinnedIP(h.path()) != "192.168.1.181" {
		t.Error("pin withdrawn while the bus was down and the server answering")
	}
	if got := len(ns.queries()); got < 10 {
		t.Errorf("only %d asks in 400 ms of 20 ms ticks — the looks are not happening", got)
	}
	if got := h.reloaded(); got != 1 {
		t.Errorf("reloads = %d, want 1 (only the original pin)", got)
	}
}

// The control plane is gone, not rebooting: the bus drops and the pinned
// address has nothing listening. The loss event itself withdraws the pin —
// not a later tick, not a timer.
func TestRun_LostBusWithdrawsWhenThePinnedServerIsGone(t *testing.T) {
	h, _ := connected(t, "192.168.1.181")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.run(ctx)
	waitFor(t, "the first pin", func() bool { return h.reloaded() == 1 })

	h.servers.gone("192.168.1.181")
	h.bus("")
	h.cfg.Trigger.Lost()
	waitFor(t, "the withdrawal on bus lost", func() bool { return h.reloaded() == 2 })
	if !absent(h.path()) {
		t.Error("resolved was restarted for the withdrawal but the drop-in is still there")
	}
}

// The safety net: the bus went quiet without a loss event we saw, and the
// pinned server — still up, still on :53 — has stopped serving the cluster's
// zone. The tick's ask finds it and withdraws. A connect probe would have
// kept this pin forever.
func TestRun_TickWithdrawsWhenThePinnedServerStopsServingTheZone(t *testing.T) {
	h := newHarness(t)
	ns := h.serve("192.168.1.181")
	h.cfg.Interval = 20 * time.Millisecond
	seedPin(t, h.cfg, "192.168.1.181")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.run(ctx)

	waitFor(t, "a few ticks", func() bool { return len(ns.queries()) >= 3 })
	if pinnedIP(h.path()) != "192.168.1.181" {
		t.Fatal("answering pin withdrawn before its server stopped serving the zone")
	}
	ns.set(nsNXDomain)
	waitFor(t, "the tick to withdraw the pin", func() bool { return h.reloaded() == 1 })
	if !absent(h.path()) {
		t.Error("resolved was restarted for the withdrawal but the drop-in is still there")
	}
}

func TestTrigger_FireAndLostNeverBlockAndNilIsSafe(t *testing.T) {
	var none *Trigger
	none.Fire() // must not panic
	none.Lost()
	if none.connectedC() != nil || none.lostC() != nil {
		t.Error("a nil Trigger must select as never-ready")
	}
	tr := NewTrigger()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			tr.Fire()
			tr.Lost()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Fire or Lost blocked with nobody receiving")
	}
	select {
	case <-tr.connectedC():
	default:
		t.Error("a fired Trigger had nothing to receive")
	}
	select {
	case <-tr.lostC():
	default:
		t.Error("a lost Trigger had nothing to receive")
	}
}
