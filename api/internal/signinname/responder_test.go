package signinname

import (
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/geekdojo/rasputin-control-plane/api/internal/lanaddr"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-995-01: three probes 250 ms apart, each an ANY question for the name with
// the unicast-response bit clear and our A records in Authority; a query
// during probing is not answered; nothing is announced until 250 ms after the
// third probe.
func TestProbing(t *testing.T) {
	g := newRig(t, snap(2, lease)).start()
	g.advance(100 * time.Millisecond)
	g.inject(query(testFQDN, dns.TypeA), otherSrc)
	g.advance(probeInterval*3 - 100*time.Millisecond - time.Millisecond)

	ss := g.conn().all()
	if len(ss) != 3 {
		t.Fatalf("sent %d messages before the win, want 3 probes: %v", len(ss), ss)
	}
	for i, s := range ss {
		if want := t0.Add(time.Duration(i) * probeInterval); !s.at.Equal(want) {
			t.Errorf("probe %d at %v, want %v", i, s.at.Sub(t0), want.Sub(t0))
		}
		m := s.msg
		if !isProbe(m) || m.Question[0].Name != testFQDN || m.Question[0].Qclass != dns.ClassINET {
			t.Errorf("probe %d = %v", i, m)
		}
		if got := aAddrs(m.Ns); !slices.Equal(got, []netip.Addr{lease}) {
			t.Errorf("probe %d Authority = %v, want our A record", i, got)
		}
	}
	if st := g.r.State(g.now); st.State != StateUnpublished || st.Cause != CauseProbing {
		t.Errorf("state while probing = %+v", st)
	}
	g.advance(time.Millisecond)
	ss = g.conn().all()
	if len(ss) != 4 || !isAnswer(ss[3].msg) || !ss[3].at.Equal(t0.Add(3*probeInterval)) {
		t.Fatalf("after the window: %d sends, last %v; want the first announcement at 750 ms", len(ss), ss[len(ss)-1])
	}
}

// TC-995-02: two announcements 1 s apart, QR and AA and the cache-flush bit,
// TTL 120, one A record per LinkIPs address, primary first; no link-local or
// IPv6 address.
func TestAnnouncing(t *testing.T) {
	in := []lanaddr.Addr{
		{IP: lease.AsSlice(), Link: "end0", Index: 2, Dynamic: true},
		{IP: fallbk.AsSlice(), Link: "end0", Index: 2},
		{IP: []byte{169, 254, 3, 4}, Link: "end0", Index: 2},
		{IP: netip.MustParseAddr("fe80::1").AsSlice(), Link: "end0", Index: 2},
	}
	g := newRig(t, lanaddr.Select(in)).start()
	g.publish()
	var ann []sent
	for _, s := range g.conn().all() {
		if s.msg.Response {
			ann = append(ann, s)
		}
	}
	if len(ann) != 2 || ann[1].at.Sub(ann[0].at) != announceInterval {
		t.Fatalf("announcements = %v, want two 1 s apart", ann)
	}
	for _, a := range ann {
		m := a.msg
		if !m.Response || !m.Authoritative {
			t.Errorf("flags: QR %v AA %v", m.Response, m.Authoritative)
		}
		if got := aAddrs(m.Answer); !slices.Equal(got, []netip.Addr{lease, fallbk}) {
			t.Errorf("rdata = %v, want lease then fallback", got)
		}
		for _, rr := range m.Answer {
			if rr.Header().Class != dns.ClassINET|cacheFlush || rr.Header().Ttl != 120 || rr.Header().Name != testFQDN {
				t.Errorf("record %v", rr)
			}
		}
	}
	g.advance(10 * time.Second)
	if n := len(g.conn().all()); n != 5 {
		t.Errorf("%d sends after announcing, want 3 probes and 2 announcements", n)
	}
}

// TC-995-03: only A and ANY for our name are answered (mixed case, trailing
// dot), on the group; <cid>.local, AAAA and other names never; no packet ever
// names <cid>.local; repeated queries within 1 s draw one answer.
func TestAnsweringOnlyOurName(t *testing.T) {
	g := newRig(t, snap(2, lease)).start()
	g.publish()
	g.advance(2 * time.Second)
	for _, c := range []struct {
		q    *dns.Msg
		want bool
	}{
		{query("SSO-Bench.Local.", dns.TypeA), true},
		{query(testFQDN, dns.TypeANY), true},
		{query(cidFQDN, dns.TypeA), false},
		{query(cidFQDN, dns.TypeANY), false},
		{query(testFQDN, dns.TypeAAAA), false},
		{query("printer.local.", dns.TypeA), false},
	} {
		before := len(g.conn().all())
		g.inject(c.q, otherSrc)
		got := len(g.conn().all()) - before
		if (got == 1) != c.want || got > 1 {
			t.Errorf("%v: %d answers, want answered=%v", c.q.Question[0], got, c.want)
		}
		if got == 1 {
			m := g.conn().all()[before].msg
			if !isAnswer(m) || !slices.Equal(aAddrs(m.Answer), []netip.Addr{lease}) {
				t.Errorf("answer %v", m)
			}
		}
		g.advance(multicastMinGap)
	}
	// Repeated queries within a second: one answer.
	before := len(g.conn().all())
	for i := 0; i < 5; i++ {
		g.inject(query(testFQDN, dns.TypeA), otherSrc)
		g.advance(150 * time.Millisecond)
	}
	if got := len(g.conn().all()) - before; got != 1 {
		t.Errorf("five queries within 750 ms drew %d answers, want 1", got)
	}
	g.advance(multicastMinGap)
	g.inject(query(testFQDN, dns.TypeA), otherSrc)
	if got := len(g.conn().all()) - before; got != 2 {
		t.Errorf("a query a second later drew no answer (%d total)", got)
	}
	for _, s := range g.conn().all() {
		for _, n := range namesIn(s.msg) {
			if n == cidFQDN {
				t.Errorf("a sent packet names %s: %v", cidFQDN, s.msg)
			}
		}
	}
}

// TC-995-04: a probe from another host is answered at once, before its next
// 250 ms slot, and is not a conflict. F-995-04: an answer to a probe may
// follow the last multicast after 250 ms, where an ordinary query waits 1 s.
func TestDefendingAgainstAProbe(t *testing.T) {
	g := newRig(t, snap(2, lease)).start()
	g.publish()
	g.advance(2 * time.Second) // no multicast in the last second
	before := len(g.conn().all())
	g.inject(otherProbe(other), otherSrc)
	ss := g.conn().from(before)
	if len(ss) != 1 || !isAnswer(ss[0].msg) || !ss[0].at.Equal(g.now) {
		t.Fatalf("probe drew %v, want one answer at once", ss)
	}
	if st := g.r.State(g.now); st.State != StateOK {
		t.Errorf("state after a probe = %+v, want ok", st)
	}

	// 300 ms after that multicast: a query is held back, a probe is answered.
	g.advance(300 * time.Millisecond)
	before = len(g.conn().all())
	g.inject(query(testFQDN, dns.TypeA), otherSrc)
	if n := len(g.conn().all()) - before; n != 0 {
		t.Errorf("a query 300 ms after the last multicast drew %d answers, want 0", n)
	}
	g.inject(otherProbe(other), otherSrc)
	if n := len(g.conn().all()) - before; n != 1 {
		t.Errorf("a probe 300 ms after the last multicast drew %d answers, want 1", n)
	}
	// And 100 ms after that one, not even a probe.
	g.advance(100 * time.Millisecond)
	g.inject(otherProbe(other), otherSrc)
	if n := len(g.conn().all()) - before; n != 1 {
		t.Errorf("a probe 100 ms after the last multicast was answered (%d)", n)
	}
}

// conflictAlert is the alert TC-995-05 and TC-995-06 expect.
func conflictAlert(since time.Time) proto.Alert {
	title := "Another device on your network is using this system's sign-in address, sso-bench.local, at 192.168.1.4. Turn that device off or rename it."
	return proto.Alert{ID: AlertConflict, Severity: proto.AlertCrit, Source: proto.AlertSourceSecurity,
		Title: title, Detail: title, Since: since}
}

func assertConflict(t *testing.T, g *rig, since time.Time) {
	t.Helper()
	if st := g.r.State(g.now); st.State != StateConflict || st.Owner != other {
		t.Errorf("state = %+v, want conflict owned by %v", st, other)
	}
	if got := g.r.Alerts(g.now); len(got) != 1 || got[0] != conflictAlert(since) {
		t.Errorf("Alerts = %+v\nwant %+v", got, conflictAlert(since))
	}
	recs := g.logs.Matching(slog.LevelWarn, "sign-in name conflict")
	if len(recs) != 1 {
		t.Fatalf("%d conflict WARN records, want 1", len(recs))
	}
	if v, _ := logkittest.Attr(recs[0], "owner"); v != other.String() {
		t.Errorf("owner field %q", v)
	}
	if v, _ := logkittest.Attr(recs[0], "event"); v != "signinname.conflict" {
		t.Errorf("event field %q", v)
	}
	if v, _ := logkittest.Attr(recs[0], "component"); v != "signinname" {
		t.Errorf("component field %q", v)
	}
}

// assertSilent checks that queries draw nothing and nothing is renamed.
func assertSilent(t *testing.T, g *rig, from int) {
	t.Helper()
	for i := 0; i < 3; i++ {
		g.advance(2 * time.Second)
		g.inject(query(testFQDN, dns.TypeA), otherSrc)
	}
	for _, s := range g.conn().from(from) {
		if s.msg.Response {
			t.Errorf("sent a response while in conflict: %v", s.msg)
		}
		for _, n := range namesIn(s.msg) {
			if n != testFQDN {
				t.Errorf("sent a packet for another name (a rename?): %v", s.msg)
			}
		}
	}
}

// TC-995-05: a conflicting response during probing stops it: no
// announcement, no answer, no rename, the conflict alert and one WARN.
func TestConflictDuringProbing(t *testing.T) {
	g := newRig(t, snap(2, lease)).start()
	g.advance(probeInterval)
	g.inject(claim(other, 120), otherSrc)
	at := g.now
	from := len(g.conn().all())
	assertSilent(t, g, from)
	assertConflict(t, g, at)
}

// TC-995-06: the same after publishing.
func TestConflictAfterPublishing(t *testing.T) {
	g := newRig(t, snap(2, lease)).start()
	g.publish()
	g.advance(2 * time.Second)
	g.inject(claim(other, 120), otherSrc)
	at := g.now
	assertSilent(t, g, len(g.conn().all()))
	assertConflict(t, g, at)
}

// TC-995-07: identical rdata, our own looped-back packet and a source port
// other than 5353 are not conflicts.
func TestNotAConflict(t *testing.T) {
	for name, c := range map[string]struct {
		m   *dns.Msg
		src netip.AddrPort
	}{
		"identical rdata":    {claim(lease, 120), otherSrc},
		"our own address":    {claim(other, 120), netip.AddrPortFrom(lease, 5353)},
		"not from port 5353": {claim(other, 120), netip.AddrPortFrom(other, 40000)},
	} {
		t.Run(name, func(t *testing.T) {
			g := newRig(t, snap(2, lease)).start()
			g.publish()
			g.advance(2 * time.Second)
			g.inject(c.m, c.src)
			if st := g.r.State(g.now); st.State != StateOK {
				t.Fatalf("state = %+v, want ok", st)
			}
			before := len(g.conn().all())
			g.inject(query(testFQDN, dns.TypeA), otherSrc)
			if n := len(g.conn().all()) - before; n != 1 {
				t.Errorf("query after it drew %d answers, want 1", n)
			}
		})
	}
}

// TC-995-08: the owner's goodbye heals the conflict with no restart: probes,
// announcements and answers again, and the alert clears.
func TestHealOnGoodbye(t *testing.T) {
	g := newRig(t, snap(2, lease)).start()
	g.publish()
	g.inject(claim(other, 120), otherSrc)
	g.advance(5 * time.Second)
	from := len(g.conn().all())
	g.inject(claim(other, 0), otherSrc)
	if n := count(g.conn().from(from), isProbe); n != 1 {
		t.Fatalf("%d probes right after the goodbye, want the first", n)
	}
	if recs := g.logs.Matching(slog.LevelInfo, "re-probing"); len(recs) != 1 {
		t.Errorf("%d re-probing records", len(recs))
	} else if v, _ := logkittest.Attr(recs[0], "how"); v != "goodbye" {
		t.Errorf("how = %q", v)
	}
	g.publish()
	if n := count(g.conn().from(from), isProbe); n != 3 {
		t.Errorf("%d probes after the goodbye, want 3", n)
	}
	if got := g.r.Alerts(g.now); len(got) != 0 {
		t.Errorf("Alerts after healing = %+v", got)
	}
	g.advance(2 * time.Second)
	before := len(g.conn().all())
	g.inject(query(testFQDN, dns.TypeA), otherSrc)
	if n := len(g.conn().all()) - before; n != 1 {
		t.Errorf("not answering after healing (%d)", n)
	}
	if len(g.conns) != 1 || len(g.opens) != 1 {
		t.Errorf("healing reopened the socket: %d opens", len(g.opens))
	}
}

// TC-995-09: with no traffic, the §5.2 queries go out at 80, 85, 90 and 95 %
// of the owner's TTL, and the responder re-probes at 100 %; when the owner
// answers the first query, it stays in conflict and sends no probe. F-995-03:
// a TTL of 2^31-1 is believed for 120 s.
func TestHealOnExpiry(t *testing.T) {
	const ttl = 100 * time.Second
	maint := func(g *rig, from int, heard time.Time) []time.Duration {
		var at []time.Duration
		for _, s := range g.conn().from(from) {
			if isMaintQuery(s.msg) {
				if s.msg.Question[0].Name != testFQDN || s.msg.Question[0].Qclass != dns.ClassINET {
					t.Errorf("maintenance query %v", s.msg.Question[0])
				}
				at = append(at, s.at.Sub(heard))
			}
		}
		return at
	}

	t.Run("unanswered", func(t *testing.T) {
		g := newRig(t, snap(2, lease)).start()
		g.publish()
		g.inject(claim(other, uint32(ttl/time.Second)), otherSrc)
		heard, from := g.now, len(g.conn().all())
		g.advance(ttl - time.Millisecond)
		want := []time.Duration{80 * time.Second, 85 * time.Second, 90 * time.Second, 95 * time.Second}
		if got := maint(g, from, heard); !slices.Equal(got, want) {
			t.Errorf("maintenance queries at %v, want %v", got, want)
		}
		if n := count(g.conn().from(from), isProbe); n != 0 {
			t.Errorf("probed before the record expired")
		}
		g.advance(time.Millisecond)
		ss := g.conn().from(from)
		if last := ss[len(ss)-1]; !isProbe(last.msg) || !last.at.Equal(heard.Add(ttl)) {
			t.Errorf("at T: %v, want a probe at %v", last, heard.Add(ttl))
		}
		g.publish()
		if v, _ := logkittest.Attr(g.logs.Matching(slog.LevelInfo, "re-probing")[0], "how"); v != "expired" {
			t.Errorf("how = %q", v)
		}
	})

	t.Run("owner answers", func(t *testing.T) {
		g := newRig(t, snap(2, lease)).start()
		g.publish()
		g.inject(claim(other, uint32(ttl/time.Second)), otherSrc)
		first, from := g.now, len(g.conn().all())
		g.advance(80 * time.Second)
		g.inject(claim(other, uint32(ttl/time.Second)), otherSrc)
		g.advance(first.Add(ttl).Sub(g.now) + time.Second)
		if n := count(g.conn().from(from), isProbe); n != 0 {
			t.Errorf("%d probes though the owner answered", n)
		}
		if st := g.r.State(g.now); st.State != StateConflict {
			t.Errorf("state = %+v, want conflict", st)
		}
	})

	t.Run("huge TTL capped", func(t *testing.T) {
		g := newRig(t, snap(2, lease)).start()
		g.publish()
		g.inject(claim(other, 1<<31-1), otherSrc)
		heard, from := g.now, len(g.conn().all())
		g.advance(maxOwnerTTL)
		if got := maint(g, from, heard); len(got) != 4 || got[0] != 96*time.Second {
			t.Errorf("maintenance queries at %v, want four from 96 s", got)
		}
		ss := g.conn().from(from)
		if last := ss[len(ss)-1]; !isProbe(last.msg) || !last.at.Equal(heard.Add(maxOwnerTTL)) {
			t.Errorf("no re-probe at 120 s: %v", last)
		}
	})
}

// TC-995-11: address changes.
func TestAddressChanges(t *testing.T) {
	g := newRig(t, snap(2, lease)).start()
	g.publish()
	g.advance(2 * time.Second)

	// (a) Same link, new address set: announce it, no probe.
	from := len(g.conn().all())
	g.setAddrs(snap(2, lease, fallbk))
	g.advance(2 * time.Second)
	ss := g.conn().from(from)
	if count(ss, isProbe) != 0 || count(ss, isAnswer) != 2 {
		t.Fatalf("(a) sent %v, want two announcements and no probe", ss)
	}
	if got := aAddrs(ss[0].msg.Answer); !slices.Equal(got, []netip.Addr{lease, fallbk}) || ss[0].msg.Answer[0].Header().Class != dns.ClassINET|cacheFlush {
		t.Errorf("(a) announced %v", ss[0].msg)
	}

	// (b) The primary moves to another link: close, Open the new index, probe, publish.
	old := g.conn()
	g.setAddrs(snap(5, other))
	if !old.isClosed() || !slices.Equal(g.opens, []int{2, 5}) {
		t.Fatalf("(b) old closed %v, opens %v", old.isClosed(), g.opens)
	}
	g.publish()
	if count(g.conn().all(), isProbe) != 3 {
		t.Errorf("(b) did not probe on the new link")
	}

	// (c) No usable address: closed, unpublished "no LAN address", alerted.
	cur := g.conn()
	g.setAddrs(lanaddr.Snapshot{})
	if !cur.isClosed() {
		t.Error("(c) socket left open")
	}
	st := g.r.State(g.now)
	if st.State != StateUnpublished || st.Cause != CauseNoAddress {
		t.Errorf("(c) state %+v", st)
	}
	if a := g.r.Alerts(g.now); len(a) != 1 || a[0].ID != AlertUnpublished || a[0].Detail != "The control plane has no LAN address." {
		t.Errorf("(c) alerts %+v", a)
	}
	if len(g.logs.Matching(slog.LevelWarn, "no LAN address")) != 1 || len(g.logs.Matching(slog.LevelError, "read error")) != 0 {
		t.Errorf("(c) logs:\n%s", g.logs.Text())
	}

	// (d) An address returns: Open, probe, publish, alert cleared.
	g.setAddrs(snap(2, lease))
	if !slices.Equal(g.opens, []int{2, 5, 2}) {
		t.Fatalf("(d) opens %v", g.opens)
	}
	g.publish()
	if a := g.r.Alerts(g.now); len(a) != 0 {
		t.Errorf("(d) alerts %+v", a)
	}
}

// TC-995-12: a published responder says goodbye once, TTL 0, then closes;
// probing or conceding, it sends nothing.
func TestGoodbyeOnStop(t *testing.T) {
	g := newRig(t, snap(2, lease)).start()
	g.publish()
	from := len(g.conn().all())
	g.r.shutdown(g.now)
	ss := g.conn().from(from)
	if len(ss) != 1 || !isGoodbye(ss[0].msg) || !slices.Equal(aAddrs(ss[0].msg.Answer), []netip.Addr{lease}) {
		t.Fatalf("on stop sent %v, want one goodbye", ss)
	}
	for _, rr := range ss[0].msg.Answer {
		if rr.Header().Ttl != 0 {
			t.Errorf("goodbye TTL %d", rr.Header().Ttl)
		}
	}
	if !g.conn().isClosed() || len(g.logs.Matching(slog.LevelInfo, "goodbye sent")) != 1 {
		t.Error("not closed, or no goodbye record")
	}

	for name, setup := range map[string]func(*rig){
		"probing":  func(g *rig) { g.advance(probeInterval) },
		"conflict": func(g *rig) { g.publish(); g.inject(claim(other, 120), otherSrc) },
	} {
		t.Run(name, func(t *testing.T) {
			g := newRig(t, snap(2, lease)).start()
			setup(g)
			from := len(g.conn().all())
			g.r.shutdown(g.now)
			if ss := g.conn().from(from); len(ss) != 0 {
				t.Errorf("sent %v on stop", ss)
			}
		})
	}
}

// TC-995-14: Open fails: nothing sent, unpublished "open failed", its alert,
// and one ERROR naming the link and the error.
func TestOpenFailure(t *testing.T) {
	g := newRig(t, snap(2, lease))
	g.openErr = errBoom
	g.start()
	if len(g.conns) != 0 {
		t.Fatal("a socket was made")
	}
	if st := g.r.State(g.now); st.State != StateUnpublished || st.Cause != CauseOpenFailed {
		t.Errorf("state %+v", st)
	}
	a := g.r.Alerts(g.now)
	if len(a) != 1 || a[0].Detail != "The sign-in name responder could not open its network socket." ||
		a[0].Title != "Sign-in isn't reachable: this system's sign-in address, sso-bench.local, is not being published." {
		t.Errorf("alerts %+v", a)
	}
	recs := g.logs.AtLevel(slog.LevelError)
	if len(recs) != 1 {
		t.Fatalf("%d ERROR records", len(recs))
	}
	if v, _ := logkittest.Attr(recs[0], "link"); v != "end0" {
		t.Errorf("link %q", v)
	}
	if v, _ := logkittest.Attr(recs[0], "err"); !strings.Contains(v, "boom") {
		t.Errorf("err %q", v)
	}
}

// A malformed packet is dropped at DEBUG and changes nothing.
func TestMalformedPacketIgnored(t *testing.T) {
	g := newRig(t, snap(2, lease)).start()
	g.publish()
	g.injectRaw([]byte{1, 2, 3}, otherSrc)
	if st := g.r.State(g.now); st.State != StateOK {
		t.Errorf("state %+v", st)
	}
	if len(g.logs.Matching(slog.LevelDebug, "malformed")) != 1 {
		t.Error("no DEBUG record for the malformed packet")
	}
}

// New refuses a missing collaborator.
func TestNewRefusesMissingCollaborators(t *testing.T) {
	log, _ := logkittest.New()
	ok := Config{Name: testHost, Addrs: &fakeAddrs{}, Open: func(int) (Conn, error) { return nil, errBoom }, Clock: SystemClock{}, Log: log}
	for name, mut := range map[string]func(*Config){
		"name": func(c *Config) { c.Name = " " }, "addrs": func(c *Config) { c.Addrs = nil },
		"open": func(c *Config) { c.Open = nil }, "clock": func(c *Config) { c.Clock = nil }, "log": func(c *Config) { c.Log = nil },
	} {
		c := ok
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
