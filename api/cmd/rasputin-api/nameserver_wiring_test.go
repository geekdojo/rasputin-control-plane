package main

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nameserver"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// sourceName labels one of controlPlaneSources' sources for a failure message.
func sourceName(i int, s nameserver.Source) string {
	return fmt.Sprintf("controlPlaneSources[%d] %T", i, s)
}

// servedNS is a real nameserver on loopback over srcs; it returns the UDP
// address to ask.
func servedNS(t *testing.T, zone string, srcs []nameserver.Source) string {
	t.Helper()
	srv := nameserver.NewServer(func() net.IP { return net.IPv4(127, 0, 0, 1) }, 0, nameserver.NewResponder(zone, srcs...))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	return srv.UDPAddr()
}

func askNS(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	m, _, err := (&dns.Client{Net: "udp", Timeout: 3 * time.Second}).Exchange(req, addr)
	if err != nil {
		t.Fatalf("%s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return m
}

func wantA(t *testing.T, m *dns.Msg, name string, ip net.IP) {
	t.Helper()
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Errorf("%s A: rcode=%s answers=%d, want one A", name, dns.RcodeToString[m.Rcode], len(m.Answer))
		return
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || !a.A.Equal(ip) {
		t.Errorf("%s A = %v, want %v", name, m.Answer, ip)
	}
}

func benchTable(t *testing.T) doors.Table {
	t.Helper()
	table, err := doors.New(rigCID)
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func notWithheld() bool { return false }

// TC-997-07: every name the home door is reached by, and <cid>.local, answers
// A at the LAN address; AAAA and HTTPS are NODATA (NOERROR, no answers, the
// SOA, authoritative), never REFUSED or NXDOMAIN.
func TestControlPlaneSources_AnswersEveryHomeDoorName(t *testing.T) {
	zone := proto.BaseDomain(rigCID)
	table := benchTable(t)
	lan := func() net.IP { return rigLAN }
	addr := servedNS(t, zone, controlPlaneSources(zone, rigCID+".local", table, true, lan, notWithheld))

	for _, name := range []string{table.Home.Host, table.Home.RPID, rigCID + ".local"} {
		wantA(t, askNS(t, addr, name, dns.TypeA), name, rigLAN)
		for _, qtype := range []uint16{dns.TypeAAAA, dns.TypeHTTPS} {
			m := askNS(t, addr, name, qtype)
			what := name + " " + dns.TypeToString[qtype]
			if m.Rcode != dns.RcodeSuccess {
				t.Errorf("%s: rcode=%s, want NOERROR (NODATA)", what, dns.RcodeToString[m.Rcode])
			}
			if len(m.Answer) != 0 {
				t.Errorf("%s: %d answers, want none", what, len(m.Answer))
			}
			if len(m.Ns) != 1 {
				t.Errorf("%s: authority %v, want one SOA", what, m.Ns)
			} else if _, ok := m.Ns[0].(*dns.SOA); !ok {
				t.Errorf("%s: authority %T, want SOA", what, m.Ns[0])
			}
			if !m.Authoritative {
				t.Errorf("%s: AA not set", what)
			}
		}
	}
}

// TC-997-08: withholding the app door leaves the home door's record in place.
func TestControlPlaneSources_AppDoorWithheldKeepsTheHomeRecord(t *testing.T) {
	zone := proto.BaseDomain(rigCID)
	lan := func() net.IP { return rigLAN }
	addr := servedNS(t, zone, controlPlaneSources(zone, rigCID+".local", benchTable(t), true, lan, func() bool { return true }))

	if m := askNS(t, addr, "signin.bench.internal", dns.TypeA); m.Rcode != dns.RcodeNameError {
		t.Errorf("signin.bench.internal A: rcode=%s, want NXDOMAIN while withheld", dns.RcodeToString[m.Rcode])
	}
	wantA(t, askNS(t, addr, "sso-bench.local", dns.TypeA), "sso-bench.local", rigLAN)
}

// TC-997-09: with the doors off there is no sso- record, <cid>.local is
// unchanged, and sso-<cid>.local is off-zone and unserved: REFUSED, as before.
func TestControlPlaneSources_DoorsOffServesNoHomeName(t *testing.T) {
	zone := proto.BaseDomain(rigCID)
	lan := func() net.IP { return rigLAN }
	srcs := controlPlaneSources(zone, rigCID+".local", doors.Table{}, false, lan, notWithheld)
	for i, s := range srcs {
		for k := range s.Records() {
			if strings.HasPrefix(k, proto.SignInHomePrefix) {
				t.Errorf("%s serves %s with the doors off", sourceName(i, s), k)
			}
		}
	}
	addr := servedNS(t, zone, srcs)
	wantA(t, askNS(t, addr, "bench.local", dns.TypeA), "bench.local", rigLAN)
	if m := askNS(t, addr, "sso-bench.local", dns.TypeA); m.Rcode != dns.RcodeRefused {
		t.Errorf("sso-bench.local A: rcode=%s, want REFUSED", dns.RcodeToString[m.Rcode])
	}
}

// TC-997-10: the name #443's invariant (TC-983-06) enumerates from
// controlPlaneSources includes sso-bench.local, served the home door's
// one-name leaf; and the rig's nameserver, built from the same list, answers it.
func TestControlPlaneSources_HomeNameIsOnItsLeafAndAnswered(t *testing.T) {
	r := newDoorRig(t, nil, nil)
	r.start()
	lan := func() net.IP { return rigLAN }
	zone := proto.BaseDomain(rigCID)
	var names []string
	for _, s := range controlPlaneSources(zone, rigCID+".local", r.table, true, lan, r.appDoor.withheld) {
		for k := range s.Records() {
			names = append(names, strings.TrimSuffix(k, "."))
		}
	}
	if !slices.Contains(names, "sso-bench.local") {
		t.Fatalf("controlPlaneSources answers %v, want sso-bench.local among them", names)
	}
	leaf, cerr, _ := doorHandshake(t, r.sni(), "sso-bench.local")
	if cerr != nil || !slices.Equal(leaf.DNSNames, []string{"sso-bench.local"}) {
		t.Errorf("sso-bench.local leaf = %v (err %v), want DNSNames [sso-bench.local]", leaf, cerr)
	}
	if bad := uncoveredNames(t, r.sni(), names); len(bad) != 0 {
		t.Errorf("names answered for the control plane with no SAN on their leaf: %v", bad)
	}
	wantA(t, r.query("sso-bench.local"), "sso-bench.local", rigLAN)
}
