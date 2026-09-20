package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/lanaddr"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nameserver"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// addrSource is an injectable lanaddr.Source standing in for the kernel.
type addrSource struct {
	mu    sync.Mutex
	addrs []lanaddr.Addr
	ch    chan struct{}
}

func newAddrSource(addrs ...lanaddr.Addr) *addrSource {
	return &addrSource{addrs: addrs, ch: make(chan struct{}, 1)}
}

func (s *addrSource) Subscribe(context.Context) (<-chan struct{}, error) { return s.ch, nil }

func (s *addrSource) List() ([]lanaddr.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]lanaddr.Addr(nil), s.addrs...), nil
}

func (s *addrSource) set(addrs ...lanaddr.Addr) {
	s.mu.Lock()
	s.addrs = addrs
	s.mu.Unlock()
	s.ch <- struct{}{}
}

var (
	benchFallback  = lanaddr.Addr{IP: net.ParseIP("192.168.1.2"), Link: "end0", Index: 2}
	benchLease     = lanaddr.Addr{IP: net.ParseIP("192.168.1.226"), Link: "end0", Index: 2, Dynamic: true}
	benchLinkLocal = lanaddr.Addr{IP: net.ParseIP("169.254.17.78"), Link: "end0", Index: 2}
	benchTailnet   = lanaddr.Addr{IP: net.ParseIP("100.64.0.1"), Link: "tailscale0", Index: 9}
)

// syncRecorder is a nameserverSyncer that records each wanted set, as the
// nameserver's Listeners would receive it.
type syncRecorder struct {
	mu    sync.Mutex
	calls []string
	cond  chan struct{}
	bound []string
}

func (r *syncRecorder) Sync(ips []net.IP) (nameserver.SyncResult, error) {
	var ss []string
	for _, ip := range ips {
		ss = append(ss, ip.String())
	}
	r.mu.Lock()
	var res nameserver.SyncResult
	prev := strings.Join(r.bound, ",")
	r.bound = ss
	if prev != strings.Join(ss, ",") {
		res.Started = ss // close enough for the log path; the set is what's under test
	}
	res.Bound = ss
	r.calls = append(r.calls, strings.Join(ss, ","))
	r.mu.Unlock()
	r.cond <- struct{}{}
	return res, nil
}

func (r *syncRecorder) waitFor(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		r.mu.Lock()
		if len(r.calls) >= n {
			out := append([]string(nil), r.calls...)
			r.mu.Unlock()
			return out
		}
		r.mu.Unlock()
		select {
		case <-r.cond:
		case <-deadline:
			t.Fatalf("waited for %d Sync calls", n)
		}
	}
}

// TestFollowLANNameserver is the event-driven lifecycle end to end from an
// address source to the nameserver's listener set: no address at API start,
// the no-DHCP fallback appears (nameserver starts), a late lease joins it and the
// fallback is released (rebind), and the address goes (nameserver stops). This
// is the #431 bench sequence that needed an api restart.
func TestFollowLANNameserver(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := newAddrSource(benchLinkLocal)
	w := lanaddr.NewWatcher(src)
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	rec := &syncRecorder{cond: make(chan struct{}, 16)}
	followLANNameserver(w, rec, "e12bench.internal")

	// One change at a time: the source coalesces back-to-back events into one
	// re-list (by design), which would skip the intermediate states under test.
	rec.waitFor(t, 1)
	src.set(benchFallback, benchLinkLocal, benchTailnet)
	rec.waitFor(t, 2)
	src.set(benchFallback, benchLease)
	rec.waitFor(t, 3)
	src.set(benchLease)
	rec.waitFor(t, 4)
	src.set(benchLinkLocal)
	got := rec.waitFor(t, 5)

	want := []string{
		"",                          // start: nothing to bind
		"192.168.1.2",               // fallback: start (tailnet ignored)
		"192.168.1.226,192.168.1.2", // late lease beside the fallback
		"192.168.1.226",             // fallback released: rebind
		"",                          // address gone: stop
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("Sync calls = %q, want %q", got, want)
	}
}

// followLANPrimary must run once at subscribe and then only when the PRIMARY
// changes: the fallback joining or leaving beside a lease is not a new address
// for the firewall's DNS forward or this node's inventory row.
func TestFollowLANPrimary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := newAddrSource()
	w := lanaddr.NewWatcher(src)
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var seen []string
	cond := make(chan struct{}, 16)
	followLANPrimary(w, func(ip net.IP) {
		mu.Lock()
		seen = append(seen, ipString(ip))
		mu.Unlock()
		cond <- struct{}{}
	})
	wait := func(n int) []string {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			mu.Lock()
			if len(seen) >= n {
				out := append([]string(nil), seen...)
				mu.Unlock()
				return out
			}
			mu.Unlock()
			select {
			case <-cond:
			case <-deadline:
				t.Fatalf("waited for %d calls, saw %v", n, seen)
			}
		}
	}

	src.set(benchFallback)
	wait(2)
	src.set(benchLease, benchFallback) // primary moves to the lease
	wait(3)
	src.set(benchLease) // fallback released: primary unchanged, no call
	src.set(benchLease, benchTailnet)
	src.set() // gone
	got := wait(4)
	want := []string{"", "192.168.1.2", "192.168.1.226", ""}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("primary calls = %q, want %q", got, want)
	}
}

// TestAPILeaf_FollowsLANAddress: the leaf served per handshake carries the
// address it was loaded for, and a new address swaps in a leaf with the new IP
// SAN without restarting anything.
func TestAPILeaf_FollowsLANAddress(t *testing.T) {
	dir := t.TempDir()
	ca, err := mesh.EnsureMeshCA(dir, "test")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	mints := 0
	leaf := &apiLeaf{mint: func(ip net.IP) (mesh.LeafPaths, error) {
		mints++
		return ensureAPILeaf(ca, dir, ip)
	}}
	if _, err := leaf.getCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("getCertificate before load should fail, not serve nothing")
	}

	hasIP := func(want string) bool {
		t.Helper()
		c, err := leaf.getCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range c.Leaf.IPAddresses {
			if ip.String() == want {
				return true
			}
		}
		return false
	}

	if err := leaf.load(net.ParseIP("192.168.1.2")); err != nil {
		t.Fatal(err)
	}
	if !hasIP("192.168.1.2") {
		t.Fatal("leaf missing the fallback's IP SAN")
	}
	if err := leaf.load(net.ParseIP("192.168.1.2")); err != nil || mints != 1 {
		t.Fatalf("same address re-minted: mints=%d err=%v", mints, err)
	}
	if err := leaf.load(net.ParseIP("192.168.1.226")); err != nil {
		t.Fatal(err)
	}
	if !hasIP("192.168.1.226") || hasIP("192.168.1.2") {
		t.Fatal("leaf did not move to the lease's IP SAN")
	}
}

// TestDNSForward_FirewallRegistrationSubmits wires the real inventory service's
// registration path to the hook main installs: the firewall agent registering
// (first time, and again on reconnect) submits firewall.dns_forward; other roles
// do not.
func TestDNSForward_FirewallRegistrationSubmits(t *testing.T) {
	ctx := context.Background()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	store, err := inventory.OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	submitted := make(chan string, 8)
	svc := inventory.NewService(store, nc)
	svc.SetOnRegistered(dnsForwardOnFirewallRegistration(func(reason string) { submitted <- reason }))
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Stop)

	register := func(id string, role proto.NodeRole) {
		t.Helper()
		b, _ := json.Marshal(proto.NodeRegisteredEvt{NodeID: id, Role: role, Hostname: id})
		if err := nc.Publish(proto.NodeRegisteredSubject(id), b); err != nil {
			t.Fatal(err)
		}
		_ = nc.Flush()
	}
	expect := func(what string) {
		t.Helper()
		select {
		case reason := <-submitted:
			if reason != "firewall-registered" {
				t.Fatalf("%s: submitted with reason %q", what, reason)
			}
		case <-time.After(2 * time.Second): // bounds the test only
			t.Fatalf("%s: no dns_forward submission", what)
		}
	}

	register("cp-firewall1", proto.RoleFirewall)
	expect("firewall first registration")
	register("cp-firewall1", proto.RoleFirewall)
	expect("firewall reconnect")

	// Compute and controlplane registrations submit nothing. A firewall one
	// after them proves they were processed (the bus delivers in order) rather
	// than still pending.
	register("cp-compute1", proto.RoleCompute)
	register("cp-1", proto.RoleControlPlane)
	register("cp-firewall1", proto.RoleFirewall)
	expect("firewall after other roles")
	select {
	case reason := <-submitted:
		t.Fatalf("a non-firewall registration submitted dns_forward (%q)", reason)
	default:
	}
}

// Nothing re-submits firewall.dns_forward on a timer: the fixed schedule has no
// entry for it, and the reconcile the old tick shared an interval with is still
// there, unchanged.
func TestReconcileEntries_NoDNSForwardTick(t *testing.T) {
	entries := reconcileEntries(5*time.Minute, 5*time.Minute, 5*time.Minute, 24*time.Hour)
	kinds := map[string]scheduler.Entry{}
	for _, e := range entries {
		kinds[e.Kind] = e
	}
	if _, ok := kinds["firewall.dns_forward"]; ok {
		t.Fatal("firewall.dns_forward is back on a timer; it must run on facts only (#431)")
	}
	fw, ok := kinds["firewall.reconcile"]
	if !ok || fw.Interval != 5*time.Minute || fw.InitialDelay != 30*time.Second {
		t.Fatalf("firewall.reconcile entry = %+v (present %v), want it unchanged", fw, ok)
	}
	for _, k := range []string{"apps.reconcile", "mesh.reconcile", mesh.LeafSweepKind} {
		if _, ok := kinds[k]; !ok {
			t.Errorf("%s missing from the schedule", k)
		}
	}
	// Leaf renewal has ONE driver. apps.leaf_rotate is still a workflow — the
	// sweep submits it — but a tick of its own would be a second place to look
	// when a certificate lapses.
	if _, ok := kinds["apps.leaf_rotate"]; ok {
		t.Error("apps.leaf_rotate has its own tick again; the leaf sweep is the one driver")
	}
}
