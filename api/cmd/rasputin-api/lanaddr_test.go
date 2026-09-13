package main

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/lanaddr"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nameserver"
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
