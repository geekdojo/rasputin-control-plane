package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/geekdojo/rasputin-control-plane/api/internal/lanaddr"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nameserver"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The functions here connect the control plane's LAN address (package lanaddr)
// to each thing in the api that derives from it, so that every one of them
// follows a change as it happens (geekdojo/geekdojo-brain#431). Each is a
// lanaddr.Watcher subscriber: called once on subscribe with the current
// snapshot, then on every change, serialized.

// ipString renders an address for the plain-string consumers, "" for none.
func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// nameserverSyncer is the part of *nameserver.Listeners the follower drives.
type nameserverSyncer interface {
	Sync(ips []net.IP) (nameserver.SyncResult, error)
}

// followLANNameserver keeps the cluster nameserver listening on every usable
// address on the primary LAN link: started when the first appears, rebound when
// they change, stopped when none remain. It replaces a single bind at api start,
// which never happened on a control plane that booted without DHCP and never
// moved on one whose lease did.
func followLANNameserver(w *lanaddr.Watcher, ls nameserverSyncer, zone string) {
	w.Subscribe(func(prev, next lanaddr.Snapshot) {
		res, err := ls.Sync(next.LinkIPs())
		if err != nil {
			// Not retried on a timer: the next address event syncs again.
			log.Printf("rasputin-api: nameserver bind (%v) — %s may not resolve via the CP on every LAN address", err, zone)
		}
		// A none-to-none call only happens as the subscribe-time replay, and the
		// start-up state is worth one line either way.
		if !res.Changed() && (len(prev.Usable) > 0 || len(next.Usable) > 0) {
			return
		}
		if len(res.Bound) > 0 {
			log.Printf("rasputin-api: nameserver authoritative for %s on %s (udp+tcp)", zone, strings.Join(res.Bound, ", "))
			return
		}
		// Worded as waiting, not as giving up, because it is: the next address
		// event starts it.
		log.Printf("rasputin-api: nameserver not listening: no usable LAN IPv4 — %s won't resolve via the CP until one appears", zone)
	})
}

// followLANPrimary calls fn with the primary address whenever it differs from
// the last one fn saw, including once for the address at subscribe time. It is
// for consumers that care about the primary alone, so a second address coming
// and going on the link does not re-run them.
func followLANPrimary(w *lanaddr.Watcher, fn func(ip net.IP)) {
	var last string
	seen := false
	w.Subscribe(func(_, next lanaddr.Snapshot) {
		ip := next.PrimaryIP()
		if seen && ipString(ip) == last {
			return
		}
		seen, last = true, ipString(ip)
		fn(ip)
	})
}

// dnsForwardOnFirewallRegistration returns the inventory registration hook that
// re-runs firewall.dns_forward when the firewall node's agent registers — which
// it does on every bus (re)connect. Other roles' registrations do not touch the
// forward and do not trigger it.
func dnsForwardOnFirewallRegistration(submit func(reason string)) func(context.Context, *proto.Node) {
	return func(_ context.Context, n *proto.Node) {
		if n != nil && n.Role == proto.RoleFirewall {
			submit("firewall-registered")
		}
	}
}

// apiLeaf holds the api's HTTPS server leaf in memory and re-mints it when the
// LAN address changes. The leaf carries the LAN IP as a SAN so an operator who
// browses by address before mDNS resolves still gets a clean lock. Loaded from
// files by ListenAndServeTLS, it kept the address from api start until the next
// restart; served through GetCertificate, it follows the address.
type apiLeaf struct {
	mint func(lanIP net.IP) (mesh.LeafPaths, error)

	mu     sync.Mutex
	loaded bool
	ip     string
	cert   atomic.Pointer[tls.Certificate]
}

// load mints (or reuses) the leaf for lanIP and swaps it in. A no-op when the
// held leaf was already made for lanIP. On error the previous leaf stays in
// service: a stale IP SAN is a warning in a browser, no certificate is an outage.
func (l *apiLeaf) load(lanIP net.IP) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := ipString(lanIP)
	if l.loaded && key == l.ip {
		return nil
	}
	paths, err := l.mint(lanIP)
	if err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(paths.CertPath, paths.KeyPath)
	if err != nil {
		return err
	}
	l.cert.Store(&c)
	l.loaded, l.ip = true, key
	return nil
}

var errNoAPILeaf = errors.New("rasputin-api: https leaf not loaded")

// getCertificate is the tls.Config hook. Each handshake reads the current leaf.
func (l *apiLeaf) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := l.cert.Load(); c != nil {
		return c, nil
	}
	return nil, errNoAPILeaf
}
