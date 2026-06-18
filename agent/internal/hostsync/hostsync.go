// Package hostsync keeps a local resolver entry for the control plane's mDNS
// name current, so clients on the same box that can't do mDNS themselves can
// still resolve it.
//
// The motivating case is the OpenWrt firewall: musl has no nss-mdns, so
// tailscaled (a pure-Go binary reading /etc/resolv.conf → dnsmasq) can't
// resolve rasputin.local, which is the mesh login server. The agent, however,
// already resolves rasputin.local over multicast DNS for the NATS bus. This
// surfaces that answer to the whole box by writing it into a dnsmasq
// `hostsdir` file; dnsmasq watches the directory and reloads automatically, so
// every local client (tailscaled included) can resolve the name. It self-heals
// when the control plane's address changes — no DHCP reservation, no hard-coded
// IP, works on any network (see the "no chicken-and-egg deps" principle).
//
// It is opt-in via RASPUTIN_CP_HOSTS_DIR and a no-op everywhere the variable is
// unset (e.g. rasputin-os, where systemd-resolved does mDNS natively).
package hostsync

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/mdns"
)

// Resolver resolves a .local name to an IP. *mdns.Resolve fits; injectable for
// tests.
type Resolver func(name string, timeout time.Duration) (string, error)

// Run resolves name on an interval and writes "<ip> <name>" into dir/<name>
// (atomic rename) whenever the resolved address changes. A dnsmasq configured
// with `hostsdir=<dir>` picks up the change automatically. Blocks until ctx is
// cancelled. dir is created if missing.
func Run(ctx context.Context, name, dir string, interval time.Duration, resolve Resolver) {
	if resolve == nil {
		resolve = mdns.Resolve
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("hostsync: cannot create %s: %v (%s won't resolve via dnsmasq)", dir, err, name)
		return
	}
	file := filepath.Join(dir, name)
	last := ""
	timer := time.NewTimer(0) // first tick fires immediately
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if ip, err := resolve(name, 3*time.Second); err == nil && ip != "" && ip != last {
				if werr := writeHost(file, ip, name); werr != nil {
					log.Printf("hostsync: write %s: %v", file, werr)
				} else {
					log.Printf("hostsync: %s -> %s (published to dnsmasq hostsdir %s)", name, ip, dir)
					last = ip
				}
			}
			timer.Reset(interval)
		}
	}
}

func writeHost(file, ip, name string) error {
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, []byte(ip+" "+name+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}
