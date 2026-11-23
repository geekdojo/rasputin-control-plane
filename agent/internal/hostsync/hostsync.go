// Package hostsync keeps a local resolver entry for the control plane's mDNS
// name current, so clients on the same box that can't do mDNS themselves can
// still resolve it.
//
// The motivating case is the OpenWrt firewall: musl has no nss-mdns, so
// tailscaled (a pure-Go binary reading /etc/resolv.conf → dnsmasq) can't
// resolve rasputin.local, which is the mesh login server. This surfaces the
// control plane's address to the whole box by writing it into a dnsmasq
// `hostsdir` file, so every local client (tailscaled included) can resolve the
// name. It self-heals when the control plane's address changes — no DHCP
// reservation, no hard-coded IP, works on any network (see the "no
// chicken-and-egg deps" principle).
//
// # WHERE THE ADDRESS COMES FROM, AND WHY IT IS NOT mDNS
//
// It is read off the live bus connection — the socket the agent is
// authenticated on — exactly as internal/clusterdns reads it, and never from a
// name lookup. The earlier version resolved the name over multicast DNS here
// and republished whatever answered.
//
// mDNS is unauthenticated: any host on the LAN can answer for
// <cluster>.local. Republishing that answer into dnsmasq took one host's
// unverified claim and served it, as unicast DNS, to every client on the
// firewall's LAN — including this box's own tailscaled, whose control URL is
// that name. So a forged answer did not just mislead one lookup, it was
// cached, distributed and given the authority of the network's own resolver
// (geekdojo/geekdojo-brain#547, F13).
//
// The bus connection cannot be forged that way: it is TLS-pinned (or, on a
// cluster still migrating, at least bound to the control plane that accepted
// this node's join token), and the address is the peer of that socket. mDNS
// still gets used to DIAL the bus — that is its one remaining job, and the pin
// is what authenticates the result. DNS is never a source of trust.
//
// It is opt-in via RASPUTIN_CP_HOSTS_DIR and a no-op everywhere the variable is
// unset (e.g. rasputin-os, where systemd-resolved does mDNS natively).
package hostsync

import (
	"context"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
)

// ServerIP returns the control plane's CURRENT address, or "" when the bus is
// not connected and so cannot say. A function, not a string, because the
// control plane's address moves: these clusters run without DHCP reservations
// by design, so the CP takes a new lease on every reboot.
//
// The same shape, and the same contract, as clusterdns.Config.ServerIP. The
// agent wires both from the live bus client.
type ServerIP func() string

// Config is everything Run needs, each piece supplied by the composition root.
type Config struct {
	// Names are the names published at the control plane's address, one
	// "<ip> <name>" line each. Names[0] also names the file (dir/Names[0]):
	// the file an upgraded firewall already holds, so the previous release's
	// one-line file is rewritten in place rather than left beside a new one
	// (dnsmasq reads every file in the directory).
	Names []string
	// Dir is the dnsmasq hosts directory; created if missing.
	Dir string
	// Interval is a safety net behind the address source, not a clock the
	// entry lives on; non-positive means 30s.
	Interval time.Duration
	// ReloadCmd, if non-empty, is run via "sh -c" after each write.
	ReloadCmd string
	// ServerIP is the live address source; required.
	ServerIP ServerIP
	// Logger receives every record Run writes; nil discards them.
	Logger *slog.Logger
}

// Run publishes one "<ip> <name>" line per name into dir/Names[0] (one atomic
// rename, so every name always carries the same address) whenever the control
// plane's address changes, and leaves the published entry alone the rest of
// the time. Blocks until ctx is cancelled.
//
// ServerIP is re-read on every look, never captured: a rollout reboots the
// control plane LAST, right after every other node has just seen its old
// address, so a captured string is a stale one.
//
// NOT KNOWING the address is not the same as having LOST the control plane —
// the same rule clusterdns learned the hard way. ServerIP reads empty at start
// (before the first dial) and whenever the bus is down. In both cases the
// published entry is KEPT: withdrawing it would take this box's own tailscaled
// off the mesh for as long as the bus was down, and put nothing better in its
// place. The entry only ever changes to another address the bus itself
// reported.
//
// Interval is a safety net behind that, not a clock the entry lives on:
// nothing is published or withdrawn because a tick happened, only because the
// address the bus reports differs from the one last written.
//
// ReloadCmd exists because dnsmasq does NOT auto-watch addn-hosts files (only
// --hostsdir, which OpenWrt's uci doesn't expose), so the resolver must be
// told to re-read — on the firewall this is "/etc/init.d/dnsmasq reload". It
// runs only after an actual write, so the reload is rare (first connect +
// CP-IP changes).
func Run(ctx context.Context, cfg Config) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	// A missing address source or name list is a wiring bug, not a reason to
	// fall back to resolving the name — that fallback is the mDNS republish
	// this package no longer does.
	if cfg.ServerIP == nil || len(cfg.Names) == 0 {
		reason := "no control-plane address source"
		if len(cfg.Names) == 0 {
			reason = "no names to publish"
		}
		logger.Error("hostsync not started", "dir", cfg.Dir, "names", cfg.Names, "reason", reason)
		return
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	// 0755/0644 (agent/internal/atrest's public helpers), set rather than
	// inherited: dnsmasq reads this directory and the files in it AFTER
	// dropping to its own unprivileged user, so an owner-only mode would stop
	// the control plane's name resolving on the firewall's LAN. What is in
	// them is "<ip> <name>" lines — the control plane's LAN address, which
	// every client on that LAN already learns by resolving the name.
	if err := atrest.EnsurePublicDir(cfg.Dir); err != nil {
		logger.Error("hostsync cannot create the hosts directory", "dir", cfg.Dir, "names", cfg.Names, "err", err)
		return
	}
	file := filepath.Join(cfg.Dir, cfg.Names[0])
	last := ""
	timer := time.NewTimer(0) // first tick fires immediately
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if ip := cfg.ServerIP(); ip != "" && ip != last {
				if werr := writeHost(file, ip, cfg.Names); werr != nil {
					logger.Error("hostsync write failed", "file", file, "err", werr)
				} else {
					logger.Info("hostsync published", "names", cfg.Names, "ip", ip, "dir", cfg.Dir, "source", "bus")
					last = ip
					if cfg.ReloadCmd != "" {
						if out, rerr := exec.CommandContext(ctx, "sh", "-c", cfg.ReloadCmd).CombinedOutput(); rerr != nil {
							logger.Error("hostsync reload failed", "cmd", cfg.ReloadCmd, "err", rerr, "output", strings.TrimSpace(string(out)))
						}
					}
				}
			}
			timer.Reset(interval)
		}
	}
}

// writeHost replaces file with one "<ip> <name>" line per name, in one rename.
func writeHost(file, ip string, names []string) error {
	var b strings.Builder
	for _, n := range names {
		b.WriteString(ip + " " + n + "\n")
	}
	return atrest.WritePublicFile(file, []byte(b.String()))
}
