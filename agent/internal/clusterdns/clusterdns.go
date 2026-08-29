// Package clusterdns keeps the cluster's own names resolvable on a node no
// matter what DNS the DHCP lease handed out.
//
// The bug it exists for: a node resolves the control plane by name — the bus
// is `nats://<cluster>.local:4222` and tailscaled's control URL is
// `https://<cluster>.local:18080`. But the DNS servers a node gets from DHCP
// are whatever the site's router hands out, typically public resolvers, and a
// public resolver can never answer a `.local` name. Resolution therefore falls
// to mDNS, where an AAAA query has nothing to answer it on an IPv4-only
// cluster and ends in `attempts-max-reached` — a timeout, not a negative.
//
// Go's resolver shrugs that off and uses the A record, which is why the agent
// itself never noticed. tailscaled does not: it treats the lookup as failed,
// falls back to Tailscale's public bootstrap DNS (which is being asked to
// resolve a `.local` name, and cannot), logs "no DNS fallback candidates
// remain", and parks in NoState. The node drops off the mesh and does not come
// back across a service restart or a reboot.
//
// It is a race, so it presents as attrition rather than an outage: on the
// bench cluster it took 16 of 24 nodes off the tailnet over several weeks of
// ordinary update cycles, a few at a time, while the UI still read 24/24
// because the agent heartbeat rides the LAN and was never affected
// (geekdojo/geekdojo-brain#202).
//
// The fix is to stop asking mDNS. We write a systemd-resolved drop-in that
// routes *only* the cluster's own domains at the control plane's nameserver,
// leaving every other query on the DHCP-provided servers where it belongs.
// Two properties make this safe to apply everywhere:
//
//   - The domains are routing-only ("~name"), so this is not a general
//     resolver override. `example.com` still goes wherever DHCP said.
//   - The address is the one the bus is already connected to, read off the
//     socket rather than resolved. No name lookup can fail on the way to
//     fixing name lookup.
//
// Nothing here touches tailscaled. Once the cluster name resolves over unicast
// DNS, tailscaled's own login retry picks it up unaided — measured at roughly
// 50 seconds on the bench, from NoState to Running with no restart. Repairing
// DNS and leaving the service alone is both simpler and less privileged than
// driving it.
//
// The drop-in lives under /run, not /etc: rasputin-os ships a read-only
// rootfs. That also makes it self-healing rather than sticky — it evaporates
// on reboot and is rewritten by the agent on the way back up, so a stale
// control-plane address can never outlive the boot that produced it.
package clusterdns

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultDir is the systemd-resolved drop-in directory we write to. /run
// rather than /etc because the OS image mounts /etc read-only; systemd-resolved
// reads drop-ins from /run with higher precedence than /usr/lib and lower than
// /etc, which is exactly the layering we want — an operator can still override.
const DefaultDir = "/run/systemd/resolved.conf.d"

// fileName is deliberately prefixed so the lexical ordering of drop-ins is
// obvious to anyone reading the directory, and suffixed with the issue so the
// next person to find it has somewhere to start.
const fileName = "50-rasputin-cluster-dns.conf"

// DefaultInterval is how often we re-check that the drop-in still says what we
// think it says. Cheap — a stat and a string compare — and only ever writes
// when the content actually differs.
const DefaultInterval = 5 * time.Minute

// Config parameterises Run. ClusterID and ServerIP are required; everything
// else has a working default.
type Config struct {
	// ClusterID is the cluster's short id ("rasputin"), from which both
	// managed domains are derived. Not the full hostname.
	ClusterID string

	// ServerIP is the control plane's LAN address. Callers should take this
	// from the live bus connection rather than resolving a name — see the
	// package comment.
	ServerIP string

	// Dir is the drop-in directory. Empty means DefaultDir.
	Dir string

	// Interval is the re-check period. Empty means DefaultInterval.
	Interval time.Duration

	// reload applies the written config. Nil means restart systemd-resolved.
	// Injected by tests.
	reload func(context.Context) error
}

func (c *Config) applyDefaults() {
	if c.Dir == "" {
		c.Dir = DefaultDir
	}
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.reload == nil {
		c.reload = restartResolved
	}
}

// Domains returns the routing-only domains we claim for the cluster: the mDNS
// name the bus and tailscaled dial, and the internal zone apex the CP
// nameserver is authoritative for. Both are prefixed "~" — routing-only, so
// they steer these names at the CP without making it the node's resolver for
// anything else.
func Domains(clusterID string) []string {
	return []string{
		"~" + clusterID + ".local",
		"~" + clusterID + ".internal",
	}
}

// Render builds the drop-in body. Exported so a test can assert on the exact
// bytes we would write, and so the content is inspectable without a filesystem.
func Render(clusterID, serverIP string) string {
	var b strings.Builder
	b.WriteString("# Written by rasputin-agent (clusterdns). Do not edit — rewritten on\n")
	b.WriteString("# every agent start. See geekdojo/geekdojo-brain#202.\n")
	b.WriteString("#\n")
	b.WriteString("# Routes ONLY the cluster's own domains at the control plane. Every other\n")
	b.WriteString("# query stays on the DNS servers DHCP provided.\n")
	b.WriteString("[Resolve]\n")
	b.WriteString("DNS=" + serverIP + "\n")
	b.WriteString("Domains=" + strings.Join(Domains(clusterID), " ") + "\n")
	return b.String()
}

// Apply writes the drop-in if it differs from what is already on disk and
// reloads systemd-resolved when it wrote. Returns whether it changed anything.
// Idempotent: the steady-state call does a read and a compare and nothing else,
// which is what makes it safe to run on an interval — restarting resolved
// flushes its cache, so we do it only on an actual change.
func Apply(ctx context.Context, cfg Config) (changed bool, err error) {
	cfg.applyDefaults()
	if cfg.ClusterID == "" {
		return false, fmt.Errorf("clusterdns: no cluster id")
	}
	if cfg.ServerIP == "" {
		return false, fmt.Errorf("clusterdns: no control-plane address")
	}

	want := Render(cfg.ClusterID, cfg.ServerIP)
	path := filepath.Join(cfg.Dir, fileName)

	if existing, rerr := os.ReadFile(path); rerr == nil && string(existing) == want {
		return false, nil
	}

	// 0755/0644, not 0600/0700, and gosec is overruled on both (G301, G306 in
	// .github/sast-register.tsv). systemd-resolved runs unprivileged and reads
	// drop-ins after dropping privileges: at 0600/0700 it SILENTLY ignores this
	// file — no error, no log, the routing domains simply never appear and the
	// cluster name falls back to mDNS, which is the exact failure this package
	// exists to prevent. Verified on the bench 2026-08-29. The contents are a
	// cluster id and a LAN address; there is no secret here to protect.
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return false, fmt.Errorf("clusterdns: mkdir %s: %w", cfg.Dir, err)
	}
	// Write-then-rename so systemd-resolved never reads a half-written file if
	// it happens to be reloading for an unrelated reason.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(want), 0o644); err != nil {
		return false, fmt.Errorf("clusterdns: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("clusterdns: rename %s: %w", path, err)
	}
	if err := cfg.reload(ctx); err != nil {
		// The file is written; a failed reload means it takes effect at the
		// next resolved restart rather than now. Worth reporting, not worth
		// unwinding — leaving correct config on disk is strictly better than
		// removing it.
		return true, fmt.Errorf("clusterdns: wrote %s but reload failed: %w", path, err)
	}
	return true, nil
}

// Run applies the drop-in and then re-applies on an interval until ctx ends.
// It is report-only about its own failures: a node whose DNS we cannot steer
// is still a working node for everything that does not need the mesh, so this
// never takes the agent down with it.
func Run(ctx context.Context, cfg Config) {
	cfg.applyDefaults()

	if cfg.ClusterID == "" || cfg.ServerIP == "" {
		log.Printf("clusterdns: cluster id or control-plane address unknown; not starting")
		return
	}
	// No systemd-resolved (the OpenWrt firewall, dev boxes, CI) means nothing
	// here applies. Detect by the parent of the drop-in dir rather than by
	// probing systemctl: it is the thing we actually need to exist, and it
	// keeps this a pure filesystem check.
	if parent := filepath.Dir(cfg.Dir); parent != "." && parent != "/" {
		if _, err := os.Stat(parent); err != nil {
			log.Printf("clusterdns: %s absent (no systemd-resolved here); not starting", parent)
			return
		}
	}

	log.Printf("clusterdns: routing %s at %s every %s",
		strings.Join(Domains(cfg.ClusterID), " "), cfg.ServerIP, cfg.Interval)

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		changed, err := Apply(ctx, cfg)
		switch {
		case err != nil:
			log.Printf("clusterdns: %v", err)
		case changed:
			log.Printf("clusterdns: wrote %s routing %s at %s",
				filepath.Join(cfg.Dir, fileName),
				strings.Join(Domains(cfg.ClusterID), " "), cfg.ServerIP)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// restartResolved is the production reload. A restart rather than a reload:
// resolved's reload semantics across the versions rasputin-os has shipped are
// not uniform, and a restart is what was verified to pick up a new drop-in on
// the bench. It is brief, and Apply only calls it when the content changed.
func restartResolved(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "systemd-resolved")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart systemd-resolved: %w (%s)",
			err, strings.TrimSpace(string(out)))
	}
	return nil
}
