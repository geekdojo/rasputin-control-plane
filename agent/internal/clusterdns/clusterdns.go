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
// The control plane fails the same way for a different reason, which is why it
// is NOT exempt from this. mDNS answers the CP's own cluster name with a
// link-local address, and dialling one without a zone index is not a timeout
// but an outright error:
//
//	fetch control key: Get "https://e3bench.local:18080/key?v=109":
//	  dial tcp [fe80::52d5:9eef:adaa:29ca]:18080: connect: invalid argument
//
// Same root cause — mDNS in tailscaled's control-URL path — reached by a
// different route. Observed on e3bench 2026-08-30, on the reboot that shipped
// the first version of this package with the control plane excluded.
//
// The control-plane case is TRANSIENT where the compute case is permanent: it
// retries into a usable address on its own, measured at 2m20s on that reboot.
//
// It is NOT fixed by this package, and cannot be. systemd-resolved
// short-circuits its own hostname and answers from its interface list,
// ignoring routing domains, so pointing the control plane at its own
// nameserver changes nothing — measured, with the drop-in applied, querying
// the stub the way Go does. See the exclusion comment in
// cmd/rasputin-agent/main.go for the numbers. A real fix has to take the name
// out of the control plane's control URL altogether.
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
// Two rules this package learned the hard way, both from the same afternoon on
// e3bench:
//
//   - The control plane's address is RE-READ every tick, never captured. These
//     clusters run without DHCP reservations by design, so the CP takes a new
//     lease on every reboot — and a rollout reboots it LAST, right after every
//     other node has just pinned its old address.
//   - A pin that does not answer is WITHDRAWN. The domains are routing-only, so
//     a stale pin does not degrade to mDNS, it black-holes the cluster's own
//     names — strictly worse than never having written anything. Withdrawing
//     restores mDNS, which is flaky, and flaky beats dead. It also lets the
//     agent reconnect and learn where the control plane went, so the next tick
//     can pin it correctly.
//
// The second rule is the general one: this package must never leave a node
// worse off than it found it. It is inserting itself into name resolution,
// which everything else depends on.
//
// A third rule, from a different afternoon (e3bench 2026-09-09,
// geekdojo/geekdojo-brain#403): NOT KNOWING the address yet is not the same
// as having LOST it. The first version applied once at start — before the bus
// had dialed, so the address read as unknown — and withdrew the pin the
// previous process had left under /run; the next look was the five-minute
// tick. Every agent restart therefore took the node off the mesh for up to
// five minutes: tailscaled failed its control-URL lookup every 15 s until the
// tick re-pinned, and reached Running 4 s after. So now:
//
//   - The bus connecting is a TRIGGER, not something the tick discovers. The
//     agent fires it from the bus client's onConnected — first dial, nats
//     reconnect and re-dial alike — and the pin is written seconds after the
//     registration goes out, from the address the bus actually connected to.
//   - An unknown address withdraws an existing pin only after a GRACE
//     (DefaultGrace) has passed with the bus still unconnected, or at once if
//     the pinned server itself stops answering. Inside the grace the pin is
//     kept and verified, not trusted.
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
	"net"
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

// DefaultGrace is how long an unknown control-plane address is tolerated
// before an existing pin is withdrawn. The address is unknown whenever the bus
// is not connected — including the seconds between the agent starting and its
// first dial succeeding, which is a startup, not a loss. Two heartbeat
// intervals (the agent heartbeats every 10 s): long enough that a restart or a
// re-dial completes inside it, short enough that a control plane that really
// has gone is handed back to mDNS promptly. Inside the grace the pinned server
// is still probed on every look, so a dead pin never rides the grace out.
const DefaultGrace = 20 * time.Second

// Trigger names, for the log lines: which event asked for the pin to be
// checked. Every pin, keep and withdrawal says which one it was, because the
// bug this package last had was only findable by matching those against
// tailscaled's own timestamps.
const (
	TriggerStart     = "start"
	TriggerConnected = "bus connected"
	TriggerTick      = "tick"
	TriggerGrace     = "grace expired"
)

// probeTimeout bounds the reachability check. Short: the control plane is on
// the LAN, and a check that hangs would stall the loop that is supposed to
// notice the control plane moved.
const probeTimeout = 3 * time.Second

// Config parameterises Run. ClusterID and ServerIP are required; everything
// else has a working default.
type Config struct {
	// ClusterID is the cluster's short id ("rasputin"), from which both
	// managed domains are derived. Not the full hostname.
	ClusterID string

	// ServerIP returns the control plane's CURRENT address. A function, not a
	// string, because the control plane's address moves: these clusters run
	// without DHCP reservations by design, so the CP takes a new lease on every
	// reboot — and a rollout reboots the CP LAST, immediately after this package
	// has pinned its old address on every other node.
	//
	// Captured once, that pin is a dead address, and because the domains are
	// routing-only the result is strictly WORSE than no drop-in: the cluster
	// name stops resolving entirely instead of falling back to mDNS. Measured on
	// e3bench 2026-08-30, on five nodes at once.
	//
	// Callers should read it from the live bus connection rather than resolving
	// a name — see the package comment.
	ServerIP func() string

	// probe reports whether serverIP still has a nameserver listening. Injected
	// by tests; nil means a real dial. See Apply for why a pin that stops
	// answering must be withdrawn rather than left in place.
	probe func(ctx context.Context, serverIP string) bool

	// Dir is the drop-in directory. Empty means DefaultDir.
	Dir string

	// Interval is the re-check period. Empty means DefaultInterval.
	Interval time.Duration

	// Grace is how long ServerIP may return "" before an existing pin is
	// withdrawn. Empty means DefaultGrace.
	Grace time.Duration

	// Trigger, when set, wakes Run outside the tick. The agent fires it from
	// the bus client's onConnected so the pin follows the connection rather
	// than waiting for the next Interval. Nil means the tick is the only
	// clock, which is the state that cost five minutes per restart.
	Trigger *Trigger

	// reload applies the written config. Nil means restart systemd-resolved.
	// Injected by tests.
	reload func(context.Context) error

	// now is the clock the grace is measured on. Injected by tests.
	now func() time.Time
}

// Trigger is a wake-up for Run: Fire when the bus (re)connects and the pin is
// checked immediately, against the address the bus is now connected to.
type Trigger struct{ ch chan struct{} }

// NewTrigger makes a Trigger. One is enough for the life of the agent.
func NewTrigger() *Trigger { return &Trigger{ch: make(chan struct{}, 1)} }

// Fire asks for an immediate check. Never blocks and never queues more than
// one: Run re-reads the address when it wakes, so two fires before it does are
// one check against the current address, which is all a second fire could ask
// for anyway.
func (t *Trigger) Fire() {
	if t == nil {
		return
	}
	select {
	case t.ch <- struct{}{}:
	default:
	}
}

// wait is the channel Run selects on; nil (never ready) when there is no
// Trigger, so the select degrades to the tick alone.
func (t *Trigger) wait() <-chan struct{} {
	if t == nil {
		return nil
	}
	return t.ch
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
	if c.probe == nil {
		c.probe = reachableNameserver
	}
	if c.Grace <= 0 {
		c.Grace = DefaultGrace
	}
	if c.now == nil {
		c.now = time.Now
	}
}

// Pinner holds the one piece of state Apply needs across calls: how long the
// control-plane address has been unknown. Build one with New and keep it for
// the life of the loop; a fresh Pinner per call would restart the grace clock
// and never withdraw.
type Pinner struct {
	cfg Config
	// unknownSince is when ServerIP first returned "" with a pin on disk, or
	// zero when the address is known (or nothing is pinned).
	unknownSince time.Time
}

// New builds a Pinner. Defaults are applied here, once.
func New(cfg Config) *Pinner {
	cfg.applyDefaults()
	return &Pinner{cfg: cfg}
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
	b.WriteString("# Written by rasputin-agent (clusterdns). Do not edit — rewritten each\n")
	b.WriteString("# time the agent connects to the bus. See geekdojo/geekdojo-brain#202.\n")
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
//
// trigger names the event that asked (TriggerStart, TriggerConnected, …) and
// appears in every line this produces, so a withdrawal can be matched against
// what the rest of the node was doing at the time.
func (p *Pinner) Apply(ctx context.Context, trigger string) (changed bool, err error) {
	cfg := p.cfg
	if cfg.ClusterID == "" {
		return false, fmt.Errorf("clusterdns: no cluster id")
	}
	if cfg.ServerIP == nil {
		return false, fmt.Errorf("clusterdns: no control-plane address source")
	}
	path := filepath.Join(cfg.Dir, fileName)

	// Re-read the address every time. Capturing it once is what put a dead
	// address on five nodes at once: a rollout reboots the control plane LAST,
	// it comes back on a new lease, and every node that was just repaired is
	// left pinned to where it used to be.
	ip := cfg.ServerIP()
	if ip == "" {
		return p.addressUnknown(ctx, path, trigger)
	}
	p.unknownSince = time.Time{}

	// Never leave a pin in place that does not answer. The domains are
	// ROUTING-ONLY, so resolved sends the cluster's names to this server and
	// nowhere else: if it is dead, the name does not resolve at all, where
	// without the drop-in mDNS would at least have answered. Being wrong here
	// is worse than doing nothing, so verify before asserting.
	if !cfg.probe(ctx, ip) {
		return withdraw(ctx, cfg, path, trigger, fmt.Sprintf("%s is not answering for the cluster name", ip))
	}

	want := Render(cfg.ClusterID, ip)

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

// addressUnknown is Apply when ServerIP returned "": the bus is not connected,
// so there is no peer to read. That is a startup as often as it is a loss —
// the agent applies once before its first dial, and /run still holds the pin
// the previous process wrote — so an existing pin is not withdrawn on sight.
// It is KEPT for the grace and VERIFIED while kept: the pinned server is
// probed every look, and a pin that has stopped answering goes at once,
// grace or not. Only when the grace runs out with the bus still unconnected
// is a live pin withdrawn, on the reasoning the package comment gives —
// flaky mDNS beats a pin nobody can vouch for.
func (p *Pinner) addressUnknown(ctx context.Context, path, trigger string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		p.unknownSince = time.Time{}
		return false, nil // nothing pinned; nothing to keep or withdraw
	}
	now := p.cfg.now()
	if p.unknownSince.IsZero() {
		p.unknownSince = now
		log.Printf("clusterdns: [%s] control-plane address not known yet; keeping the existing pin for up to %s while the bus connects",
			trigger, p.cfg.Grace)
	}
	if pinned := pinnedIP(path); pinned != "" && !p.cfg.probe(ctx, pinned) {
		return withdraw(ctx, p.cfg, path, trigger,
			fmt.Sprintf("control-plane address unknown and the pinned %s is not answering", pinned))
	}
	if elapsed := now.Sub(p.unknownSince); elapsed < p.cfg.Grace {
		return false, nil
	}
	return withdraw(ctx, p.cfg, path, trigger,
		fmt.Sprintf("control-plane address unknown for %s, longer than the %s grace",
			now.Sub(p.unknownSince).Round(time.Second), p.cfg.Grace))
}

// graceRemaining is how long until a pin kept under the grace is due to be
// withdrawn, or 0 when nothing is deferred. Run arms a timer on it so the
// grace expires on its own clock rather than at the next tick.
func (p *Pinner) graceRemaining() time.Duration {
	if p.unknownSince.IsZero() {
		return 0
	}
	if left := p.cfg.Grace - p.cfg.now().Sub(p.unknownSince); left > 0 {
		return left
	}
	// Due already; a nanosecond keeps the timer distinguishable from "none".
	return time.Nanosecond
}

// pinnedIP reads the DNS= address back out of a drop-in we wrote, or "" if
// the file is unreadable or not ours. Used only when the bus cannot tell us
// where the control plane is: the pin is then the only address we have, and
// it is probed rather than trusted.
func pinnedIP(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(line, "DNS="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// Run applies the drop-in and then re-applies whenever the Trigger fires, when
// a grace runs out, and on an interval as the safety net, until ctx ends. It
// is report-only about its own failures: a node whose DNS we cannot steer is
// still a working node for everything that does not need the mesh, so this
// never takes the agent down with it.
func Run(ctx context.Context, cfg Config) {
	cfg.applyDefaults()

	if cfg.ClusterID == "" || cfg.ServerIP == nil {
		log.Printf("clusterdns: cluster id or control-plane address source missing; not starting")
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

	log.Printf("clusterdns: keeping %s pointed at the control plane — pinned when the bus connects, re-checked every %s, an unknown address tolerated for %s",
		strings.Join(Domains(cfg.ClusterID), " "), cfg.Interval, cfg.Grace)

	p := New(cfg)
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	trigger := TriggerStart
	for {
		changed, err := p.Apply(ctx, trigger)
		switch {
		case err != nil:
			log.Printf("clusterdns: %v", err)
		case changed:
			// Log the address as it is NOW, not as it was at startup — a
			// changed line here is usually the control plane having moved,
			// which is the event worth seeing.
			log.Printf("clusterdns: [%s] %s now routes %s at %s", trigger,
				filepath.Join(cfg.Dir, fileName),
				strings.Join(Domains(cfg.ClusterID), " "), cfg.ServerIP())
		}
		// A pin kept under the grace is re-examined when the grace is up,
		// not at the next tick — otherwise "withdraw after 20 s" would read
		// "withdraw after up to five minutes".
		var graceUp <-chan time.Time
		var graceTimer *time.Timer
		if left := p.graceRemaining(); left > 0 {
			graceTimer = time.NewTimer(left)
			graceUp = graceTimer.C
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trigger = TriggerTick
		case <-cfg.Trigger.wait():
			trigger = TriggerConnected
		case <-graceUp:
			trigger = TriggerGrace
		}
		if graceTimer != nil {
			graceTimer.Stop()
		}
	}
}

// withdraw removes the drop-in, if present, and reloads so the removal takes
// effect. Used whenever we cannot stand behind the pin any more.
//
// Removing is deliberately the failure mode. Because the domains are
// routing-only, a stale or unreachable pin does not degrade to mDNS — it
// black-holes the cluster's own names, which is worse than never having written
// anything. Withdrawing hands resolution back to mDNS: flaky, which is the
// original complaint, but flaky beats dead, and it lets the agent reconnect and
// learn the control plane's new address so the next tick can pin it correctly.
func withdraw(ctx context.Context, cfg Config, path, trigger, why string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return false, nil // nothing pinned; nothing to undo
	}
	if err := os.Remove(path); err != nil {
		return false, fmt.Errorf("clusterdns: [%s] %s, but could not remove %s: %w", trigger, why, path, err)
	}
	if err := cfg.reload(ctx); err != nil {
		return true, fmt.Errorf("clusterdns: [%s] withdrew %s (%s) but reload failed: %w", trigger, path, why, err)
	}
	return true, fmt.Errorf("clusterdns: [%s] withdrew %s — %s; the cluster name falls back to mDNS until this resolves", trigger, path, why)
}

// reachableNameserver reports whether serverIP has a nameserver accepting
// connections on port 53.
//
// A DIRECT DIAL, deliberately, not a resolver lookup. The obvious
// implementation — net.Resolver with PreferGo and a custom Dial — is wrong
// here, and wrong silently: Go consults /etc/hosts before it dials, so any
// hosts entry for the cluster name makes the probe return true WITHOUT EVER
// CONTACTING the server. Measured while writing this: dialed=false against an
// unroutable address, because the name was in /etc/hosts.
//
// A probe that can pass while the server is dead is worse than no probe at
// all — it re-arms the black-hole this check exists to prevent.
//
// This verifies liveness, not zone contents, and that is the failure mode being
// guarded: a pinned address going stale or dead. The address comes from our own
// bus socket, so it is the control plane rather than an impostor; the question
// is only whether it is still there.
func reachableNameserver(ctx context.Context, serverIP string) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(serverIP, "53"))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
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
