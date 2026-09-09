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
//   - The control plane's address is RE-READ every look, never captured. These
//     clusters run without DHCP reservations by design, so the CP takes a new
//     lease on every reboot — and a rollout reboots it LAST, right after every
//     other node has just pinned its old address.
//   - A pin that does not answer is WITHDRAWN. The domains are routing-only, so
//     a stale pin does not degrade to mDNS, it black-holes the cluster's own
//     names — strictly worse than never having written anything. Withdrawing
//     restores mDNS, which is flaky, and flaky beats dead. It also lets the
//     agent reconnect and learn where the control plane went, so the next look
//     can pin it correctly.
//
// The second rule is the general one: this package must never leave a node
// worse off than it found it. It is inserting itself into name resolution,
// which everything else depends on.
//
// A third rule, from a different afternoon (e3bench 2026-09-09,
// geekdojo/geekdojo-brain#403): NOT KNOWING the address is not the same as
// having LOST the server. The first version applied once at start — before the
// bus had dialed, so the address read as unknown — and withdrew the pin the
// previous process had left under /run; the next look was the five-minute
// tick. Every agent restart therefore took the node off the mesh for up to
// five minutes: tailscaled failed its control-URL lookup every 15 s until the
// tick re-pinned, and reached Running 4 s after. So the rule is DATA-DRIVEN,
// with no clock in it:
//
//   - PIN when the bus connects. The agent fires a Trigger from the bus
//     client's onConnected — first dial, nats reconnect and re-dial alike —
//     and the pin is written seconds after the registration goes out, from
//     the address the bus actually connected to.
//   - KEEP an existing pin as long as the pinned server answers. Whenever the
//     bus cannot say where the control plane is — at start before the first
//     dial, and on every bus-lost event — the pinned address is read back out
//     of the drop-in and PROBED: asked, on the wire, for the cluster's own
//     name (see answersClusterName). It answers with an address: the pin
//     stays, however long the bus is down. The bus state and the clock are
//     not inputs.
//   - WITHDRAW only when the probe fails: the pinned server does not answer
//     the cluster's name — gone, or listening but not serving it. That is the
//     one fact that makes a pin harmful, and it is the only thing that
//     removes one.
//   - REPLACE when the bus connects to a different address than the one
//     pinned. A write and a resolved restart, and only on an actual change.
//
// The revision before this one withdrew an unverified pin after a 20 s grace.
// That grace was aligned with nothing: the bus client itself only declares a
// loss after its ~60 s ping cycle, and an ordinary control-plane reboot is
// longer than 20 s, so the grace would have pulled a perfectly good pin on
// every rollout — and been noticed as attrition, again. Timeouts doing work is
// how this package keeps getting bitten; the probe's I/O bound (probeTimeout)
// is the only one left, and its comment says why it has to exist.
//
// The drop-in lives under /run, not /etc: rasputin-os ships a read-only
// rootfs. That also makes it self-healing rather than sticky — it evaporates
// on reboot and is rewritten by the agent on the way back up, so a stale
// control-plane address can never outlive the boot that produced it.
package clusterdns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
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
// think it says and that the pinned server still answers. Cheap — a stat, a
// string compare and one probe — and only ever writes when the content
// actually differs. It is a safety net behind the bus events, not the clock
// the pin lives on: nothing is withdrawn because a tick happened, only because
// the probe the tick ran came back empty.
const DefaultInterval = 5 * time.Minute

// Trigger names, for the log lines: which event asked for the pin to be
// checked. Every pin, keep and withdrawal says which one it was, because the
// bug this package last had was only findable by matching those against
// tailscaled's own timestamps.
const (
	TriggerStart     = "start"
	TriggerConnected = "bus connected"
	TriggerLost      = "bus lost"
	TriggerTick      = "tick"
)

// probeTimeout bounds one probe's I/O: the query to <server>:53 and the wait
// for its answer, TCP retry included.
//
// It is the ONE timeout this package keeps, and it is not a decision — it is
// the bound a blocking read needs so that the question "does the pinned
// server answer?" can come back NO at all. A datagram to an address that has
// left the network is not refused, it is simply never answered, and the read
// would wait forever; the loop would sit inside it past the next tick and the
// next bus event, holding a pin it was in the middle of checking. Every other
// timeout this package once had decided something on the clock's say-so (a
// grace before withdrawing a pin the bus could not vouch for) and was removed
// for it; this one only says how long we are willing to wait to hear the
// answer. Short, because the control plane is on the LAN and a LAN nameserver
// that is up answers its own zone from memory in milliseconds.
const probeTimeout = 3 * time.Second

// Config parameterises Run. ClusterID and ServerIP are required; everything
// else has a working default.
type Config struct {
	// ClusterID is the cluster's short id ("rasputin"), from which both
	// managed domains are derived. Not the full hostname.
	ClusterID string

	// ServerIP returns the control plane's CURRENT address, or "" when the
	// bus is not connected and so cannot say. A function, not a string,
	// because the control plane's address moves: these clusters run without
	// DHCP reservations by design, so the CP takes a new lease on every
	// reboot — and a rollout reboots the CP LAST, immediately after this
	// package has pinned its old address on every other node.
	//
	// Captured once, that pin is a dead address, and because the domains are
	// routing-only the result is strictly WORSE than no drop-in: the cluster
	// name stops resolving entirely instead of falling back to mDNS. Measured on
	// e3bench 2026-08-30, on five nodes at once.
	//
	// Callers should read it from the live bus connection rather than resolving
	// a name — see the package comment.
	ServerIP func() string

	// probe asks the nameserver at serverIP for name (the cluster's internal
	// apex, see probeName) and returns nil when the answer carries an
	// address — the one fact a pin rests on — or an error saying why it did
	// not. Injected by tests, which point it at an in-process nameserver;
	// nil means the real query (answersClusterName). See Apply for why a pin
	// whose server does not answer must be withdrawn rather than left in
	// place.
	probe func(ctx context.Context, serverIP, name string) error

	// Dir is the drop-in directory. Empty means DefaultDir.
	Dir string

	// Interval is the re-check period. Empty means DefaultInterval.
	Interval time.Duration

	// Trigger, when set, wakes Run outside the tick: Fire when the bus
	// (re)connects, Lost when it drops. The agent wires both from the bus
	// client, so the pin follows the connection rather than waiting for the
	// next Interval. Nil means the tick is the only clock, which is the state
	// that cost five minutes per restart.
	Trigger *Trigger

	// reload applies the written config. Nil means restart systemd-resolved.
	// Injected by tests.
	reload func(context.Context) error
}

// Trigger is a wake-up for Run from the bus client: Fire when the bus
// (re)connects, Lost when it drops. Either way Run re-reads the address and
// re-checks the pin at once, against what the bus can say right now.
type Trigger struct{ connected, lost chan struct{} }

// NewTrigger makes a Trigger. One is enough for the life of the agent.
func NewTrigger() *Trigger {
	return &Trigger{connected: make(chan struct{}, 1), lost: make(chan struct{}, 1)}
}

// Fire says the bus has connected and asks for an immediate check. Never
// blocks and never queues more than one: Run re-reads the address when it
// wakes, so two fires before it does are one check against the current
// address, which is all a second fire could ask for anyway.
func (t *Trigger) Fire() {
	if t == nil {
		return
	}
	select {
	case t.connected <- struct{}{}:
	default:
	}
}

// Lost says the bus has dropped and asks for an immediate check. The address
// reads as unknown from here on, so the check is of the pin already on disk:
// its server is probed, and the pin is kept if it answers. Same never-blocks,
// never-queues-twice contract as Fire.
func (t *Trigger) Lost() {
	if t == nil {
		return
	}
	select {
	case t.lost <- struct{}{}:
	default:
	}
}

// connectedC and lostC are the channels Run selects on; nil (never ready)
// when there is no Trigger, so the select degrades to the tick alone.
func (t *Trigger) connectedC() <-chan struct{} {
	if t == nil {
		return nil
	}
	return t.connected
}

func (t *Trigger) lostC() <-chan struct{} {
	if t == nil {
		return nil
	}
	return t.lost
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
		c.probe = answersClusterName
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

// Apply is one look at the pin, and it has no memory: everything it decides
// it decides from what ServerIP says now, what is on disk now, and whether
// the server in question answers now.
//
// With an address from the bus, it writes the drop-in if it differs from what
// is on disk and reloads systemd-resolved when it wrote — pin or replace.
// Idempotent: the steady-state call does a read and a compare and nothing
// else, which is what makes it safe to run on an interval; restarting resolved
// flushes its cache, so we do it only on an actual change. Without an address
// — the bus not yet connected, or lost — it verifies the pin already on disk
// (see verifyPinned). Either way a server that does not answer is withdrawn,
// and nothing else is.
//
// Returns whether it changed anything. trigger names the event that asked
// (TriggerStart, TriggerConnected, …) and appears in every line this
// produces, so a withdrawal can be matched against what the rest of the node
// was doing at the time.
func Apply(ctx context.Context, cfg Config, trigger string) (changed bool, err error) {
	cfg.applyDefaults()
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
		return verifyPinned(ctx, cfg, path, trigger)
	}

	// Never leave a pin in place that does not answer. The domains are
	// ROUTING-ONLY, so resolved sends the cluster's names to this server and
	// nowhere else: if it does not answer them, the name does not resolve at
	// all, where without the drop-in mDNS would at least have answered. Being
	// wrong here is worse than doing nothing, so ask before asserting — for
	// the cluster's own name, not for a listening port (see answersClusterName).
	name := probeName(cfg.ClusterID)
	if perr := cfg.probe(ctx, ip, name); perr != nil {
		return withdraw(ctx, cfg, path, trigger, fmt.Sprintf("%s does not answer %s (%v)", ip, name, perr))
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

// verifyPinned is Apply when ServerIP returned "": the bus is not connected,
// so there is no peer to read. That is a startup as often as it is a loss —
// the agent applies once before its first dial, and /run still holds the pin
// the previous process wrote — and a loss is as often the control plane
// rebooting as it is the control plane gone. None of that is the pin's
// business. The pin is judged on ONE thing: the pinned address is read back
// out of the drop-in and probed. It answers, the pin is kept — for as long as
// that stays true, with no clock running against it. It does not answer, the
// pin is withdrawn, on the reasoning the package comment gives: flaky mDNS
// beats a black hole.
//
// A drop-in with no DNS= line to probe is withdrawn too. It is not a pin this
// package would write, so there is nothing to vouch for, and a routing-only
// Domains= with no server behind it is precisely the black hole.
func verifyPinned(ctx context.Context, cfg Config, path, trigger string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return false, nil // nothing pinned; nothing to keep or withdraw
	}
	pinned := pinnedIP(path)
	if pinned == "" {
		return withdraw(ctx, cfg, path, trigger, "control-plane address unknown and the drop-in names no server to verify")
	}
	name := probeName(cfg.ClusterID)
	if perr := cfg.probe(ctx, pinned, name); perr != nil {
		return withdraw(ctx, cfg, path, trigger,
			fmt.Sprintf("control-plane address unknown and the pinned %s does not answer %s (%v)", pinned, name, perr))
	}
	log.Printf("clusterdns: [%s] control-plane address not known from the bus; keeping the pin at %s — it answers %s",
		trigger, pinned, name)
	return false, nil
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

// Run applies the drop-in at start and then re-applies whenever the bus
// connects or drops (the Trigger) and on an interval as the safety net, until
// ctx ends. It is report-only about its own failures: a node whose DNS we
// cannot steer is still a working node for everything that does not need the
// mesh, so this never takes the agent down with it.
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

	log.Printf("clusterdns: keeping %s pointed at the control plane — pinned when the bus connects, verified when it drops and every %s, withdrawn only when the pinned server stops answering",
		strings.Join(Domains(cfg.ClusterID), " "), cfg.Interval)

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	trigger := TriggerStart
	for {
		changed, err := Apply(ctx, cfg, trigger)
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
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trigger = TriggerTick
		case <-cfg.Trigger.connectedC():
			trigger = TriggerConnected
		case <-cfg.Trigger.lostC():
			trigger = TriggerLost
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
// learn the control plane's new address so the next look can pin it correctly.
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

// probeName is the name the probe asks the pinned server for: the apex of
// the cluster's internal zone, which the control plane's nameserver
// (api/internal/nameserver) is authoritative for and answers with its own LAN
// address. It is one of the two names the drop-in routes at the pinned
// server (see Domains), so an answer for it proves the exact thing the pin
// asserts. Canonical form, with the trailing dot the wire format needs.
func probeName(clusterID string) string {
	return clusterID + ".internal."
}

// answersClusterName is the production probe: one A query for name, put on
// the wire to <serverIP>:53, and the answer read back. nil means the server
// answered with an address; anything else says why it did not.
//
// A WIRE-LEVEL QUERY, deliberately — a packet this package builds and parses
// itself — and neither of the two obvious shortcuts, each of which fails in
// a way that re-arms the black hole the probe exists to prevent:
//
//   - Not a net.Resolver lookup, even with PreferGo and a custom Dial. That
//     is still a name-service lookup: Go's goLookupIPCNAMEOrder consults
//     /etc/hosts, in the order nsswitch says, BEFORE it dials anything, so a
//     hosts entry for the cluster name makes the lookup pass without ever
//     contacting the server. Measured on the first version of this package
//     (dialed=false against an unroutable address, because the name was in
//     /etc/hosts) and checked again against the Go 1.26 source before this
//     rewrite: the resolver has no option that skips the files stage. The
//     bypass is not a resolver setting; it is not using the resolver. Nothing
//     below consults hosts, nsswitch or resolv.conf, by construction — there
//     is no name-service layer between the query and the socket.
//   - Not a TCP connect to :53, which the previous probe did. That proves a
//     process is listening. It does not prove it is the cluster's nameserver,
//     that it holds the zone, or that it is answering — a resolver stub, a
//     forwarder, a half-started api all accept the SYN, and a pin resting on
//     any of them black-holes the cluster's names exactly as a dead one does.
//
// The pin asserts one thing: "send the cluster's names here and they will be
// answered". So the probe asks exactly that question, of exactly that server,
// over the same wire resolved will use, and requires an answer carrying an
// address. NXDOMAIN, SERVFAIL, REFUSED, an empty NOERROR, a port nothing
// listens on and a server that listens but never replies are all the same
// verdict — does not answer — and the reason is carried into the withdrawal
// line so it can be read against tailscaled's own timestamps.
//
// The address comes from our own bus socket or from a drop-in we wrote, so
// impersonation is not the concern, and the zone's contents are the api's
// tests' concern, not this one's. The question is only whether the pinned
// address is, right now, a working nameserver for the cluster.
func answersClusterName(ctx context.Context, serverIP, name string) error {
	return queryA(ctx, net.JoinHostPort(serverIP, "53"), name)
}

// queryA sends one A query for name to addr and returns nil if the reply
// carries at least one address. UDP first, as a stub resolver would; if the
// reply comes back truncated before any address, once more over TCP (RFC
// 1035 §4.2.1), inside the same bound. The whole exchange — dial, send, wait,
// and the TCP retry if there is one — sits under the single probeTimeout.
func queryA(ctx context.Context, addr, name string) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	query, id, err := buildAQuery(name)
	if err != nil {
		return err
	}
	reply, err := exchange(ctx, "udp", addr, id, query)
	if err != nil {
		return err
	}
	answered, truncated, err := replyHasAddress(reply, id)
	if err == nil && !answered && truncated {
		if reply, err = exchange(ctx, "tcp", addr, id, query); err != nil {
			return err
		}
		answered, _, err = replyHasAddress(reply, id)
	}
	if err != nil {
		return err
	}
	if !answered {
		return errors.New("NOERROR with no address in the answer")
	}
	return nil
}

// buildAQuery is a standard query for the A record of name: a random id,
// recursion desired (what resolved's stub sends; an authoritative server
// ignores the bit, so the probe's question is shaped like the real ones).
func buildAQuery(name string) ([]byte, uint16, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, fmt.Errorf("query id: %w", err)
	}
	id := binary.BigEndian.Uint16(idb[:])
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, 0, fmt.Errorf("query name %q: %w", name, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	msg, err := b.Finish()
	if err != nil {
		return nil, 0, err
	}
	return msg, id, nil
}

// exchange sends query to addr over network ("udp" or "tcp") and returns the
// first reply bearing our id, or the error that stood in the way. Every read
// and write is bounded by the deadline on ctx, which queryA has already set.
func exchange(ctx context.Context, network, addr string, id uint16, query []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return nil, err
		}
	}

	if network == "tcp" {
		// RFC 1035 §4.2.2: a two-byte length prefix each way.
		n := len(query)
		if n > math.MaxUint16 {
			return nil, fmt.Errorf("query of %d bytes cannot be framed for tcp", n)
		}
		framed := make([]byte, 2+n)
		binary.BigEndian.PutUint16(framed, uint16(n))
		copy(framed[2:], query)
		if _, err := conn.Write(framed); err != nil {
			return nil, err
		}
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, err
		}
		reply := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return nil, err
		}
		if len(reply) < 2 || binary.BigEndian.Uint16(reply[:2]) != id {
			return nil, errors.New("reply id does not match the query")
		}
		return reply, nil
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	// The socket is connected, so only the server's datagrams arrive; a
	// stray one with the wrong id is skipped and the wait continues, still
	// under the deadline. No EDNS, so a reply is at most 512 bytes; the
	// buffer is larger only so an over-size one is read whole and then
	// judged, not silently cut.
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && binary.BigEndian.Uint16(buf[:2]) == id {
			return buf[:n], nil
		}
	}
}

// replyHasAddress judges one reply: answered is whether the answer section
// holds at least one A record; truncated is the TC bit, so the caller can try
// again over TCP when a truncated reply held no address; err is a reply that
// is not an answer at all — malformed, not a response, not for our id, or an
// error RCODE, named the way an operator would look it up.
func replyHasAddress(reply []byte, id uint16) (answered, truncated bool, err error) {
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil {
		return false, false, fmt.Errorf("malformed reply: %w", err)
	}
	if h.ID != id {
		return false, false, errors.New("reply id does not match the query")
	}
	if !h.Response {
		return false, false, errors.New("reply is not a response")
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return false, h.Truncated, errors.New(rcodeName(h.RCode))
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false, h.Truncated, fmt.Errorf("malformed reply: %w", err)
	}
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return false, h.Truncated, nil
		}
		if err != nil {
			return false, h.Truncated, fmt.Errorf("malformed reply: %w", err)
		}
		if ah.Type == dnsmessage.TypeA {
			return true, h.Truncated, nil
		}
		if err := p.SkipAnswer(); err != nil {
			return false, h.Truncated, fmt.Errorf("malformed reply: %w", err)
		}
	}
}

// rcodeName spells an error RCODE the way dig and resolvectl do, so the
// withdrawal line reads as a DNS operator expects.
func rcodeName(rc dnsmessage.RCode) string {
	switch rc {
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return rc.String()
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
