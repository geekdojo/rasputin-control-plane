// Package nameguard keeps the control plane's own mDNS name published, and
// reports when another cluster has taken it.
//
// The bug it exists for: systemd-resolved probes for its hostname at boot and,
// if another host on the LAN already claims it, backs off and never re-probes.
// It does not auto-rename, and it does not report a conflict — it silently
// declines to publish, permanently. Observed on the bench 2026-07-28 with two
// control planes on one /24: after the colliding host was shut down the
// survivor still could not resolve its own name (`ping` → "bad address"),
// despite MulticastDNS=yes and the mDNS scope being active on the link, until
// systemd-resolved was restarted by hand.
//
// Two consequences worth designing against, and both are why this package
// reports as loudly as it repairs. A control plane that boots while another
// Rasputin is up is unreachable by name for the rest of its uptime. And the
// operator gets no signal at any point — the failure surfaces downstream as an
// unrelated TLS/CA error ("certificate signed by unknown authority", because
// both clusters' Mesh CAs share a CN), which is what made this cost a day to
// diagnose during the Turing Pi bring-up.
//
// nameguard probes the wire on an interval and classifies what answers:
//
//	StateOK           the name answers with one of our own addresses
//	StateConflict     it answers with someone else's — another cluster owns it
//	StateUnpublished  nobody answers — we should be publishing and are not
//
// Only StateUnpublished triggers recovery. A conflict is deliberately NOT
// recovered: the other host legitimately holds the name, so restarting the
// responder would re-probe, lose again, and flap. It is reported and left
// alone. When the conflict later clears, resolved is still backed off — so the
// state becomes StateUnpublished on the next probe and recovery fires then.
// That transition is precisely the "re-probe once the conflict clears"
// behaviour the bench found missing.
package nameguard

import (
	"context"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/mdns"
)

// State classifies what a single probe found on the wire.
type State string

const (
	// StateUnknown is the zero value — no probe has completed yet, or the
	// guard isn't running on this node. Callers must not read it as healthy.
	StateUnknown     State = ""
	StateOK          State = "ok"
	StateConflict    State = "conflict"
	StateUnpublished State = "unpublished"
)

// Status is the most recent verdict, readable by anything that wants to
// surface it (diag.health, logs). Zero value means "not running".
type Status struct {
	State State
	// Name is the name being guarded, e.g. "rasputin.local".
	Name string
	// OwnerIP is who answered, when anyone did. On StateConflict this is the
	// other cluster's control plane — the single most useful value here,
	// because it turns a mystery into an address the operator can go look at.
	OwnerIP string
	// Since is when the state last changed (not when it was last probed).
	Since time.Time
	// Recoveries counts responder restarts attempted in the current episode;
	// it resets once a probe comes back healthy.
	Recoveries int
}

// Resolver resolves a .local name to an IP. mdns.Resolve fits; injectable so
// the classification logic is unit-tested without a network.
type Resolver func(name string, timeout time.Duration) (string, error)

// LocalIPs returns this host's own non-loopback IPv4 addresses as strings.
// Injectable for the same reason.
type LocalIPs func() []string

// SystemLookup resolves a name through the host's ordinary resolver stack
// (on rasputin-os, resolved's stub). Used only to second-guess a silent mDNS
// probe — see Probe.
type SystemLookup func(name string) ([]string, error)

// Config configures Run. Zero fields take the defaults noted on each.
type Config struct {
	// Name is the mDNS name this node should own, e.g. "rasputin.local".
	Name string
	// Interval between probes. Default 60s.
	Interval time.Duration
	// ProbeTimeout bounds a single mDNS query. Default 3s.
	ProbeTimeout time.Duration
	// RecoverCmd is run via "sh -c" to restart the mDNS responder — on
	// rasputin-os, "systemctl restart systemd-resolved". Empty means
	// detect-and-report only, which is the correct behaviour anywhere
	// without systemd (the OpenWrt firewall) and in dev/CI.
	RecoverCmd string
	// MissesBeforeRecover is how many consecutive unpublished probes must
	// stack up before recovery fires. Default 2 — one probe can miss for
	// benign reasons (a dropped multicast packet, a busy responder), and
	// restarting the resolver on a single miss would be its own bug.
	MissesBeforeRecover int
	// MaxRecoveries caps restarts within one episode, so a recovery that
	// cannot work never becomes a restart loop. Default 3. Hitting the cap
	// is logged as needing a human and the guard falls back to reporting.
	MaxRecoveries int

	Resolve Resolver
	Local   LocalIPs
	// Lookup second-guesses a silent mDNS probe through the ordinary resolver
	// stack, so our own multicast loopback quirks never cause a needless
	// responder restart. Defaults to net.LookupHost.
	Lookup SystemLookup

	// runCmd executes the recovery command. Injected so tests exercise the
	// decision to recover without shelling out; defaults to "sh -c".
	runCmd func(ctx context.Context, cmd string) (string, error)
	// onStatus, when set, is called with every probe's Status. Tests observe
	// transitions through it rather than polling the package-level snapshot,
	// which would race across parallel runs.
	onStatus func(Status)
}

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = 60 * time.Second
	}
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = 3 * time.Second
	}
	if c.MissesBeforeRecover <= 0 {
		c.MissesBeforeRecover = 2
	}
	if c.MaxRecoveries <= 0 {
		c.MaxRecoveries = 3
	}
	if c.Resolve == nil {
		c.Resolve = mdns.Resolve
	}
	if c.Local == nil {
		c.Local = LocalIPv4s
	}
	if c.runCmd == nil {
		c.runCmd = shRun
	}
}

func shRun(ctx context.Context, cmd string) (string, error) {
	out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

// snapshot holds the latest Status for readers outside the loop. One guard runs
// per process, so a package-level cell is the whole of the coordination needed.
var snapshot atomic.Value // Status

// Snapshot returns the most recent Status. The zero Status (StateUnknown) means
// the guard is not running on this node — callers must distinguish that from
// healthy rather than defaulting it to OK.
func Snapshot() Status {
	if s, ok := snapshot.Load().(Status); ok {
		return s
	}
	return Status{}
}

// Run probes cfg.Name on an interval, repairing an unpublished name and
// reporting a conflicting one, until ctx is cancelled. It is safe to call with
// an empty RecoverCmd, in which case it only ever observes and logs.
func Run(ctx context.Context, cfg Config) {
	cfg.applyDefaults()
	if cfg.Name == "" {
		log.Printf("nameguard: no name to guard; not starting")
		return
	}
	log.Printf("nameguard: guarding %s every %s (recover=%t)", cfg.Name, cfg.Interval, cfg.RecoverCmd != "")

	var (
		misses     int
		recoveries int
		gaveUp     bool
		prev       = StateUnknown
		since      = time.Now().UTC()
	)
	timer := time.NewTimer(0) // first probe fires immediately
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			state, owner := probe(cfg.Name, cfg.ProbeTimeout, cfg.Resolve, cfg.Local, cfg.Lookup)
			if state != prev {
				since = time.Now().UTC()
				logTransition(cfg.Name, prev, state, owner)
				prev = state
			}

			switch state {
			case StateOK:
				// A healthy probe ends the episode: reset the budget so a
				// future conflict-then-clear cycle gets a full one again.
				misses, recoveries, gaveUp = 0, 0, false
			case StateConflict:
				// Not ours to fix — restarting would re-probe, lose, and flap.
				misses = 0
			case StateUnpublished:
				misses++
				if misses >= cfg.MissesBeforeRecover && cfg.RecoverCmd != "" {
					switch {
					case recoveries >= cfg.MaxRecoveries:
						if !gaveUp {
							log.Printf("nameguard: %s still unpublished after %d recovery attempts — "+
								"giving up and reporting only; this needs a human (%s)",
								cfg.Name, recoveries, cfg.RecoverCmd)
							gaveUp = true
						}
					default:
						recoveries++
						restartResponder(ctx, cfg, recoveries)
						misses = 0
					}
				}
			}

			st := Status{
				State:      state,
				Name:       cfg.Name,
				OwnerIP:    owner,
				Since:      since,
				Recoveries: recoveries,
			}
			snapshot.Store(st)
			if cfg.onStatus != nil {
				cfg.onStatus(st)
			}
			timer.Reset(cfg.Interval)
		}
	}
}

// Probe classifies a single lookup of name. Exported so diag tooling can ask
// the same question the loop asks, without starting a loop.
//
// The mDNS query is the primary signal because it is the only one that reveals
// WHO answers, which is what separates a conflict from silence. But it relies
// on our own responder's multicast answer coming back to our socket, so silence
// is not by itself proof that nothing is published. Before concluding the name
// is unpublished — the one verdict that triggers a responder restart — we
// second-guess it through the ordinary resolver stack. That path is also the
// one the operator experiences: the bench symptom was `ping rasputin.local` →
// "bad address". If the resolver can still map the name to one of our
// addresses, the name IS published and the mDNS silence was our own loopback,
// not a fault; restarting on that would be a self-inflicted outage.
func Probe(name string, timeout time.Duration, resolve Resolver, local LocalIPs) (State, string) {
	return probe(name, timeout, resolve, local, nil)
}

func probe(name string, timeout time.Duration, resolve Resolver, local LocalIPs, lookup SystemLookup) (State, string) {
	if resolve == nil {
		resolve = mdns.Resolve
	}
	if local == nil {
		local = LocalIPv4s
	}
	if lookup == nil {
		lookup = net.LookupHost
	}
	mine := local()
	ip, err := resolve(name, timeout)
	if err == nil && ip != "" {
		if containsIP(mine, ip) {
			return StateOK, ip
		}
		return StateConflict, ip
	}
	// Silent on the wire — corroborate before calling it unpublished.
	if addrs, lerr := lookup(name); lerr == nil {
		for _, a := range addrs {
			if containsIP(mine, a) {
				return StateOK, a
			}
		}
	}
	return StateUnpublished, ""
}

func containsIP(list []string, ip string) bool {
	for _, s := range list {
		if s == ip {
			return true
		}
	}
	return false
}

func restartResponder(ctx context.Context, cfg Config, attempt int) {
	log.Printf("nameguard: %s is unpublished — restarting the mDNS responder (attempt %d): %s",
		cfg.Name, attempt, cfg.RecoverCmd)
	out, err := cfg.runCmd(ctx, cfg.RecoverCmd)
	if err != nil {
		log.Printf("nameguard: recovery command failed: %v (%s)", err, strings.TrimSpace(out))
	}
}

// logTransition writes the operator-facing line. These are deliberately
// explicit: the whole failure class exists because the system gave no signal,
// and the symptom an operator actually sees (a certificate error) points
// nowhere near the cause.
func logTransition(name string, from, to State, owner string) {
	switch to {
	case StateOK:
		if from == StateUnknown {
			log.Printf("nameguard: %s resolves to us — OK", name)
		} else {
			log.Printf("nameguard: %s resolves to us again — recovered from %s", name, from)
		}
	case StateConflict:
		log.Printf("nameguard: NAME CONFLICT — %s is answered by %s, which is not us. "+
			"Another Rasputin cluster is on this network and owns the name. This node is "+
			"unreachable by name until that host leaves, and downstream failures will look "+
			"like certificate errors rather than a name clash. Give one cluster a different "+
			"cluster-id and re-provision it.", name, owner)
	case StateUnpublished:
		log.Printf("nameguard: %s is not published by anyone (was %s) — the responder has "+
			"most likely backed off after losing a probe and will not retry on its own", name, from)
	}
}

// LocalIPv4s returns this host's non-loopback IPv4 addresses.
func LocalIPv4s() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() {
			out = append(out, ip4.String())
		}
	}
	return out
}
