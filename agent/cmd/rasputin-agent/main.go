package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/docker"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/health"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/host"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/hostsync"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/ids"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/openwrt"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/sdnotify"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/system"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/tailscale"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// rasputin-agent: runs on every Rasputin node (control plane, firewall, compute).
// Dials the control-plane NATS broker outbound; never listens.
//
// Architecture: projects/rasputin/design/control-plane/architecture.md
//   in the geekdojo-brain.

// AgentVersion is the version the agent reports on registration/heartbeat
// (surfaced as the node's control-plane software version). A var, not a const,
// so the release build can stamp the real version via
// `-ldflags -X main.AgentVersion=<version>` (build-release.sh). Unstamped
// local/dev builds report this default.
var AgentVersion = "0.0.1-dev"

const heartbeatInterval = 10 * time.Second

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	nodeID := envOr("RASPUTIN_NODE_ID", "node-dev")
	natsURL := envOr("RASPUTIN_NATS_URL", nats.DefaultURL)
	roleStr := envOr("RASPUTIN_NODE_ROLE", string(proto.RoleCompute))
	role := proto.NodeRole(roleStr)
	if !proto.ValidRole(role) {
		log.Fatalf("rasputin-agent: invalid RASPUTIN_NODE_ROLE %q; expected one of %v",
			roleStr, proto.AllRoles)
	}

	// All backend subsystems (apps, openwrt, updater, tailscale, bmc) keep
	// state in subdirs of one state dir. Resolve and create it up front so
	// a bad location fails loudly here — on a read-only rootfs with cwd=/
	// the relative dev default fails with EROFS, which used to surface as
	// a confusing mkdir error from whichever backend touched it first.
	stateDir := agentStateDir(nodeID)
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		log.Fatalf("rasputin-agent: create state dir %s: %v (set RASPUTIN_AGENT_STATE_DIR to a writable absolute path)", stateDir, err)
	}
	log.Printf("rasputin-agent: state dir %s", stateDir)

	// Bus join token (RASPUTIN_CP_JOIN_TOKEN): presented to the api's
	// auth-callout so it can mint a per-node scoped credential. Empty on a
	// controlplane (trusted via loopback) and harmless when the server has no
	// auth enabled. See agent/internal/bus.Connect.
	joinToken := os.Getenv("RASPUTIN_CP_JOIN_TOKEN")
	// Storage snapshot paths for the register event: statfs the same
	// filesystem the disk metric measures (the persistent partition — never
	// "/", the read-only squashfs), and read the growpart breadcrumb from the
	// persistent root (stateDir's parent on the appliance layout).
	storageDataPath := envOr("RASPUTIN_DISK_METRIC_PATH", stateDir)
	growpartLogPath := envOr("RASPUTIN_GROWPART_LOG", filepath.Join(filepath.Dir(stateDir), "growpart.log"))
	// BMC host — every agent runs one (bmc-settings.md §4-5). HARD
	// on/off (bmc.md §2a): boot resolves the env pin (RASPUTIN_BMC_BACKEND,
	// the dev/bench path — selecting a backend IS the host opt-in), else
	// the persisted settings-pushed selection, else off: nothing
	// registers or advertises until Settings pushes a selection.
	// Constructed before the bus connects so the first registration can
	// advertise bmc-targets; the configure handler attaches after.
	bmcHost, err := bmc.NewHost(nodeID, filepath.Join(stateDir, "bmc"),
		os.Getenv("RASPUTIN_BMC_BACKEND"), bmc.Config{
			StateDir:       filepath.Join(stateDir, "bmc"),
			BitScopeDev:    os.Getenv("RASPUTIN_BMC_BITSCOPE_DEV"),
			BitScopeUnlock: os.Getenv("RASPUTIN_BMC_BITSCOPE_UNLOCK"),
			BitScopeMap:    os.Getenv("RASPUTIN_BMC_BITSCOPE_MAP"),
			MockTargets:    splitCSV(os.Getenv("RASPUTIN_BMC_MOCK_TARGETS")),
		})
	if err != nil {
		log.Fatalf("rasputin-agent: bmc host: %v", err)
	}
	reregister := func(c *nats.Conn) {
		publishRegistered(c, nodeID, role, host.Storage(storageDataPath, growpartLogPath), bmcHost.Advertisement())
	}
	// Retry the initial NATS connect instead of exiting on failure. On real
	// hardware the firewall can boot before the control plane (it IS the
	// network), so rasputin.local may not resolve yet at startup. Exiting let
	// procd exhaust its respawn budget and the agent never recovered (bench
	// 2026-06-18). Loop here with capped backoff until the control plane
	// appears; only a shutdown signal aborts.
	var nc *nats.Conn
	for attempt := 1; ; attempt++ {
		var cerr error
		nc, cerr = bus.Connect(natsURL, nodeID, joinToken, reregister)
		if cerr == nil {
			break
		}
		wait := min(time.Duration(attempt)*2*time.Second, 30*time.Second)
		log.Printf("rasputin-agent: NATS connect to %s failed (%v); retry %d in %s (control plane may still be coming up)", natsURL, cerr, attempt, wait)
		select {
		case <-ctx.Done():
			log.Fatalf("rasputin-agent: aborted waiting for NATS: %v", ctx.Err())
		case <-time.After(wait):
		}
	}
	defer func() { _ = nc.Drain() }()

	pingSubj := proto.NodeCmdSubject(nodeID, "diag.ping")
	pingSub, err := nc.Subscribe(pingSubj, func(m *nats.Msg) {
		handlePing(nodeID, m)
	})
	if err != nil {
		log.Fatalf("rasputin-agent: subscribe %s: %v", pingSubj, err)
	}
	defer func() { _ = pingSub.Unsubscribe() }()
	log.Printf("rasputin-agent: subscribed to %s", pingSubj)

	// diag.health — role-aware health probe the node.update saga uses as its
	// post-reboot commit/rollback gate (richer than diag.ping's liveness).
	healthSubj := proto.NodeCmdSubject(nodeID, "diag.health")
	healthSub, err := nc.Subscribe(healthSubj, func(m *nats.Msg) {
		handleHealth(ctx, nodeID, role, m)
	})
	if err != nil {
		log.Fatalf("rasputin-agent: subscribe %s: %v", healthSubj, err)
	}
	defer func() { _ = healthSub.Unsubscribe() }()
	log.Printf("rasputin-agent: subscribed to %s", healthSubj)

	rebootSub, err := system.RegisterRebootHandler(nc, nodeID, reregister)
	if err != nil {
		log.Fatalf("rasputin-agent: register reboot handler: %v", err)
	}
	defer func() { _ = rebootSub.Unsubscribe() }()
	log.Printf("rasputin-agent: subscribed to %s", proto.NodeCmdSubject(nodeID, "system.reboot"))

	// Docker handlers — on compute and controlplane agents (the latter hosts
	// the api's own sidecars in Tier 2). Picks `docker` if the CLI is on
	// PATH, otherwise mocks. Force via RASPUTIN_DOCKER_BACKEND=mock|docker.
	if role == proto.RoleCompute || role == proto.RoleControlPlane {
		appsDir := filepath.Join(stateDir, "apps")
		backendChoice := envOr("RASPUTIN_DOCKER_BACKEND", autodetectDockerBackend())

		var dockerBackend docker.Backend
		switch backendChoice {
		case "docker":
			cb, err := docker.NewComposeBackend(appsDir)
			if err != nil {
				log.Fatalf("rasputin-agent: docker compose backend: %v", err)
			}
			dockerBackend = cb
		case "mock":
			mb, err := docker.NewMockBackend(appsDir)
			if err != nil {
				log.Fatalf("rasputin-agent: docker mock backend: %v", err)
			}
			dockerBackend = mb
		default:
			log.Fatalf("rasputin-agent: unknown RASPUTIN_DOCKER_BACKEND %q (expected docker|mock)", backendChoice)
		}

		dockerSubs, err := docker.RegisterHandlers(nc, nodeID, dockerBackend)
		if err != nil {
			log.Fatalf("rasputin-agent: register docker handlers: %v", err)
		}
		defer func() {
			for _, sub := range dockerSubs {
				_ = sub.Unsubscribe()
			}
		}()
	}

	// Firewall handlers — only on firewall-role agents. Picks the real uci
	// backend when the agent is actually on OpenWrt (uci on PATH AND
	// /etc/config/firewall present), the file-backed mock otherwise (state
	// under $RASPUTIN_AGENT_STATE_DIR/openwrt/). Force via
	// RASPUTIN_UCI_BACKEND=uci|mock.
	if role == proto.RoleFirewall {
		backendChoice := envOr("RASPUTIN_UCI_BACKEND", autodetectUCIBackend())
		var uciClient openwrt.UCIClient
		switch backendChoice {
		case "uci":
			real, err := openwrt.NewRealClient(filepath.Join(stateDir, "openwrt"))
			if err != nil {
				log.Fatalf("rasputin-agent: openwrt uci backend: %v", err)
			}
			uciClient = real
		case "mock":
			mock, err := openwrt.NewMockClient(filepath.Join(stateDir, "openwrt"))
			if err != nil {
				log.Fatalf("rasputin-agent: openwrt mock: %v", err)
			}
			uciClient = mock
		default:
			log.Fatalf("rasputin-agent: unknown RASPUTIN_UCI_BACKEND %q (expected uci|mock)", backendChoice)
		}
		log.Printf("rasputin-agent: uci backend=%s", backendChoice)
		fwSubs, err := openwrt.RegisterHandlers(nc, nodeID, uciClient)
		if err != nil {
			log.Fatalf("rasputin-agent: register firewall handlers: %v", err)
		}
		defer func() {
			for _, sub := range fwSubs {
				_ = sub.Unsubscribe()
			}
		}()

		// IDS alert tailer — tails snort3's alert_fast log (path comes
		// from the firewall image's /etc/config/snort log_dir UCI option;
		// 99-rasputin seeds it to /var/log/snort) and publishes one event
		// per parsed alert on rasputin.node.<id>.evt.ids.alert. Only
		// firewall-role agents start this loop (compute/controlplane
		// agents don't run snort and have no log to tail). The path
		// override is honored via RASPUTIN_IDS_ALERT_LOG for dev/test;
		// blank means use the default in the ids package.
		go ids.Run(ctx, nc, nodeID, os.Getenv("RASPUTIN_IDS_ALERT_LOG"))
	}

	// Publish rasputin.local into a local resolver dir (a dnsmasq hostsdir) so
	// clients on this box that can't do mDNS themselves can still resolve the
	// control plane. The firewall sets RASPUTIN_CP_HOSTS_DIR for exactly this:
	// musl has no nss-mdns, so tailscaled couldn't otherwise reach the mesh
	// login server at https://rasputin.local. Env-gated — unset on rasputin-os
	// (systemd-resolved does mDNS natively) → no-op. The agent already resolves
	// the name over mDNS for NATS; this surfaces it to the whole box and
	// self-heals when the control plane's address changes.
	if hostsDir := os.Getenv("RASPUTIN_CP_HOSTS_DIR"); hostsDir != "" {
		// RASPUTIN_CP_HOSTS_RELOAD_CMD re-reads the resolver after a change —
		// dnsmasq doesn't auto-watch addn-hosts files. The firewall sets it to
		// "/etc/init.d/dnsmasq reload".
		go hostsync.Run(ctx, "rasputin.local", hostsDir, 30*time.Second, os.Getenv("RASPUTIN_CP_HOSTS_RELOAD_CMD"), nil)
	}

	// OS update handlers — every node gets them. The firewall (OpenWrt, no
	// RAUC) uses the custom A/B backend; compute/controlplane use `rauc` when
	// the CLI is on PATH; everything else falls back to mock. Force via
	// RASPUTIN_UPDATE_BACKEND=rauc|openwrt-ab|mock.
	{
		updaterDir := filepath.Join(stateDir, "updater")
		backendChoice := envOr("RASPUTIN_UPDATE_BACKEND", autodetectUpdaterBackend(role))

		var upBackend updater.Backend
		switch backendChoice {
		case "rauc":
			rb, err := updater.NewRAUCBackend(updaterDir)
			if err != nil {
				log.Fatalf("rasputin-agent: rauc backend: %v", err)
			}
			rb.SetMuteHook(system.MutedAtomic())
			// Trust the Mesh CA when pulling bundles — the api serves them
			// over its mesh-CA HTTPS leaf, which the system roots don't cover.
			rb.SetCABundle(tailscale.CABundlePath())
			upBackend = rb
		case "openwrt-ab":
			ab, err := updater.NewOpenWrtABBackend(updaterDir)
			if err != nil {
				log.Fatalf("rasputin-agent: openwrt-ab backend: %v", err)
			}
			ab.SetMuteHook(system.MutedAtomic())
			ab.SetCABundle(tailscale.CABundlePath())
			upBackend = ab
		case "mock":
			mb, err := updater.NewMockBackend(updaterDir)
			if err != nil {
				log.Fatalf("rasputin-agent: updater mock: %v", err)
			}
			mb.SetMuteHook(system.MutedAtomic())
			// Reregister after a simulated reboot so the api's saga step 6
			// unblocks. Real rauc reboots the whole agent process, so the
			// fresh process publishes its own registration on connect.
			mb.SetReregisterHook(func() { reregister(nc) })
			upBackend = mb
		default:
			log.Fatalf("rasputin-agent: unknown RASPUTIN_UPDATE_BACKEND %q (expected rauc|openwrt-ab|mock)", backendChoice)
		}
		upSubs, err := updater.RegisterHandlers(nc, nodeID, upBackend)
		if err != nil {
			log.Fatalf("rasputin-agent: register update handlers: %v", err)
		}
		defer func() {
			for _, sub := range upSubs {
				_ = sub.Unsubscribe()
			}
		}()
		log.Printf("rasputin-agent: update backend=%s", upBackend.Name())

		// On the firewall (openwrt-ab), reset the running slot's GRUB boot-counter
		// now that the agent is up — the firewall's equivalent of compute's
		// rasputin-mark-good.service. REQUIRED: grub.cfg consumes one TRY per boot,
		// so without this a second ordinary reboot would skip the (already-tried)
		// running slot and fall through to the stale other slot. Backgrounded +
		// best-effort; an error (e.g. ESP not mounted) is logged, never fatal.
		if ab, ok := upBackend.(*updater.OpenWrtABBackend); ok {
			go func() {
				if err := ab.MarkGoodOnBoot(ctx); err != nil {
					log.Printf("rasputin-agent: openwrt-ab boot mark-good: %v", err)
				}
			}()
		}
	}

	// Tailscale handlers — every node joins the tailnet (per
	// design/control-plane/mesh.md §5). Picks the real backend if the
	// tailscale binary is on PATH, otherwise mocks. Force via
	// RASPUTIN_TAILSCALE_BACKEND=mock|tailscale.
	{
		backendChoice := envOr("RASPUTIN_TAILSCALE_BACKEND", autodetectTailscaleBackend())
		var tsBackend tailscale.Backend
		switch backendChoice {
		case "tailscale":
			rb, err := tailscale.NewRealBackend()
			if err != nil {
				log.Fatalf("rasputin-agent: tailscale real backend: %v", err)
			}
			tsBackend = rb
		case "mock":
			mb, err := tailscale.NewMockBackend(filepath.Join(stateDir, "tailscale"))
			if err != nil {
				log.Fatalf("rasputin-agent: tailscale mock backend: %v", err)
			}
			tsBackend = mb
		default:
			log.Fatalf("rasputin-agent: unknown RASPUTIN_TAILSCALE_BACKEND %q (expected tailscale|mock)", backendChoice)
		}
		tsSubs, err := tailscale.RegisterHandlers(nc, nodeID, tsBackend)
		if err != nil {
			log.Fatalf("rasputin-agent: register tailscale handlers: %v", err)
		}
		defer func() {
			for _, sub := range tsSubs {
				_ = sub.Unsubscribe()
			}
		}()
		log.Printf("rasputin-agent: tailscale backend=%s", tsBackend.Name())
	}

	// BMC handlers — the backend itself was constructed before the bus
	// connect (see above) so registration could advertise bmc-targets.
	// Attach subscribes bmc.configure on every agent (a Settings push can
	// turn BMC on) and the power/SoL handlers when a backend is active.
	if err := bmcHost.Attach(nc, func() { reregister(nc) }); err != nil {
		log.Fatalf("rasputin-agent: bmc host attach: %v", err)
	}
	defer bmcHost.Shutdown()
	if bmcHost.Active() {
		adv := bmcHost.Advertisement()
		log.Printf("rasputin-agent: bmc backend=%s (host, targets=%d, pinned=%t)", bmcHost.Name(), len(adv.Targets), adv.Pinned)
	}

	go runHeartbeats(ctx, nc, nodeID)
	// Disk metric measures the persistent data partition, not "/" (the
	// read-only squashfs rootfs, ~100% by design on the appliance). Default to
	// the agent's own state dir — on the appliance that's
	// /var/lib/rasputin/agent-state, the same partition as Docker + obs data —
	// and statfs is filesystem-level. Overridable if a node's layout differs.
	go metrics.Run(ctx, nc, nodeID, storageDataPath, host.Uptime)

	// systemd integration (Buildroot nodes; procd on OpenWrt has no
	// NOTIFY_SOCKET so both calls no-op there). The liveness probe is
	// deliberately scheduling-only: a down NATS connection means the api
	// is restarting and the agent's reconnect loop IS healthy behavior —
	// it must not stop the watchdog pets. See internal/sdnotify.
	sdnotify.Ready()
	sdnotify.StartWatchdog(ctx, func(context.Context) error { return nil })

	<-ctx.Done()
	log.Println("rasputin-agent: shutting down")
}

func publishRegistered(nc *nats.Conn, nodeID string, role proto.NodeRole, storage *proto.StorageInfo, bmcAdv *bmc.Advertisement) {
	meta := map[string]any{}
	if cidr := host.PrimaryLanCIDR(); cidr != "" {
		// Carried in Metadata rather than as a top-level field so the
		// shared proto.NodeRegisteredEvt stays small / additive: anything
		// that needs the value reads metadata["primaryLanCidr"]. The api's
		// mesh enroll-defaults endpoint surfaces it to the UI.
		meta["primaryLanCidr"] = cidr
	}
	var caps []string
	if bmcAdv != nil {
		// This node hosts an active BMC backend: advertise the reachable
		// targets so the api/UI gate power + console per-node (bmc.md
		// §2a), the applied settings-config hash so the api can re-push
		// after a miss or reflash, and the env-pin marker so Settings
		// renders read-only (bmc-settings.md §4-5). BMC-off nodes
		// advertise nothing — hard off.
		caps = append(caps, proto.CapabilityBMCTargets)
		meta[proto.MetadataBMCTargets] = bmcAdv.Targets
		if bmcAdv.ConfigHash != "" {
			meta[proto.MetadataBMCConfigHash] = bmcAdv.ConfigHash
		}
		if bmcAdv.Pinned {
			meta[proto.MetadataBMCConfigPinned] = true
		}
	}
	ev := proto.NodeRegisteredEvt{
		NodeID:       nodeID,
		Role:         role,
		Hostname:     host.Hostname(),
		AgentVersion: AgentVersion,
		ImageVersion: host.ImageVersion(),
		// The agent ships per-arch (one binary per OS image arch), so the
		// compile-time GOARCH is the node's CPU arch.
		Architecture: runtime.GOARCH,
		Capabilities: caps,
		Metadata:     meta,
		Storage:      storage,
		Ts:           time.Now().UTC(),
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		log.Printf("rasputin-agent: marshal registered: %v", err)
		return
	}
	if err := nc.Publish(proto.NodeRegisteredSubject(nodeID), payload); err != nil {
		log.Printf("rasputin-agent: publish registered: %v", err)
		return
	}
	log.Printf("rasputin-agent: registered as %s (role=%s)", nodeID, role)
}

func runHeartbeats(ctx context.Context, nc *nats.Conn, nodeID string) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	subj := proto.NodeHeartbeatSubject(nodeID)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if system.IsMuted() {
				continue
			}
			hb := proto.HeartbeatEvt{
				NodeID:       nodeID,
				Uptime:       host.Uptime().String(),
				AgentVersion: AgentVersion,
				Ts:           time.Now().UTC(),
			}
			payload, err := json.Marshal(hb)
			if err != nil {
				log.Printf("rasputin-agent: marshal heartbeat: %v", err)
				continue
			}
			if err := nc.Publish(subj, payload); err != nil {
				log.Printf("rasputin-agent: publish heartbeat: %v", err)
			}
		}
	}
}

func handlePing(nodeID string, m *nats.Msg) {
	var cmd proto.DiagPingCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		log.Printf("rasputin-agent: ping: bad cmd: %v", err)
		return
	}
	pong := proto.DiagPongEvt{
		JobID:    cmd.JobID,
		NodeID:   nodeID,
		Hostname: host.Hostname(),
		Uptime:   host.Uptime().String(),
		Ts:       time.Now().UTC(),
	}
	payload, err := json.Marshal(pong)
	if err != nil {
		log.Printf("rasputin-agent: ping: marshal pong: %v", err)
		return
	}
	if err := m.Respond(payload); err != nil {
		log.Printf("rasputin-agent: ping: respond: %v", err)
	}
}

func handleHealth(ctx context.Context, nodeID string, role proto.NodeRole, m *nats.Msg) {
	var cmd proto.DiagHealthCmd
	_ = json.Unmarshal(m.Data, &cmd) // JobID is optional; ignore decode errors
	// Bound the checks so a hung command can't hold the reply past the saga's
	// health-check timeout.
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ack := health.Check(cctx, role)
	ack.JobID = cmd.JobID
	ack.NodeID = nodeID
	payload, err := json.Marshal(ack)
	if err != nil {
		log.Printf("rasputin-agent: health: marshal ack: %v", err)
		return
	}
	if err := m.Respond(payload); err != nil {
		log.Printf("rasputin-agent: health: respond: %v", err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// splitCSV splits a comma-separated env value, trimming whitespace and
// dropping empty entries; "" yields nil.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// agentStateDir resolves the agent's state directory.
// $RASPUTIN_AGENT_STATE_DIR is used verbatim when set — deployed images
// set it to an absolute path on persistent storage (one agent per host,
// so no per-node suffix). The dev default is ./agent-state/<nodeID>
// relative to cwd; the nodeID suffix keeps multiple dev agents started
// from the same repo checkout apart.
func agentStateDir(nodeID string) string {
	if v := os.Getenv("RASPUTIN_AGENT_STATE_DIR"); v != "" {
		return v
	}
	return filepath.Join("agent-state", nodeID)
}

// autodetectDockerBackend returns "docker" if the docker CLI is on PATH,
// "mock" otherwise. Lets the agent come up cleanly on machines without
// Docker Desktop installed.
func autodetectDockerBackend() string {
	if _, err := exec.LookPath("docker"); err == nil {
		return "docker"
	}
	return "mock"
}

// autodetectUpdaterBackend picks the OS-update backend. The firewall runs
// OpenWrt (no RAUC package exists for it) and updates via the custom A/B
// backend — selected when the node is firewall-role AND actually on OpenWrt
// (/etc/config/firewall present, same signal autodetectUCIBackend uses). Every
// other node uses `rauc` when the CLI is on PATH, else mock. The env override
// (RASPUTIN_UPDATE_BACKEND) forces any of rauc|openwrt-ab|mock.
func autodetectUpdaterBackend(role proto.NodeRole) string {
	if role == proto.RoleFirewall {
		if _, err := os.Stat("/etc/config/firewall"); err == nil {
			return "openwrt-ab"
		}
		return "mock"
	}
	if _, err := exec.LookPath("rauc"); err == nil {
		return "rauc"
	}
	return "mock"
}

// autodetectUCIBackend returns "uci" when the agent is running on a real
// OpenWrt system — the uci CLI on PATH AND /etc/config/firewall present —
// "mock" otherwise. Mirrors autodetectTailscaleBackend; the env-var
// override (RASPUTIN_UCI_BACKEND) lets the user force one or the other.
// The config-file check matters: a dev box could have a stray `uci`
// binary installed, but only a real OpenWrt root has /etc/config/firewall.
func autodetectUCIBackend() string {
	return autodetectUCIBackendAt("/etc/config/firewall")
}

// autodetectUCIBackendAt is the testable core — the firewall config path
// is a parameter so tests don't need a real /etc/config/firewall.
func autodetectUCIBackendAt(firewallConfig string) string {
	if _, err := exec.LookPath("uci"); err != nil {
		return "mock"
	}
	if _, err := os.Stat(firewallConfig); err != nil {
		return "mock"
	}
	return "uci"
}

// autodetectTailscaleBackend returns "tailscale" if the tailscale CLI is
// on PATH and a working tailscaled is reachable, "mock" otherwise. v0
// only checks for the binary — `tailscale status` would prove tailscaled
// is alive but adds 1-2s to startup; we let the first enroll fail loudly
// if the daemon isn't running.
func autodetectTailscaleBackend() string {
	if _, err := exec.LookPath("tailscale"); err == nil {
		return "tailscale"
	}
	return "mock"
}
