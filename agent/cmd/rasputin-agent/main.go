package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/clusterdns"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/configfault"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/docker"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/health"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/host"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/hostsync"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/ids"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/nameguard"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/openwrt"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/proxy"
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
	// One-shot commands (help, version, verify-artifact) run and exit before
	// any daemon setup. Both shipping units start the agent with no arguments,
	// so this is inert on the boot path. See cli.go.
	exitCLI()

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	nodeID := envOr("RASPUTIN_NODE_ID", "node-dev")
	natsURL := envOr("RASPUTIN_NATS_URL", nats.DefaultURL)
	// Operator-configuration mistakes are survived and REPORTED, never fatal.
	// agent/internal/configfault carries the full reasoning; the short version
	// is that Restart=always + a hand-edited node.env + a read-only rootfs turn
	// any startup exit into a permanently unreachable node, and the agent is
	// the only repair path we have. See #89.
	var faults configfault.Set

	roleStr := envOr("RASPUTIN_NODE_ROLE", string(proto.RoleCompute))
	role := proto.NodeRole(roleStr)
	if !proto.ValidRole(role) {
		// ⚠️ THE ONE FALLBACK THAT ASSERTS SOMETHING, and it is forced.
		//
		// Passing the bad value through would be more honest — we would claim
		// no role at all — but the api REJECTS a registration whose role fails
		// proto.ValidRole (inventory/service.go), so the node would never
		// appear and we would be back to an invisible box by another route.
		// Falling back to the default keeps it visible; the fault recorded
		// alongside is what stops that from being a silent lie.
		//
		// Known cost, worth stating plainly: role selects the health battery
		// and the updater backend autodetect, so a mis-roled controlplane is
		// gated on the compute battery. That is a weaker gate than it should
		// have — but it applies to a node whose node.env is already broken and
		// which is now loudly saying so, and it is strictly better than a node
		// nobody can reach at all.
		faults.Reject("RASPUTIN_NODE_ROLE", roleStr, rolesAsStrings(),
			fmt.Sprintf("this node is running as %q instead; its health checks and update backend are chosen for that role", proto.RoleCompute))
		role = proto.RoleCompute
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

	// Update-path fault injection (updater/fault.go). Resolved once, here.
	// updater.Arm cannot fail and cannot exit — an unrecognised value, or any
	// value at all on a released image, logs loudly and arms nothing. It used
	// to be fatal, which meant a typo in hand-edited node.env crash-looped the
	// agent forever against Restart=always. See updater.Arm.
	updateFault := updater.Arm(host.ImageVersion())
	updateFault.Announce()

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
	bmcKind := os.Getenv("RASPUTIN_BMC_BACKEND")
	bmcHost, err := bmc.NewHost(nodeID, filepath.Join(stateDir, "bmc"),
		bmcKind, bmcConfigFromEnv(filepath.Join(stateDir, "bmc")))
	if err != nil {
		// THE SITE THAT WAS PROVEN ON HARDWARE (tp-cp1, 2026-07-28): an env pin
		// naming a backend this image doesn't carry used to be fatal, and took
		// metrics, updates, mesh and docker down with it — on the controlplane,
		// whose api kept serving a UI for a node that no longer had an agent.
		//
		// Only an unknown NAME degrades: hard-off is already the documented
		// safe default state (bmc.md §2a) and the persisted-selection path next
		// door has always come up off on a bad read. A backend that exists but
		// fails to CONSTRUCT is a real environment problem and stays fatal —
		// that is a different bug with a different fix.
		if errors.Is(err, bmc.ErrUnknownBackend) {
			faults.Reject("RASPUTIN_BMC_BACKEND", bmcKind, append([]string{bmc.BackendNone}, bmc.Names()...),
				"BMC is OFF on this node — no power control, no serial console")
			bmcHost, err = bmc.NewHost(nodeID, filepath.Join(stateDir, "bmc"), bmc.BackendNone,
				bmcConfigFromEnv(filepath.Join(stateDir, "bmc")))
		}
		if err != nil {
			log.Fatalf("rasputin-agent: bmc host: %v", err)
		}
	}
	// Registration is gated until every command handler is subscribed:
	// the registration event advertises capabilities (bmc-targets among
	// them) and the api acts on it immediately — the BMC status seed's
	// first sweep raced the handler subscriptions and got "no
	// responders" (dev bench 2026-07-26). handlersReady flips after the
	// full handler setup below, which then registers explicitly;
	// reconnects (handlers long since up) re-register as before.
	var handlersReady atomic.Bool
	// How this node answers "which address do others reach me on". The default
	// is the default-route heuristic, which is right everywhere EXCEPT the
	// router — see the openwrt override below and
	// geekdojo/geekdojo-brain#193. Assigned before the first registration:
	// registration is gated on handlersReady, which flips after the backend
	// selection that may replace this.
	lanAddr := func() (ip, cidr string) { return host.PrimaryLANIP(), host.PrimaryLanCIDR() }
	reregister := func(c *nats.Conn) {
		if !handlersReady.Load() {
			return
		}
		publishRegistered(c, nodeID, role, host.Storage(storageDataPath, growpartLogPath), bmcHost.Advertisement(), &faults, lanAddr)
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
		handleHealth(ctx, nodeID, role, m, updateFault == updater.FaultFailHealth)
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
			faults.Reject("RASPUTIN_DOCKER_BACKEND", backendChoice, []string{"docker", "mock"},
				"app deploy/start/stop is disabled on this node")
		}

		if dockerBackend != nil {
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

		// Node-local reverse proxy (ADR-0004 §1/§6/§9): the agent runs the stock
		// caddy binary, receives per-app TLS leaves + route metadata, and pushes
		// the Caddy config (Host-routes to loopback, TLS from the leaves) via the
		// admin API. Listen addresses: the node's LAN IP (host) and tailnet IP
		// (tailscale). Best-effort — a proxy failure never blocks the agent.
		leafStore := proxy.NewLeafStore(filepath.Join(stateDir, "proxy"))
		reconciler := proxy.NewReconciler(leafStore, proxy.CaddyAdminAddr,
			func() string { return nodeTailnetIP() },
			host.PrimaryLANIP)
		if caddyBin := caddyBinary(); caddyBin != "" {
			go reconciler.RunCaddy(ctx, caddyBin)
		} else {
			log.Printf("rasputin-agent: caddy binary not found on PATH — node-local proxy disabled (leaves still delivered)")
		}
		leafSub, err := proxy.RegisterHandlers(nc, nodeID, leafStore, reconciler.Reconcile)
		if err != nil {
			log.Fatalf("rasputin-agent: register proxy handlers: %v", err)
		}
		defer func() { _ = leafSub.Unsubscribe() }()
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
			lanAddr = uciLANAddr(real.LANAddress, lanAddr)
		case "mock":
			mock, err := openwrt.NewMockClient(filepath.Join(stateDir, "openwrt"))
			if err != nil {
				log.Fatalf("rasputin-agent: openwrt mock: %v", err)
			}
			uciClient = mock
		default:
			faults.Reject("RASPUTIN_UCI_BACKEND", backendChoice, []string{"uci", "mock"},
				"firewall configuration is disabled on this node")
		}
		if uciClient != nil {
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
		}

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
		go hostsync.Run(ctx, clusterName(), hostsDir, 30*time.Second, os.Getenv("RASPUTIN_CP_HOSTS_RELOAD_CMD"), nil)
	}

	// Keep our own mDNS name published, and say so loudly when another cluster
	// has taken it. systemd-resolved backs off permanently if it loses the
	// boot-time probe — it neither renames nor reports — so a control plane
	// that came up beside another Rasputin is unreachable by name for its
	// entire uptime, and the operator's only clue is a downstream certificate
	// error. See internal/nameguard for the full failure signature.
	//
	// Controlplane-only: it is the role that publishes the shared name (every
	// other role takes its node id as hostname). RASPUTIN_MDNS_RECOVER_CMD is
	// unset anywhere without systemd — the OpenWrt firewall, dev, CI — which
	// degrades the guard to detect-and-report, the correct behaviour there.
	if role == proto.RoleControlPlane {
		go nameguard.Run(ctx, nameguard.Config{
			Name:       envOr("RASPUTIN_CP_MDNS_NAME", clusterName()),
			RecoverCmd: os.Getenv("RASPUTIN_MDNS_RECOVER_CMD"),
		})
	}

	// Keep the cluster's own names resolvable without depending on the DNS the
	// DHCP lease handed out. A node otherwise resolves <cluster>.local by mDNS,
	// where the AAAA query times out on an IPv4-only cluster; tailscaled reads
	// that as a failed lookup of its control URL, falls back to Tailscale's
	// public bootstrap DNS (which cannot resolve a .local name), and never
	// rejoins the mesh. See internal/clusterdns for the full signature.
	//
	// The address comes off the live bus socket, never from a name lookup —
	// resolving a name is precisely what we are here to repair.
	//
	// The control plane is excluded, and NOT for the reason first given here
	// ("it is the nameserver"). That reasoning was wrong: the CP's own
	// tailscaled does have to resolve <cluster>.local to reach Headscale on
	// :18080, and on e3bench it failed doing so — mDNS answered the CP's own
	// name with six addresses including docker-bridge and link-local ones, and
	// dialling fe80:: without a zone index errors outright.
	//
	// It is excluded because THIS MECHANISM CANNOT FIX IT. systemd-resolved
	// short-circuits its own hostname and answers from its interface list,
	// ignoring routing domains entirely. Measured on e3bench 2026-08-30 with
	// the drop-in applied, querying the stub the way Go does:
	//
	//	A    e3bench.local -> 100.64.0.1, 172.17.0.1     (not the LAN IP)
	//	AAAA e3bench.local -> fe80::..., fe80::..., fe80::...
	//
	// Identical with and without the drop-in. Do not "fix" the control plane by
	// deleting this exclusion — it was tried, it changes nothing, and the test
	// that would have caught the mistake is a live resolver, not a unit test.
	//
	// The fault it leaves is real but transient: the CP retried into a usable
	// address on its own after 2m20s. A genuine fix has to remove the name from
	// the CP's control URL altogether (the mesh leaf already covers 127.0.0.1),
	// which is an enrolment change with migration consequences and out of
	// proportion to minutes of downtime per CP reboot. Tracked on
	// geekdojo/geekdojo-brain#202.
	if role != proto.RoleControlPlane {
		if cpHost, _, aerr := net.SplitHostPort(nc.ConnectedAddr()); aerr != nil {
			log.Printf("clusterdns: cannot read the bus peer address (%v); not starting", aerr)
		} else {
			go clusterdns.Run(ctx, clusterdns.Config{
				ClusterID: clusterID(),
				ServerIP:  cpHost,
				Dir:       envOr("RASPUTIN_RESOLVED_DROPIN_DIR", clusterdns.DefaultDir),
			})
		}
	}

	// OS update handlers — every node gets them. The firewall (OpenWrt, no
	// RAUC) uses the custom A/B backend; compute/controlplane use `rauc` when
	// the CLI is on PATH; everything else falls back to mock. Force via
	// RASPUTIN_UPDATE_BACKEND=rauc|openwrt-ab|mock.
	{
		updaterDir := updaterStateDir(stateDir)
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
			faults.Reject("RASPUTIN_UPDATE_BACKEND", backendChoice, []string{"rauc", "openwrt-ab", "mock"},
				"OS updates are disabled on this node — it will not accept a new image")
		}
		if upBackend != nil {
			upSubs, err := updater.RegisterHandlersWithFault(nc, nodeID, upBackend, updateFault)
			if err != nil {
				log.Fatalf("rasputin-agent: register update handlers: %v", err)
			}
			defer func() {
				for _, sub := range upSubs {
					_ = sub.Unsubscribe()
				}
			}()
			log.Printf("rasputin-agent: update backend=%s", upBackend.Name())
		}

		// On the firewall (openwrt-ab), reset the running slot's GRUB boot-counter
		// now that the agent is up — the firewall's equivalent of compute's
		// rasputin-mark-good.service. REQUIRED: grub.cfg consumes one TRY per boot,
		// so without this a second ordinary reboot would skip the (already-tried)
		// running slot and fall through to the stale other slot. Backgrounded +
		// best-effort; an error (e.g. ESP not mounted) is logged, never fatal.
		if ab, ok := upBackend.(*updater.OpenWrtABBackend); ok && ab != nil {
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
			faults.Reject("RASPUTIN_TAILSCALE_BACKEND", backendChoice, []string{"tailscale", "mock"},
				"mesh join/leave is disabled on this node")
		}
		if tsBackend != nil {
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

	// Every command handler is subscribed — announce ourselves. (The
	// connect-time registration above was suppressed by the gate.)
	handlersReady.Store(true)
	reregister(nc)
	if faults.Any() {
		log.Printf("rasputin-agent: ⚠️  started WITH %s — this node is reachable but degraded; "+
			"the control plane has been told, and the detail is above.", faults.Summary())
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

// uciLANAddr wraps a UCI-backed LAN lookup with the heuristic as a fallback.
//
// ⚠️ On the firewall the default route leaves via WAN, so the generic heuristic
// reports the WAN address as this node's lanIP — which the control plane
// publishes as the node's cluster-DNS answer and as the mesh advertise-routes
// suggestion. Both then point at an interface whose own WAN input policy
// rejects everything but DHCP-renew, ping and IGMP. The box knows the real
// answer, so ask it rather than infer. geekdojo/geekdojo-brain#193.
//
// It NEVER returns empty when the fallback can answer: an absent lanIP wipes
// the node out of cluster DNS entirely, which is worse than the
// wrong-interface answer this exists to fix. Named rather than inlined so that
// guarantee is testable — it is the kind of promise that silently stops being
// true.
func uciLANAddr(lookup func(context.Context) (string, string, error), fallback func() (ip, cidr string)) func() (string, string) {
	return func() (string, string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ip, cidr, err := lookup(ctx)
		if err != nil || ip == "" {
			log.Printf("rasputin-agent: could not read the LAN address from uci (err=%v, ip=%q); "+
				"falling back to the default-route heuristic, which on a router reports the WAN address", err, ip)
			return fallback()
		}
		return ip, cidr
	}
}

func publishRegistered(nc *nats.Conn, nodeID string, role proto.NodeRole, storage *proto.StorageInfo, bmcAdv *bmc.Advertisement, faults *configfault.Set, lanAddr func() (ip, cidr string)) {
	meta := map[string]any{}
	lanIP, lanCIDR := lanAddr()
	if cidr := lanCIDR; cidr != "" {
		// Carried in Metadata rather than as a top-level field so the
		// shared proto.NodeRegisteredEvt stays small / additive: anything
		// that needs the value reads metadata["primaryLanCidr"]. The api's
		// mesh enroll-defaults endpoint surfaces it to the UI.
		meta["primaryLanCidr"] = cidr
	}
	// Configuration faults ride along on every registration, so a node that
	// survived a bad node.env says so to the control plane rather than only to
	// a journal nobody is tailing. Absent entirely on a healthy node. See
	// agent/internal/configfault and proto.MetadataConfigFaults (#89).
	if faults != nil {
		if fs := faults.Metadata(); fs != nil {
			meta[proto.MetadataConfigFaults] = fs
		}
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
		meta[proto.MetadataBMCCapabilities] = bmcAdv.Capabilities
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
		// The node's LAN IPv4, re-detected here so every (re)connect carries the
		// current address — the reboot-time IP churn from making no DHCP
		// reservations lands as a fresh registration (ADR-0004 §8).
		LANIP:        lanIP,
		Capabilities: caps,
		Metadata:     meta,
		Storage:      storage,
		// The kernel's identity for this boot, so the update saga can tell a
		// post-reboot registration from the pre-reboot agent still answering
		// (ADR-0005 Decision 1). Read per publish rather than cached at
		// startup: the file cannot change under a running process, and
		// re-reading keeps this consistent with the precheck handler.
		BootID: host.BootID(),
		Ts:     time.Now().UTC(),
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

func handleHealth(ctx context.Context, nodeID string, role proto.NodeRole, m *nats.Msg, injectFailure bool) {
	var cmd proto.DiagHealthCmd
	_ = json.Unmarshal(m.Data, &cmd) // JobID is optional; ignore decode errors
	// Bound the checks so a hung command can't hold the reply past the saga's
	// health-check timeout.
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ack := health.Check(cctx, role)
	// FaultFailHealth: answer unhealthy AFTER running the real battery, so the
	// reply is shaped exactly like a genuine failure rather than a special case
	// the api might treat differently. Drives the mark-bad branch — the one that
	// unconfirms inventory instead of recording a version, because the node is
	// on the new slot but about to revert away from it.
	if injectFailure {
		log.Printf("rasputin-agent: ⚠️  FAULT %s: reporting UNHEALTHY (real result was ok=%v)",
			updater.FaultFailHealth, ack.OK)
		ack.OK = false
		ack.Detail = "fault injection: " + string(updater.FaultFailHealth)
	}
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

// clusterName returns the cluster's mDNS name — "<cluster-id>.local".
//
// Both places the agent needs it mean the SAME name: on the controlplane the
// name guard defends the node's own, and on the firewall hostsync republishes
// the control plane's into dnsmasq. One cluster, one name.
//
// RASPUTIN_CLUSTER_ID reaches the agent from node.env on rasputin-os, and from
// the seed via UCI + procd on the firewall. It defaults to "rasputin" per
// ADR-0003, so a node that predates per-cluster naming — or one whose operator
// never chose a name — derives exactly "rasputin.local", the literal both call
// sites used to hardcode.
func clusterName() string {
	return clusterID() + ".local"
}

// clusterID is the bare cluster id, without the .local suffix clusterName
// appends. clusterdns needs it raw because it derives two domains from it —
// the mDNS name and the internal zone apex.
func clusterID() string {
	id := strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID"))
	if id == "" {
		id = "rasputin"
	}
	return id
}

// rolesAsStrings renders proto.AllRoles for an operator-facing message. The
// valid options belong in the error: a typo should be self-correcting without
// anyone reading the source.
func rolesAsStrings() []string {
	out := make([]string, 0, len(proto.AllRoles))
	for _, r := range proto.AllRoles {
		out = append(out, string(r))
	}
	return out
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// bmcConfigFromEnv reads every RASPUTIN_BMC_* driver setting into the
// registry's Config. It is a named function purely so a test can hold it
// against bmc.Config's field set: the turingpi driver shipped with its
// six env vars documented in registry.go and read by NOBODY (CP #46), so
// RASPUTIN_BMC_BACKEND=turingpi died at construction and took the agent
// down with it. Every backend unit test builds Config directly, so no
// test could see the gap. TestBMCConfigFromEnvCoversEveryField closes it
// for the next driver too.
func bmcConfigFromEnv(bmcStateDir string) bmc.Config {
	return bmc.Config{
		StateDir:       bmcStateDir,
		BitScopeDev:    os.Getenv("RASPUTIN_BMC_BITSCOPE_DEV"),
		BitScopeUnlock: os.Getenv("RASPUTIN_BMC_BITSCOPE_UNLOCK"),
		BitScopeMap:    os.Getenv("RASPUTIN_BMC_BITSCOPE_MAP"),
		MockTargets:    splitCSV(os.Getenv("RASPUTIN_BMC_MOCK_TARGETS")),

		TuringPiEndpoint:    os.Getenv("RASPUTIN_BMC_TURINGPI_ENDPOINT"),
		TuringPiUser:        os.Getenv("RASPUTIN_BMC_TURINGPI_USER"),
		TuringPiPass:        os.Getenv("RASPUTIN_BMC_TURINGPI_PASS"),
		TuringPiMap:         os.Getenv("RASPUTIN_BMC_TURINGPI_MAP"),
		TuringPiFingerprint: os.Getenv("RASPUTIN_BMC_TURINGPI_FINGERPRINT"),
		TuringPiInsecure:    envBool("RASPUTIN_BMC_TURINGPI_INSECURE"),
	}
}

// envBool reads a boolean env var. Anything strconv.ParseBool rejects —
// including unset — is false: an env var that disables TLS verification
// must never be turned on by a typo.
func envBool(key string) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(key)))
	return err == nil && v
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
// updaterStateDir is the one place the updater's state directory is derived.
// The fault marker lives here and must be looked for here — deriving it twice
// is what let the arm and consume sites disagree (bench 2026-08-13).
func updaterStateDir(stateDir string) string { return filepath.Join(stateDir, "updater") }

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

// caddyBinary returns the caddy binary path (RASPUTIN_CADDY_BIN override, else
// `caddy` on PATH), or "" when absent — the node-local proxy then stays off and
// leaves are still delivered/stored for when it appears.
func caddyBinary() string {
	if p := strings.TrimSpace(os.Getenv("RASPUTIN_CADDY_BIN")); p != "" {
		return p
	}
	if p, err := exec.LookPath("caddy"); err == nil {
		return p
	}
	return ""
}

// nodeTailnetIP returns the node's tailnet IPv4 (best-effort, `tailscale ip -4`),
// or "" if the node isn't on the tailnet yet — resolved per reconcile so it
// appears once enrollment completes.
func nodeTailnetIP() string {
	out, err := exec.Command("tailscale", "ip", "-4").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
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
