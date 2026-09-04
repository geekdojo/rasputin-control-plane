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
	"github.com/geekdojo/rasputin-control-plane/agent/internal/quiesce"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/sdnotify"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/storage"
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
	// Every command handler the agent serves is collected here and
	// subscribed by subscribeAll on EVERY bus connection the agent makes —
	// not once, inline, on a conn assumed to live forever. nats.go closes a
	// conn for good when it decides a failure is permanent, and the bus
	// Client then dials a new one on which nothing is subscribed (e3bench
	// 2026-09-04: five nodes off the bus for 17 hours after a controlplane
	// wipe; see agent/internal/bus). Registration follows subscription on
	// each conn, so the api never acts on a registration whose handlers are
	// not up yet — the BMC status seed's first sweep once raced exactly that
	// and got "no responders" (dev bench 2026-07-26).
	//
	// The backends the handlers serve are constructed ONCE, below, before
	// the first dial; only the subscriptions are per-conn.
	var subscribers []func(*nats.Conn) error
	subscribe := func(fn func(*nats.Conn) error) { subscribers = append(subscribers, fn) }
	subscribeAll := func(c *nats.Conn) error {
		for _, fn := range subscribers {
			if err := fn(c); err != nil {
				return err
			}
		}
		return nil
	}
	// How this node answers "which address do others reach me on". The default
	// is the default-route heuristic, which is right everywhere EXCEPT the
	// router — see the openwrt override below and
	// geekdojo/geekdojo-brain#193. Assigned before the first registration:
	// registration is gated on handlersReady, which flips after the backend
	// selection that may replace this.
	lanAddr := func() (ip, cidr string) { return host.PrimaryLANIP(), host.PrimaryLanCIDR() }
	// The mesh backend, chosen below (before handlersReady flips, so every
	// registration can ask it which mesh CA this node trusts). nil when mesh
	// join is disabled on this node, which reports as trusting none.
	var tsBackend tailscale.Backend
	trustFingerprint := func() string {
		if tsBackend == nil {
			return proto.MeshCAFingerprintNone
		}
		return tsBackend.TrustFingerprint()
	}
	reregister := func(c *nats.Conn) {
		publishRegistered(c, nodeID, role, host.Storage(storageDataPath, growpartLogPath), bmcHost.Advertisement(), &faults, lanAddr, trustFingerprint)
	}
	// The bus connection, for the life of the process. Not dialed yet: the
	// handlers below are collected first and subscribed on each conn by
	// subscribeAll, then the registration goes out. Everything that
	// publishes on a timer takes the client rather than a conn, so a
	// publish lands on whichever connection is current.
	client := bus.New(natsURL, nodeID, joinToken, subscribeAll, reregister)
	defer client.Close()
	// For hooks that re-register outside a bus event (a simulated reboot, a
	// mesh enroll, a BMC swap): always the current conn, never a captured one.
	rereg := func() { reregister(client.Conn()) }

	pingSubj := proto.NodeCmdSubject(nodeID, "diag.ping")
	subscribe(func(c *nats.Conn) error {
		if _, err := c.Subscribe(pingSubj, func(m *nats.Msg) { handlePing(nodeID, m) }); err != nil {
			return fmt.Errorf("subscribe %s: %w", pingSubj, err)
		}
		log.Printf("rasputin-agent: subscribed to %s", pingSubj)
		return nil
	})

	// diag.health — role-aware health probe the node.update saga uses as its
	// post-reboot commit/rollback gate (richer than diag.ping's liveness).
	healthSubj := proto.NodeCmdSubject(nodeID, "diag.health")
	subscribe(func(c *nats.Conn) error {
		_, err := c.Subscribe(healthSubj, func(m *nats.Msg) {
			handleHealth(ctx, nodeID, role, m, updateFault == updater.FaultFailHealth)
		})
		if err != nil {
			return fmt.Errorf("subscribe %s: %w", healthSubj, err)
		}
		log.Printf("rasputin-agent: subscribed to %s", healthSubj)
		return nil
	})

	subscribe(func(c *nats.Conn) error {
		if _, err := system.RegisterRebootHandler(c, nodeID, reregister); err != nil {
			return fmt.Errorf("register reboot handler: %w", err)
		}
		log.Printf("rasputin-agent: subscribed to %s", proto.NodeCmdSubject(nodeID, "system.reboot"))
		return nil
	})

	// Docker handlers — on compute and controlplane agents (the latter hosts
	// the api's own sidecars in Tier 2). Picks `docker` if the CLI is on PATH;
	// if it isn't, apps are DISABLED and reported, never pretend-served by the
	// mock. Force via RASPUTIN_DOCKER_BACKEND=mock|docker.
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
		case backendUnavailable:
			faults.Unavailable("RASPUTIN_DOCKER_BACKEND", []string{"docker"}, dockerMissingPrereq(),
				"app deploy/start/stop is disabled on this node — no container runtime is present")
		default:
			faults.Reject("RASPUTIN_DOCKER_BACKEND", backendChoice, []string{"docker", "mock"},
				"app deploy/start/stop is disabled on this node")
		}

		if dockerBackend != nil {
			subscribe(func(c *nats.Conn) error {
				if _, err := docker.RegisterHandlers(c, nodeID, dockerBackend); err != nil {
					return fmt.Errorf("register docker handlers: %w", err)
				}
				return nil
			})

			// The app-volume staging verbs (design/storage.md §4.3 / §4.7)
			// go wherever apps are hosted, on the SAME staging root the
			// backup write verb reads — one derivation, storage.StagingRoot,
			// so there is one directory to budget, sweep and exclude. Both
			// docker backends satisfy quiesce.Runtime; the mock is the same
			// explicit-only mock as above and is never inferred.
			//
			// Two §4.7 disciplines run BEFORE the verbs are exposed:
			//   1. the boot sweep of orphaned staged files (a crash mid-copy
			//      leaves a `.partial-*` under the root; on a controlplane the
			//      storage block below sweeps the same root again, harmlessly);
			//   2. the restart of any app a previous agent process stopped
			//      for a backup and did not live to start — the watchdog
			//      surviving the death of the process that armed it.
			rt, ok := dockerBackend.(quiesce.Runtime)
			if !ok {
				log.Fatalf("rasputin-agent: docker backend %s does not implement the quiesce runtime", dockerBackend.Name())
			}
			stagingRoot := storage.StagingRoot(stateDir)
			if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
				log.Printf("rasputin-agent: backup staging dir %s: %v", stagingRoot, err)
			}
			if n, freed := storage.CleanStaging(stagingRoot); n > 0 {
				log.Printf("rasputin-agent: swept %d orphaned staged file(s) from %s (%d bytes)", n, stagingRoot, freed)
			}
			stager := quiesce.New(rt, stagingRoot, quiesce.MarkerDir(stateDir))
			// The transfer verb uploads sealed volumes to the api's ingest
			// endpoint over the api's mesh-CA HTTPS leaf; the same bundle
			// the updater's download client trusts.
			stager.SetCABundle(tailscale.CABundlePath())
			// The restore verb (#291 phase 2) stages beside each volume and
			// records where, so a tree a dying process left is swept here —
			// the previous contents a restore keeps aside are never touched.
			stager.SetRestoreRecordDir(quiesce.RestoreRecordDir(stateDir))
			if n := stager.SweepArmedStops(); n > 0 {
				log.Printf("rasputin-agent: quiesce: restarted %d app(s) a previous agent left stopped for a backup", n)
			}
			if n := stager.SweepRestoreStaging(); n > 0 {
				log.Printf("rasputin-agent: restore: removed %d staging tree(s) a previous agent left beside app volumes", n)
			}
			subscribe(func(c *nats.Conn) error {
				if _, err := quiesce.RegisterHandlers(c, nodeID, stager); err != nil {
					return fmt.Errorf("register quiesce handlers: %w", err)
				}
				return nil
			})
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
		subscribe(func(c *nats.Conn) error {
			if _, err := proxy.RegisterHandlers(c, nodeID, leafStore, reconciler.Reconcile); err != nil {
				return fmt.Errorf("register proxy handlers: %w", err)
			}
			return nil
		})
	}

	// Firewall handlers — only on firewall-role agents. Picks the real uci
	// backend when the agent is actually on OpenWrt (uci on PATH AND
	// /etc/config/firewall present); if it isn't, firewall configuration is
	// DISABLED and reported. The file-backed mock is dev-only and must be
	// asked for: RASPUTIN_UCI_BACKEND=uci|mock.
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
		case backendUnavailable:
			faults.Unavailable("RASPUTIN_UCI_BACKEND", []string{"uci"}, uciMissingPrereq(),
				"firewall configuration is disabled on this node — rules cannot be read or applied, "+
					"and none are being silently simulated")
		default:
			faults.Reject("RASPUTIN_UCI_BACKEND", backendChoice, []string{"uci", "mock"},
				"firewall configuration is disabled on this node")
		}
		if uciClient != nil {
			log.Printf("rasputin-agent: uci backend=%s", backendChoice)
			subscribe(func(c *nats.Conn) error {
				if _, err := openwrt.RegisterHandlers(c, nodeID, uciClient); err != nil {
					return fmt.Errorf("register firewall handlers: %w", err)
				}
				return nil
			})
		}
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
		// Read the peer off the socket EVERY time rather than capturing it
		// once. nats reconnects when the control plane reboots, so this
		// follows the CP to its new address; a captured string does not, and a
		// captured string is what pinned five nodes to a dead server the
		// moment the control plane took a new lease.
		go clusterdns.Run(ctx, clusterdns.Config{
			ClusterID: clusterID(),
			ServerIP:  func() string { return hostOf(client.ConnectedAddr()) },
			Dir:       envOr("RASPUTIN_RESOLVED_DROPIN_DIR", clusterdns.DefaultDir),
		})
	}

	// OS update handlers — every node that can actually take an image gets
	// them. The firewall (OpenWrt, no RAUC) uses the custom A/B backend;
	// compute/controlplane use `rauc` when the CLI is on PATH. A node with
	// neither has OS updates DISABLED and reported — it does not get the mock,
	// which would report a successful install of an image never written. Force
	// via RASPUTIN_UPDATE_BACKEND=rauc|openwrt-ab|mock.
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
			mb.SetReregisterHook(rereg)
			upBackend = mb
		case backendUnavailable:
			faults.Unavailable("RASPUTIN_UPDATE_BACKEND", updaterExpectedFor(role), updaterMissingPrereq(role),
				"OS updates are disabled on this node — it will not accept a new image, and it will "+
					"NOT report a fake successful install")
		default:
			faults.Reject("RASPUTIN_UPDATE_BACKEND", backendChoice, []string{"rauc", "openwrt-ab", "mock"},
				"OS updates are disabled on this node — it will not accept a new image")
		}
		if upBackend != nil {
			subscribe(func(c *nats.Conn) error {
				if _, err := updater.RegisterHandlersWithFault(c, nodeID, upBackend, updateFault); err != nil {
					return fmt.Errorf("register update handlers: %w", err)
				}
				return nil
			})
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

	// Backup-target storage handlers (design/storage.md §4.8) — enumerate
	// candidate disks, claim one, format it, mount it. Real backend when
	// util-linux is on PATH; if any required tool is missing the subsystem is
	// DISABLED and the missing tool named. It must never fall back to the mock:
	// that is the 2026-09-01 e3bench incident, where fixture disks were offered
	// for a destructive format on real hardware. Force via
	// RASPUTIN_STORAGE_BACKEND=blockdev|mock.
	//
	// Registered on the controlplane and on storage-role nodes only, and
	// deliberately not on every node the way the updater is. `storage.claim` is
	// the one agent verb that force-formats a disk; a compute node or the
	// firewall has nothing that uses it today (#302's data-disk contract is
	// where a storage node will), so arming them would be surface with no
	// consumer. Widen this when something consumes it, not before.
	if role == proto.RoleControlPlane || role == proto.RoleStorage {
		backendChoice := envOr("RASPUTIN_STORAGE_BACKEND", autodetectStorageBackend())

		var stBackend storage.Backend
		switch backendChoice {
		case "blockdev":
			bd, err := storage.NewBlockDevBackend(stateDir)
			if err != nil {
				log.Fatalf("rasputin-agent: storage blockdev backend: %v", err)
			}
			stBackend = bd
		case "mock":
			mb, err := storage.NewMockBackend(stateDir)
			if err != nil {
				log.Fatalf("rasputin-agent: storage mock: %v", err)
			}
			stBackend = mb
		case backendUnavailable:
			// The 2026-09-01 e3bench incident lands here now instead of on the
			// mock. Everything else the agent does keeps working — this node
			// still heartbeats, holds the mesh and serves updates; it just
			// cannot enumerate or claim disks, and says so.
			faults.Unavailable("RASPUTIN_STORAGE_BACKEND", []string{"blockdev"}, storageMissingPrereq(),
				"backup-target selection is disabled on this node — no disk can be enumerated or "+
					"claimed, and NO fixture disks are being reported in their place")
		default:
			faults.Reject("RASPUTIN_STORAGE_BACKEND", backendChoice, []string{"blockdev", "mock"},
				"backup-target selection is disabled on this node — no disk can be claimed as a backup target")
		}
		if stBackend != nil {
			// §4.7's staging path, and §4.7's third discipline with it: an
			// orphaned staged archive after a crash or a power cut is a
			// permanent disk leak with no owner and no alert, on the one
			// partition §5's budget table is about. Swept at start, before the
			// write verb is exposed, so a run that died mid-seal cannot leave
			// its bytes there indefinitely.
			//
			// The api writes into this same directory — both halves read
			// RASPUTIN_BACKUP_STAGING_DIR — and it is the ONLY directory the
			// backup write verb will read a file from.
			stagingRoot := storage.StagingRoot(stateDir)
			if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
				log.Printf("rasputin-agent: backup staging dir %s: %v", stagingRoot, err)
			}
			if n, freed := storage.CleanStaging(stagingRoot); n > 0 {
				log.Printf("rasputin-agent: swept %d orphaned staged backup archive(s) from %s (%d bytes)", n, stagingRoot, freed)
			}
			subscribe(func(c *nats.Conn) error {
				if _, err := storage.RegisterHandlers(c, nodeID, stBackend, stagingRoot); err != nil {
					return fmt.Errorf("register storage handlers: %w", err)
				}
				return nil
			})
			log.Printf("rasputin-agent: storage backend=%s", stBackend.Name())
		}
	}

	// Tailscale handlers — every node joins the tailnet (per
	// design/control-plane/mesh.md §5). Picks the real backend if the tailscale
	// binary is on PATH; without it mesh join/leave is DISABLED and reported,
	// rather than mocked into looking joined. Force via
	// RASPUTIN_TAILSCALE_BACKEND=mock|tailscale.
	{
		backendChoice := envOr("RASPUTIN_TAILSCALE_BACKEND", autodetectTailscaleBackend())
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
		case backendUnavailable:
			faults.Unavailable("RASPUTIN_TAILSCALE_BACKEND", []string{"tailscale"}, tailscaleMissingPrereq(),
				"mesh join/leave is disabled on this node — it will not report itself as meshed "+
					"when it is not")
		default:
			faults.Reject("RASPUTIN_TAILSCALE_BACKEND", backendChoice, []string{"tailscale", "mock"},
				"mesh join/leave is disabled on this node")
		}
		if tsBackend != nil {
			// Re-register after every successful enroll: the registration
			// carries the CA fingerprint this node now trusts, and the api's
			// converge_trust reads it from inventory — without this the api
			// would see the pre-delivery fingerprint until the next reconnect.
			subscribe(func(c *nats.Conn) error {
				if _, err := tailscale.RegisterHandlers(c, nodeID, tsBackend, rereg); err != nil {
					return fmt.Errorf("register tailscale handlers: %w", err)
				}
				return nil
			})
			log.Printf("rasputin-agent: tailscale backend=%s", tsBackend.Name())
		}
	}

	// BMC handlers — the backend itself was constructed before the bus
	// connect (see above) so registration could advertise bmc-targets.
	// Attach subscribes bmc.configure on every agent (a Settings push can
	// turn BMC on) and the power/SoL handlers when a backend is active; it
	// is re-callable, and re-attaches on every new conn.
	subscribe(func(c *nats.Conn) error {
		if err := bmcHost.Attach(c, rereg); err != nil {
			return fmt.Errorf("bmc host attach: %w", err)
		}
		return nil
	})
	defer bmcHost.Shutdown()
	if bmcHost.Active() {
		adv := bmcHost.Advertisement()
		log.Printf("rasputin-agent: bmc backend=%s (host, targets=%d, pinned=%t)", bmcHost.Name(), len(adv.Targets), adv.Pinned)
	}

	// Every backend is built and every handler is collected — dial. The
	// client subscribes them all on the new conn and then publishes the
	// registration, and keeps doing both for the life of the process.
	//
	// Retry the first connect instead of exiting on failure. On real hardware
	// the firewall can boot before the control plane (it IS the network), so
	// rasputin.local may not resolve yet at startup. Exiting let procd exhaust
	// its respawn budget and the agent never recovered (bench 2026-06-18).
	// Loop here with capped backoff until the control plane appears; only a
	// shutdown signal aborts. After the first success the client re-dials on
	// its own — see agent/internal/bus.
	for attempt := 1; ; attempt++ {
		cerr := client.Dial()
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
	if faults.Any() {
		log.Printf("rasputin-agent: ⚠️  started WITH %s — this node is reachable but degraded; "+
			"the control plane has been told, and the detail is above.", faults.Summary())
	}

	// IDS alert tailer — tails snort3's alert_fast log (path comes from the
	// firewall image's /etc/config/snort log_dir UCI option; 99-rasputin
	// seeds it to /var/log/snort) and publishes one event per parsed alert
	// on rasputin.node.<id>.evt.ids.alert. Only firewall-role agents start
	// this loop (compute/controlplane agents don't run snort and have no log
	// to tail). The path override is honored via RASPUTIN_IDS_ALERT_LOG for
	// dev/test; blank means use the default in the ids package.
	if role == proto.RoleFirewall {
		go ids.Run(ctx, client, nodeID, os.Getenv("RASPUTIN_IDS_ALERT_LOG"))
	}

	go runHeartbeats(ctx, client, nodeID)
	// Disk metric measures the persistent data partition, not "/" (the
	// read-only squashfs rootfs, ~100% by design on the appliance). Default to
	// the agent's own state dir — on the appliance that's
	// /var/lib/rasputin/agent-state, the same partition as Docker + obs data —
	// and statfs is filesystem-level. Overridable if a node's layout differs.
	go metrics.Run(ctx, client, nodeID, storageDataPath, host.Uptime)

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

func publishRegistered(nc *nats.Conn, nodeID string, role proto.NodeRole, storage *proto.StorageInfo, bmcAdv *bmc.Advertisement, faults *configfault.Set, lanAddr func() (ip, cidr string), trustFingerprint func() string) {
	meta := map[string]any{}
	// Which mesh CA this node trusts, as a fingerprint — never the PEM. The
	// api compares it with its own on every mesh.reconcile and re-delivers
	// the CA when they differ (converge_trust; e3bench 2026-09-04, where an
	// identity restore changed the api's CA under an enrolled node).
	if trustFingerprint != nil {
		if fp := trustFingerprint(); fp != "" {
			meta[proto.MetadataMeshCAFingerprint] = fp
		}
	}
	lanIP, lanCIDR := lanAddr()
	if cidr := lanCIDR; cidr != "" {
		// Carried in Metadata rather than as a top-level field so the
		// shared proto.NodeRegisteredEvt stays small / additive: anything
		// that needs the value reads metadata["primaryLanCidr"]. The api's
		// mesh enroll-defaults endpoint surfaces it to the UI as the
		// suggested advertise route, so it is the NETWORK (192.168.1.0/24),
		// never this node's address with a mask — the top-level LANIP
		// carries the address.
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

// runHeartbeats publishes a heartbeat every heartbeatInterval on the current
// bus connection. A run of publish failures — the bus is down, the client is
// re-dialing — logs once and is counted, not written every 10s (bus.Squelch).
func runHeartbeats(ctx context.Context, pub bus.Publisher, nodeID string) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	subj := proto.NodeHeartbeatSubject(nodeID)
	publishLog := bus.Squelch{What: "publish heartbeat"}
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
			publishLog.Report(pub.Publish(subj, payload))
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

// hostOf strips the port from a host:port, returning "" for anything it cannot
// parse. Extracted from the clusterdns wiring so the parse is testable: it
// returns "" on failure, which reads as "we do not know where the control plane
// is" and withdraws the DNS pin — a silent path worth having a test on.
func hostOf(addr string) string {
	if addr == "" {
		return ""
	}
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return h
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

// backendUnavailable is what every autodetect below returns when no REAL
// backend's prerequisites are met on this node.
//
// ⚠️ It is NOT "mock". Autodetecting to mock is the 2026-09-01 e3bench
// incident: a missing `wipefs` in the OS image made storage.ToolingAvailable()
// false, the storage autodetect answered "mock", and a real n100 controlplane
// reported three fixture disks that do not exist in it — with ok:true — into
// the backup-target picker, one confirmation away from formatting a device that
// was not there. Mock is opt-in and never inferred; see agent/internal/
// configfault for the full argument.
//
// Empty string rather than a sentinel word so it can never collide with a
// backend name an operator might type, and so the `case backendUnavailable`
// arms below also catch RASPUTIN_*_BACKEND="" (set-but-empty in node.env).
const backendUnavailable = ""

// autodetectDockerBackend returns "docker" if the docker CLI is on PATH, and
// backendUnavailable otherwise — app deploy/start/stop is then disabled rather
// than pretend-served by the mock, whose Deploy reports AppStatusRunning and
// "pretend-deployed" for a container that does not exist.
//
// On a dev box without Docker, ask for the mock explicitly:
// RASPUTIN_DOCKER_BACKEND=mock.
func autodetectDockerBackend() string {
	if _, err := exec.LookPath("docker"); err == nil {
		return "docker"
	}
	return backendUnavailable
}

// dockerMissingPrereq names what autodetectDockerBackend could not find.
func dockerMissingPrereq() string { return "the docker CLI is not on PATH" }

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
// other node uses `rauc` when the CLI is on PATH, else backendUnavailable. The
// env override (RASPUTIN_UPDATE_BACKEND) forces any of rauc|openwrt-ab|mock.
//
// ROLE MATTERS HERE, and it was the one place worth checking before making
// absence disabling: a firewall node legitimately has no `rauc`, and this
// function already accounts for that — firewall-role nodes are never asked for
// it. What each role needs is therefore what each role actually has, and a
// missing prerequisite means the node genuinely cannot take an image:
//
//   - firewall WITHOUT /etc/config/firewall is not on OpenWrt at all, so
//     openwrt-ab's ESP/GRUB-counter machinery has nothing to drive;
//   - compute/controlplane/storage WITHOUT rauc has no A/B updater.
//
// Neither may fall back to the mock. The mock's Install reports success and
// SetReregisterHook fakes the post-reboot re-registration, so the node.update
// saga COMMITS: the fleet run goes green, the canary gate passes, and the
// failure budget is never charged — for an image that was never written. A
// disabled updater fails the saga honestly instead (ErrNoResponders, the same
// shape as a node that is down), which is a result an operator can act on.
func autodetectUpdaterBackend(role proto.NodeRole) string {
	if role == proto.RoleFirewall {
		if _, err := os.Stat("/etc/config/firewall"); err == nil {
			return "openwrt-ab"
		}
		return backendUnavailable
	}
	if _, err := exec.LookPath("rauc"); err == nil {
		return "rauc"
	}
	return backendUnavailable
}

// updaterExpectedFor names the real backend this role would have used, so the
// fault says "openwrt-ab" on the firewall and "rauc" everywhere else rather
// than listing a backend the node could never have run.
func updaterExpectedFor(role proto.NodeRole) []string {
	if role == proto.RoleFirewall {
		return []string{"openwrt-ab"}
	}
	return []string{"rauc"}
}

// updaterMissingPrereq names what autodetectUpdaterBackend could not find, in
// the terms that role actually needs.
func updaterMissingPrereq(role proto.NodeRole) string {
	if role == proto.RoleFirewall {
		return "/etc/config/firewall is not present, so this firewall-role node is not running OpenWrt"
	}
	return "the rauc CLI is not on PATH"
}

// autodetectUCIBackend returns "uci" when the agent is running on a real
// OpenWrt system — the uci CLI on PATH AND /etc/config/firewall present —
// "mock" otherwise. Mirrors autodetectTailscaleBackend; the env-var
// override (RASPUTIN_UCI_BACKEND) lets the user force one or the other.
// The config-file check matters: a dev box could have a stray `uci`
// binary installed, but only a real OpenWrt root has /etc/config/firewall.
// autodetectStorageBackend picks the backup-target backend: the real one when
// every util-linux tool it shells out to is on PATH, else backendUnavailable —
// a backend that discovers a missing tool halfway through a repartition is
// worse than one that never started.
//
// ⚠️ THIS IS THE FUNCTION FROM THE 2026-09-01 INCIDENT. It used to return
// "mock" here. On e3bench — a real n100 controlplane — `wipefs` was absent from
// the OS image, so this returned "mock" and storage.enumerate answered:
//
//	{"backend":"mock","ok":true,"candidates":[
//	  {"model":"CT500P3SSD8"},{"model":"CT2000P3SSD8"},
//	  {"model":"SanDisk Ultra","partitions":[{"fsType":"exfat","label":"MYSTUFF"}]}]}
//
// None of those disks exist in that machine. The operator would have seen them
// in Storage → Backups and could have confirmed a destructive format against a
// device that was not there — and `storage.claim` is the one agent verb that
// force-formats a disk. The mock's own doc explains why it is so convincing: it
// models disks, partitions and live mounts precisely so the safety rules can be
// tested against it. That fidelity is exactly what makes it dangerous to infer.
//
// Disabling storage is safe to do this way: the handlers simply do not
// register, so the controlplane still heartbeats, holds the mesh and serves
// updates, and only the disk verbs are gone.
func autodetectStorageBackend() string {
	if storage.ToolingAvailable() {
		return "blockdev"
	}
	return backendUnavailable
}

// storageMissingPrereq names the util-linux tools that are not on PATH — the
// sentence the incident needed. Never called when tooling is complete.
func storageMissingPrereq() string {
	missing := storage.MissingTools()
	if len(missing) == 0 {
		return "the block tooling is incomplete"
	}
	return "not on PATH: " + strings.Join(missing, ", ")
}

func autodetectUCIBackend() string {
	return autodetectUCIBackendAt(defaultFirewallConfig)
}

// defaultFirewallConfig is the OpenWrt firewall config whose presence proves
// this is a real OpenWrt root rather than a dev box with a stray `uci`.
const defaultFirewallConfig = "/etc/config/firewall"

// autodetectUCIBackendAt is the testable core — the firewall config path
// is a parameter so tests don't need a real /etc/config/firewall.
//
// Returns backendUnavailable rather than "mock" when this is not a real
// OpenWrt root. The mock here is the sharpest lie of the five after storage:
// it is file-backed, so an operator who adds a deny rule gets an applied-looking
// ack and a rule list that reads back correctly, while the actual firewall has
// no such rule. A security control believed to be enforced and absent is worse
// than one visibly disabled.
func autodetectUCIBackendAt(firewallConfig string) string {
	if _, err := exec.LookPath("uci"); err != nil {
		return backendUnavailable
	}
	if _, err := os.Stat(firewallConfig); err != nil {
		return backendUnavailable
	}
	return "uci"
}

// uciMissingPrereq names which of the two OpenWrt signals is absent.
func uciMissingPrereq() string { return uciMissingPrereqAt(defaultFirewallConfig) }

func uciMissingPrereqAt(firewallConfig string) string {
	if _, err := exec.LookPath("uci"); err != nil {
		return "the uci CLI is not on PATH, so this is not a real OpenWrt root"
	}
	return firewallConfig + " is not present, so this is not a real OpenWrt root " +
		"(a stray uci binary on a dev box is not enough)"
}

// autodetectTailscaleBackend returns "tailscale" if the tailscale CLI is
// on PATH, backendUnavailable otherwise. v0 only checks for the binary —
// `tailscale status` would prove tailscaled is alive but adds 1-2s to startup;
// we let the first enroll fail loudly if the daemon isn't running.
//
// Not mock: the mock's Enroll writes file-backed state and reports a joined
// tailnet, so the control plane would record the node as meshed and route to a
// tailnet IP it never obtained. "Mesh join is disabled" is a fact an operator
// can fix; "joined" when it did not is a fact they will act on wrongly.
func autodetectTailscaleBackend() string {
	if _, err := exec.LookPath("tailscale"); err == nil {
		return "tailscale"
	}
	return backendUnavailable
}

// tailscaleMissingPrereq names what autodetectTailscaleBackend could not find.
func tailscaleMissingPrereq() string { return "the tailscale CLI is not on PATH" }
