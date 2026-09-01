package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	apipkg "github.com/geekdojo/rasputin-control-plane/api/internal/api"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalog/floor"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/ids"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nameserver"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/api/internal/sdnotify"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// rasputin-api: the Rasputin control-plane backend.
//
// Architecture: projects/rasputin/design/control-plane/architecture.md
//   in the geekdojo-brain.

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	dataDir := envOr("RASPUTIN_DATA_DIR", "./data")
	httpAddr := envOr("RASPUTIN_HTTP_ADDR", ":8080")
	// Native HTTPS for first-run WebAuthn bootstrap: browsers only run the
	// passkey ceremony in a secure context with a domain-name RP ID, so an
	// appliance reached as https://rasputin.local must terminate TLS itself.
	// Empty (the default) keeps dev behavior exactly as before — plain HTTP
	// only. The OS image's systemd unit sets :443 (plus RASPUTIN_HTTP_ADDR=:80,
	// RASPUTIN_RP_ID=rasputin.local, RASPUTIN_RP_ORIGINS=https://rasputin.local,
	// RASPUTIN_PUBLIC_BASE_URL=https://rasputin.local).
	httpsAddr := os.Getenv("RASPUTIN_HTTPS_ADDR")
	// obsIngestAddr is the dedicated mTLS remote-write ingress for per-node obs
	// collectors (Slice 1.2b, observability-stack.md §3.10). It comes up only in
	// appliance mode (HTTPS on) — dev has no mesh server leaf and no compute
	// nodes — and defaults to :8443 on all interfaces so compute/storage nodes
	// can reach it via rasputin.local, the same mDNS path they already use for
	// NATS. mTLS-only (RequireAndVerifyClientCert against the mesh CA): a
	// connection without a mesh-CA-signed client cert never completes the
	// handshake, so an always-open :8443 is not an open door, and VM stays
	// loopback-only behind it.
	obsIngestAddr := ""
	if httpsAddr != "" {
		obsIngestAddr = envOr("RASPUTIN_OBS_INGEST_ADDR", ":8443")
	}

	if err := os.MkdirAll(filepath.Join(dataDir, "nats"), 0o755); err != nil {
		log.Fatalf("rasputin-api: data dir: %v", err)
	}
	dbPath := filepath.Join(dataDir, "rasputin.db")

	// NATS bind defaults to 127.0.0.1:4222 (api-local agents only). Operators
	// federating agents from other nodes set RASPUTIN_NATS_HOST=0.0.0.0
	// (or a specific LAN IP) so the embedded server is reachable. Port
	// override is rarely useful but kept symmetric.
	natsHost := envOr("RASPUTIN_NATS_HOST", "127.0.0.1")
	natsPort := 4222
	if p, err := strconv.Atoi(envOr("RASPUTIN_NATS_PORT", "4222")); err == nil && p > 0 {
		natsPort = p
	}

	// Bus auth (RASPUTIN_BUS_AUTH=off|enforce). Under enforcement, external
	// agents must present a per-node join token that the in-process busauth
	// responder validates → mints a subject-scoped JWT; the api's own connection
	// authenticates as an AuthUser and bypasses the callout. See architecture §5.4.
	//
	// FAIL-CLOSED DEFAULT: enforce unless explicitly disabled with `=off`. Every
	// node is onboarded with a bound join token (firstboot fails loud without one)
	// and the controlplane preloads the matching hashes, so enforcement is the
	// safe default — a matched set has always shipped enforced (rasputin-provision
	// bakes `=enforce`). The old `off` default was fail-OPEN: a hand-written or
	// incomplete CP seed that omitted the setting silently degraded to an open bus
	// with no signal (bit rasputin-local 2026-07-12 — an OTA-test hand-seed left 24
	// nodes on an unauthenticated bus). Now the only way to an open bus is a
	// deliberate, visible `=off` (surfaced by the bus-auth-off alert). DEPLOY NOTE:
	// a cluster already running open should verify token-readiness (dry-run
	// reconciliation: every live node's token hashes to an active bound record)
	// before updating to a build carrying this default, or set `=off` explicitly.
	busAuthEnforce := envOr("RASPUTIN_BUS_AUTH", "enforce") != "off"
	busCfg := bus.Config{Host: natsHost, Port: natsPort, StoreDir: filepath.Join(dataDir, "nats")}
	var (
		busIssuer *busauth.Issuer
		err       error
	)
	if busAuthEnforce {
		busIssuer, err = busauth.EnsureIssuer(filepath.Join(dataDir, "bus"))
		if err != nil {
			log.Fatalf("rasputin-api: bus auth issuer: %v", err)
		}
		apiPass, err := randomSecret()
		if err != nil {
			log.Fatalf("rasputin-api: bus auth secret: %v", err)
		}
		busCfg.AuthEnforce = true
		busCfg.IssuerPublicKey = busIssuer.PublicKey()
		busCfg.APIUser = "rasputin-api"
		busCfg.APIPass = apiPass
		log.Printf("rasputin-api: bus auth ENFORCED (issuer=%s)", busIssuer.PublicKey())
	} else {
		log.Printf("rasputin-api: bus auth OFF (explicitly disabled via RASPUTIN_BUS_AUTH=off — the bus accepts any connection; unset it to fail closed)")
	}

	busSrv, err := bus.Start(ctx, busCfg)
	if err != nil {
		log.Fatalf("rasputin-api: bus: %v", err)
	}
	defer busSrv.Stop()
	log.Printf("rasputin-api: nats listening on %s", busSrv.ClientURL())

	// Token store backs both the auth-callout responder and the token-mgmt
	// endpoints. Opened regardless of enforcement so an operator can mint
	// tokens BEFORE flipping enforce on.
	busTokenStore, err := busauth.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: bus token store: %v", err)
	}
	defer busTokenStore.Close()

	// Preload any provisioning matched-set tokens (hashes + node bindings) the
	// controlplane shipped with — firstboot drops the file on the persistent
	// partition (token-provisioning-pipeline.md §4c). Idempotent, so it's safe on
	// every boot; done regardless of enforcement so the tokens are known before a
	// later flip to enforce. A bad/missing file never blocks boot — a node that
	// can't join is a better failure than a controlplane that won't start.
	if n, err := loadBusPreseed(ctx, busTokenStore, busPreseedPath(dataDir)); err != nil {
		log.Printf("rasputin-api: bus token preseed: %v (continuing)", err)
	} else if n > 0 {
		log.Printf("rasputin-api: preloaded %d bus token(s) from provisioning seed", n)
	}

	if busAuthEnforce {
		responder := busauth.NewResponder(busSrv.Conn(), busIssuer, busTokenStore)
		if err := responder.Start(); err != nil {
			log.Fatalf("rasputin-api: bus auth responder: %v", err)
		}
		defer responder.Stop()
	}

	jobStore, err := jobs.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: jobs store: %v", err)
	}
	defer jobStore.Close()

	invStore, err := inventory.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: inventory store: %v", err)
	}
	defer invStore.Close()

	authStore, err := auth.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: auth store: %v", err)
	}
	defer authStore.Close()

	fwStore, err := firewall.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: firewall store: %v", err)
	}
	defer fwStore.Close()

	metricsStore, err := metrics.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: metrics store: %v", err)
	}
	defer metricsStore.Close()

	appsStore, err := apps.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: apps store: %v", err)
	}
	defer appsStore.Close()

	updaterStore, err := updater.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: updater store: %v", err)
	}
	defer updaterStore.Close()

	meshStore, err := mesh.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: mesh store: %v", err)
	}
	defer meshStore.Close()

	bmcStore, err := bmc.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: bmc store: %v", err)
	}
	defer bmcStore.Close()

	setupStore, err := setup.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: setup store: %v", err)
	}
	defer setupStore.Close()

	// backup_targets — design/storage.md §4.8's ledger of claimed backup disks.
	backupStore, err := storage.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: storage store: %v", err)
	}
	defer backupStore.Close()

	// Trust material lives at <trustDir>/. Used by:
	//   - updater.Verifier (root-ca.pem; bundle signatures)
	//   - mesh.EnsureMeshCA (mesh-ca.{key,pem}; per-installation TLS CA)
	//   - the .mobileconfig endpoint (serves mesh-ca.pem to operator devices)
	// Set up ahead of mesh because the docker supervisor needs the Mesh CA
	// at construction time. See wiki design/control-plane/certificates.md.
	trustDir := envOr("RASPUTIN_TRUST_DIR", filepath.Join(dataDir, "trust"))
	if err := os.MkdirAll(trustDir, 0o755); err != nil {
		log.Fatalf("rasputin-api: trust dir: %v", err)
	}

	// Mesh subsystem. The controlplane self-hosts Headscale: when Docker is
	// present (production and most dev), the api brings up the Headscale
	// container, mints its own admin API key against it, and talks to it for
	// real — no operator input, no provision-time secret. Only when there's
	// no Docker daemon AND no external Headscale configured does it fall back
	// to the file-backed mock (CI, bare dev). Override the autodetect with
	// RASPUTIN_MESH_BACKEND=mock|headscale|auto (default auto); point at an
	// externally-managed Headscale with RASPUTIN_HEADSCALE_URL +
	// RASPUTIN_HEADSCALE_API_KEY. See wiki design/control-plane/mesh.md §2.
	meshStateDir := envOr("RASPUTIN_MESH_STATE_DIR", filepath.Join(dataDir, "mesh"))
	if err := os.MkdirAll(meshStateDir, 0o755); err != nil {
		log.Fatalf("rasputin-api: mesh state dir: %v", err)
	}
	installName := envOr("RASPUTIN_INSTALL_NAME", "rasputin")
	meshCA, err := mesh.EnsureMeshCA(trustDir, installName)
	if err != nil {
		log.Fatalf("rasputin-api: mesh CA: %v", err)
	}
	log.Printf("rasputin-api: mesh CA loaded (CN=%s, expires=%s)",
		meshCA.Cert.Subject.CommonName, meshCA.Cert.NotAfter.Format("2006-01-02"))
	defaultLogin := envOr("RASPUTIN_MESH_LOGIN_SERVER", "https://mesh.rasputin.local")
	mw, err := wireMesh(meshStateDir, meshCA, defaultLogin)
	if err != nil {
		log.Fatalf("rasputin-api: mesh: %v", err)
	}
	meshSvc := mesh.NewService(mesh.Config{
		LoginServer:  mw.login,
		DefaultUser:  envOr("RASPUTIN_MESH_DEFAULT_USER", "rasputin-operator"),
		HeadplaneURL: os.Getenv("RASPUTIN_HEADPLANE_URL"),
		MeshCAPEM:    mw.caPEM,
		ClusterID:    strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")),
	}, meshStore, mw.client, mw.sup)
	if mw.bootstrap != nil {
		meshSvc.SetBootstrap(mw.bootstrap)
	}
	// Feed the tailnet app-name DNS projection (ADR-0004 §9): each app resolves at
	// <app>.<cluster-id>.internal → its target node's tailnet IP via Headscale
	// extra_records. Read live per reconcile (store error → project nothing).
	meshSvc.SetAppLister(func() []mesh.AppDNS {
		list, err := appsStore.List(ctx)
		if err != nil {
			log.Printf("rasputin-api: mesh app-DNS projection: %v", err)
			return nil
		}
		out := make([]mesh.AppDNS, 0, len(list))
		for _, a := range list {
			out = append(out, mesh.AppDNS{Name: a.Name, TargetNode: a.TargetNode})
		}
		return out
	})
	// Start is non-blocking: mesh bring-up runs in the background so a slow or
	// failing Headscale never delays /healthz or kills the api.
	_ = meshSvc.Start(ctx)
	defer meshSvc.Stop()

	// Bundles live on disk; the api streams them to agents. The
	// bundle-signing root-ca.pem lives at <trustDir>/root-ca.pem and is
	// owned by Rasputin Inc. (separate CA from the Mesh TLS CA above —
	// see certificates.md for why).
	bundleDir := envOr("RASPUTIN_BUNDLE_DIR", filepath.Join(dataDir, "bundles"))
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		log.Fatalf("rasputin-api: bundle dir: %v", err)
	}
	verifier := wireBundleVerifier(trustDir)
	// Public URL the agent uses to fetch bundles. In dev the api is at
	// :8080; in production this is the api's tailnet hostname.
	publicBaseURL := envOr("RASPUTIN_PUBLIC_BASE_URL", applianceOr(
		func(h string) string { return "https://" + h }, "http://localhost:8080"))
	// The api's own node id — the system.update saga skips this one (the
	// operator updates the controlplane node manually after the cascade).
	selfNodeID := os.Getenv("RASPUTIN_SELF_NODE_ID")
	// The BMC host's node id lives in settings (bmc.host_node_id,
	// bmc-settings.md S-5) and is read live so a Settings change
	// redirects routing without a restart. The env var seeds first boot
	// only (seedObsEnabled recipe); the operator's choice wins after.
	seedBMCHostNode(ctx, setupStore, envOr("RASPUTIN_BMC_HOST_NODE_ID", selfNodeID))
	bmcSvc := bmc.NewService(bmc.Config{HostFn: func(ctx context.Context) string {
		v, err := setupStore.Get(ctx, setup.KeyBMCHostNode)
		if err != nil {
			log.Printf("bmc: read %s: %v", setup.KeyBMCHostNode, err)
			return ""
		}
		return v
	}}, bmcStore, busSrv.Conn())

	// Setup wizard service. Probes are functions over the other
	// subsystems' stores; defined here so the setup package stays narrow
	// and import-cycle-free.
	setupSvc := setup.NewService(setupStore, setup.Probes{
		HasUsers: func(ctx context.Context) (bool, error) {
			n, err := authStore.CountUsers(ctx)
			return n > 0, err
		},
		TrustConfigured: func() bool { return verifier.TrustConfigured() },
		MeshEnrolled: func(ctx context.Context, selfNodeID string) (bool, error) {
			devices, err := meshStore.ListDevices(ctx)
			if err != nil {
				return false, err
			}
			for _, d := range devices {
				if d.RasputinNodeID == selfNodeID && d.Kind == "rasputin" {
					return true, nil
				}
			}
			return false, nil
		},
		HasFirewallNode: func(ctx context.Context) (bool, error) {
			nodes, err := invStore.ListByRole(ctx, proto.RoleFirewall)
			if err != nil {
				return false, err
			}
			return len(nodes) > 0, nil
		},
	}, selfNodeID, clusterHostname(), strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")))

	// Capture the operator's SSH key as a cluster setting on first sight:
	// the control plane's own authorized_keys holds exactly the bootstrap
	// seed's key, so a fresh cluster prefills the Add-node wizard before
	// it's ever opened. Only fires while the setting has NEVER been set
	// (an operator's explicit empty list sticks); best-effort — a missing
	// or unreadable file must never block boot (dev api has no seed).
	akPath := envOr("RASPUTIN_CP_AUTHORIZED_KEYS", "/var/lib/rasputin/dropbear/authorized_keys")
	if keys, err := setupSvc.SeedOperatorSSHKeysFromFile(ctx, akPath); err != nil {
		log.Printf("setup: seed operator SSH keys from %s: %v (continuing)", akPath, err)
	} else if len(keys) > 0 {
		log.Printf("setup: captured %d operator SSH key(s) from %s", len(keys), akPath)
	}

	// Default origins cover both ways the UI reaches the api on localhost:
	// the Next dev server (:3000, cross-origin) and the api-served static
	// export (:8080, same-origin — including `ssh -L 8080:localhost:8080`
	// tunnels, still a valid escape hatch). On a real appliance the OS
	// image overrides these to rasputin.local + https origins and enables
	// the native HTTPS listener (RASPUTIN_HTTPS_ADDR above) so the passkey
	// ceremony gets its secure context without any tunnel.
	authCfg := auth.Config{
		RPDisplayName: envOr("RASPUTIN_RP_NAME", "Rasputin"),
		RPID:          envOr("RASPUTIN_RP_ID", applianceOr(func(h string) string { return h }, "localhost")),
		RPOrigins: splitCSV(envOr("RASPUTIN_RP_ORIGINS", applianceOr(
			func(h string) string { return "https://" + h },
			"http://localhost:3000,http://localhost:8080"))),
		SecureCookies: secureCookies(httpsAddr, envBoolPtr("RASPUTIN_SECURE_COOKIES")),
	}
	// Say what this node believes its identity IS, on startup, verbatim.
	//
	// These four values are DERIVED from RASPUTIN_CLUSTER_ID now (ADR-0003), and
	// until this line they appeared in no log, no endpoint and no health check —
	// so a wrong derivation surfaced only when an operator's passkey silently
	// failed to work. WebAuthn binds credentials to the RP ID, which makes this
	// the least forgiving value on the box to get wrong quietly.
	//
	// It is also the only channel CI can see: the QEMU boot smoke has no shell
	// into the guest and asserts by grepping the serial console. A value that
	// never reaches the console is a value no build can ever check — the exact
	// gap that let a truncated RASPUTIN_MDNS_RECOVER_CMD ship for a whole
	// release past green CI (rasputin-os #23).
	log.Printf("rasputin-api: cluster identity: rp-id=%q origins=%q public-base-url=%q (cluster-id=%q)",
		authCfg.RPID, strings.Join(authCfg.RPOrigins, ","), publicBaseURL,
		envOr("RASPUTIN_CLUSTER_ID", "<unset — dev defaults>"))
	// A provisioned appliance (self-node id set) that still derived a loopback
	// public-base-url is misconfigured: nodes cannot fetch update bundles from
	// here, and node.update will be refused (see updater.remoteLoopbackBundleURL).
	// This is the RASPUTIN_CLUSTER_ID-unset trap on a cluster whose node.env
	// predates per-cluster naming — the rasputin-os backfill migration fixes it
	// going forward; warn loudly (and greppably, for CI) if we hit it. #75.
	if selfNodeID != "" && updater.IsLoopbackURL(publicBaseURL) {
		log.Printf("rasputin-api: WARNING — public-base-url is loopback (%q) on a provisioned appliance (self-node %s); nodes cannot fetch update bundles and node.update will be refused. Set RASPUTIN_CLUSTER_ID (default %q) in /var/lib/rasputin/node.env and restart. See control-plane #75.",
			publicBaseURL, selfNodeID, "rasputin")
	}

	authSvc, err := auth.NewService(authStore, authCfg)
	if err != nil {
		log.Fatalf("rasputin-api: auth service: %v", err)
	}
	// On every successful login (and first-credential registration), ensure
	// a matching Headscale user exists. EnsureUser is idempotent + cached,
	// so this costs at most one HTTP round-trip on cold start per user;
	// the mock backend turns it into a single map write. Errors are logged
	// inside runLoginHook and never block the login response — auth stays
	// usable when mesh/Headscale are unhealthy.
	// Use meshSvc.Client() (not a captured client) so this picks up the real
	// Headscale client once the self-hosted bring-up swaps it in; before that
	// it returns ErrMeshNotReady, which the hook logs and ignores.
	authSvc.SetLoginHook(func(ctx context.Context, u *auth.User) error {
		return meshSvc.Client().EnsureUser(ctx, u.Name)
	})
	authSvc.Start(ctx)
	defer authSvc.Stop()

	runner := jobs.NewRunner(jobStore, busSrv.Conn())
	runner.Register(jobs.PingWorkflow())
	runner.Register(jobs.RebootWorkflow())
	// Firewall is managed in every mode except LAN-peer, where the existing
	// router firewalls and our box (if any) is idle. Unset mode (pre-wizard)
	// defaults to managed so a mid-setup box still reconciles.
	fwManaged := func(ctx context.Context) (bool, error) {
		m, err := setupStore.Get(ctx, setup.KeyMode)
		if err != nil {
			return false, err
		}
		return setup.Mode(m) != setup.ModeLANPeer, nil
	}
	runner.Register(firewall.ApplyWorkflow(fwStore, invStore, busSrv.Conn(), fwManaged))
	runner.Register(firewall.ReconcileWorkflow(fwStore, invStore, busSrv.Conn(), fwManaged))
	runner.Register(firewall.SetActiveWorkflow(invStore, busSrv.Conn()))
	// AA-11 Mode-A/C zero-touch DNS (ADR-0004 §10): keep the firewall's dnsmasq
	// conditional-forward for <cluster-id>.internal pointed at the control plane's
	// current LAN IP, auto-applying when it moves. Gated to firewall-present modes
	// by fwManaged; a dev box with no cluster id emits no forward.
	runner.Register(firewall.DNSForwardWorkflow(fwStore, runner, firewall.DNSForwardConfig{
		Zone: func() string {
			if id := strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")); id != "" {
				return id + ".internal"
			}
			return ""
		},
		Target: func() string {
			if ip := primaryLanIP(); ip != nil {
				return ip.String()
			}
			return ""
		},
		Managed: fwManaged,
	}))
	// Per-app TLS-leaf minter for the deploy saga (ADR-0004 §6): mints a Mesh-CA
	// leaf for the app's FQDN(s) and fills the delivery command. nil (no CA)
	// disables leaf delivery; the app still deploys, just without the proxy.
	var (
		mintAppLeaf   apps.LeafMinter
		rotateAppLeaf apps.LeafRotator
		removeAppLeaf apps.LeafRemover
	)
	if meshCA != nil {
		clusterID := strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID"))
		appLeafDir := filepath.Join(dataDir, "tls", "apps")
		// buildAppLeafCmd fills the delivery command from freshly-minted PEMs —
		// shared by the deploy minter and the rotation path so the wire shape
		// (FQDNs, upstream port) can't drift between them.
		//
		// The cert and the route come from different places on purpose. The leaf
		// carries BOTH of the app's names whatever its exposure (a cert is an
		// identity, not an access control), so the route hosts — and only they —
		// decide what the node's proxy will answer for. AppRouteHosts leaves
		// LANFQDN empty for a tailnet-only app, and RenderCaddyConfig drops any
		// app with no LAN host from the LAN listener.
		buildAppLeafCmd := func(app *apps.App, certPEM, keyPEM []byte) proto.AppLeafCmd {
			tailnetFQDN, lanFQDN := mesh.AppRouteHosts(clusterID, app.Name, app.ExposeLAN)
			return proto.AppLeafCmd{
				AppID:        app.ID,
				Name:         app.Name,
				CertPEM:      certPEM,
				KeyPEM:       keyPEM,
				TailnetFQDN:  tailnetFQDN,
				LANFQDN:      lanFQDN,
				UpstreamPort: app.PublishedPort,
				UpstreamTLS:  app.WebTLS,
			}
		}
		mintAppLeaf = func(app *apps.App) (proto.AppLeafCmd, error) {
			certPEM, keyPEM, err := mesh.MintAppLeaf(meshCA, clusterID, app.Name)
			if err != nil {
				return proto.AppLeafCmd{}, err
			}
			return buildAppLeafCmd(app, certPEM, keyPEM), nil
		}
		// rotateAppLeaf is the disk-backed form used by the rotation sweep and by
		// the exposure toggle. It always returns the app's CURRENT desired state
		// — RotateAppLeaf delivers it either way — and renewed reports only
		// whether the cert in it is new, which is what decides the commit
		// (apps.LeafRotator).
		rotateAppLeaf = func(app *apps.App) (proto.AppLeafCmd, bool, func() error, error) {
			dir := filepath.Join(appLeafDir, app.ID)
			certPEM, keyPEM, renewed, err := mesh.PrepareAppLeaf(meshCA, dir, clusterID, app.Name)
			if err != nil {
				return proto.AppLeafCmd{}, false, nil, err
			}
			commit := func() error { return mesh.CommitAppLeaf(dir, certPEM, keyPEM) }
			return buildAppLeafCmd(app, certPEM, keyPEM), renewed, commit, nil
		}
		removeAppLeaf = func(appID string) error {
			return os.RemoveAll(filepath.Join(appLeafDir, appID))
		}
	}
	runner.Register(apps.DeployWorkflow(appsStore, invStore, busSrv.Conn(), mintAppLeaf))
	runner.Register(apps.StopWorkflow(appsStore, invStore, busSrv.Conn()))
	runner.Register(apps.DeleteWorkflow(appsStore, invStore, busSrv.Conn(), removeAppLeaf))
	runner.Register(apps.ReconcileWorkflow(appsStore, invStore, busSrv.Conn(), mintAppLeaf))
	runner.Register(apps.RotateLeavesWorkflow(appsStore, invStore, busSrv.Conn(), rotateAppLeaf))
	runner.Register(updater.UpdateWorkflow(updaterStore, invStore, busSrv.Conn(), updater.Config{
		PublicBaseURL: publicBaseURL,
		SelfNodeID:    selfNodeID,
	}))
	runner.Register(updater.SystemUpdateWorkflow(updaterStore, invStore, jobStore, runner, busSrv.Conn(), updater.SystemUpdateConfig{
		SelfNodeID: selfNodeID,
	}))
	runner.Register(mesh.ApplyWorkflow(meshSvc, invStore, busSrv.Conn()))
	runner.Register(mesh.ReconcileWorkflow(meshSvc, invStore, jobStore, runner, busSrv.Conn()))
	runner.Register(mesh.EnrollNodeWorkflow(meshSvc, invStore, busSrv.Conn()))
	// backup.target.claim — the only path in the system that formats a disk
	// (design/storage.md §4.8). The cluster id is stamped into the on-disk
	// marker so a disk can say which cluster wrote it.
	runner.Register(storage.ClaimWorkflow(backupStore, invStore, storage.Config{
		ClusterID: strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")),
	}))
	runner.Register(bmc.PowerWorkflow(bmcSvc, invStore))
	// bmc.configure is registered after NewServer below — it needs the
	// server's SoL SessionManager to refuse swaps under a live console.

	// Abort any jobs left in-flight from a previous run before we expose
	// HTTP. v0 policy is honest-failure, not resume — see saga.go — EXCEPT a
	// control-plane self-update, which intentionally reboots the api mid-saga:
	// the decider defers it so ResumeSelfUpdates can finish it on the new slot.
	// Since #56 that applies to the parent system.update too, when self was
	// the last target of a fleet run — ResumeSystemUpdates finishes that one.
	runner.SetRecoverDecider(updater.SelfUpdateRecoverDecider(ctx, jobStore, selfNodeID))
	if err := runner.Recover(ctx); err != nil {
		log.Fatalf("rasputin-api: recover in-flight jobs: %v", err)
	}
	// Clear per-node update rows stranded in_progress by a job that already
	// reached a terminal state (#53). The OnTerminal hook closes this path
	// going forward; this one-shot sweep is what reaches back to rows stranded
	// before it existed, or by a process that died between failing the job and
	// firing the hook. Runs AFTER Recover so orphans it just failed are swept
	// in the same pass. Non-fatal: a stale history row is a display problem,
	// not a reason to refuse to start.
	if err := updater.ReconcileStrandedRows(ctx, updaterStore, jobStore); err != nil {
		log.Printf("rasputin-api: reconcile stranded node_updates: %v", err)
	}
	// Same sweep for backup-target claims: a row left `pending` by a process
	// that died mid-saga renders as a claim still running, forever.
	if err := storage.ReconcileStrandedRows(ctx, backupStore, jobStore); err != nil {
		log.Printf("rasputin-api: reconcile stranded backup_targets: %v", err)
	}
	// Finish any self-update that rebooted us onto the new slot (no-op when
	// there isn't one). Non-blocking — reconciles in the background once the
	// co-located agent reconnects.
	updater.ResumeSelfUpdates(ctx, updaterStore, invStore, jobStore, runner, busSrv.Conn(), selfNodeID)
	// And the fleet run that self-update belonged to, if it was one (#56).
	// Ordered after ResumeSelfUpdates because it waits on the child that call
	// drives — starting it first would just poll for longer.
	updater.ResumeSystemUpdates(ctx, jobStore, runner, busSrv.Conn(), selfNodeID)

	invSvc := inventory.NewService(invStore, busSrv.Conn())
	// On a firewall-role node's FIRST registration, seed the stock-equivalent
	// baseline firewall rules (Allow-DHCP-Renew / Allow-Ping / Allow-IGMP) as
	// real, visible, deletable intents. SeedBaselineRules is idempotent via a
	// persistent marker and never reseeds, so a baseline rule the operator
	// later deletes does not resurrect. Errors are logged and swallowed — a
	// seeding failure must never break node registration. Wired here (not in
	// the inventory package) to avoid an inventory→firewall import cycle,
	// mirroring auth.SetLoginHook → mesh.EnsureUser above.
	invSvc.SetOnNodeAdded(func(hookCtx context.Context, n *proto.Node) {
		// Firewall-only: seed the stock-equivalent baseline rules.
		if n.Role == proto.RoleFirewall {
			if _, err := firewall.SeedBaselineRules(hookCtx, fwStore, n.ID); err != nil {
				log.Printf("rasputin-api: seed baseline firewall rules for %s: %v", n.ID, err)
			}
		}
		// Auto-enroll every managed node — firewall INCLUDED — into the mesh so it
		// receives the mesh CA (needed to verify the control plane's TLS when
		// downloading update bundles) and a tailnet identity. The controlplane
		// self-enrolls during setup. Without this, a day-2 node added through the
		// wizard joins the bus but never the mesh, and its first update fails on the
		// bundle download with "certificate signed by unknown authority" (found on
		// bench-compute1 2026-06-22; and on the firewall 2026-07-02 once it became a
		// deployable A/B OTA target — the firewall was previously excluded here).
		// The DELETE /api/nodes cascade removes the headscale node + device.
		// This hook is best-effort fast-path only: the mesh.reconcile workflow's
		// converge_enrollment step retries any node this misses (e.g. one that
		// registered before Headscale finished bring-up), every reconcile tick.
		if slices.Contains(mesh.AutoEnrollRoles, n.Role) {
			spec, _ := json.Marshal(mesh.EnrollSpec{NodeID: n.ID})
			if _, err := runner.Submit(hookCtx, "mesh.enroll_node", spec, "auto-enroll"); err != nil {
				log.Printf("rasputin-api: auto mesh-enroll %s: %v", n.ID, err)
			} else {
				log.Printf("rasputin-api: auto-enrolling %s (%s) into the mesh", n.ID, n.Role)
			}
		}
	})
	if err := invSvc.Start(ctx); err != nil {
		log.Fatalf("rasputin-api: inventory service: %v", err)
	}
	defer invSvc.Stop()

	metricsSvc := metrics.NewService(metricsStore, busSrv.Conn())
	if err := metricsSvc.Start(ctx); err != nil {
		log.Fatalf("rasputin-api: metrics service: %v", err)
	}
	defer metricsSvc.Stop()

	// Authoritative DNS for the internal zone <cluster-id>.internal, plus the
	// <cluster>.local unicast name, both → the control plane's own LAN IP
	// (ADR-0004 §3/§8). Slice 1 serves CP-self answers only; node + app records
	// arrive with Slice 2. Binds the LAN IP:53 by value — never 0.0.0.0 — so
	// systemd-resolved's 127.0.0.53 stub, which publishes the cluster's mDNS
	// .local (ADR-0003), is left untouched. A bind failure (no LAN route, or no
	// privilege on a dev box) is logged and skipped, never fatal: a control
	// plane that won't start is worse than one without name resolution.
	// nsResp is hoisted so the api server can hot-swap its AA-11 forwarding stub
	// after construction (below); nil when the nameserver is disabled/unstarted.
	var nsResp *nameserver.Responder
	if envOr("RASPUTIN_DNS", "on") != "off" {
		zone := "rasputin.internal"
		if id := strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")); id != "" {
			zone = id + ".internal"
		}
		// Project node + app A records live from inventory + apps, under the
		// **.lan subzone** (ADR-0004 §9): <hostname>.lan.<zone> → node LAN IP,
		// <app>.lan.<zone> → its target node's LAN IP. The bare base domain is the
		// tailnet name (MagicDNS / extra_records), so the CP nameserver serves LAN
		// IPs only under .lan and NXDOMAINs bare node/app names — a LAN-only client
		// can't route a tailnet IP anyway. Read on every query (store errors →
		// serve nothing that round, never crash).
		lanZone := "lan." + zone
		clusterSrc := nameserver.NewClusterSource(lanZone,
			func() []nameserver.NodeAddr {
				nodes, err := invStore.List(ctx)
				if err != nil {
					log.Printf("rasputin-api: nameserver node projection: %v", err)
					return nil
				}
				out := make([]nameserver.NodeAddr, 0, len(nodes))
				for _, n := range nodes {
					out = append(out, nameserver.NodeAddr{ID: n.ID, Hostname: n.Hostname, IP: net.ParseIP(n.LANIP)})
				}
				return out
			},
			func() []nameserver.AppRec {
				list, err := appsStore.List(ctx)
				if err != nil {
					log.Printf("rasputin-api: nameserver app projection: %v", err)
					return nil
				}
				out := make([]nameserver.AppRec, 0, len(list))
				for _, a := range list {
					out = append(out, nameserver.AppRec{Name: a.Name, TargetNode: a.TargetNode, ExposeLAN: a.ExposeLAN})
				}
				return out
			})
		nsResp = nameserver.NewResponder(zone,
			nameserver.NewSelfSource(zone, clusterHostname(), primaryLanIP),
			clusterSrc)
		nsSrv := nameserver.NewServer(primaryLanIP, 53, nsResp)
		if err := nsSrv.Start(ctx); err != nil {
			log.Printf("rasputin-api: nameserver not started (%v) — %s won't resolve via the CP", err, zone)
		} else {
			log.Printf("rasputin-api: nameserver authoritative for %s on %s (udp+tcp)", zone, nsSrv.UDPAddr())
			defer nsSrv.Stop()
		}
	}

	// IDS alert subscriber — appends each firewall snort alert to a JSONL
	// file the obs Alloy tails (when EnableLoki + EnableIDSPipe are on).
	// Even with obs off, the file is still written so operators can
	// `tail -f` / `jq` it from disk. Path is under dataDir so it survives
	// the same way every other persistent state does.
	//
	// idsLogDir is passed to mustWireObs so the supervisor knows where to
	// mount the host dir into the Alloy container; same constant both
	// sides → no path-mismatch class of bug.
	idsLogDir := filepath.Join(dataDir, "obs", "ids-alerts")
	idsLogPath := filepath.Join(idsLogDir, "alerts.jsonl")
	idsWriter, err := ids.NewWriter(idsLogPath)
	if err != nil {
		log.Fatalf("rasputin-api: ids writer: %v", err)
	}
	defer func() { _ = idsWriter.Close() }()
	idsSvc := ids.NewService(idsWriter, busSrv.Conn())
	if err := idsSvc.Start(ctx); err != nil {
		log.Fatalf("rasputin-api: ids service: %v", err)
	}
	defer idsSvc.Stop()

	// Tier 2 observability — VictoriaMetrics sidecar + metrics fan-out.
	// Off by default so dev runs don't require Docker. The supervisor is
	// always constructed; the operator's stored obs.enabled setting decides
	// whether the stack actually runs, and Settings toggles it at runtime
	// through the obs.enable / obs.disable jobs below. RASPUTIN_OBS_ENABLED
	// only seeds that setting on a first boot.
	// See wiki design/control-plane/observability-stack.md §3.8.
	seedObsEnabled(ctx, setupStore)
	obsEnabled := func(ctx context.Context) (bool, error) {
		return setupStore.GetBool(ctx, setup.KeyObsEnabled, false)
	}
	obsSup, obsSink, obsStatus := mustWireObs(ctx, dataDir, selfNodeID, metricsSvc, idsLogDir, obsEnabled)
	defer func() {
		// Only tear down what we brought up. Stop shells out to `docker
		// compose stop`; on a never-started stack that's a pointless
		// subprocess, and on a host with no runtime it's a noisy one.
		if on, err := obsEnabled(context.Background()); err != nil || !on {
			return
		}
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		if err := obsSup.Stop(stopCtx); err != nil {
			log.Printf("rasputin-api: obs supervisor stop: %v", err)
		}
	}()
	// The operator-facing toggle. Registered here rather than with the other
	// workflows above because these close over the supervisor + sink that
	// mustWireObs just built. Runner.Register is mutex-guarded and workflows
	// resolve at Submit time, so late registration is safe.
	setObsEnabled := func(ctx context.Context, on bool) error {
		return setupStore.SetBool(ctx, setup.KeyObsEnabled, on)
	}
	setObsSink := func(on bool) {
		if on {
			metricsSvc.SetSink(obsSink)
			return
		}
		metricsSvc.SetSink(nil)
	}
	runner.Register(obs.EnableWorkflow(obsSup, setObsEnabled, setObsSink, func() bool {
		return dockerBinAvailable(obsDockerBin())
	}))
	runner.Register(obs.DisableWorkflow(obsSup, setObsEnabled, setObsSink))

	// Per-node observability collectors (Slice 1.2b, §3.10). Only in appliance
	// mode: the mTLS ingress the collectors write to is appliance-only
	// (obsIngestAddr), and dev has no compute/storage nodes. The reconcile
	// converges the fleet to the operator's obs opt-in — deploy collectors when
	// on, tear them down when off.
	var obsCollectorEntries []scheduler.Entry
	if obsIngestAddr != "" {
		ingressBaseURL, ingressServerName, err := obs.DeriveIngressEndpoint(publicBaseURL, obsIngestAddr)
		if err != nil {
			log.Fatalf("rasputin-api: obs collector ingress endpoint: %v", err)
		}
		// Mint (idempotently, near-expiry renewal via MintLeafToDisk) each
		// node's client-auth leaf under the mesh CA. CN = node_id is what the
		// ingress reads back; the DNS SAN is cosmetic for a client leaf (Go
		// verifies the chain + clientAuth EKU, not SANs, on the server side).
		mintCollectorLeaf := func(nodeID string) (certPEM, keyPEM, caPEM string, err error) {
			paths, err := mesh.MintLeafToDisk(meshCA,
				filepath.Join(dataDir, "tls", "collectors", nodeID),
				mesh.LeafSpec{CommonName: nodeID, DNSNames: []string{nodeID}, ClientAuth: true})
			if err != nil {
				return "", "", "", err
			}
			cert, err := os.ReadFile(paths.CertPath)
			if err != nil {
				return "", "", "", fmt.Errorf("read collector leaf cert: %w", err)
			}
			key, err := os.ReadFile(paths.KeyPath)
			if err != nil {
				return "", "", "", fmt.Errorf("read collector leaf key: %w", err)
			}
			return string(cert), string(key), string(meshCA.CertPEM), nil
		}
		runner.Register(obs.CollectorReconcileWorkflow(obs.CollectorReconcileDeps{
			Inv: invStore, Jobs: jobStore, Runner: runner, Enabled: obsEnabled,
		}))
		runner.Register(obs.CollectorDeployWorkflow(obs.CollectorDeployDeps{
			Inv: invStore, Mint: mintCollectorLeaf,
			IngressBaseURL: ingressBaseURL, ServerName: ingressServerName,
		}))
		runner.Register(obs.CollectorTeardownWorkflow())
		obsCollectorReconcileEvery := parseDurationOr(
			os.Getenv("RASPUTIN_OBS_COLLECTOR_RECONCILE_INTERVAL"), 5*time.Minute)
		obsCollectorEntries = append(obsCollectorEntries, scheduler.Entry{
			Kind: obs.CollectorReconcileKind, Interval: obsCollectorReconcileEvery,
			InitialDelay: 2 * time.Minute,
		})
		log.Printf("rasputin-api: obs collectors enabled — ingress %s (server_name %s)", ingressBaseURL, ingressServerName)
	}

	// Reconciliation tickers. One scheduler entry per drift-prone
	// subsystem; staggered so the bus doesn't stampede at startup. All
	// intervals are env-overridable (parsed by parseDurationOr below).
	// Defaults match the firewall + mesh §6 docs (5 min).
	fwReconcileEvery := parseDurationOr(os.Getenv("RASPUTIN_FW_RECONCILE_INTERVAL"), 5*time.Minute)
	appsReconcileEvery := parseDurationOr(os.Getenv("RASPUTIN_APPS_RECONCILE_INTERVAL"), 5*time.Minute)
	meshReconcileEvery := parseDurationOr(os.Getenv("RASPUTIN_MESH_RECONCILE_INTERVAL"), 5*time.Minute)
	// Per-app TLS leaves live a year and renew at <60d left (mesh.renewWindow);
	// a daily sweep is ample and cheap (it no-ops until a leaf enters the window).
	leafRotateEvery := parseDurationOr(os.Getenv("RASPUTIN_APPS_LEAF_ROTATE_INTERVAL"), 24*time.Hour)
	sched := scheduler.New(runner, append([]scheduler.Entry{
		{Kind: "firewall.reconcile", Interval: fwReconcileEvery, InitialDelay: 30 * time.Second},
		{Kind: "firewall.dns_forward", Interval: fwReconcileEvery, InitialDelay: 100 * time.Second},
		{Kind: "apps.reconcile", Interval: appsReconcileEvery, InitialDelay: 60 * time.Second},
		{Kind: "mesh.reconcile", Interval: meshReconcileEvery, InitialDelay: 90 * time.Second},
		{Kind: "apps.leaf_rotate", Interval: leafRotateEvery, InitialDelay: 2 * time.Minute},
	}, obsCollectorEntries...))
	sched.Start(ctx)
	defer sched.Stop()

	srv := apipkg.NewServer(jobStore, runner, invStore, invSvc, fwStore, appsStore, metricsStore, updaterStore, verifier, bundleDir, trustDir, meshSvc, bmcSvc, setupSvc, authSvc, obsStatus, busTokenStore, busSrv.Conn())
	// The SAME rotator closure the leaf-rotation workflow uses, so PATCH
	// /api/apps/{id} applies a LAN-exposure change (#197) to the proxy
	// immediately instead of leaving the .lan name resolving until the next
	// sweep. One rotator, two callers — a second one would differ in exactly
	// the case that matters, an offline node.
	srv.SetAppLeafRotator(rotateAppLeaf)
	// The backup-target ledger, for GET/POST /api/backup/targets.
	srv.SetBackupStore(backupStore)

	// AA-11 DNS forwarding (ADR-0004 §10): reconcile the nameserver's off-zone
	// forwarding stub from the persisted setting, and hand the api the hook to
	// re-apply it when the operator toggles it. Blank upstream → inherit the CP's
	// DHCP resolver, falling back to a public resolver when that would loop
	// (detect-and-fall-back). Kept plain-typed so api needn't import nameserver.
	if nsResp != nil {
		applyDNS := func(ctx context.Context) (string, bool, error) {
			cfg, err := setupSvc.GetDNSForwarding(ctx)
			if err != nil {
				return "", false, err
			}
			if !cfg.Enabled {
				nsResp.SetForwarder(nil)
				return "", false, nil
			}
			up := nameserver.ResolveUpstream(cfg.Upstream, primaryLanIP(),
				nameserver.SystemUpstreams("/etc/resolv.conf", "/run/systemd/netif/leases"))
			nsResp.SetForwarder(nameserver.NewForwarder(nameserver.ForwarderConfig{
				Upstream: up.Addr,
				SelfIP:   primaryLanIP,
			}))
			return up.Addr, up.FellBack, nil
		}
		if _, _, err := applyDNS(ctx); err != nil {
			log.Printf("rasputin-api: DNS forwarding initial apply: %v", err)
		}
		srv.SetDNSForwardingApplier(applyDNS)
	}

	// Host LAN IP + MAC for the DNS-forwarding reservation guidance (AA-11) —
	// available whether or not the nameserver runs.
	srv.SetHostLANInfo(func() (string, string) {
		ip := primaryLanIP()
		if ip == nil {
			return "", ""
		}
		return ip.String(), hardwareAddrForIP(ip)
	})

	// bmc.configure: delivers the operator's Settings selection to the
	// host agent (bmc-settings.md §4); refuses while a console is open or
	// a bmc.power job is running. Registered here because it shares the
	// server's SoL SessionManager.
	runner.Register(bmc.ConfigureWorkflow(bmcSvc, invStore, setupStore, srv.BMCSessions(), func(ctx context.Context) (bool, error) {
		running, err := jobStore.ListJobsByStatus(ctx, []jobs.Status{jobs.StatusRunning})
		if err != nil {
			return false, err
		}
		for _, j := range running {
			if j.Kind == "bmc.power" {
				return true, nil
			}
		}
		return false, nil
	}))
	// Event-driven reconcile: re-push the selection when the host
	// re-registers stale (reflash / missed push). No ticker
	// (bmc-settings.md §4).
	stopBMCReconcile, err := bmc.StartReconcile(busSrv.Conn(), setupStore, func(ctx context.Context) (bool, error) {
		// Stand down while any bmc.configure job is queued or running —
		// mid-job the advertised and desired states legitimately differ.
		inflight, ferr := jobStore.ListJobsByStatus(ctx, []jobs.Status{jobs.StatusQueued, jobs.StatusRunning})
		if ferr != nil {
			return false, ferr
		}
		for _, j := range inflight {
			if j.Kind == "bmc.configure" {
				return true, nil
			}
		}
		return false, nil
	}, func(ctx context.Context, kind string, spec json.RawMessage, createdBy string) error {
		_, serr := runner.Submit(ctx, kind, spec, createdBy)
		return serr
	})
	if err != nil {
		log.Fatalf("rasputin-api: bmc reconcile: %v", err)
	}
	defer stopBMCReconcile()

	// Event-driven status seed: when a host advertises bmc-targets,
	// sweep a read-only status query across them so every reachable
	// node has a power state before the first operator verb.
	stopBMCSeed, err := bmc.StartStatusSeed(busSrv.Conn(), bmcSvc)
	if err != nil {
		log.Fatalf("rasputin-api: bmc status seed: %v", err)
	}
	defer stopBMCSeed()

	// Web UI (Next.js static export). The OS image installs it at the
	// default path (see rasputin-os package/rasputin-api); dev boxes
	// usually don't have it, so the api quietly stays headless there and
	// `next dev` serves the UI on :3000 instead.
	uiDir := envOr("RASPUTIN_UI_DIR", "/usr/share/rasputin/ui")
	if _, err := os.Stat(filepath.Join(uiDir, "index.html")); err == nil {
		srv.SetUIDir(uiDir)
		log.Printf("rasputin-api: serving web UI from %s", uiDir)
	} else {
		log.Printf("rasputin-api: no web UI at %s (%v); serving API only", uiDir, err)
	}

	// Real alerting (Slice 1.5): open the persisted alerts store and
	// wire a Service that merges aggregator + persisted views. Always
	// on — the store is shared with the rest of the api's SQLite and
	// is cheap when no rules are firing. The webhook receiver and
	// /ws/alerts push are no-ops until vmalert (in the obs compose
	// stack) starts POSTing.
	alertsStore, err := alerts.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: alerts store: %v", err)
	}
	defer alertsStore.Close()
	srv.SetAlertsService(alerts.New(invStore, jobStore, appsStore, setupSvc, alertsStore, busSrv.Conn(), busAuthEnforce))
	if secret := os.Getenv("RASPUTIN_ALERTS_WEBHOOK_SECRET"); secret != "" {
		srv.SetAlertsWebhookSecret(secret)
		log.Printf("rasputin-api: alerts webhook protected by shared secret")
	} else {
		log.Printf("rasputin-api: WARNING — alerts webhook is unauthenticated " +
			"(set RASPUTIN_ALERTS_WEBHOOK_SECRET to enable header auth)")
	}
	// Update discovery: the control plane reads signed releases directly from
	// each component's PUBLIC source repo over anonymous HTTPS — no token on the
	// appliance (ADR-0002; the rasputin-releases mirror is retired). Authenticity
	// is gated by the bundle signature, not repo privacy. RASPUTIN_RELEASE_API_BASE
	// is overridable for a proxy/CDN or tests.
	releaseChannel := envOr("RASPUTIN_RELEASE_CHANNEL", "stable")
	releaseAPIBase := envOr("RASPUTIN_RELEASE_API_BASE", "https://api.github.com")
	srv.SetReleaseSource(releases.NewGithubPublicSource(releaseAPIBase), releaseChannel)
	srv.SetReleaseDownloadBase(envOr("RASPUTIN_RELEASE_DOWNLOAD_BASE", "https://github.com"))
	log.Printf("rasputin-api: update channel = %s (direct from source repos)", releaseChannel)

	// App catalog (ADR-0006). The floor embedded in this build is what a
	// cluster has before it has ever completed a verified fetch; the poller
	// replaces it with the newest signed catalog it can verify. Resolution has
	// no third case, so nothing here merges the two.
	//
	// A floor that does not parse is a BUILD defect — every cluster from this
	// image would inherit it — so it is fatal rather than degraded.
	catalogFloor, err := floor.Load()
	if err != nil {
		log.Fatalf("rasputin-api: %v", err)
	}
	catalogStore, err := catalogsync.New(dataDir, catalogsync.NewVerifier(filepath.Join(trustDir, "root-ca.pem")), catalogFloor)
	if err != nil {
		log.Fatalf("rasputin-api: catalog store: %v", err)
	}
	catalogPoller := catalogsync.NewPoller(
		catalogsync.NewFetcher(
			envOr("RASPUTIN_CATALOG_REPO", ""),
			envOr("RASPUTIN_CATALOG_API_BASE", releaseAPIBase),
			releaseChannel,
		),
		catalogStore,
	)
	srv.SetCatalogSync(catalogStore, catalogPoller)
	go catalogPoller.Run(ctx)
	{
		v, fetched, note := catalogStore.State()
		src := "embedded floor"
		if fetched {
			src = "verified fetch"
		}
		log.Printf("rasputin-api: app catalog v%d (%s), polling %s every %s%s",
			v, src, releaseChannel, catalogsync.DefaultInterval,
			map[bool]string{true: " — " + note, false: ""}[note != ""])
	}

	handler := srv.Handler()

	// With HTTPS on, the plain-HTTP listener demotes to the bootstrap
	// surface (trust page + CA download + healthz; everything else 302s to
	// https). With HTTPS off — every dev run — it serves the full handler
	// exactly as before.
	httpHandler := handler
	var httpsSrv, obsIngestSrv *http.Server
	if httpsAddr != "" {
		httpsSrv = &http.Server{
			Addr:              httpsAddr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			// http/1.1 only: with h2 offered, Chrome rides WebSockets on an
			// RFC 8441 extended-CONNECT h2 stream (Go ≥1.25 advertises it),
			// and the SoL console's browser→api leg silently stalled on the
			// bench (2026-07-26) — frames sent, never delivered to the
			// handler. Pin ALPN to the classic Upgrade path until WS-over-h2
			// is deliberately validated; the dashboard loses nothing.
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"http/1.1"},
			},
		}
		// The obs mTLS ingress shares the api's own server leaf for its
		// identity (started with the same cert/key below, once minted) but
		// adds RequireAndVerifyClientCert against the mesh CA — a per-node
		// collector authenticates purely by presenting a mesh-CA-signed client
		// leaf, whose node_id is the cert CN (see obs_ingest.go). Constructed
		// synchronously here (like httpsSrv) so shutdown can reach it; it only
		// starts serving inside the clock-gated goroutine, after the leaf exists.
		if obsIngestAddr != "" {
			clientCAs := x509.NewCertPool()
			clientCAs.AddCert(meshCA.Cert)
			obsIngestSrv = &http.Server{
				Addr:              obsIngestAddr,
				Handler:           srv.ObsIngestHandler(),
				ReadHeaderTimeout: 10 * time.Second,
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					ClientAuth: tls.RequireAndVerifyClientCert,
					ClientCAs:  clientCAs,
				},
			}
		}
		// HTTP demotes to the bootstrap surface right away so the node is
		// reachable immediately; HTTPS comes up asynchronously once the clock
		// is trustworthy (below). Minting the leaf must NOT block main() —
		// this unit is Type=notify with the default ~90s start timeout, and a
		// no-RTC node may wait tens of seconds for NTP.
		httpHandler = srv.BootstrapHandler()
		go func() {
			// Don't mint the API leaf against an untrusted clock. A no-RTC node
			// (e.g. Pi 5) boots to a bogus pre-NTP time; minting then anchors
			// the cert's validity window in the past, so the browser reports an
			// "expired" (or "not yet valid") certificate even though the image
			// is fine. Wait — bounded — for systemd-timesyncd to synchronize
			// first. Bounded so a genuinely offline node (no reachable NTP at
			// all) still eventually serves HTTPS, degraded and logged loudly.
			// See provisioning.md "Time sync".
			synced := waitForTrustworthyClock(ctx, clockGateTimeout)
			if ctx.Err() != nil {
				return // shutting down before the clock settled
			}
			if !synced {
				log.Printf("rasputin-api: WARNING — system clock not NTP-synchronized after %s; "+
					"minting the HTTPS leaf against the current clock. If the UI shows an expired or "+
					"not-yet-valid certificate, fix time sync (NTP) and restart rasputin-api.", clockGateTimeout)
			}
			leafPaths, err := ensureAPILeaf(meshCA, dataDir)
			if err != nil {
				log.Fatalf("rasputin-api: https leaf: %v", err)
			}
			log.Printf("rasputin-api: https listening on %s (leaf %s)", httpsAddr, leafPaths.CertPath)
			// Bring up the obs mTLS ingress on the same leaf, in its own
			// goroutine so it serves alongside (not after) HTTPS. Both listeners
			// load the leaf files at serve time; the leaf's SAN-drift re-mint
			// path (MintLeafToDisk) applies on the next restart, same as HTTPS.
			if obsIngestSrv != nil {
				go func() {
					log.Printf("rasputin-api: obs mTLS ingress listening on %s", obsIngestAddr)
					if err := obsIngestSrv.ListenAndServeTLS(leafPaths.CertPath, leafPaths.KeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
						log.Fatalf("rasputin-api: obs ingress: %v", err)
					}
				}()
			}
			if err := httpsSrv.ListenAndServeTLS(leafPaths.CertPath, leafPaths.KeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("rasputin-api: https: %v", err)
			}
		}()
	}

	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           httpHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("rasputin-api: http listening on %s", httpAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("rasputin-api: http: %v", err)
		}
	}()

	// systemd integration: declare startup complete, then keep the
	// watchdog fed for as long as the liveness probe (a trivial SQLite
	// query) keeps passing. See internal/sdnotify for the war story.
	sdnotify.Ready()
	sdnotify.StartWatchdog(ctx, func(pctx context.Context) error {
		_, err := authStore.CountUsers(pctx)
		return err
	})

	<-ctx.Done()
	log.Println("rasputin-api: shutting down")

	// Hard cap: exit within 20s no matter which teardown step wedges, so we never
	// sit at systemd's 90s SIGKILL default (the stop job seen on the n100 console).
	// runner.Wait() below was UNBOUNDED and could block shutdown indefinitely; the
	// deferred subsystem stops (obs/sched/ids/alerts/bus) are best-effort within
	// this window. See #8.
	go func() {
		time.Sleep(20 * time.Second)
		log.Println("rasputin-api: shutdown deadline (20s) exceeded; forcing exit")
		os.Exit(0)
	}()

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = httpSrv.Shutdown(shutCtx)
	if httpsSrv != nil {
		_ = httpsSrv.Shutdown(shutCtx)
	}
	if obsIngestSrv != nil {
		_ = obsIngestSrv.Shutdown(shutCtx)
	}
	// Bound the job-runner drain — a stuck worker must not wedge shutdown (#8).
	runnerDone := make(chan struct{})
	go func() { runner.Wait(); close(runnerDone) }()
	select {
	case <-runnerDone:
	case <-time.After(5 * time.Second):
		log.Println("rasputin-api: job runner did not drain in 5s; proceeding to exit")
	}
}

// clockGateTimeout bounds how long ensureAPILeaf waits for the wall clock to
// NTP-synchronize before minting the HTTPS leaf. Kept under the api unit's
// ~90s Type=notify start timeout headroom — but it runs in the HTTPS
// goroutine, off the readiness path, so it never trips that timeout anyway.
const clockGateTimeout = 90 * time.Second

// clockSyncDir / clockSyncMarker locate systemd-timesyncd's synchronization
// signal. timesyncd touches the marker on its first successful sync; this is
// the same file time-sync.target / systemd-time-wait-sync key on. Package vars
// (not consts) so tests can point them at a temp dir.
var (
	clockSyncDir    = "/run/systemd/timesync"
	clockSyncMarker = "/run/systemd/timesync/synchronized"
)

// waitForTrustworthyClock blocks until systemd-timesyncd reports the wall clock
// has synchronized (via NTP), ctx is cancelled, or timeout elapses. It returns
// true only when synchronization was observed. On a host without
// systemd-timesyncd (every dev run / CI — no /run/systemd/timesync) it returns
// true immediately: the gate exists solely to stop a no-RTC appliance from
// minting its TLS leaf against a bogus pre-NTP clock (the "expired cert"
// failure). The deadline uses the monotonic clock, so an NTP step mid-wait
// does not distort it.
func waitForTrustworthyClock(ctx context.Context, timeout time.Duration) bool {
	if _, err := os.Stat(clockSyncDir); err != nil {
		return true // not a systemd-timesyncd system; nothing to wait for
	}
	if _, err := os.Stat(clockSyncMarker); err == nil {
		return true // already synchronized
	}
	log.Printf("rasputin-api: waiting up to %s for the system clock to NTP-synchronize before minting the HTTPS leaf…", timeout)
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
			if _, err := os.Stat(clockSyncMarker); err == nil {
				return true
			}
			if !time.Now().Before(deadline) {
				return false
			}
		}
	}
}

// ensureAPILeaf mints (or reuses — MintLeafToDisk is idempotent with
// SAN-drift and <60d re-mint logic) the api's own HTTPS server leaf under
// the Mesh CA. Lives at <dataDir>/tls/api/leaf.{pem,key}, parallel to the
// Headscale leaf at <dataDir>/mesh/headscale/certs/.
func ensureAPILeaf(meshCA *mesh.MeshCA, dataDir string) (mesh.LeafPaths, error) {
	hostname, _ := os.Hostname()
	spec := apiLeafSpec(hostname, primaryLanIP())
	return mesh.MintLeafToDisk(meshCA, filepath.Join(dataDir, "tls", "api"), spec)
}

// apiLeafSpec builds the SAN set for the api's HTTPS leaf:
//
//	DNS: rasputin.local (the mDNS name the OS image advertises via
//	     systemd-resolved), localhost (same-host curl/debug, and
//	     symmetric with the Headscale leaf), the machine hostname, and
//	     <hostname>.local when the hostname is a bare label.
//	IP:  127.0.0.1 plus the discovered primary LAN IP, so operators who
//	     browse by address before mDNS resolves still get a clean lock.
//
// MintLeafToDisk's SAN-drift check re-mints automatically when any of
// these change (new hostname, node moved subnets).
func apiLeafSpec(hostname string, lanIP net.IP) mesh.LeafSpec {
	dns := []string{"rasputin.local", "localhost"}
	seen := map[string]bool{"rasputin.local": true, "localhost": true}
	add := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" && !seen[name] {
			seen[name] = true
			dns = append(dns, name)
		}
	}
	host := strings.ToLower(strings.TrimSpace(hostname))
	add(host)
	if host != "" && !strings.Contains(host, ".") {
		add(host + ".local")
	}
	ips := []net.IP{net.IPv4(127, 0, 0, 1)}
	if lanIP != nil {
		ips = append(ips, lanIP)
	}
	return mesh.LeafSpec{
		CommonName:  "rasputin.local",
		DNSNames:    dns,
		IPAddresses: ips,
	}
}

// primaryLanIP returns the IP of the interface holding the default route,
// or nil when there is none (air-gapped box). Mirrors the "dial 8.8.8.8
// and inspect LocalAddr" trick in agent/internal/host.PrimaryLanCIDR —
// mirrored rather than imported because that package is internal to the
// agent module and the api can't reach across the module boundary. No
// packet leaves the host: net.Dial("udp", ...) only does a route lookup.
func primaryLanIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return local.IP
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// hardwareAddrForIP returns the MAC of the interface holding ip, best-effort
// ("" if not found). Used to recommend a DHCP reservation for the control plane
// (AA-11) so its address survives reboots.
func hardwareAddrForIP(ip net.IP) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var aip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				aip = v.IP
			case *net.IPAddr:
				aip = v.IP
			}
			if aip != nil && aip.Equal(ip) {
				return iface.HardwareAddr.String()
			}
		}
	}
	return ""
}

// clusterHostname returns the cluster's mDNS name — "<cluster-id>.local" — or
// "" when this process is not running on a provisioned node.
//
// RASPUTIN_CLUSTER_ID is written into node.env by firstboot and by nothing
// else, so its PRESENCE is the signal "I am a provisioned appliance". That is
// what lets the appliance defaults below derive a name while dev keeps its
// localhost defaults untouched — the alternative, deriving unconditionally,
// would rename every developer's origin and break the local passkey flow.
//
// Per ADR-0003 the id defaults to "rasputin", so a node that predates
// per-cluster naming — or any node whose operator never chose a name —
// derives exactly the values the OS image hardcodes today. That is the
// mechanism by which per-cluster naming ships with no migration.
func clusterHostname() string {
	id := strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID"))
	if id == "" {
		return ""
	}
	return id + ".local"
}

// applianceOr returns the appliance value derived from the cluster name, or
// devDefault when there is no cluster id (i.e. a dev box). Callers still let an
// explicit env var win — this only supplies the default.
func applianceOr(appliance func(host string) string, devDefault string) string {
	if h := clusterHostname(); h != "" {
		return appliance(h)
	}
	return devDefault
}

// busPreseedPath is where the controlplane reads its provisioning matched-set
// token preseed (hashes + node bindings). firstboot copies it here from the
// seed FAT. Overridable for tests / non-default layouts.
func busPreseedPath(dataDir string) string {
	return envOr("RASPUTIN_BUS_PRESEED", filepath.Join(dataDir, "bus", "preseed.json"))
}

// loadBusPreseed reads a JSON array of {hash,nodeId,label} and preloads it into
// the token store. A missing file is normal (not every install is a pre-paired
// matched set) and returns (0, nil). Idempotent via Store.PreloadHashes.
func loadBusPreseed(ctx context.Context, store *busauth.Store, path string) (int, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var toks []busauth.PreseedToken
	if err := json.Unmarshal(data, &toks); err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	return store.PreloadHashes(ctx, toks)
}

// randomSecret returns a 32-byte hex secret for the bus AuthUser. Generated
// per boot; only ever used by the api's own in-process connection, so it never
// needs to persist.
func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// secureCookies decides whether the session and pending-auth cookies carry
// the Secure attribute.
//
// It is DERIVED from whether this process terminates TLS, rather than read
// from a standalone env var, because `httpsAddr != ""` is the exact condition
// under which the cookie actually travels over TLS: it is the same value that
// starts the HTTPS listener AND demotes the plain-HTTP listener to the
// bootstrap surface, where everything but the trust page and healthz 302s to
// https. So whenever this returns true, an authenticated request cannot be
// served over plaintext, and whenever it returns false there is no https
// listener for a Secure cookie to be sent to.
//
// It previously read `os.Getenv("RASPUTIN_SECURE_COOKIES") == "1"` — opt-in,
// defaulting to OFF. That variable was set nowhere in rasputin-control-plane,
// rasputin-os or rasputin-openwrt-firewall, so the 7-day passkey session
// cookie shipped without Secure on every appliance, even though the appliance
// serves https (the OS image's unit sets RASPUTIN_HTTPS_ADDR=:443). The
// default was the bench value and production had to remember to opt in; a
// derived value cannot be forgotten the way an env var can.
//
// The override remains for deployments this process cannot observe — TLS
// terminated by a reverse proxy in front of a plain-HTTP api (force true), or
// an https listener reached over a path where Secure would strand the session
// (force false). Unset means derived, which is what every current deployment
// wants.
func secureCookies(httpsAddr string, override *bool) bool {
	if override != nil {
		return *override
	}
	return httpsAddr != ""
}

// envBoolPtr returns nil when the env var is unset (so the config's own
// default applies) and a non-nil bool when explicitly set. "1"/"true"/"yes"
// → true; anything else → false. The pointer return shape is what the obs
// config uses for tri-state ("not set" vs "explicitly false" vs "true").
func envBoolPtr(key string) *bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		t := true
		return &t
	default:
		f := false
		return &f
	}
}

// updateTrustEnv is the one way to reach the dev-permissive OS-update verifier.
// Named, never inferred — the whole point of wireBundleVerifier below.
const updateTrustEnv = "RASPUTIN_UPDATE_TRUST"

// wireBundleVerifier selects the OS-update signature verifier
// (RASPUTIN_UPDATE_TRUST, default "require"):
//
//	require        — <trustDir>/root-ca.pem must load. If it does not, the
//	                 verifier is UNAVAILABLE and every bundle is refused.
//	dev-permissive — a dev box with no PKI: with no root CA present, bundle
//	                 signatures are parsed but not checked. Explicit only.
//
// ⚠️ THE MISSING FILE USED TO SELECT THE PERMISSIVE MODE BY ITSELF, and that is
// the same class of bug as the 2026-09-01 storage incident and the mock-mesh
// fallback #220 removed: an absent prerequisite silently became a confident
// answer. Here the answer was "this OS update bundle is fine to install",
// produced without checking a single signature, on the artifact that decides
// what code a node boots. It was visible only as SignedBy "<unverified>" in a
// manifest, which nothing alerts on. `require` means require.
//
// NOT log.Fatalf, for the reason #89 settled: an appliance that will not start
// is unreachable and unfixable. The api boots, /healthz answers, every other
// page works; only bundle upload and staging refuse, naming the missing file.
// An unrecognised value falls back to `require` — never to permissive.
func wireBundleVerifier(trustDir string) *updater.Verifier {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(updateTrustEnv)))
	if mode == "dev-permissive" {
		v := updater.NewDevPermissiveVerifier(trustDir)
		if v.TrustConfigured() {
			log.Printf("rasputin-api: %s=dev-permissive, but a root CA loaded from %s — bundle "+
				"signatures are still verified against it. The opt-in only takes effect with no trust root.",
				updateTrustEnv, trustDir)
		} else {
			log.Printf("rasputin-api: ⚠️  %s=dev-permissive — OS update bundles are accepted WITHOUT any "+
				"signature check and recorded as SignedBy \"<unverified>\". EXPLICITLY REQUESTED; this must "+
				"never be set on hardware.", updateTrustEnv)
		}
		return v
	}
	if mode != "" && mode != "require" {
		log.Printf("rasputin-api: ⚠️  CONFIG FAULT: %s=%q is not recognised (expected require|dev-permissive) "+
			"— falling back to require, never to permissive. Correct it and restart the api.", updateTrustEnv, mode)
	}
	v := updater.NewVerifier(trustDir)
	if !v.Available() {
		log.Printf("rasputin-api: ⚠️  OS UPDATE VERIFICATION UNAVAILABLE: %s. No unverified mode was "+
			"substituted — an update bundle nobody checked is the one artifact that decides what code a "+
			"node boots. The api is starting anyway so this control plane stays reachable and fixable; "+
			"bundle upload and staging refuse until the trust root is in place, or set %s=dev-permissive "+
			"explicitly if this is a dev box with no PKI.", v.UnavailableReason(), updateTrustEnv)
	}
	return v
}

// wireMesh selects, builds, and bootstraps the mesh backend, returning the
// client, the supervisor, and the effective login-server URL agents should
// dial. The choice (RASPUTIN_MESH_BACKEND, default "auto"):
//
//	auto      — external Headscale creds set → real client against them
//	            (noop supervisor); else Docker present → self-hosted (the
//	            supervisor brings up Headscale and mints its own admin key,
//	            real client against it); else → file-backed mock (CI/dev).
//	mock      — force the file-backed mock + noop supervisor.
//	headscale — force real; requires external creds OR Docker (errors if
//	            neither is available, rather than silently mocking).
//
// "Self-hosted" is the production path and needs no operator input: the
// supervisor owns the container so it can mint the very API key the client
// needs (see DockerSupervisor.EnsureAPIKey). This is why mesh can't be
// provisioned via a seed env var — the Headscale instance doesn't exist
// until first boot — and why autodetect-on-Docker is the right default.
//
// wireMesh is non-blocking: the self-hosted path returns a placeholder client
// plus a `bootstrap` closure that the mesh.Service runs in the BACKGROUND
// (container up → key mint → real client). The api must boot and serve
// /healthz regardless of whether Headscale can start — a control plane gated
// on a container coming up is fragile.
type meshWiring struct {
	client    mesh.Client
	sup       mesh.Supervisor
	login     string
	caPEM     []byte                                     // shipped to nodes so tailscaled trusts the Headscale leaf
	bootstrap func(context.Context) (mesh.Client, error) // nil for eager (mock/external) modes
}

func wireMesh(stateDir string, meshCA *mesh.MeshCA, defaultLogin string) (meshWiring, error) {
	backend := strings.ToLower(envOr("RASPUTIN_MESH_BACKEND", "auto"))
	extURL := os.Getenv("RASPUTIN_HEADSCALE_URL")
	extKey := os.Getenv("RASPUTIN_HEADSCALE_API_KEY")
	hasExternal := extURL != "" && extKey != ""
	dockerWanted := dockerAvailable() ||
		strings.ToLower(envOr("RASPUTIN_HEADSCALE_SUPERVISOR", "")) == "docker"

	switch backend {
	case "mock":
		return wireMockMesh(stateDir, defaultLogin)
	case "auto", "":
		if hasExternal {
			return wireExternalMesh(stateDir, meshCA, defaultLogin, extURL, extKey)
		}
		if dockerWanted {
			return wireSelfHostedMesh(stateDir, meshCA, defaultLogin)
		}
		// ⚠️ THIS USED TO FALL THROUGH TO THE MOCK, and that is the same
		// class of bug as the 2026-09-01 storage incident: a missing
		// prerequisite silently became a confident, fabricated answer. The
		// mock mesh mints keys and the enroll saga invents a 100.64.0.x
		// tailnet address per node, which /api/mesh/devices then serves as
		// though the node were really on the tailnet.
		//
		// `auto` means "detect a real backend", so when there is no real
		// backend to detect the honest result is none. The api still boots
		// and serves everything else; mesh verbs fail with this reason.
		// Dev and CI ask for the mock by name.
		return wireUnavailableMesh(defaultLogin,
			"no external Headscale is configured (RASPUTIN_HEADSCALE_URL + "+
				"RASPUTIN_HEADSCALE_API_KEY) and the docker CLI needed for the "+
				"self-hosted one is not on PATH")
	case "headscale":
		if hasExternal {
			return wireExternalMesh(stateDir, meshCA, defaultLogin, extURL, extKey)
		}
		if dockerWanted {
			return wireSelfHostedMesh(stateDir, meshCA, defaultLogin)
		}
		return meshWiring{}, errors.New("RASPUTIN_MESH_BACKEND=headscale requires either RASPUTIN_HEADSCALE_URL+RASPUTIN_HEADSCALE_API_KEY (external) or the docker CLI on PATH (self-hosted)")
	default:
		return meshWiring{}, errors.New("unknown RASPUTIN_MESH_BACKEND: " + backend)
	}
}

// wireUnavailableMesh is what `auto` returns when it finds no real backend. The
// api boots normally; every mesh verb refuses with reason. See
// mesh.UnavailableClient for why this is not a fallback to the mock.
func wireUnavailableMesh(defaultLogin, reason string) (meshWiring, error) {
	log.Printf("rasputin-api: ⚠️  mesh backend UNAVAILABLE: %s. No mock was substituted — a mock "+
		"mesh reports nodes as enrolled with invented tailnet addresses. The api is starting "+
		"anyway; mesh enroll/list will fail with this reason until a real backend is configured, "+
		"or set RASPUTIN_MESH_BACKEND=mock explicitly if this is a dev box.", reason)
	return meshWiring{
		client: mesh.NewUnavailableClient(reason),
		sup:    mesh.NewNoopSupervisor(),
		login:  defaultLogin,
	}, nil
}

// wireMockMesh is the dev/CI fixture: file-backed client, no supervisor. Only
// ever reached by an explicit RASPUTIN_MESH_BACKEND=mock — never autodetected.
func wireMockMesh(stateDir, defaultLogin string) (meshWiring, error) {
	log.Printf("rasputin-api: mesh backend = mock (file-backed at %s) — EXPLICITLY REQUESTED; "+
		"enrollments and tailnet addresses reported from here are simulated", stateDir)
	c, err := mesh.NewMockClient(stateDir)
	if err != nil {
		return meshWiring{}, err
	}
	return meshWiring{client: c, sup: mesh.NewNoopSupervisor(), login: defaultLogin}, nil
}

// wireExternalMesh talks to a Headscale the operator runs themselves. We
// trust the system pool unless RASPUTIN_HEADSCALE_CA_FILE points at a PEM
// bundle (e.g. their internal CA) — in which case nodes need that CA too, so
// we ship it in the enroll command. The container lifecycle is theirs (noop
// supervisor) unless they explicitly asked us to drive it. Eager: the client
// is constructed up front (EnsureUser still runs in the background Start).
func wireExternalMesh(stateDir string, meshCA *mesh.MeshCA, defaultLogin, url, key string) (meshWiring, error) {
	cfg := mesh.RealClientConfig{BaseURL: url, APIKey: key}
	var caToShip []byte
	if caFile := os.Getenv("RASPUTIN_HEADSCALE_CA_FILE"); caFile != "" {
		tlsCfg, err := loadCATLSConfig(caFile)
		if err != nil {
			return meshWiring{}, err
		}
		cfg.TLSConfig = tlsCfg
		if pem, rerr := os.ReadFile(caFile); rerr == nil {
			caToShip = pem // nodes trust the same custom CA before tailscale up
		}
	}
	c, err := mesh.NewRealClient(cfg)
	if err != nil {
		return meshWiring{}, err
	}
	var sup mesh.Supervisor = mesh.NewNoopSupervisor()
	if strings.ToLower(envOr("RASPUTIN_HEADSCALE_SUPERVISOR", "noop")) == "docker" {
		ds, derr := newDockerSupervisor(stateDir, meshCA)
		if derr != nil {
			return meshWiring{}, derr
		}
		sup = ds
	}
	log.Printf("rasputin-api: mesh backend = headscale (external, url=%s)", url)
	return meshWiring{client: c, sup: sup, login: url, caPEM: caToShip}, nil
}

// wireSelfHostedMesh is the production path. It builds the supervisor cheaply
// (no container work) and returns a placeholder client plus a bootstrap
// closure that mesh.Service runs in the background: bring the container up,
// mint+persist an admin key, and point a real client at the local HTTPS
// endpoint trusting the per-installation Mesh CA. Ships meshCA.CertPEM to
// nodes so tailscaled trusts the same leaf. Nothing here blocks api boot.
func wireSelfHostedMesh(stateDir string, meshCA *mesh.MeshCA, defaultLogin string) (meshWiring, error) {
	sup, err := newDockerSupervisor(stateDir, meshCA)
	if err != nil {
		return meshWiring{}, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(meshCA.CertPEM) {
		return meshWiring{}, errors.New("mesh: failed to build trust pool from mesh CA")
	}
	url := sup.ServerURL() // resolved at construction; no container needed
	bootstrap := func(ctx context.Context) (mesh.Client, error) {
		if err := sup.Start(ctx); err != nil {
			return nil, fmt.Errorf("start headscale container: %w", err)
		}
		key, err := sup.EnsureAPIKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("bootstrap headscale api key: %w", err)
		}
		return mesh.NewRealClient(mesh.RealClientConfig{
			BaseURL:   url,
			APIKey:    key,
			TLSConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		})
	}
	log.Printf("rasputin-api: mesh backend = headscale (self-hosted, url=%s, tls=mesh-ca; bringing up in background)", url)
	return meshWiring{
		client:    mesh.NewNotReadyClient("headscale"),
		sup:       sup,
		login:     url,
		caPEM:     meshCA.CertPEM,
		bootstrap: bootstrap,
	}, nil
}

// newDockerSupervisor builds a DockerSupervisor from env overrides + the Mesh
// CA (which switches it into HTTPS mode with a per-installation leaf).
func newDockerSupervisor(stateDir string, meshCA *mesh.MeshCA) (*mesh.DockerSupervisor, error) {
	cfg := mesh.DockerSupervisorConfig{
		StateDir:   filepath.Join(stateDir, "headscale"),
		Image:      os.Getenv("RASPUTIN_HEADSCALE_IMAGE"),
		ListenAddr: os.Getenv("RASPUTIN_HEADSCALE_LISTEN_ADDR"),
		// The URL agents dial for `tailscale up --login-server`, and the host
		// the Headscale leaf is minted for. Derived from the cluster name on a
		// provisioned node; "" in dev, where the supervisor falls back to
		// resolveServerHost(ListenAddr) exactly as before.
		//
		// NOTE this is the ONLY place RASPUTIN_HEADSCALE_URL gets a default.
		// Its other read (wireMesh) uses the variable's presence to select an
		// EXTERNAL Headscale, so defaulting it there would make every
		// self-hosted appliance believe it had external creds.
		ServerURL:     envOr("RASPUTIN_HEADSCALE_URL", applianceOr(func(h string) string { return "https://" + h + ":18080" }, "")),
		ContainerName: os.Getenv("RASPUTIN_HEADSCALE_CONTAINER"),
		// Bare cluster id → the MagicDNS base domain "<cluster-id>.internal".
		ClusterID: strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")),
		MeshCA:    meshCA,
	}
	log.Printf("rasputin-api: mesh supervisor = docker (state=%s, tls=%v)",
		cfg.StateDir, cfg.MeshCA != nil)
	return mesh.NewDockerSupervisor(cfg)
}

// dockerBinAvailable reports whether the named docker CLI is on PATH.
// Split out from dockerAvailable so obs can preflight against its OWN
// configured binary: dockerAvailable keys off RASPUTIN_HEADSCALE_DOCKER_BIN,
// and an obs preflight that consulted a mesh-namespaced variable would be
// quietly wrong for anyone who set only one of them.
func dockerBinAvailable(bin string) bool {
	if bin == "" {
		bin = "docker"
	}
	_, err := exec.LookPath(bin)
	return err == nil
}

// dockerAvailable reports whether a docker CLI is on PATH — mirrors the
// agent's autodetect for its docker/rauc/uci/tailscale backends.
func dockerAvailable() bool {
	return dockerBinAvailable(envOr("RASPUTIN_HEADSCALE_DOCKER_BIN", "docker"))
}

// obsDockerBin is the container runtime obs shells out to. Its own env var,
// defaulted to "docker".
func obsDockerBin() string { return envOr("RASPUTIN_OBS_DOCKER_BIN", "docker") }

func loadCATLSConfig(caFile string) (*tls.Config, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.New("read RASPUTIN_HEADSCALE_CA_FILE: " + err.Error())
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("RASPUTIN_HEADSCALE_CA_FILE: no certs parsed from " + caFile)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// mustWireObs constructs the Tier 2 observability stack — supervisor +
// VictoriaMetrics fan-out sink + read-only status surface. The supervisor is
// built UNCONDITIONALLY; whether the stack actually runs is the operator's
// stored `obs.enabled` setting, read through the `enabled` closure.
//
// That unconditional construction is the whole point of Slice 1.6. Before
// it, an unset RASPUTIN_OBS_ENABLED returned a nil supervisor — so there was
// no object to Start() later and the only way to turn observability on was
// to restart the process with a different environment. On an appliance
// (read-only rootfs, no shell, no SSH server) that is not a thing an
// operator can do, which meant a complete Tier 2 stack shipped unreachable.
// Constructing always costs a struct; it buys a UI toggle.
//
// Building the supervisor does no I/O beyond an mkdir — no Docker contact,
// no containers — so this is cheap even when the operator never opts in.
//
// Why "must" — the failure modes here (mkdir, supervisor construction) are
// configuration / system issues the operator needs to fix before the api can
// usefully run with obs on. We don't paper over them by silently disabling
// obs; that would mask the real problem. Note the *start* failure path is
// deliberately not fatal: a stack that won't come up must not take the api
// down with it.
//
// Env vars (all now *defaults* — the operator's stored choice wins; see
// seedObsEnabled):
//
//	RASPUTIN_OBS_ENABLED       — seeds obs.enabled on first boot only.
//	RASPUTIN_OBS_DOCKER_BIN    — container runtime binary. Default "docker".
//	RASPUTIN_OBS_STATE_DIR     — host dir for compose + VM data.
//	                              Defaults to <dataDir>/obs.
//	RASPUTIN_OBS_VM_IMAGE      — VictoriaMetrics image override.
//	RASPUTIN_OBS_VM_LISTEN     — host bind for VM's HTTP listener.
//	                              Defaults to 127.0.0.1:8428.
//	RASPUTIN_OBS_VM_RETENTION  — VM -retentionPeriod flag. Default "1y".
//	RASPUTIN_OBS_VM_MIN_FREE_DISK — free space VM reserves on the partition
//	                              before refusing writes. Default "2GB".
//	RASPUTIN_OBS_LOKI_RETENTION — how long logs are kept. Default "720h" (30d).
//
// Side effect: when the stored setting says on, this starts the stack in the
// background and calls metricsSvc.SetSink so every received MetricsEvt fans
// out to VM after the SQLite insert.
func mustWireObs(ctx context.Context, dataDir, selfNodeID string, metricsSvc *metrics.Service, idsLogDir string, enabled obs.EnabledFn) (*obs.DockerComposeSupervisor, *obs.VMSink, *obs.Status) {
	stateDir := envOr("RASPUTIN_OBS_STATE_DIR", filepath.Join(dataDir, "obs"))
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		log.Fatalf("rasputin-api: obs state dir: %v", err)
	}
	sup, err := obs.NewDockerComposeSupervisor(obs.DockerComposeSupervisorConfig{
		StateDir:            stateDir,
		ControlPlaneNodeID:  selfNodeID,
		DockerBin:           obsDockerBin(),
		VMImage:             os.Getenv("RASPUTIN_OBS_VM_IMAGE"),
		VMListenAddr:        os.Getenv("RASPUTIN_OBS_VM_LISTEN"),
		VMRetention:         os.Getenv("RASPUTIN_OBS_VM_RETENTION"),
		VMMinFreeDiskSpace:  os.Getenv("RASPUTIN_OBS_VM_MIN_FREE_DISK"),
		AlloyImage:          os.Getenv("RASPUTIN_OBS_ALLOY_IMAGE"),
		AlloyListenAddr:     os.Getenv("RASPUTIN_OBS_ALLOY_LISTEN"),
		EnableCadvisor:      envBoolPtr("RASPUTIN_OBS_ALLOY_CADVISOR"),
		LokiImage:           os.Getenv("RASPUTIN_OBS_LOKI_IMAGE"),
		LokiListenAddr:      os.Getenv("RASPUTIN_OBS_LOKI_LISTEN"),
		LokiRetention:       os.Getenv("RASPUTIN_OBS_LOKI_RETENTION"),
		EnableLoki:          envBoolPtr("RASPUTIN_OBS_LOKI"),
		GrafanaImage:        os.Getenv("RASPUTIN_OBS_GRAFANA_IMAGE"),
		GrafanaListenAddr:   os.Getenv("RASPUTIN_OBS_GRAFANA_LISTEN"),
		EnableGrafana:       envBoolPtr("RASPUTIN_OBS_GRAFANA"),
		VMAlertImage:        os.Getenv("RASPUTIN_OBS_VMALERT_IMAGE"),
		AlertsWebhookURL:    os.Getenv("RASPUTIN_OBS_ALERTS_WEBHOOK_URL"),
		AlertsWebhookSecret: os.Getenv("RASPUTIN_ALERTS_WEBHOOK_SECRET"),
		EnableVMAlert:       envBoolPtr("RASPUTIN_OBS_VMALERT"),
		// IDS log dir mounted into Alloy at /var/log/rasputin so
		// loki.source.file can ship the api's alerts.jsonl to Loki.
		// Same path the api's ids.Writer just opened a few lines above
		// — passed through as a string both ends use literally so a
		// rename in one place trips a build error not a runtime miss.
		IDSLogDir:     idsLogDir,
		EnableIDSPipe: envBoolPtr("RASPUTIN_OBS_IDS_PIPE"),
	})
	if err != nil {
		log.Fatalf("rasputin-api: obs supervisor: %v", err)
	}
	sink, err := obs.NewVMSink(obs.VMSinkConfig{Supervisor: sup})
	if err != nil {
		log.Fatalf("rasputin-api: obs sink: %v", err)
	}
	// LogsClient wraps the same supervisor — when Loki is on, LokiBaseURL()
	// is non-empty and queries proxy through; when off, the client returns
	// a clean "Loki not configured" error.
	logs, err := obs.NewLogsClient(obs.LogsClientConfig{Supervisor: sup})
	if err != nil {
		log.Fatalf("rasputin-api: obs logs client: %v", err)
	}
	status := obs.NewStatus(sup, sink, logs)
	status.SetEnabled(enabled)

	on, err := enabled(ctx)
	if err != nil {
		log.Fatalf("rasputin-api: read obs setting: %v", err)
	}
	if !on {
		// Constructed but idle. No sink is installed: VMSink.Write errors
		// when the stack is down and metrics.Service logs every failure, so
		// an always-installed sink would spam the log every 10s per node.
		// obs.enable installs it as its last step.
		log.Printf("rasputin-api: obs off (state=%s) — turn it on from Settings", stateDir)
		return sup, sink, status
	}
	log.Printf("rasputin-api: obs supervisor = docker (state=%s, vm=%s)",
		stateDir, sup.VMBaseURL())
	// Start asynchronously so first-boot doesn't block the api's HTTP
	// listener behind a slow `docker pull`. The supervisor's health
	// probe drives the sink's "is it worth trying to write?" check; if
	// VM never comes up, writes simply fail-fast.
	go func() {
		startCtx, startCancel := context.WithTimeout(ctx, 10*time.Minute)
		defer startCancel()
		if err := sup.Start(startCtx); err != nil {
			log.Printf("rasputin-api: obs supervisor start: %v", err)
		} else {
			log.Printf("rasputin-api: obs supervisor up; VM at %s", sup.VMBaseURL())
		}
	}()
	metricsSvc.SetSink(sink)
	return sup, sink, status
}

// seedObsEnabled captures RASPUTIN_OBS_ENABLED as the initial value of the
// obs.enabled setting — but only when the setting has NEVER been set, so an
// explicit operator choice sticks. Mirrors SeedOperatorSSHKeysFromFile.
//
// This is what keeps the env var from becoming a rival source of truth. A
// dev box that exports RASPUTIN_OBS_ENABLED=1 still comes up with obs on;
// but once anyone uses the UI toggle, the stored choice is authoritative and
// the env var is never consulted again. Without the "only if unset" guard,
// every restart would silently undo the operator's last click.
// seedBMCHostNode writes the env-derived BMC host into settings once —
// only if the operator has never chosen (IsSet). Same recipe as
// seedObsEnabled: env seeds first boot, the Settings choice wins
// permanently (bmc-settings.md S-5).
func seedBMCHostNode(ctx context.Context, store *setup.Store, hostNodeID string) {
	if hostNodeID == "" {
		return
	}
	set, err := store.IsSet(ctx, setup.KeyBMCHostNode)
	if err != nil {
		log.Printf("rasputin-api: read %s: %v", setup.KeyBMCHostNode, err)
		return
	}
	if set {
		return
	}
	if err := store.Set(ctx, setup.KeyBMCHostNode, hostNodeID); err != nil {
		log.Printf("rasputin-api: seed %s: %v", setup.KeyBMCHostNode, err)
		return
	}
	log.Printf("rasputin-api: seeded %s=%s from env (operator choice wins from here on)", setup.KeyBMCHostNode, hostNodeID)
}

func seedObsEnabled(ctx context.Context, store *setup.Store) {
	set, err := store.IsSet(ctx, setup.KeyObsEnabled)
	if err != nil {
		log.Printf("rasputin-api: read obs.enabled: %v", err)
		return
	}
	if set {
		return
	}
	raw, ok := os.LookupEnv("RASPUTIN_OBS_ENABLED")
	if !ok {
		return // stay unset; the default (off) applies and a later boot can seed
	}
	on := setup.ParseBool(raw)
	if err := store.SetBool(ctx, setup.KeyObsEnabled, on); err != nil {
		log.Printf("rasputin-api: seed obs.enabled: %v", err)
		return
	}
	log.Printf("rasputin-api: seeded obs.enabled=%v from RASPUTIN_OBS_ENABLED (operator choice wins from here on)", on)
}

// parseDurationOr parses s as a duration; on parse error or zero/negative,
// returns def. Lets env-var overrides degrade safely.
func parseDurationOr(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
