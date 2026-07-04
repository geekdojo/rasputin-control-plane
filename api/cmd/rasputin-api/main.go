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
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/ids"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/api/internal/sdnotify"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
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

	// Bus auth (RASPUTIN_BUS_AUTH=off|enforce, default off). Under enforcement,
	// external agents must present a per-node join token that the in-process
	// busauth responder validates → mints a subject-scoped JWT; the api's own
	// connection authenticates as an AuthUser and bypasses the callout. Default
	// off keeps the bus byte-identical to today until the bench validates the
	// cutover. See design plan / architecture §5.4.
	busAuthEnforce := envOr("RASPUTIN_BUS_AUTH", "off") == "enforce"
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
		log.Printf("rasputin-api: bus auth OFF (set RASPUTIN_BUS_AUTH=enforce to require node join tokens)")
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
	}, meshStore, mw.client, mw.sup)
	if mw.bootstrap != nil {
		meshSvc.SetBootstrap(mw.bootstrap)
	}
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
	verifier, err := updater.NewVerifier(trustDir)
	if err != nil {
		log.Fatalf("rasputin-api: updater verifier: %v", err)
	}
	if !verifier.TrustConfigured() {
		log.Printf("rasputin-api: WARNING — no root CA at %s/root-ca.pem; bundle signatures will not be verified. Run scripts/pki-init.sh.", trustDir)
	}
	// Public URL the agent uses to fetch bundles. In dev the api is at
	// :8080; in production this is the api's tailnet hostname.
	publicBaseURL := envOr("RASPUTIN_PUBLIC_BASE_URL", "http://localhost:8080")
	// The api's own node id — the system.update saga skips this one (the
	// operator updates the controlplane node manually after the cascade).
	selfNodeID := os.Getenv("RASPUTIN_SELF_NODE_ID")
	// The BMC host's node id — the node whose agent owns the BMC bus and
	// receives bmc.* commands. Defaults to selfNodeID (the controlplane in
	// MVS); override via RASPUTIN_BMC_HOST_NODE_ID for split-brain layouts.
	bmcHostNodeID := envOr("RASPUTIN_BMC_HOST_NODE_ID", selfNodeID)
	bmcSvc := bmc.NewService(bmc.Config{HostNodeID: bmcHostNodeID}, bmcStore, busSrv.Conn())

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
	}, selfNodeID)

	// Default origins cover both ways the UI reaches the api on localhost:
	// the Next dev server (:3000, cross-origin) and the api-served static
	// export (:8080, same-origin — including `ssh -L 8080:localhost:8080`
	// tunnels, still a valid escape hatch). On a real appliance the OS
	// image overrides these to rasputin.local + https origins and enables
	// the native HTTPS listener (RASPUTIN_HTTPS_ADDR above) so the passkey
	// ceremony gets its secure context without any tunnel.
	authCfg := auth.Config{
		RPDisplayName: envOr("RASPUTIN_RP_NAME", "Rasputin"),
		RPID:          envOr("RASPUTIN_RP_ID", "localhost"),
		RPOrigins:     splitCSV(envOr("RASPUTIN_RP_ORIGINS", "http://localhost:3000,http://localhost:8080")),
		SecureCookies: os.Getenv("RASPUTIN_SECURE_COOKIES") == "1",
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
	runner.Register(firewall.ApplyWorkflow(fwStore, invStore, busSrv.Conn()))
	runner.Register(firewall.ReconcileWorkflow(fwStore, invStore, busSrv.Conn()))
	runner.Register(apps.DeployWorkflow(appsStore, invStore, busSrv.Conn()))
	runner.Register(apps.StopWorkflow(appsStore, invStore, busSrv.Conn()))
	runner.Register(apps.ReconcileWorkflow(appsStore, invStore, busSrv.Conn()))
	runner.Register(updater.UpdateWorkflow(updaterStore, invStore, busSrv.Conn(), updater.Config{
		PublicBaseURL: publicBaseURL,
	}))
	runner.Register(updater.SystemUpdateWorkflow(updaterStore, invStore, jobStore, runner, busSrv.Conn(), updater.SystemUpdateConfig{
		SelfNodeID: selfNodeID,
	}))
	runner.Register(mesh.ApplyWorkflow(meshSvc, invStore, busSrv.Conn()))
	runner.Register(mesh.ReconcileWorkflow(meshSvc, busSrv.Conn()))
	runner.Register(mesh.EnrollNodeWorkflow(meshSvc, invStore, busSrv.Conn()))
	runner.Register(bmc.PowerWorkflow(bmcSvc, invStore))

	// Abort any jobs left in-flight from a previous run before we expose
	// HTTP. v0 policy is honest-failure, not resume — see saga.go — EXCEPT a
	// control-plane self-update, which intentionally reboots the api mid-saga:
	// the decider defers it so ResumeSelfUpdates can finish it on the new slot.
	runner.SetRecoverDecider(updater.SelfUpdateRecoverDecider(selfNodeID))
	if err := runner.Recover(ctx); err != nil {
		log.Fatalf("rasputin-api: recover in-flight jobs: %v", err)
	}
	// Finish any self-update that rebooted us onto the new slot (no-op when
	// there isn't one). Non-blocking — reconciles in the background once the
	// co-located agent reconnects.
	updater.ResumeSelfUpdates(ctx, updaterStore, jobStore, runner, busSrv.Conn(), selfNodeID)

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
		switch n.Role {
		case proto.RoleFirewall, proto.RoleCompute, proto.RoleStorage:
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
	// Off by default so dev runs don't require Docker; set
	// RASPUTIN_OBS_ENABLED=1 to bring up VM and start remote-writing every
	// agent sample. See wiki design/control-plane/observability-stack.md.
	obsSup, obsSink, obsStatus := mustWireObs(ctx, dataDir, metricsSvc, idsLogDir)
	if obsSup != nil {
		defer func() {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer stopCancel()
			if err := obsSup.Stop(stopCtx); err != nil {
				log.Printf("rasputin-api: obs supervisor stop: %v", err)
			}
		}()
	}
	_ = obsSink // referenced via the metricsSvc sink + obsStatus; kept named for clarity.

	// Reconciliation tickers. One scheduler entry per drift-prone
	// subsystem; staggered so the bus doesn't stampede at startup. All
	// intervals are env-overridable (parsed by parseDurationOr below).
	// Defaults match the firewall + mesh §6 docs (5 min).
	fwReconcileEvery := parseDurationOr(os.Getenv("RASPUTIN_FW_RECONCILE_INTERVAL"), 5*time.Minute)
	appsReconcileEvery := parseDurationOr(os.Getenv("RASPUTIN_APPS_RECONCILE_INTERVAL"), 5*time.Minute)
	meshReconcileEvery := parseDurationOr(os.Getenv("RASPUTIN_MESH_RECONCILE_INTERVAL"), 5*time.Minute)
	sched := scheduler.New(runner, []scheduler.Entry{
		{Kind: "firewall.reconcile", Interval: fwReconcileEvery, InitialDelay: 30 * time.Second},
		{Kind: "apps.reconcile", Interval: appsReconcileEvery, InitialDelay: 60 * time.Second},
		{Kind: "mesh.reconcile", Interval: meshReconcileEvery, InitialDelay: 90 * time.Second},
	})
	sched.Start(ctx)
	defer sched.Stop()

	srv := apipkg.NewServer(jobStore, runner, invStore, invSvc, fwStore, appsStore, metricsStore, updaterStore, verifier, bundleDir, trustDir, meshSvc, bmcSvc, setupSvc, authSvc, obsStatus, busTokenStore, busSrv.Conn())

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
	srv.SetAlertsService(alerts.New(invStore, jobStore, appsStore, setupSvc, alertsStore, busSrv.Conn()))
	if secret := os.Getenv("RASPUTIN_ALERTS_WEBHOOK_SECRET"); secret != "" {
		srv.SetAlertsWebhookSecret(secret)
		log.Printf("rasputin-api: alerts webhook protected by shared secret")
	} else {
		log.Printf("rasputin-api: WARNING — alerts webhook is unauthenticated " +
			"(set RASPUTIN_ALERTS_WEBHOOK_SECRET to enable header auth)")
	}
	// Update discovery: the control plane pulls signed bundles from a PUBLIC
	// release channel repo (source repos stay private; only signed artifacts
	// are mirrored there) over anonymous HTTPS — no token on the appliance.
	// RASPUTIN_RELEASE_API_BASE is overridable for a mirror/CDN or tests.
	releaseRepo := envOr("RASPUTIN_RELEASE_REPO", "geekdojo/rasputin-releases")
	releaseChannel := envOr("RASPUTIN_RELEASE_CHANNEL", "stable")
	releaseAPIBase := envOr("RASPUTIN_RELEASE_API_BASE", "https://api.github.com")
	srv.SetReleaseSource(releases.NewGithubPublicSource(releaseAPIBase, releaseRepo), releaseChannel)
	srv.SetReleaseRepo(releaseRepo, envOr("RASPUTIN_RELEASE_DOWNLOAD_BASE", "https://github.com"))
	log.Printf("rasputin-api: update channel = %s (repo %s)", releaseChannel, releaseRepo)

	handler := srv.Handler()

	// With HTTPS on, the plain-HTTP listener demotes to the bootstrap
	// surface (trust page + CA download + healthz; everything else 302s to
	// https). With HTTPS off — every dev run — it serves the full handler
	// exactly as before.
	httpHandler := handler
	var httpsSrv *http.Server
	if httpsAddr != "" {
		leafPaths, err := ensureAPILeaf(meshCA, dataDir)
		if err != nil {
			log.Fatalf("rasputin-api: https leaf: %v", err)
		}
		httpsSrv = &http.Server{
			Addr:              httpsAddr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		}
		go func() {
			log.Printf("rasputin-api: https listening on %s (leaf %s)", httpsAddr, leafPaths.CertPath)
			if err := httpsSrv.ListenAndServeTLS(leafPaths.CertPath, leafPaths.KeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("rasputin-api: https: %v", err)
			}
		}()
		httpHandler = srv.BootstrapHandler()
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

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = httpSrv.Shutdown(shutCtx)
	if httpsSrv != nil {
		_ = httpsSrv.Shutdown(shutCtx)
	}
	runner.Wait()
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
		log.Printf("rasputin-api: mesh backend = mock (auto: no Docker and no external Headscale configured)")
		return wireMockMesh(stateDir, defaultLogin)
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

// wireMockMesh is the dev/CI fallback: file-backed client, no supervisor.
func wireMockMesh(stateDir, defaultLogin string) (meshWiring, error) {
	log.Printf("rasputin-api: mesh backend = mock (file-backed at %s)", stateDir)
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
		StateDir:      filepath.Join(stateDir, "headscale"),
		Image:         os.Getenv("RASPUTIN_HEADSCALE_IMAGE"),
		ListenAddr:    os.Getenv("RASPUTIN_HEADSCALE_LISTEN_ADDR"),
		ServerURL:     os.Getenv("RASPUTIN_HEADSCALE_URL"),
		ContainerName: os.Getenv("RASPUTIN_HEADSCALE_CONTAINER"),
		MeshCA:        meshCA,
	}
	log.Printf("rasputin-api: mesh supervisor = docker (state=%s, tls=%v)",
		cfg.StateDir, cfg.MeshCA != nil)
	return mesh.NewDockerSupervisor(cfg)
}

// dockerAvailable reports whether a docker CLI is on PATH — mirrors the
// agent's autodetect for its docker/rauc/uci/tailscale backends.
func dockerAvailable() bool {
	bin := envOr("RASPUTIN_HEADSCALE_DOCKER_BIN", "docker")
	_, err := exec.LookPath(bin)
	return err == nil
}

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
// VictoriaMetrics fan-out sink + read-only status surface — when
// RASPUTIN_OBS_ENABLED is set. When obs is off (the default), returns a
// nil supervisor + nil sink and a non-nil obs.Status whose snapshots
// report Enabled=false; the api stays fully functional on the Tier 1
// SQLite path.
//
// Why "must" — the failure modes here (mkdir, supervisor construction,
// initial container start) are configuration / system issues that the
// operator needs to fix before the api can usefully run with obs on. We
// don't paper over them by silently disabling obs; that would mask the
// real problem.
//
// Env vars:
//
//	RASPUTIN_OBS_ENABLED       — "1" to turn on. Anything else → off.
//	RASPUTIN_OBS_STATE_DIR     — host dir for compose + VM data.
//	                              Defaults to <dataDir>/obs.
//	RASPUTIN_OBS_VM_IMAGE      — VictoriaMetrics image override.
//	RASPUTIN_OBS_VM_LISTEN     — host bind for VM's HTTP listener.
//	                              Defaults to 127.0.0.1:8428.
//	RASPUTIN_OBS_VM_RETENTION  — VM -retentionPeriod flag. Default "1y".
//
// Side effect: when obs is enabled, this also calls metricsSvc.SetSink
// so every received MetricsEvt fans out to VM after the SQLite insert.
func mustWireObs(ctx context.Context, dataDir string, metricsSvc *metrics.Service, idsLogDir string) (*obs.DockerComposeSupervisor, *obs.VMSink, *obs.Status) {
	if os.Getenv("RASPUTIN_OBS_ENABLED") != "1" {
		log.Printf("rasputin-api: obs disabled (set RASPUTIN_OBS_ENABLED=1 to enable)")
		return nil, nil, obs.NewStatus(nil, nil, nil)
	}
	stateDir := envOr("RASPUTIN_OBS_STATE_DIR", filepath.Join(dataDir, "obs"))
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		log.Fatalf("rasputin-api: obs state dir: %v", err)
	}
	sup, err := obs.NewDockerComposeSupervisor(obs.DockerComposeSupervisorConfig{
		StateDir:            stateDir,
		VMImage:             os.Getenv("RASPUTIN_OBS_VM_IMAGE"),
		VMListenAddr:        os.Getenv("RASPUTIN_OBS_VM_LISTEN"),
		VMRetention:         os.Getenv("RASPUTIN_OBS_VM_RETENTION"),
		AlloyImage:          os.Getenv("RASPUTIN_OBS_ALLOY_IMAGE"),
		AlloyListenAddr:     os.Getenv("RASPUTIN_OBS_ALLOY_LISTEN"),
		EnableCadvisor:      envBoolPtr("RASPUTIN_OBS_ALLOY_CADVISOR"),
		LokiImage:           os.Getenv("RASPUTIN_OBS_LOKI_IMAGE"),
		LokiListenAddr:      os.Getenv("RASPUTIN_OBS_LOKI_LISTEN"),
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
	sink, err := obs.NewVMSink(obs.VMSinkConfig{Supervisor: sup})
	if err != nil {
		log.Fatalf("rasputin-api: obs sink: %v", err)
	}
	metricsSvc.SetSink(sink)
	// LogsClient wraps the same supervisor — when Loki is on, LokiBaseURL()
	// is non-empty and queries proxy through; when off, the client returns
	// a clean "Loki not configured" error.
	logs, err := obs.NewLogsClient(obs.LogsClientConfig{Supervisor: sup})
	if err != nil {
		log.Fatalf("rasputin-api: obs logs client: %v", err)
	}
	return sup, sink, obs.NewStatus(sup, sink, logs)
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
