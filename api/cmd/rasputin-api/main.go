package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	apipkg "github.com/geekdojo/rasputin-control-plane/api/internal/api"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
)

// rasputin-api: the Rasputin control-plane backend.
//
// Architecture: projects/rasputin/design/control-plane/architecture.md
//   in the geekdojo-wiki.

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	dataDir := envOr("RASPUTIN_DATA_DIR", "./data")
	httpAddr := envOr("RASPUTIN_HTTP_ADDR", ":8080")

	if err := os.MkdirAll(filepath.Join(dataDir, "nats"), 0o755); err != nil {
		log.Fatalf("rasputin-api: data dir: %v", err)
	}

	busSrv, err := bus.Start(ctx, bus.Config{
		Host:     "127.0.0.1",
		Port:     4222,
		StoreDir: filepath.Join(dataDir, "nats"),
	})
	if err != nil {
		log.Fatalf("rasputin-api: bus: %v", err)
	}
	defer busSrv.Stop()
	log.Printf("rasputin-api: nats listening on %s", busSrv.ClientURL())

	dbPath := filepath.Join(dataDir, "rasputin.db")
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

	// Mesh subsystem: backend defaults to the file-backed mock client.
	// Set RASPUTIN_MESH_BACKEND=headscale (plus RASPUTIN_HEADSCALE_URL and
	// RASPUTIN_HEADSCALE_API_KEY) to talk to a real Headscale instance.
	// Real Docker container supervision lands separately. See wiki
	// design/control-plane/mesh.md.
	meshStateDir := envOr("RASPUTIN_MESH_STATE_DIR", filepath.Join(dataDir, "mesh"))
	if err := os.MkdirAll(meshStateDir, 0o755); err != nil {
		log.Fatalf("rasputin-api: mesh state dir: %v", err)
	}
	meshClient, err := newMeshClient(meshStateDir)
	if err != nil {
		log.Fatalf("rasputin-api: mesh client: %v", err)
	}
	meshSvc := mesh.NewService(mesh.Config{
		LoginServer: envOr("RASPUTIN_MESH_LOGIN_SERVER", "https://mesh.rasputin.local"),
		DefaultUser: envOr("RASPUTIN_MESH_DEFAULT_USER", "rasputin-operator"),
	}, meshStore, meshClient, mesh.NewNoopSupervisor())
	if err := meshSvc.Start(ctx); err != nil {
		log.Fatalf("rasputin-api: mesh service: %v", err)
	}
	defer meshSvc.Stop()

	// Bundles live on disk; the api streams them to agents. PKI trust
	// material lives next door — root-ca.pem expected at <trustDir>/root-ca.pem.
	bundleDir := envOr("RASPUTIN_BUNDLE_DIR", filepath.Join(dataDir, "bundles"))
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		log.Fatalf("rasputin-api: bundle dir: %v", err)
	}
	trustDir := envOr("RASPUTIN_TRUST_DIR", filepath.Join(dataDir, "trust"))
	if err := os.MkdirAll(trustDir, 0o755); err != nil {
		log.Fatalf("rasputin-api: trust dir: %v", err)
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
	}, selfNodeID)

	authCfg := auth.Config{
		RPDisplayName: envOr("RASPUTIN_RP_NAME", "Rasputin"),
		RPID:          envOr("RASPUTIN_RP_ID", "localhost"),
		RPOrigins:     splitCSV(envOr("RASPUTIN_RP_ORIGINS", "http://localhost:3000")),
		SecureCookies: os.Getenv("RASPUTIN_SECURE_COOKIES") == "1",
	}
	authSvc, err := auth.NewService(authStore, authCfg)
	if err != nil {
		log.Fatalf("rasputin-api: auth service: %v", err)
	}
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
	// HTTP. v0 policy is honest-failure, not resume — see saga.go.
	if err := runner.Recover(ctx); err != nil {
		log.Fatalf("rasputin-api: recover in-flight jobs: %v", err)
	}

	invSvc := inventory.NewService(invStore, busSrv.Conn())
	if err := invSvc.Start(ctx); err != nil {
		log.Fatalf("rasputin-api: inventory service: %v", err)
	}
	defer invSvc.Stop()

	metricsSvc := metrics.NewService(metricsStore, busSrv.Conn())
	if err := metricsSvc.Start(ctx); err != nil {
		log.Fatalf("rasputin-api: metrics service: %v", err)
	}
	defer metricsSvc.Stop()

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

	srv := apipkg.NewServer(jobStore, runner, invStore, fwStore, appsStore, metricsStore, updaterStore, verifier, bundleDir, meshSvc, bmcSvc, setupSvc, authSvc, busSrv.Conn())
	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("rasputin-api: http listening on %s", httpAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("rasputin-api: http: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("rasputin-api: shutting down")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = httpSrv.Shutdown(shutCtx)
	runner.Wait()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// newMeshClient builds the mesh.Client implementation chosen by env. The
// default is the file-backed mock, suitable for dev and CI. Set
// RASPUTIN_MESH_BACKEND=headscale to talk to a real Headscale instance —
// then RASPUTIN_HEADSCALE_URL and RASPUTIN_HEADSCALE_API_KEY are required.
// RASPUTIN_HEADSCALE_CA_FILE optionally points at a PEM CA bundle (the
// Rasputin internal CA root) to trust when Headscale's leaf cert is signed
// by something the system pool doesn't know about.
func newMeshClient(stateDir string) (mesh.Client, error) {
	backend := strings.ToLower(envOr("RASPUTIN_MESH_BACKEND", "mock"))
	switch backend {
	case "", "mock":
		log.Printf("rasputin-api: mesh backend = mock (file-backed at %s)", stateDir)
		return mesh.NewMockClient(stateDir)
	case "headscale":
		url := os.Getenv("RASPUTIN_HEADSCALE_URL")
		key := os.Getenv("RASPUTIN_HEADSCALE_API_KEY")
		if url == "" || key == "" {
			return nil, errors.New("RASPUTIN_MESH_BACKEND=headscale requires RASPUTIN_HEADSCALE_URL and RASPUTIN_HEADSCALE_API_KEY")
		}
		cfg := mesh.RealClientConfig{BaseURL: url, APIKey: key}
		if caFile := os.Getenv("RASPUTIN_HEADSCALE_CA_FILE"); caFile != "" {
			tlsCfg, err := loadCATLSConfig(caFile)
			if err != nil {
				return nil, err
			}
			cfg.TLSConfig = tlsCfg
		}
		log.Printf("rasputin-api: mesh backend = headscale (url=%s)", url)
		return mesh.NewRealClient(cfg)
	default:
		return nil, errors.New("unknown RASPUTIN_MESH_BACKEND: " + backend)
	}
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
