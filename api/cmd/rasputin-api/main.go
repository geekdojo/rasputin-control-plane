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

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	apipkg "github.com/geekdojo/rasputin-control-plane/api/internal/api"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/ids"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
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

	// Mesh subsystem: backend defaults to the file-backed mock client.
	// Set RASPUTIN_MESH_BACKEND=headscale (plus RASPUTIN_HEADSCALE_URL and
	// RASPUTIN_HEADSCALE_API_KEY) to talk to a real Headscale instance.
	// Supervisor defaults to noop; set RASPUTIN_HEADSCALE_SUPERVISOR=docker
	// to have the api manage the Headscale container itself. See wiki
	// design/control-plane/mesh.md.
	meshStateDir := envOr("RASPUTIN_MESH_STATE_DIR", filepath.Join(dataDir, "mesh"))
	if err := os.MkdirAll(meshStateDir, 0o755); err != nil {
		log.Fatalf("rasputin-api: mesh state dir: %v", err)
	}
	meshClient, err := newMeshClient(meshStateDir)
	if err != nil {
		log.Fatalf("rasputin-api: mesh client: %v", err)
	}
	installName := envOr("RASPUTIN_INSTALL_NAME", "rasputin")
	meshCA, err := mesh.EnsureMeshCA(trustDir, installName)
	if err != nil {
		log.Fatalf("rasputin-api: mesh CA: %v", err)
	}
	log.Printf("rasputin-api: mesh CA loaded (CN=%s, expires=%s)",
		meshCA.Cert.Subject.CommonName, meshCA.Cert.NotAfter.Format("2006-01-02"))
	meshSup, err := newMeshSupervisor(meshStateDir, meshCA)
	if err != nil {
		log.Fatalf("rasputin-api: mesh supervisor: %v", err)
	}
	meshSvc := mesh.NewService(mesh.Config{
		LoginServer:  envOr("RASPUTIN_MESH_LOGIN_SERVER", "https://mesh.rasputin.local"),
		DefaultUser:  envOr("RASPUTIN_MESH_DEFAULT_USER", "rasputin-operator"),
		HeadplaneURL: os.Getenv("RASPUTIN_HEADPLANE_URL"),
	}, meshStore, meshClient, meshSup)
	if err := meshSvc.Start(ctx); err != nil {
		log.Fatalf("rasputin-api: mesh service: %v", err)
	}
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
	// On every successful login (and first-credential registration), ensure
	// a matching Headscale user exists. EnsureUser is idempotent + cached,
	// so this costs at most one HTTP round-trip on cold start per user;
	// the mock backend turns it into a single map write. Errors are logged
	// inside runLoginHook and never block the login response — auth stays
	// usable when mesh/Headscale are unhealthy.
	authSvc.SetLoginHook(func(ctx context.Context, u *auth.User) error {
		return meshClient.EnsureUser(ctx, u.Name)
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

	// IDS alert subscriber — appends each firewall snort alert to a JSONL
	// file the obs Alloy tails (when EnableLoki + EnableIDSPipe are on).
	// Even with obs off, the file is still written so operators can
	// `tail -f` / `jq` it from disk. Path is under dataDir so it survives
	// the same way every other persistent state does.
	idsLogPath := filepath.Join(dataDir, "obs", "ids-alerts", "alerts.jsonl")
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
	obsSup, obsSink, obsStatus := mustWireObs(ctx, dataDir, metricsSvc)
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

	srv := apipkg.NewServer(jobStore, runner, invStore, invSvc, fwStore, appsStore, metricsStore, updaterStore, verifier, bundleDir, trustDir, meshSvc, bmcSvc, setupSvc, authSvc, obsStatus, busSrv.Conn())

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

// newMeshSupervisor builds the mesh.Supervisor chosen by env. Default is
// the noop supervisor — appropriate when running against the mock client,
// or when an operator manages Headscale themselves (e.g. via host-level
// systemd or compose). Set RASPUTIN_HEADSCALE_SUPERVISOR=docker to have
// the api drive the Headscale container's lifecycle via the local docker
// CLI. RASPUTIN_HEADSCALE_IMAGE and RASPUTIN_HEADSCALE_LISTEN_ADDR
// override the pinned defaults.
func newMeshSupervisor(stateDir string, meshCA *mesh.MeshCA) (mesh.Supervisor, error) {
	choice := strings.ToLower(envOr("RASPUTIN_HEADSCALE_SUPERVISOR", "noop"))
	switch choice {
	case "", "noop":
		return mesh.NewNoopSupervisor(), nil
	case "docker":
		cfg := mesh.DockerSupervisorConfig{
			StateDir:      filepath.Join(stateDir, "headscale"),
			Image:         os.Getenv("RASPUTIN_HEADSCALE_IMAGE"),
			ListenAddr:    os.Getenv("RASPUTIN_HEADSCALE_LISTEN_ADDR"),
			ServerURL:     os.Getenv("RASPUTIN_HEADSCALE_URL"),
			ContainerName: os.Getenv("RASPUTIN_HEADSCALE_CONTAINER"),
			MeshCA:        meshCA, // enables HTTPS mode with a per-installation leaf
		}
		log.Printf("rasputin-api: mesh supervisor = docker (state=%s, tls=%v)",
			cfg.StateDir, cfg.MeshCA != nil)
		return mesh.NewDockerSupervisor(cfg)
	default:
		return nil, errors.New("unknown RASPUTIN_HEADSCALE_SUPERVISOR: " + choice)
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
func mustWireObs(ctx context.Context, dataDir string, metricsSvc *metrics.Service) (*obs.DockerComposeSupervisor, *obs.VMSink, *obs.Status) {
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
