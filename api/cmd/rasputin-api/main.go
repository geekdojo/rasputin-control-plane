package main

import (
	"context"
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
	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
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
	runner.Register(updater.UpdateWorkflow(updaterStore, invStore, busSrv.Conn(), updater.Config{
		PublicBaseURL: publicBaseURL,
	}))

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

	srv := apipkg.NewServer(jobStore, runner, invStore, fwStore, appsStore, metricsStore, updaterStore, verifier, bundleDir, authSvc, busSrv.Conn())
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
