package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	apipkg "github.com/geekdojo/rasputin-control-plane/api/internal/api"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
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

	store, err := jobs.OpenStore(ctx, filepath.Join(dataDir, "rasputin.db"))
	if err != nil {
		log.Fatalf("rasputin-api: jobs store: %v", err)
	}
	defer store.Close()

	runner := jobs.NewRunner(store, busSrv.Conn())
	runner.Register(jobs.PingWorkflow())

	srv := apipkg.NewServer(store, runner, busSrv.Conn())
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
