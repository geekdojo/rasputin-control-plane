package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// certPort is where the node-local Caddy terminates app TLS. 443 — the app
// FQDNs resolve to the node, and clients dial https:// with no port.
const certPort = 443

// Reconciler rebuilds the node-local Caddy config from the delivered leaves and
// pushes it to Caddy's admin API. It is called on every leaf change (delivery /
// teardown) and once at startup, so Caddy's live config always matches the set
// of apps whose leaves the node holds.
type Reconciler struct {
	store     *LeafStore
	adminAddr string
	// tailnetIP / lanIP resolve the node's listen addresses at reconcile time
	// (they move: LAN is DHCP, tailnet appears on enrollment). "" omits that
	// server — a not-yet-enrolled node serves nothing on the tailnet, a node
	// with no LAN route serves nothing on the LAN.
	tailnetIP func() string
	lanIP     func() string
	client    *http.Client
}

// NewReconciler builds a reconciler pushing to adminAddr (normally
// CaddyAdminAddr). tailnetIP/lanIP are best-effort address resolvers.
func NewReconciler(store *LeafStore, adminAddr string, tailnetIP, lanIP func() string) *Reconciler {
	return &Reconciler{
		store:     store,
		adminAddr: adminAddr,
		tailnetIP: tailnetIP,
		lanIP:     lanIP,
		client:    &http.Client{Timeout: 5 * time.Second},
	}
}

// Reconcile renders the current config and loads it into Caddy. Idempotent —
// Caddy no-ops an unchanged config, and the render is stable.
func (r *Reconciler) Reconcile() error {
	routes, err := r.store.Routes()
	if err != nil {
		return fmt.Errorf("proxy: assemble routes: %w", err)
	}
	cfg, err := RenderCaddyConfig(routes, r.tailnetIP(), r.lanIP(), certPort)
	if err != nil {
		return fmt.Errorf("proxy: render config: %w", err)
	}
	return pushConfig(r.client, r.adminAddr, cfg)
}

// RunCaddy supervises the stock `caddy` binary (admin API on CaddyAdminAddr,
// default localhost:2019) until ctx is cancelled, restarting it on exit. After
// each (re)start it waits for the admin API and re-pushes the current config —
// a restarted Caddy comes up empty, so this restores the app routes.
//
// Bench-gated: whether Caddy actually terminates TLS and routes on the
// appliance is validated on real hardware; this just runs and feeds it.
func (r *Reconciler) RunCaddy(ctx context.Context, caddyBin string) {
	backoff := time.Second
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, caddyBin, "run")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			log.Printf("rasputin-agent: start caddy (%s): %v; retry in %s", caddyBin, err, backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		go r.reconcileWhenReady(ctx)
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return
		}
		log.Printf("rasputin-agent: caddy exited; restarting")
		_ = sleepCtx(ctx, time.Second)
	}
}

// reconcileWhenReady polls the admin API until it answers, then reconciles.
func (r *Reconciler) reconcileWhenReady(ctx context.Context) {
	for i := 0; i < 60 && ctx.Err() == nil; i++ {
		resp, err := r.client.Get("http://" + r.adminAddr + "/config/")
		if err == nil {
			_ = resp.Body.Close()
			if err := r.Reconcile(); err != nil {
				log.Printf("rasputin-agent: proxy reconcile after caddy start: %v", err)
			}
			return
		}
		if !sleepCtx(ctx, 500*time.Millisecond) {
			return
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// pushConfig POSTs a full Caddy JSON config to the admin API's /load endpoint,
// which swaps it in atomically with zero downtime.
func pushConfig(client *http.Client, adminAddr string, cfg []byte) error {
	req, err := http.NewRequest(http.MethodPost, "http://"+adminAddr+"/load", bytes.NewReader(cfg))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("proxy: push config to %s: %w", adminAddr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("proxy: caddy rejected config (%d): %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return nil
}
