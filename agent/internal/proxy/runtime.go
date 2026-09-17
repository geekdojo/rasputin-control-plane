package proxy

import (
	"bytes"
	"context"
	"encoding/json"
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

// defaultLegacyStopWait bounds how long startup waits for a Caddy on the legacy TCP
// admin address to exit after being told to stop. Caddy's own graceful
// shutdown is well inside this; a Caddy still answering afterwards fails this
// start attempt, and the supervisor's backoff asks again.
const defaultLegacyStopWait = 15 * time.Second

// Reconciler rebuilds the node-local Caddy config from the delivered leaves and
// pushes it to Caddy's admin API. It is called on every leaf change (delivery /
// teardown) and once at startup, so Caddy's live config always matches the set
// of apps whose leaves the node holds.
type Reconciler struct {
	store *LeafStore
	// adminSocket is the unix socket Caddy's admin API listens on — the only
	// admin listener Caddy is ever given (see DefaultAdminSocket).
	adminSocket string
	// legacyAdmin is the TCP address pre-#450 agents configured. It is only
	// probed, to retire a Caddy still listening there; "" skips the probe.
	legacyAdmin    string
	legacyStopWait time.Duration
	// tailnetIP / lanIP resolve the node's listen addresses at reconcile time
	// (they move: LAN is DHCP, tailnet appears on enrollment). "" omits that
	// server — a not-yet-enrolled node serves nothing on the tailnet, a node
	// with no LAN route serves nothing on the LAN.
	tailnetIP    func() string
	lanIP        func() string
	client       *http.Client
	legacyClient *http.Client
}

// NewReconciler builds a reconciler pushing to the admin API on adminSocket
// (normally DefaultAdminSocket). tailnetIP/lanIP are best-effort address
// resolvers.
func NewReconciler(store *LeafStore, adminSocket string, tailnetIP, lanIP func() string) *Reconciler {
	return &Reconciler{
		store:          store,
		adminSocket:    adminSocket,
		legacyAdmin:    LegacyAdminAddr,
		legacyStopWait: defaultLegacyStopWait,
		tailnetIP:      tailnetIP,
		lanIP:          lanIP,
		client:         newAdminClient(adminSocket),
		legacyClient:   &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}},
	}
}

// Reconcile renders the current config and loads it into Caddy. Idempotent —
// Caddy no-ops an unchanged config, and the render is stable.
func (r *Reconciler) Reconcile() error {
	routes, err := r.store.Routes()
	if err != nil {
		return fmt.Errorf("proxy: assemble routes: %w", err)
	}
	cfg, err := RenderCaddyConfig(routes, r.tailnetIP(), r.lanIP(), certPort, r.adminSocket)
	if err != nil {
		return fmt.Errorf("proxy: render config: %w", err)
	}
	return pushConfig(r.client, r.adminSocket, cfg)
}

// RunCaddy supervises the stock `caddy` binary until ctx is cancelled,
// restarting it on exit. After each (re)start it waits for the admin API and
// re-pushes the current config — a restarted Caddy comes up empty, so this
// restores the app routes.
//
// Every start re-establishes the admin socket's safety rather than trusting the
// previous one: the directory is re-checked (PrepareAdminDir), and Caddy is
// given the socket through CADDY_ADMIN so that its very first admin listener —
// before any config is loaded — is the socket. Without that, `caddy run` opens
// its built-in default, TCP localhost:2019, until the first push replaces it.
//
// Bench-gated: whether Caddy actually terminates TLS and routes on the
// appliance is validated on real hardware; this just runs and feeds it.
func (r *Reconciler) RunCaddy(ctx context.Context, caddyBin string) {
	backoff := time.Second
	retry := func(format string, args ...any) bool {
		log.Printf("rasputin-agent: "+format+"; retry in %s", append(args, backoff)...)
		if !sleepCtx(ctx, backoff) {
			return false
		}
		backoff = min(backoff*2, 30*time.Second)
		return true
	}
	for ctx.Err() == nil {
		listen, err := AdminListen(r.adminSocket)
		if err != nil {
			// A bad path is a programming error, not a transient: never start
			// Caddy without a socket to put its admin API on.
			log.Printf("rasputin-agent: caddy not started: %v", err)
			return
		}
		if err := PrepareAdminDir(r.adminSocket); err != nil {
			if !retry("caddy not started: %v", err) {
				return
			}
			continue
		}
		if err := r.stopLegacyCaddy(ctx); err != nil {
			if !retry("caddy not started: %v", err) {
				return
			}
			continue
		}

		cmd := exec.CommandContext(ctx, caddyBin, "run")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		// Appended last, so it wins over any CADDY_ADMIN already in the
		// environment.
		cmd.Env = append(os.Environ(), "CADDY_ADMIN="+listen)
		if err := cmd.Start(); err != nil {
			if !retry("start caddy (%s): %v", caddyBin, err) {
				return
			}
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

// stopLegacyCaddy retires a Caddy still serving its admin API on the legacy TCP
// address, so the node converges on the socket with nobody touching it.
//
// On the appliance this is belt and braces: Caddy is a child of the agent and
// lives in rasputin-agent.service's cgroup, so systemd stops it with the agent,
// and an A/B update reboots. It is here for the case that cgroup teardown does
// not cover — a Caddy that outlived the agent that started it — which would
// otherwise hold :443 (the new Caddy could never bind) and keep the
// unauthenticated TCP listener open indefinitely.
//
// It stops only a Caddy whose live config is recognisably one a pre-#450 agent
// pushed, or that has no config at all (isLegacyAgentConfig): a developer's own
// Caddy on a workstation also answers on localhost:2019 and is left alone. The
// probe sends nothing but a GET and, on a match, a bodyless POST /stop, so it
// discloses nothing to whatever might be squatting on the port.
//
// It returns an error only when it asked a legacy Caddy to stop and that Caddy
// is still answering after legacyStopWait — the new Caddy is then not started
// beside it, and the supervisor retries.
func (r *Reconciler) stopLegacyCaddy(ctx context.Context) error {
	if r.legacyAdmin == "" {
		return nil
	}
	cfg, ok := r.legacyConfig(ctx)
	if !ok {
		return nil
	}
	if !isLegacyAgentConfig(cfg, r.legacyAdmin) {
		log.Printf("rasputin-agent: something answers on TCP %s but its config is not one an agent rendered; leaving it alone", r.legacyAdmin)
		return nil
	}
	log.Printf("rasputin-agent: a caddy admin API is still listening on TCP %s; stopping it (geekdojo-brain#450)", r.legacyAdmin)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+r.legacyAdmin+"/stop", nil)
	if err != nil {
		return err
	}
	if resp, err := r.legacyClient.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}
	deadline := time.Now().Add(r.legacyStopWait)
	for time.Now().Before(deadline) {
		if _, answers := r.legacyConfig(ctx); !answers {
			log.Printf("rasputin-agent: legacy caddy admin on TCP %s is gone", r.legacyAdmin)
			return nil
		}
		if !sleepCtx(ctx, 250*time.Millisecond) {
			return ctx.Err()
		}
	}
	return fmt.Errorf("legacy caddy admin on TCP %s still answering %s after /stop", r.legacyAdmin, r.legacyStopWait)
}

// legacyConfig fetches the live config from the legacy admin address. ok is
// false when nothing answers there.
func (r *Reconciler) legacyConfig(ctx context.Context) (body []byte, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+r.legacyAdmin+"/config/", nil)
	if err != nil {
		return nil, false
	}
	resp, err := r.legacyClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, true
	}
	return body, true
}

// isLegacyAgentConfig reports whether cfg is a config RenderCaddyConfig
// produced before #450 — admin on the legacy TCP address (legacyAdmin), a tls app loading
// files, and no HTTP servers other than the agent's "tailnet" and "lan" — or
// no config at all, which is what a pre-#450 agent's Caddy holds until its
// first push. An empty Caddy serves nothing, so stopping one costs nothing.
func isLegacyAgentConfig(cfg []byte, legacyAdmin string) bool {
	if string(bytes.TrimSpace(cfg)) == "null" {
		return true
	}
	var c struct {
		Admin *struct {
			Listen string `json:"listen"`
		} `json:"admin"`
		Apps *struct {
			HTTP *struct {
				Servers map[string]json.RawMessage `json:"servers"`
			} `json:"http"`
			TLS *struct {
				Certificates *struct {
					LoadFiles json.RawMessage `json:"load_files"`
				} `json:"certificates"`
			} `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		return false
	}
	if c.Admin == nil || c.Admin.Listen != legacyAdmin || c.Apps == nil || c.Apps.HTTP == nil ||
		c.Apps.TLS == nil || c.Apps.TLS.Certificates == nil || c.Apps.TLS.Certificates.LoadFiles == nil {
		return false
	}
	for name := range c.Apps.HTTP.Servers {
		if name != "tailnet" && name != "lan" {
			return false
		}
	}
	return true
}

// reconcileWhenReady polls the admin API until it answers, then reconciles.
func (r *Reconciler) reconcileWhenReady(ctx context.Context) {
	for i := 0; i < 60 && ctx.Err() == nil; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, adminURL("/config/"), nil)
		if err != nil {
			return
		}
		resp, err := r.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if err := CheckAdminSocket(r.adminSocket); err != nil {
				// The 0700 directory still keeps other uids out, but the
				// socket's own mode is the second layer and must not be
				// lost silently (e.g. a Caddy that ignores the mode suffix).
				log.Printf("rasputin-agent: WARNING caddy admin socket check failed: %v", err)
			}
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
// which swaps it in atomically with zero downtime. client must dial the admin
// socket (newAdminClient); adminSocket is named in errors only.
func pushConfig(client *http.Client, adminSocket string, cfg []byte) error {
	req, err := http.NewRequest(http.MethodPost, adminURL("/load"), bytes.NewReader(cfg))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("proxy: push config to %s: %w", adminSocket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("proxy: caddy rejected config (%d): %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return nil
}
