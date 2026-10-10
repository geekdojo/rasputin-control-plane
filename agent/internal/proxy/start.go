package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// NodeProxyConfig carries every collaborator the node-local app proxy needs.
// The agent's main, the composition root, builds it; nothing here is reached
// for.
type NodeProxyConfig struct {
	// NodeID scopes the app.leaf subscription.
	NodeID string
	// StateDir is the agent's state root; leaves are kept under
	// <StateDir>/proxy.
	StateDir string
	// AdminSocket is Caddy's admin unix socket (DefaultAdminSocket in the
	// agent).
	AdminSocket string
	// CaddyBin is the caddy binary to supervise; "" means none was found, and
	// the proxy runs without Caddy (leaves are still delivered).
	CaddyBin string
	// TailnetIP and LANIP resolve the node's listen addresses at reconcile
	// time; "" omits that server.
	TailnetIP func() string
	LANIP     func() string
	// Subscribe registers a per-connection bus subscription with the agent.
	Subscribe func(func(*nats.Conn) error)
	Logger    *slog.Logger
}

// StartNodeProxy starts the node-local app proxy (ADR-0004 §1/§6/§9) on a role
// that accepts apps and returns its Reconciler; on any other role it starts
// nothing, registers nothing, logs why, and returns nil.
//
// The proxy runs the stock caddy binary, receives per-app TLS leaves and route
// metadata over the bus, and pushes the Caddy config through the admin API on
// a root-only unix socket, never TCP (geekdojo-brain#450). Its listen addresses
// are the node's LAN IP and tailnet IP on :443. It is best-effort: a proxy
// failure never blocks the agent.
//
// It runs only where proto.AcceptsApps holds, which is compute. On a
// controlplane rasputin-api owns wildcard :443, and a Caddy there would race it
// for the port at every boot (geekdojo/geekdojo-brain#831); a controlplane is
// never given an app to serve, so it has no use for the proxy.
func StartNodeProxy(ctx context.Context, role proto.NodeRole, cfg NodeProxyConfig) *Reconciler {
	if !proto.AcceptsApps(role) {
		cfg.Logger.Info("rasputin-agent: node-local app proxy not started",
			"role", string(role),
			"reason", "this role accepts no apps; rasputin-api owns :443 on a controlplane")
		return nil
	}

	store := NewLeafStore(filepath.Join(cfg.StateDir, "proxy"))
	r := NewReconciler(store, cfg.AdminSocket, cfg.TailnetIP, cfg.LANIP)
	if cfg.CaddyBin != "" {
		go r.RunCaddy(ctx, cfg.CaddyBin)
	} else {
		cfg.Logger.Warn("rasputin-agent: caddy binary not found on PATH — node-local proxy disabled (leaves still delivered)",
			"node_id", cfg.NodeID)
	}
	cfg.Subscribe(func(c *nats.Conn) error {
		if _, err := RegisterHandlers(c, cfg.NodeID, store, r.Reconcile); err != nil {
			return fmt.Errorf("register proxy handlers: %w", err)
		}
		return nil
	})
	return r
}
