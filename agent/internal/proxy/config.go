package proxy

import (
	"encoding/json"
	"fmt"
	"sort"
)

// CaddyAdminAddr is where the node-local Caddy exposes its admin API — loopback
// only. The agent pushes config there (a later slice); this file just renders
// the config that gets pushed.
const CaddyAdminAddr = "localhost:2019"

// AppRoute is one app's routing into the node-local Caddy: the Host names to
// match, the loopback upstream port the app's container listens on, and the
// paths to the app's delivered TLS leaf (LeafStore.CertPath/KeyPath).
type AppRoute struct {
	AppID        string
	TailnetFQDN  string // matched on the tailnet listener — always present
	LANFQDN      string // matched on the LAN listener; "" when the app is tailnet-only
	UpstreamPort int
	CertPath     string
	KeyPath      string
}

// RenderCaddyConfig builds the full Caddy admin JSON for a node's app routes.
// Exposure (ADR-0004 §9) is enforced by BIND, using two HTTP servers:
//
//   - the tailnet server (bound to tailnetAddr) carries EVERY app, matched on
//     its tailnet FQDN, so a tailnet-only app is reachable only here;
//   - the LAN server (bound to lanAddr) carries ONLY LAN-exposed apps, matched
//     on their .lan FQDN.
//
// A "" listener address omits that server (e.g. a node not yet enrolled has no
// tailnet address; a node with no LAN route has no LAN server). auto_https is
// OFF — TLS uses the per-app leaves the control plane delivers, never Caddy's
// own ACME (ADR-0004 §7). certPort is normally 443.
func RenderCaddyConfig(routes []AppRoute, tailnetAddr, lanAddr string, certPort int) ([]byte, error) {
	// Stable order so the same app set renders byte-identical config (cheap
	// idempotence for the admin-API push).
	sorted := append([]AppRoute(nil), routes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].AppID < sorted[j].AppID })

	servers := map[string]any{}
	if tailnetAddr != "" {
		var tr []any
		for _, r := range sorted {
			if r.TailnetFQDN == "" || r.UpstreamPort == 0 {
				continue
			}
			tr = append(tr, httpRoute(r.TailnetFQDN, r.UpstreamPort))
		}
		servers["tailnet"] = httpServer(fmt.Sprintf("%s:%d", tailnetAddr, certPort), tr)
	}
	if lanAddr != "" {
		var lr []any
		for _, r := range sorted {
			if r.LANFQDN == "" || r.UpstreamPort == 0 {
				continue // tailnet-only app: no LAN route
			}
			lr = append(lr, httpRoute(r.LANFQDN, r.UpstreamPort))
		}
		servers["lan"] = httpServer(fmt.Sprintf("%s:%d", lanAddr, certPort), lr)
	}

	// Load each app's delivered leaf once (shared by both servers). MUST be a
	// non-nil slice: a nil renders as JSON `null`, which Caddy's tls app rejects
	// ("load_files: module value cannot be null") — so a node with zero apps
	// would fail every config load until its first leaf arrived (caught on the
	// bench, 2026-08-09). An empty `[]` is accepted.
	loadFiles := []any{}
	for _, r := range sorted {
		if r.CertPath == "" || r.KeyPath == "" {
			continue
		}
		loadFiles = append(loadFiles, map[string]any{
			"certificate": r.CertPath,
			"key":         r.KeyPath,
			"tags":        []string{r.AppID},
		})
	}

	cfg := map[string]any{
		"admin": map[string]any{"listen": CaddyAdminAddr},
		"apps": map[string]any{
			"http": map[string]any{"servers": servers},
			"tls":  map[string]any{"certificates": map[string]any{"load_files": loadFiles}},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func httpServer(listen string, routes []any) map[string]any {
	if routes == nil {
		routes = []any{}
	}
	return map[string]any{
		"listen":          []string{listen},
		"automatic_https": map[string]any{"disable": true},
		"routes":          routes,
		// An empty connection policy makes Caddy select from the loaded
		// certificates by SNI; the leaves' SANs are the app FQDNs.
		"tls_connection_policies": []any{map[string]any{}},
	}
}

func httpRoute(host string, upstreamPort int) map[string]any {
	return map[string]any{
		"match": []any{map[string]any{"host": []string{host}}},
		"handle": []any{map[string]any{
			"handler":   "reverse_proxy",
			"upstreams": []any{map[string]any{"dial": fmt.Sprintf("127.0.0.1:%d", upstreamPort)}},
		}},
	}
}
