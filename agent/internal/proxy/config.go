package proxy

import (
	"encoding/json"
	"fmt"
	"sort"
)

// AppRoute is one app's routing into the node-local Caddy: the Host names to
// match, the loopback upstream port the app's container listens on, and the
// paths to the app's delivered TLS leaf (LeafStore.CertPath/KeyPath).
type AppRoute struct {
	AppID        string
	TailnetFQDN  string // matched on the tailnet listener — always present
	LANFQDN      string // matched on the LAN listener; "" when the app is tailnet-only
	UpstreamPort int
	UpstreamTLS  bool // the app speaks HTTPS on UpstreamPort — dial it over TLS
	CertPath     string
	KeyPath      string
	// CertSHA256 is the hex SHA-256 of the certificate file's bytes at render
	// time (LeafStore.Routes). It is rendered into the config so that the
	// config changes when — and only when — the leaf does; see certDigestTag.
	CertSHA256 string
}

// certDigestTagPrefix marks the load_files tag that carries a leaf's content
// digest (geekdojo-brain#611).
//
// Caddy reads load_files certificates only when it loads a config, and its
// /load compares the new config's bytes with the running one and does nothing
// when they match (caddy.changeConfig, Caddy 2.11.4). The config names each
// leaf by FILE PATH, and a renewal rewrites the same path, so before this tag a
// renewed leaf produced a byte-identical config: /load no-oped, and Caddy went
// on serving the old certificate until something restarted it. Carrying the
// digest makes the config a function of what is on disk, so Caddy's own
// comparison reloads exactly when a leaf's bytes changed.
//
// Not Cache-Control: must-revalidate on every push, which forces a reload even
// for an identical config: every Caddy reload closes every proxied WebSocket
// on the node (reverse_proxy stream_close_delay defaults to 0), and the leaf
// sweep re-delivers every app's leaf daily, so forcing would cut every app's
// streams once per app per day. Caddy 2.11.4 has no admin endpoint that
// reloads certificates alone.
//
// A tag, because tags are the one free-form field on a load_files entry
// (Caddy decodes config strictly and rejects unknown keys); nothing selects
// certificates by tag here (the connection policies select by SNI). Only the
// certificate is hashed: a renewal always issues a new certificate, a key that
// changed without one would not match it anyway, and a key-derived value has
// no business in a config Caddy autosaves to disk and serves on GET /config/.
const certDigestTagPrefix = "rasputin-leaf-sha256:"

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
//
// adminSocket is the unix socket the admin API stays on (normally
// DefaultAdminSocket). Every pushed config names it: a config that omitted
// `admin` would move Caddy's admin API back to its built-in default, TCP
// localhost:2019, which any local user can reach (geekdojo-brain#450).
func RenderCaddyConfig(routes []AppRoute, tailnetAddr, lanAddr string, certPort int, adminSocket string) ([]byte, error) {
	adminListen, err := AdminListen(adminSocket)
	if err != nil {
		return nil, err
	}

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
			tr = append(tr, httpRoute(r.TailnetFQDN, r.UpstreamPort, r.UpstreamTLS))
		}
		servers["tailnet"] = httpServer(fmt.Sprintf("%s:%d", tailnetAddr, certPort), tr)
	}
	if lanAddr != "" {
		var lr []any
		for _, r := range sorted {
			if r.LANFQDN == "" || r.UpstreamPort == 0 {
				continue // tailnet-only app: no LAN route
			}
			lr = append(lr, httpRoute(r.LANFQDN, r.UpstreamPort, r.UpstreamTLS))
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
		tags := []string{r.AppID}
		if r.CertSHA256 != "" {
			tags = append(tags, certDigestTagPrefix+r.CertSHA256)
		}
		loadFiles = append(loadFiles, map[string]any{
			"certificate": r.CertPath,
			"key":         r.KeyPath,
			"tags":        tags,
		})
	}

	cfg := map[string]any{
		"admin": map[string]any{"listen": adminListen},
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

func httpRoute(host string, upstreamPort int, upstreamTLS bool) map[string]any {
	handler := map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": []any{map[string]any{"dial": fmt.Sprintf("127.0.0.1:%d", upstreamPort)}},
	}
	if upstreamTLS {
		// The app serves HTTPS on its own port, so the upstream leg has to be
		// TLS or Caddy speaks cleartext at a TLS listener (#387).
		//
		// Verification is deliberately skipped, and the reason is the dial
		// address rather than convenience: the upstream is 127.0.0.1 on this
		// same host, so the connection never touches a network and there is no
		// one to be in the middle of. A container's self-signed cert asserts
		// nothing loopback has not already guaranteed. Approved by Bryce
		// 2026-08-30 on exactly that reasoning — it does NOT generalise to any
		// upstream that leaves the host, and the dial above is what keeps it
		// true.
		handler["transport"] = map[string]any{
			"protocol": "http",
			"tls":      map[string]any{"insecure_skip_verify": true},
		}
	}
	return map[string]any{
		"match":  []any{map[string]any{"host": []string{host}}},
		"handle": []any{handler},
	}
}
