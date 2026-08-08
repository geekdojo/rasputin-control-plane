package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func renderAndParse(t *testing.T, routes []AppRoute, tailnetAddr, lanAddr string) map[string]any {
	t.Helper()
	data, err := RenderCaddyConfig(routes, tailnetAddr, lanAddr, 443)
	if err != nil {
		t.Fatalf("RenderCaddyConfig: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, data)
	}
	return cfg
}

func servers(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	return cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
}

// routeHosts returns the set of Host names matched by a server's routes.
func routeHosts(t *testing.T, srv map[string]any) []string {
	t.Helper()
	var out []string
	for _, r := range srv["routes"].([]any) {
		for _, m := range r.(map[string]any)["match"].([]any) {
			for _, h := range m.(map[string]any)["host"].([]any) {
				out = append(out, h.(string))
			}
		}
	}
	return out
}

func TestRenderCaddyConfig_ExposureSplitByBind(t *testing.T) {
	routes := []AppRoute{
		{AppID: "a1", TailnetFQDN: "jellyfin.home1.internal", LANFQDN: "jellyfin.lan.home1.internal",
			UpstreamPort: 8096, CertPath: "/c/a1/leaf.pem", KeyPath: "/c/a1/leaf.key"},
		{AppID: "a2", TailnetFQDN: "vaultwarden.home1.internal", LANFQDN: "", // tailnet-only
			UpstreamPort: 8080, CertPath: "/c/a2/leaf.pem", KeyPath: "/c/a2/leaf.key"},
	}
	cfg := renderAndParse(t, routes, "100.64.0.2", "192.168.1.2")
	srv := servers(t, cfg)

	// Tailnet server carries BOTH apps.
	tn := srv["tailnet"].(map[string]any)
	if hosts := routeHosts(t, tn); len(hosts) != 2 {
		t.Errorf("tailnet hosts = %v, want both apps", hosts)
	}
	if lis := tn["listen"].([]any); lis[0] != "100.64.0.2:443" {
		t.Errorf("tailnet listen = %v, want 100.64.0.2:443", lis)
	}
	if !tn["automatic_https"].(map[string]any)["disable"].(bool) {
		t.Error("auto_https not disabled on tailnet server")
	}

	// LAN server carries ONLY the LAN-exposed app.
	lan := srv["lan"].(map[string]any)
	hosts := routeHosts(t, lan)
	if len(hosts) != 1 || hosts[0] != "jellyfin.lan.home1.internal" {
		t.Errorf("lan hosts = %v, want only jellyfin.lan...", hosts)
	}

	// Both leaves are loaded.
	lf := cfg["apps"].(map[string]any)["tls"].(map[string]any)["certificates"].(map[string]any)["load_files"].([]any)
	if len(lf) != 2 {
		t.Errorf("load_files = %d, want 2", len(lf))
	}

	// The upstream dials loopback:port.
	if !strings.Contains(string(mustJSON(t, tn)), "127.0.0.1:8096") {
		t.Error("tailnet route missing 127.0.0.1:8096 upstream")
	}
}

func TestRenderCaddyConfig_OmitsServerWithNoAddress(t *testing.T) {
	routes := []AppRoute{{AppID: "a1", TailnetFQDN: "x.home1.internal", UpstreamPort: 80, CertPath: "/c", KeyPath: "/k"}}

	// No LAN address → no lan server.
	if srv := servers(t, renderAndParse(t, routes, "100.64.0.2", "")); srv["lan"] != nil || srv["tailnet"] == nil {
		t.Errorf("want only tailnet server, got %v", keysOf(srv))
	}
	// Neither address → no servers at all.
	if srv := servers(t, renderAndParse(t, routes, "", "")); len(srv) != 0 {
		t.Errorf("want no servers, got %v", keysOf(srv))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func keysOf(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
