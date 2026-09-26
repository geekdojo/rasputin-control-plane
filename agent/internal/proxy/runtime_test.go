package proxy

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLeafStore_Routes(t *testing.T) {
	s := NewLeafStore(t.TempDir())
	if err := s.Write("a1", []byte("C1"), []byte("K1"), RouteMeta{
		TailnetFQDN: "jellyfin.home1.internal", LANFQDN: "jellyfin.lan.home1.internal", UpstreamPort: 8096,
	}); err != nil {
		t.Fatalf("write a1: %v", err)
	}
	if err := s.Write("a2", []byte("C2"), []byte("K2"), RouteMeta{
		TailnetFQDN: "vault.home1.internal", UpstreamPort: 8080, // tailnet-only
	}); err != nil {
		t.Fatalf("write a2: %v", err)
	}

	routes, err := s.Routes()
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	byID := map[string]AppRoute{}
	for _, r := range routes {
		byID[r.AppID] = r
	}
	if r := byID["a1"]; r.TailnetFQDN != "jellyfin.home1.internal" || r.LANFQDN != "jellyfin.lan.home1.internal" ||
		r.UpstreamPort != 8096 || r.CertPath != s.CertPath("a1") || r.KeyPath != s.KeyPath("a1") {
		t.Errorf("a1 route wrong: %+v", r)
	}
	if r := byID["a2"]; r.LANFQDN != "" || r.UpstreamPort != 8080 {
		t.Errorf("a2 route wrong: %+v", r)
	}
}

func TestReconcile_PushesRenderedConfigOverSocket(t *testing.T) {
	var (
		got      []byte
		gotHost  string
		gotCType string
	)
	sock := serveAdminSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/load" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		got, _ = io.ReadAll(r.Body)
		gotHost, gotCType = r.Host, r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))

	store := NewLeafStore(t.TempDir())
	if err := store.Write("a1", []byte("C"), []byte("K"), RouteMeta{
		TailnetFQDN: "jellyfin.home1.internal", UpstreamPort: 8096,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := NewReconciler(store, sock,
		func() string { return "100.64.0.2" },
		func() string { return "192.168.1.2" })
	if err := r.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	body := string(got)
	if !strings.Contains(body, "jellyfin.home1.internal") || !strings.Contains(body, "127.0.0.1:8096") {
		t.Errorf("pushed config missing route: %s", body)
	}
	var cfg struct {
		Admin struct {
			Listen string `json:"listen"`
		} `json:"admin"`
	}
	if err := json.Unmarshal(got, &cfg); err != nil {
		t.Fatalf("pushed config is not JSON: %v", err)
	}
	if want := "unix/" + sock + "|0600"; cfg.Admin.Listen != want {
		t.Errorf("pushed admin.listen = %q, want %q", cfg.Admin.Listen, want)
	}
	if gotHost != adminHost || gotCType != "application/json" {
		t.Errorf("request Host=%q Content-Type=%q, want %q and application/json", gotHost, gotCType, adminHost)
	}
}

// TestReconcile_RenewedLeafReloadsCaddy is the unit half of
// geekdojo-brain#611. The config names each leaf by FILE PATH, and a renewal
// rewrites the same path, so a config rendered from paths alone is byte-identical
// before and after — and Caddy's /load compares bytes and no-ops an identical
// config, so the new leaf was never read. The pushed config must therefore
// change whenever the leaf's bytes change, and ONLY then: every Caddy reload
// closes every proxied WebSocket on the node (reverse_proxy's
// stream_close_delay defaults to 0), and the sweep re-delivers every app's leaf
// daily, so a reload on an unchanged leaf would cut every app's streams daily.
// That is also why the fix is not Cache-Control: must-revalidate on every push,
// and the request must not carry it.
func TestReconcile_RenewedLeafReloadsCaddy(t *testing.T) {
	type push struct {
		body         string
		cacheControl string
	}
	var pushes []push
	sock := serveAdminSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/load" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b, _ := io.ReadAll(r.Body)
		pushes = append(pushes, push{body: string(b), cacheControl: r.Header.Get("Cache-Control")})
		w.WriteHeader(http.StatusOK)
	}))

	store := NewLeafStore(t.TempDir())
	meta := RouteMeta{TailnetFQDN: "kuma.home1.internal", LANFQDN: "kuma.lan.home1.internal", UpstreamPort: 3001}
	other := RouteMeta{TailnetFQDN: "jellyfin.home1.internal", UpstreamPort: 8096}
	if err := store.Write("other", []byte("OTHER-CERT"), []byte("OTHER-KEY"), other); err != nil {
		t.Fatal(err)
	}
	r := NewReconciler(store, sock, func() string { return "100.64.0.2" }, func() string { return "192.168.1.2" })
	deliver := func(cert, key string) {
		t.Helper()
		if err := store.Write("kuma", []byte(cert), []byte(key), meta); err != nil {
			t.Fatal(err)
		}
		if err := r.Reconcile(); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}

	deliver("CERT-1", "KEY-1") // deploy
	deliver("CERT-2", "KEY-2") // renewal: same paths, new bytes
	deliver("CERT-2", "KEY-2") // the daily sweep re-asserting the same leaf
	if len(pushes) != 3 {
		t.Fatalf("got %d pushes, want 3", len(pushes))
	}

	if pushes[1].body == pushes[0].body {
		t.Errorf("a renewed leaf pushed a byte-identical config, which Caddy no-ops: the old leaf keeps being served (#611)\n%s", pushes[1].body)
	}
	if pushes[2].body != pushes[1].body {
		t.Errorf("re-delivering an unchanged leaf changed the pushed config, so Caddy reloads and drops every app's streams:\nbefore: %s\nafter:  %s", pushes[1].body, pushes[2].body)
	}
	for i, p := range pushes {
		if p.cacheControl != "" {
			t.Errorf("push %d sent Cache-Control %q; a forced reload on every push would cut every app's streams on each daily re-delivery", i, p.cacheControl)
		}
	}
	// The key never enters the config: Caddy autosaves every loaded config to
	// disk and serves it back on GET /config/.
	for i, p := range pushes {
		for _, secret := range []string{"KEY-1", "KEY-2", "OTHER-KEY"} {
			if strings.Contains(p.body, secret) {
				t.Errorf("push %d carries key material %q", i, secret)
			}
		}
	}
}

func TestReconcile_NoSocketIsAnError(t *testing.T) {
	sock := shortTempDir(t) + "/absent.sock"
	r := NewReconciler(NewLeafStore(t.TempDir()), sock, func() string { return "" }, func() string { return "" })
	err := r.Reconcile()
	if err == nil || !strings.Contains(err.Error(), sock) {
		t.Fatalf("Reconcile with no socket = %v, want an error naming %s", err, sock)
	}
}

func TestPushConfig_ErrorsOnReject(t *testing.T) {
	sock := serveAdminSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad config"))
	}))
	err := pushConfig(newAdminClient(sock), sock, []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Errorf("want a 'rejected' error, got %v", err)
	}
}

// serveAdminSocket serves h on a unix socket in a fresh short temp dir and
// returns the socket path.
func serveAdminSocket(t *testing.T, h http.Handler) string {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// shortTempDir is a temp dir with a short path: a unix socket path is capped at
// 104 bytes on macOS (108 on Linux), and t.TempDir() nests deep enough to
// exceed it.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rpx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
