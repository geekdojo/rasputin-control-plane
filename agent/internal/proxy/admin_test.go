package proxy

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testAdminSocket is a well-formed socket path for render-only tests.
const testAdminSocket = "/run/rasputin-caddy/admin.sock"

func TestDefaultAdminSocketIsAbsoluteAndUnderRun(t *testing.T) {
	if err := validateAdminSocket(DefaultAdminSocket); err != nil {
		t.Fatalf("DefaultAdminSocket invalid: %v", err)
	}
	// /run is tmpfs on the appliance (a fresh directory every boot) and any
	// /run bind mount is host-trusting in tileschema, so no lower-tier tile can
	// be handed the socket. Moving the socket elsewhere needs both re-checked.
	if !strings.HasPrefix(DefaultAdminSocket, "/run/") {
		t.Errorf("DefaultAdminSocket = %q, want it under /run", DefaultAdminSocket)
	}
}

func TestAdminListen(t *testing.T) {
	got, err := AdminListen("/run/rasputin-caddy/admin.sock")
	if err != nil {
		t.Fatalf("AdminListen: %v", err)
	}
	if want := "unix//run/rasputin-caddy/admin.sock|0600"; got != want {
		t.Errorf("AdminListen = %q, want %q", got, want)
	}

	for _, bad := range []string{
		"",
		"run/caddy.sock",              // relative
		"/run/rasputin/../caddy.sock", // unclean
		"/run/rasputin/caddy/",        // unclean (trailing slash)
		"/run/a|0666/admin.sock",      // would override the mode
		"/run/{env.HOME}/admin.sock",  // Caddy placeholder
		"localhost:2019",              // a TCP address is not a socket path
	} {
		if _, err := AdminListen(bad); err == nil {
			t.Errorf("AdminListen(%q) accepted, want an error", bad)
		}
	}
}

// The admin API must never be rendered onto TCP: a config that named a TCP
// address — or omitted admin and fell back to Caddy's default — would reopen
// geekdojo-brain#450 on the next push.
func TestRenderCaddyConfig_AdminOnlyOnUnixSocket(t *testing.T) {
	routes := []AppRoute{{AppID: "a1", TailnetFQDN: "a.home1.internal", LANFQDN: "a.lan.home1.internal",
		UpstreamPort: 8096, CertPath: "/c/a1/leaf.pem", KeyPath: "/c/a1/leaf.key"}}
	data, err := RenderCaddyConfig(routes, "100.64.0.2", "192.168.1.2", 443, testAdminSocket)
	if err != nil {
		t.Fatalf("RenderCaddyConfig: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	admin, ok := cfg["admin"].(map[string]any)
	if !ok {
		t.Fatalf("config has no admin block — Caddy would fall back to TCP localhost:2019:\n%s", data)
	}
	if got, want := admin["listen"], "unix/"+testAdminSocket+"|0600"; got != want {
		t.Errorf("admin.listen = %v, want %q", got, want)
	}
	for k := range admin {
		if k != "listen" {
			// disabled/remote/origins/enforce_origin are all deliberate
			// omissions; anything new here needs its own review.
			t.Errorf("unexpected admin key %q", k)
		}
	}
	if strings.Contains(string(data), "2019") {
		t.Errorf("rendered config mentions port 2019:\n%s", data)
	}

	if _, err := RenderCaddyConfig(routes, "100.64.0.2", "", 443, "localhost:2019"); err == nil {
		t.Error("RenderCaddyConfig accepted a TCP admin address")
	}
}

func TestPrepareAdminDir_CreatesPrivateDir(t *testing.T) {
	base := shortTempDir(t)
	sock := filepath.Join(base, "caddy", "admin.sock")
	if err := PrepareAdminDir(sock); err != nil {
		t.Fatalf("PrepareAdminDir: %v", err)
	}
	fi, err := os.Lstat(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("admin dir mode = %s, want a 0700 directory", fi.Mode())
	}
	// Idempotent.
	if err := PrepareAdminDir(sock); err != nil {
		t.Fatalf("second PrepareAdminDir: %v", err)
	}
	// Nothing above the directory is created: a missing parent is an error.
	if err := PrepareAdminDir(filepath.Join(base, "absent", "caddy", "admin.sock")); err == nil {
		t.Error("PrepareAdminDir created a missing parent")
	}
}

func TestPrepareAdminDir_TightensLoosenedDir(t *testing.T) {
	base := shortTempDir(t)
	dir := filepath.Join(base, "caddy")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil { // loosen it past umask
		t.Fatal(err)
	}
	if err := PrepareAdminDir(filepath.Join(dir, "admin.sock")); err != nil {
		t.Fatalf("PrepareAdminDir: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("loosened dir left at %04o, want 0700", uint32(fi.Mode().Perm()))
	}
}

func TestPrepareAdminDir_RefusesSymlinkAndFile(t *testing.T) {
	base := shortTempDir(t)
	target := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "caddy")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := PrepareAdminDir(filepath.Join(link, "admin.sock")); err == nil {
		t.Error("PrepareAdminDir followed a symlinked admin dir, want refusal")
	}

	file := filepath.Join(base, "notadir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareAdminDir(filepath.Join(file, "admin.sock")); err == nil {
		t.Error("PrepareAdminDir accepted a regular file as the admin dir")
	}
}

// A directory another uid owns is refused, not chowned: someone else already
// had a hand in the path. Only root can hand a directory to another uid, so
// this runs where the functional test runs.
func TestPrepareAdminDir_RefusesForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a directory owned by another uid")
	}
	base := shortTempDir(t)
	dir := filepath.Join(base, "caddy")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	err := PrepareAdminDir(filepath.Join(dir, "admin.sock"))
	if err == nil || !strings.Contains(err.Error(), "owned by uid 65534") {
		t.Errorf("PrepareAdminDir on a foreign-owned dir = %v, want an ownership refusal", err)
	}
}

func TestCheckAdminSocket(t *testing.T) {
	base := shortTempDir(t)
	sock := filepath.Join(base, "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if err := os.Chmod(sock, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckAdminSocket(sock); err != nil {
		t.Errorf("0600 socket rejected: %v", err)
	}
	if err := os.Chmod(sock, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := CheckAdminSocket(sock); err == nil || !strings.Contains(err.Error(), "0666") {
		t.Errorf("0666 socket = %v, want a mode error", err)
	}

	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckAdminSocket(file); err == nil {
		t.Error("regular file accepted as the admin socket")
	}
	if err := CheckAdminSocket(filepath.Join(base, "absent")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("absent socket = %v, want not-exist", err)
	}
}

// legacyRenderedConfig is what a pre-#450 agent pushed: today's render with the
// admin block pointed at the TCP address. It reports with t.Error, never
// t.Fatal, because fake servers call it from their handler goroutines.
func legacyRenderedConfig(t *testing.T, addr string, lanAddr string) []byte {
	t.Helper()
	data, err := RenderCaddyConfig(nil, "", lanAddr, 443, testAdminSocket)
	if err != nil {
		t.Error(err)
		return nil
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Error(err)
		return nil
	}
	cfg["admin"] = map[string]any{"listen": addr}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Error(err)
		return nil
	}
	return out
}

func TestIsLegacyAgentConfig(t *testing.T) {
	const legacy = "localhost:2019"
	cases := []struct {
		name string
		cfg  []byte
		want bool
	}{
		{"agent render, no servers", legacyRenderedConfig(t, legacy, ""), true},
		{"agent render, lan server", legacyRenderedConfig(t, legacy, "192.168.1.2"), true},
		{"empty caddy", []byte("null\n"), true},
		{"admin elsewhere", legacyRenderedConfig(t, "localhost:2020", ""), false},
		{"foreign server name", []byte(`{"admin":{"listen":"localhost:2019"},"apps":{"http":{"servers":{"srv0":{}}},"tls":{"certificates":{"load_files":[]}}}}`), false},
		{"no tls app", []byte(`{"admin":{"listen":"localhost:2019"},"apps":{"http":{"servers":{}}}}`), false},
		{"caddyfile-style default admin", []byte(`{"apps":{"http":{"servers":{"srv0":{}}}}}`), false},
		{"not json", []byte("<html>"), false},
		{"nothing", nil, false},
	}
	for _, tc := range cases {
		if got := isLegacyAgentConfig(tc.cfg, legacy); got != tc.want {
			t.Errorf("%s: isLegacyAgentConfig = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// fakeLegacyCaddy serves a legacy admin API over TCP. cfg renders the live
// config from the address the request reached (so an agent-shaped config can
// name the fake's own address as its admin listener). With stopOnRequest it
// shuts itself down after answering POST /stop, as Caddy does.
func fakeLegacyCaddy(t *testing.T, cfg func(addr string) []byte, stopOnRequest bool) (addr string, stops *atomic.Int32) {
	t.Helper()
	stops = new(atomic.Int32)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_, _ = w.Write(cfg(r.Host))
		case r.Method == http.MethodPost && r.URL.Path == "/stop":
			stops.Add(1)
			w.WriteHeader(http.StatusOK)
			if stopOnRequest {
				go srv.Close()
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), stops
}

func legacyTestReconciler(addr string) *Reconciler {
	r := NewReconciler(nil, testAdminSocket, func() string { return "" }, func() string { return "" })
	r.legacyAdmin = addr
	r.legacyStopWait = 5 * time.Second
	return r
}

func TestStopLegacyCaddy_StopsAgentCaddy(t *testing.T) {
	for name, render := range map[string]func(string) []byte{
		"rendered config": func(addr string) []byte { return legacyRenderedConfig(t, addr, "192.168.1.2") },
		"empty caddy":     func(string) []byte { return []byte("null\n") },
	} {
		t.Run(name, func(t *testing.T) {
			addr, stops := fakeLegacyCaddy(t, render, true)
			r := legacyTestReconciler(addr)
			if err := r.stopLegacyCaddy(t.Context()); err != nil {
				t.Fatalf("stopLegacyCaddy: %v", err)
			}
			if n := stops.Load(); n != 1 {
				t.Errorf("legacy caddy got %d /stop requests, want 1", n)
			}
			if _, answers := r.legacyConfig(t.Context()); answers {
				t.Error("legacy admin still answers after stopLegacyCaddy returned nil")
			}
		})
	}
}

func TestStopLegacyCaddy_LeavesForeignCaddyAlone(t *testing.T) {
	addr, stops := fakeLegacyCaddy(t, func(string) []byte {
		return []byte(`{"apps":{"http":{"servers":{"srv0":{}}}}}`)
	}, true)
	r := legacyTestReconciler(addr)
	if err := r.stopLegacyCaddy(t.Context()); err != nil {
		t.Fatalf("stopLegacyCaddy: %v", err)
	}
	if n := stops.Load(); n != 0 {
		t.Errorf("a foreign caddy got %d /stop requests, want 0", n)
	}
}

func TestStopLegacyCaddy_NothingListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if err := legacyTestReconciler(addr).stopLegacyCaddy(t.Context()); err != nil {
		t.Fatalf("stopLegacyCaddy with nothing listening: %v", err)
	}
}

// A legacy Caddy that ignores /stop fails the start attempt: the new Caddy is
// not started beside it, and the supervisor retries.
func TestStopLegacyCaddy_StillAnsweringIsAnError(t *testing.T) {
	addr, stops := fakeLegacyCaddy(t, func(addr string) []byte { return legacyRenderedConfig(t, addr, "") }, false)
	r := legacyTestReconciler(addr)
	r.legacyStopWait = 600 * time.Millisecond
	err := r.stopLegacyCaddy(t.Context())
	if err == nil || !strings.Contains(err.Error(), "still answering") {
		t.Fatalf("stopLegacyCaddy on a Caddy that will not stop = %v, want a still-answering error", err)
	}
	if n := stops.Load(); n != 1 {
		t.Errorf("got %d /stop requests, want 1", n)
	}
}
