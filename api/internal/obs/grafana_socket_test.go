package obs

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// socketSup builds a supervisor with Grafana forced onto a unix socket,
// whatever the host OS is, so the rendered artefacts are asserted on every
// platform CI runs on.
func socketSup(t *testing.T, stateDir string) *DockerComposeSupervisor {
	t.Helper()
	on := true
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:         stateDir,
		UseGrafanaSocket: &on,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	return sup
}

func tcpSup(t *testing.T, stateDir string) *DockerComposeSupervisor {
	t.Helper()
	off := false
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:         stateDir,
		UseGrafanaSocket: &off,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	return sup
}

// The rendered grafana.ini is the artefact that decides whether #453 is
// fixed, so it is asserted directly rather than through the template.
func TestGrafanaIni_SocketMode(t *testing.T) {
	ini, err := socketSup(t, t.TempDir()).renderGrafanaIni()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"\nprotocol = socket\n",
		"socket = " + grafanaContainerSocketPath,
		"socket_mode = 0600",
		"disable_initial_admin_creation = true",
		// auth-proxy itself stays: it is how the api asserts the
		// session's identity. What changed is who can reach it.
		"[auth.proxy]",
		"enabled = true",
		"header_name = X-Webauth-User",
		// The UI's generated URLs must not become socket://… — see the
		// comment in grafanaIniTmpl.
		"root_url = http://%(domain)s/observability/",
		"serve_from_sub_path = true",
	} {
		if !strings.Contains(ini, want) {
			t.Errorf("grafana.ini missing %q\n---\n%s", want, ini)
		}
	}
	for _, unwanted := range []string{
		// No TCP listener at all — not even the in-container port.
		"http_port",
		// The hardcoded credential is gone, and with
		// disable_initial_admin_creation there is no account to hold one.
		"admin_password",
		"rasputin-admin",
		"admin_user",
	} {
		if strings.Contains(ini, unwanted) {
			t.Errorf("grafana.ini still contains %q\n---\n%s", unwanted, ini)
		}
	}
	// whitelist must be present AND empty. A non-empty value 401s every
	// request over a socket (no source IP to match), so a future edit that
	// "hardens" it by filling it in would silently break every dashboard.
	if !strings.Contains(ini, "\nwhitelist =\n") {
		t.Errorf("auth_proxy whitelist must be present and empty\n---\n%s", ini)
	}
}

func TestGrafanaIni_TCPFallbackStillHasNoAdminAccount(t *testing.T) {
	ini, err := tcpSup(t, t.TempDir()).renderGrafanaIni()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(ini, "http_port = 3000") {
		t.Errorf("TCP fallback should keep http_port\n---\n%s", ini)
	}
	// Line-anchored: the template's comments mention the phrase.
	if strings.Contains(ini, "\nprotocol = socket\n") {
		t.Errorf("TCP fallback should not claim socket protocol\n---\n%s", ini)
	}
	// The admin account is gone on every platform — it is not part of the
	// socket switch.
	for _, unwanted := range []string{"admin_password", "rasputin-admin"} {
		if strings.Contains(ini, unwanted) {
			t.Errorf("grafana.ini still contains %q", unwanted)
		}
	}
}

func TestRenderCompose_GrafanaSocketHasNoPublishedPort(t *testing.T) {
	dir := t.TempDir()
	sup := socketSup(t, dir)
	body, err := sup.renderCompose()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, sup.cfg.GrafanaSocketDir+":"+grafanaContainerSocketDir) {
		t.Errorf("compose missing grafana socket mount\n---\n%s", s)
	}
	// 13000 is the old host publish; 3000 is the container port it mapped
	// to. Neither may appear anywhere in the rendered project.
	for _, unwanted := range []string{"13000", ":3000\"", ":3000'"} {
		if strings.Contains(s, unwanted) {
			t.Errorf("compose still publishes grafana (%q)\n---\n%s", unwanted, s)
		}
	}
}

func TestRenderCompose_AlloyIsNeverPublished(t *testing.T) {
	// Both modes: Alloy's publish removal is independent of Grafana's.
	for name, sup := range map[string]*DockerComposeSupervisor{
		"socket": socketSup(t, t.TempDir()),
		"tcp":    tcpSup(t, t.TempDir()),
	} {
		body, err := sup.renderCompose()
		if err != nil {
			t.Fatalf("%s: render: %v", name, err)
		}
		s := string(body)
		if strings.Contains(s, "12345:12345") || strings.Contains(s, "127.0.0.1:12345") {
			t.Errorf("%s: alloy is published to the host\n---\n%s", name, s)
		}
		if !strings.Contains(s, "--server.http.enable-pprof=false") {
			t.Errorf("%s: alloy pprof not disabled\n---\n%s", name, s)
		}
	}
}

func TestRenderCompose_GrafanaContainerUserOnlyWhenNotRoot(t *testing.T) {
	sup := socketSup(t, t.TempDir())
	body, _ := sup.renderCompose()
	s := string(body)
	hasUser := strings.Contains(s, "\n    user: \"")
	if os.Geteuid() == 0 && hasUser {
		t.Error("running as root: grafana must keep the image's own unprivileged user")
	}
	if os.Geteuid() != 0 && !hasUser {
		t.Errorf("running as uid %d: grafana must be pinned to it so it can bind the socket\n---\n%s",
			os.Geteuid(), s)
	}
}

func TestGrafanaBaseURLAndTransport(t *testing.T) {
	sock := socketSup(t, t.TempDir())
	if got, want := sock.GrafanaBaseURL(), "http://"+grafanaSocketHost; got != want {
		t.Errorf("socket GrafanaBaseURL = %q, want %q", got, want)
	}
	if sock.GrafanaTransport() == nil {
		t.Error("socket mode must supply a transport; the URL host does not resolve")
	}
	if !strings.HasSuffix(sock.GrafanaSocketPath(), grafanaSocketFile) {
		t.Errorf("GrafanaSocketPath = %q", sock.GrafanaSocketPath())
	}

	tcp := tcpSup(t, t.TempDir())
	if got := tcp.GrafanaBaseURL(); got != "http://"+defaultGrafanaListenAddr {
		t.Errorf("tcp GrafanaBaseURL = %q", got)
	}
	if tcp.GrafanaTransport() != nil {
		t.Error("tcp mode must use the default transport")
	}
	if tcp.GrafanaSocketPath() != "" {
		t.Errorf("tcp GrafanaSocketPath = %q, want empty", tcp.GrafanaSocketPath())
	}

	off := false
	dis, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:      t.TempDir(),
		EnableGrafana: &off,
	})
	if dis.GrafanaBaseURL() != "" || dis.GrafanaTransport() != nil {
		t.Error("disabled grafana must report neither URL nor transport")
	}
}

// The transport is the only thing that reaches Grafana in socket mode, so it
// is exercised against a real unix listener rather than asserted to be
// non-nil.
func TestUnixTransport_DialsTheSocket(t *testing.T) {
	// NOT t.TempDir(): macOS puts it under /var/folders/... and a unix
	// socket path over ~104 bytes fails to bind, which would turn this
	// into a permanent skip on the platform most of this is written on.
	dir, err := os.MkdirTemp("/tmp", "rsock")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "probe.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sockPath, err)
	}
	srv := &httptest.Server{
		Listener: ln,
		Config: &http.Server{Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "hit "+r.URL.Path)
			})},
	}
	srv.Start()
	defer srv.Close()

	c := &http.Client{Transport: newUnixTransport(sockPath)}
	resp, err := c.Get("http://" + grafanaSocketHost + "/observability/api/health")
	if err != nil {
		t.Fatalf("GET over socket: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "hit /observability/api/health" {
		t.Errorf("body = %q", got)
	}
}

func TestPrepareGrafanaSocketDir_CreatesAndTightens(t *testing.T) {
	sup := socketSup(t, t.TempDir())
	dir := sup.cfg.GrafanaSocketDir

	if err := sup.prepareGrafanaSocketDir(); err != nil {
		t.Fatalf("first prepare: %v", err)
	}
	assertMode(t, dir, 0o700)

	// A loosened directory is re-tightened, not inherited — the whole
	// control is that only one uid can enter it.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := sup.prepareGrafanaSocketDir(); err != nil {
		t.Fatalf("second prepare: %v", err)
	}
	assertMode(t, dir, 0o700)
}

func TestPrepareGrafanaSocketDir_RefusesSymlinkAndFile(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		state := t.TempDir()
		target := filepath.Join(state, "elsewhere")
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(state, "grafana-socket")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		sup := socketSup(t, state)
		err := sup.prepareGrafanaSocketDir()
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("want symlink refusal, got %v", err)
		}
	})
	t.Run("file", func(t *testing.T) {
		state := t.TempDir()
		if err := os.WriteFile(filepath.Join(state, "grafana-socket"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		sup := socketSup(t, state)
		err := sup.prepareGrafanaSocketDir()
		if err == nil {
			t.Fatal("want refusal for a non-directory, got nil")
		}
	})
}

func TestPrepareGrafanaSocketDir_RefusesRelativePath(t *testing.T) {
	on := true
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:         t.TempDir(),
		UseGrafanaSocket: &on,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	// The constructor absolutises it; a later hand-edit must still be
	// refused, because compose reads a relative source as a named volume.
	sup.cfg.GrafanaSocketDir = "grafana-socket"
	if err := sup.prepareGrafanaSocketDir(); err == nil ||
		!strings.Contains(err.Error(), "absolute") {
		t.Fatalf("want absolute-path refusal, got %v", err)
	}
}

// Root can chown, so this is the only place the "wrong owner is corrected"
// branch can run. Skipped as an ordinary user.
func TestPrepareGrafanaSocketDir_ChownsToGrafanaUIDAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	sup := socketSup(t, t.TempDir())
	dir := sup.cfg.GrafanaSocketDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := sup.prepareGrafanaSocketDir(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := fileUID(fi)
	if err != nil {
		t.Fatal(err)
	}
	if uid != grafanaImageUID {
		t.Errorf("socket dir uid = %d, want %d", uid, grafanaImageUID)
	}
}

// Start must prepare the directory before compose runs, not after — a
// directory that only becomes 0700 later has already had a window.
func TestStart_PreparesSocketDirBeforeCompose(t *testing.T) {
	state := t.TempDir()
	on := true
	var sawDirAtCompose os.FileMode
	var dir string
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:         state,
		UseGrafanaSocket: &on,
		HealthTimeout:    1, // fail fast; we only care about ordering
		Runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) > 1 && args[len(args)-1] == "-d" || contains(args, "up") {
				if fi, err := os.Lstat(dir); err == nil {
					sawDirAtCompose = fi.Mode().Perm()
				}
			}
			return []byte("{}"), nil
		},
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	dir = sup.cfg.GrafanaSocketDir
	_ = sup.Start(context.Background()) // health will fail; irrelevant here
	if sawDirAtCompose != 0o700 {
		t.Errorf("socket dir was %#o when compose ran, want 0700", sawDirAtCompose)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s mode = %#o, want %#o", path, got, want)
	}
}

// The placeholder host must never resolve: a caller that forgets the socket
// transport has to fail closed. A bare "grafana" resolved, through a search
// domain, to a host on the internet in the functional test's sandbox — and
// the probe followed it there.
func TestGrafanaSocketHost_NeverResolves(t *testing.T) {
	if !strings.HasSuffix(grafanaSocketHost, ".invalid") {
		t.Fatalf("grafanaSocketHost = %q; it must be under .invalid (RFC 2606) so "+
			"a request that misses the socket transport cannot leave the box",
			grafanaSocketHost)
	}
	u := socketSup(t, t.TempDir()).GrafanaBaseURL()
	if !strings.Contains(u, ".invalid") {
		t.Errorf("GrafanaBaseURL = %q, want the .invalid placeholder", u)
	}
}

// The supervisor's own readiness probe must go through the socket too. This
// is the bug the functional test caught: the probe used the plain TCP client
// and never reached Grafana at all.
func TestGrafanaReady_ProbesOverTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rgr")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, grafanaSocketFile))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Atomic: the handler runs on the server goroutine, and the race
	// detector does not see the socket round trip as a happens-before.
	var hits atomic.Int32
	srv := &httptest.Server{
		Listener: ln,
		Config: &http.Server{Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/health" {
					hits.Add(1)
				}
				w.WriteHeader(http.StatusOK)
			})},
	}
	srv.Start()
	defer srv.Close()

	on := true
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:         t.TempDir(),
		UseGrafanaSocket: &on,
		GrafanaSocketDir: dir,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	ok, err := sup.grafanaReady(context.Background())
	if err != nil || !ok {
		t.Fatalf("grafanaReady over the socket = %v, %v", ok, err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("socket server saw %d /api/health hits, want 1", n)
	}
}

// checkGrafanaSocket is a tripwire (it logs, it never fails a Start), so the
// assertions are on what it logs for each shape the socket path can be in.
func TestCheckGrafanaSocket_Tripwire(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rgt")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	on := true
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:         t.TempDir(),
		UseGrafanaSocket: &on,
		GrafanaSocketDir: dir,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	var buf strings.Builder
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	check := func() string {
		buf.Reset()
		sup.checkGrafanaSocket()
		return buf.String()
	}
	path := sup.GrafanaSocketPath()

	if got := check(); !strings.Contains(got, "no such file") {
		t.Errorf("missing socket: log = %q", got)
	}

	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := check(); !strings.Contains(got, "is not a socket") {
		t.Errorf("regular file: log = %q", got)
	}
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// As root (the CI job) the expected owner is Grafana's uid, not ours.
	if os.Geteuid() == 0 {
		if err := os.Lchown(path, grafanaImageUID, -1); err != nil {
			t.Fatal(err)
		}
	}
	if got := check(); strings.Contains(got, "WARNING") {
		t.Errorf("0600 socket owned by the expected uid: unexpected warning %q", got)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if got := check(); !strings.Contains(got, "is 0666, want 0600") {
		t.Errorf("0666 socket: log = %q", got)
	}
}
