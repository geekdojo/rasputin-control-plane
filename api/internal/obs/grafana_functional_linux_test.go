//go:build linux

// Functional test for geekdojo-brain#453 against the real, pinned Grafana
// image. It drives the supervisor — not a hand-rolled container — so what it
// proves is what an appliance runs.
//
// It answers the three questions the issue's acceptance criteria ask, as
// behaviour rather than as configuration:
//
//  1. Does the OLD published port actually go away on an existing cluster
//     that updates? (TestGrafanaSocket_TransitionFromPublishedPort)
//  2. Can a caller that is not the socket's owner reach Grafana at all — by
//     any X-Webauth-User value, including `admin`?
//  3. Do the api's dashboards still work over the socket?
//
// Requires Linux + a working docker. Skipped otherwise, unless
// RASPUTIN_GRAFANA_FUNCTIONAL=required, which turns every skip into a
// failure — that is what CI sets, so the test can never quietly stop running.
// Same shape as the agent's caddy_functional_linux_test.go (PR #329).

package obs

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	grafanaFuncProject   = "rasputin-obs-grafanafunc"
	grafanaFuncContainer = "rasputin-grafana"
	// A port nothing else on a runner is likely to hold, used for the
	// "before" half of the transition test.
	grafanaFuncLegacyAddr = "127.0.0.1:19313"
	// funcCurlImage speaks HTTP over a unix socket (busybox nc cannot: no
	// -U). Pinned, and pre-pulled by the CI job.
	funcCurlImage = "curlimages/curl:8.11.1"
)

// funcRequired reports whether skips must become failures.
func funcRequired() bool {
	return os.Getenv("RASPUTIN_GRAFANA_FUNCTIONAL") == "required"
}

func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if funcRequired() {
		t.Fatalf("RASPUTIN_GRAFANA_FUNCTIONAL=required but "+format, args...)
	}
	t.Skipf(format, args...)
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		skipOrFail(t, "docker not on PATH: %v", err)
	}
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput()
	if err != nil {
		skipOrFail(t, "docker daemon unreachable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
}

// grafanaFuncSupervisor builds a Grafana-only obs stack: VM stays (the
// supervisor's health gate polls it) but Loki, vmalert and cAdvisor are off
// so the test is about Grafana and starts in well under a minute.
func grafanaFuncSupervisor(t *testing.T, stateDir string, socket bool) *DockerComposeSupervisor {
	t.Helper()
	off := false
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:     stateDir,
		ProjectName:  grafanaFuncProject,
		VMListenAddr: "127.0.0.1:19314",
		// The legacy publish, used only by the "before" half of the
		// transition test. Ignored entirely in socket mode.
		GrafanaListenAddr: grafanaFuncLegacyAddr,
		UseGrafanaSocket:  &socket,
		EnableLoki:        &off,
		EnableVMAlert:     &off,
		EnableCadvisor:    &off,
		HealthTimeout:     150 * time.Second,
		PullTimeout:       5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	return sup
}

// funcStateDir returns a SHORT absolute state dir. t.TempDir() is fine on
// Linux, but the socket path has to stay under the ~104-byte sun_path limit
// once the test name is in it, so this keeps the prefix tiny.
func funcStateDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rgf")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func composeDown() {
	_ = exec.Command("docker", "compose", "-p", grafanaFuncProject, "down", "-v",
		"--remove-orphans").Run()
}

// grafanaGet issues a request through whatever transport the supervisor says
// reaches Grafana — the socket on Linux — and returns status and body.
func grafanaGet(t *testing.T, sup *DockerComposeSupervisor, path, webauthUser string) (int, string) {
	t.Helper()
	c := &http.Client{Timeout: 15 * time.Second}
	if tr := sup.GrafanaTransport(); tr != nil {
		c.Transport = tr
	}
	req, err := http.NewRequest(http.MethodGet, sup.GrafanaBaseURL()+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if webauthUser != "" {
		req.Header.Set("X-Webauth-User", webauthUser)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// dialAsUID tries to reach Grafana through the socket from inside a throwaway
// container running as uid, with the socket directory bind-mounted. It
// returns nil only when Grafana answered. A host-network container cannot
// reach a unix socket at all, so this is the STRONGER test: it grants the
// caller the filesystem too and it still must be refused by permissions
// alone. It sends `X-Webauth-User: admin` — the worst value #453 named — so
// a refusal is a refusal of exactly the bypass.
func dialAsUID(uid int, sockDir string) error {
	cmd := exec.Command("docker", "run", "--rm",
		"--user", fmt.Sprintf("%d:%d", uid, uid),
		"-v", sockDir+":/sock",
		funcCurlImage,
		"-sS", "-o", "/dev/null", "-w", "%{http_code}",
		"--max-time", "10",
		"--unix-socket", "/sock/"+grafanaSocketFile,
		"-H", "X-Webauth-User: admin",
		"http://"+grafanaSocketHost+"/observability/api/user")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	if code := strings.TrimSpace(string(out)); code != "200" {
		return fmt.Errorf("connected but got HTTP %s", code)
	}
	return nil
}

// containerTCPListeners returns the listening TCP sockets HELD BY A PROCESS
// INSIDE the container. Reading /proc/net/tcp alone is not enough: on a
// compose network Docker's embedded DNS resolver listens on 127.0.0.11 in
// every container's network namespace, but the socket belongs to dockerd,
// outside the container. Matching LISTEN inodes against the container's own
// /proc/*/fd is what "Grafana has no TCP listener" actually means.
func containerTCPListeners(t *testing.T, container string) []string {
	t.Helper()
	netOut, err := exec.Command("docker", "exec", container,
		"sh", "-c", "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null").CombinedOutput()
	if err != nil {
		t.Fatalf("read /proc/net/tcp: %v (%s)", err, netOut)
	}
	listenByInode := map[string]string{}
	for _, line := range strings.Split(string(netOut), "\n") {
		f := strings.Fields(line)
		// sl local rem st tx:rx tr:when retrnsmt uid timeout inode
		if len(f) > 9 && f[3] == "0A" { // 0A == TCP_LISTEN
			listenByInode[f[9]] = strings.TrimSpace(line)
		}
	}
	fdOut, err := exec.Command("docker", "exec", container, "sh", "-c",
		`for f in /proc/[0-9]*/fd/*; do readlink "$f"; done 2>/dev/null`).CombinedOutput()
	if err != nil && len(fdOut) == 0 {
		t.Fatalf("list container fds: %v", err)
	}
	var held []string
	for _, l := range strings.Split(string(fdOut), "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")
		if row, ok := listenByInode[inode]; ok {
			held = append(held, row)
			delete(listenByInode, inode)
		}
	}
	for _, row := range listenByInode {
		t.Logf("ignoring a TCP listener no container process holds (Docker's "+
			"embedded DNS on 127.0.0.11 is expected): %s", row)
	}
	return held
}

// waitForStarterDashboard polls until the provisioned starter dashboard is
// searchable, with a hard deadline. Grafana answers /api/health before its
// file provisioner has indexed the dashboards, so a single read straight
// after Start can see `[]` (observed: 1 run in 5). What is under test is that
// provisioning still happens over the socket — an eventual property — not
// that it has happened by an arbitrary instant.
func waitForStarterDashboard(t *testing.T, sup *DockerComposeSupervisor, user string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var code int
	var body string
	for {
		code, body = grafanaGet(t, sup, "/api/search?type=dash-db", user)
		if code == http.StatusOK && strings.Contains(body, "Cluster Overview") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("starter dashboard not searchable after 60s: %d %s", code, body)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestGrafanaSocket_TransitionFromPublishedPort is the zero-touch proof: an
// existing cluster that is serving Grafana on the old published port
// converges to the socket on the next Start, with nothing done by hand, and
// the old port stops answering.
func TestGrafanaSocket_TransitionFromPublishedPort(t *testing.T) {
	requireDocker(t)
	stateDir := funcStateDir(t)
	composeDown()
	t.Cleanup(composeDown)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// --- BEFORE: today's shape, Grafana published on a host port.
	before := grafanaFuncSupervisor(t, stateDir, false)
	if err := before.Start(ctx); err != nil {
		t.Fatalf("start (published-port shape): %v", err)
	}
	code, _ := grafanaGet(t, before, "/api/health", "")
	if code != http.StatusOK {
		t.Fatalf("published-port Grafana /api/health = %d, want 200", code)
	}
	// This is the bug, reproduced against the shipped image: no
	// credential, one header, authenticated.
	code, body := grafanaGet(t, before, "/api/user", "mallory-not-an-account")
	if code != http.StatusOK {
		t.Fatalf("precondition failed: the bypass should exist on the old shape, got %d", code)
	}
	if !strings.Contains(body, "mallory-not-an-account") {
		t.Fatalf("precondition failed: expected an auto-created account, got %s", body)
	}
	// Positive control for the listener check used after the transition:
	// on the old shape Grafana DOES hold a TCP listener, so an empty
	// answer later means "gone", not "the check cannot see".
	if len(containerTCPListeners(t, grafanaFuncContainer)) == 0 {
		t.Fatal("positive control failed: published-port Grafana holds no TCP " +
			"listener, so the no-listener assertion below would prove nothing")
	}

	// --- AFTER: the same state dir and project, started by the new code.
	// No manual step in between — this is exactly what an api restart
	// after an A/B update does.
	after := grafanaFuncSupervisor(t, stateDir, true)
	if err := after.Start(ctx); err != nil {
		t.Fatalf("start (socket shape): %v", err)
	}

	t.Run("old port is gone", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", grafanaFuncLegacyAddr, 3*time.Second)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("%s still answers after the transition", grafanaFuncLegacyAddr)
		}
	})

	t.Run("container publishes nothing", func(t *testing.T) {
		out, err := exec.Command("docker", "inspect", "--format",
			"{{json .NetworkSettings.Ports}}", grafanaFuncContainer).CombinedOutput()
		if err != nil {
			t.Fatalf("docker inspect: %v (%s)", err, out)
		}
		if got := strings.TrimSpace(string(out)); strings.Contains(got, "HostPort") {
			t.Errorf("grafana still publishes a port: %s", got)
		}
	})

	t.Run("container has no TCP listener at all", func(t *testing.T) {
		for _, row := range containerTCPListeners(t, grafanaFuncContainer) {
			t.Errorf("grafana holds a listening TCP socket: %s", row)
		}
	})

	t.Run("socket and directory permissions", func(t *testing.T) {
		dir := after.cfg.GrafanaSocketDir
		assertMode(t, dir, 0o700)
		fi, err := os.Lstat(after.GrafanaSocketPath())
		if err != nil {
			t.Fatalf("stat socket: %v", err)
		}
		if fi.Mode()&os.ModeSocket == 0 {
			t.Fatalf("%s is not a socket (%v)", after.GrafanaSocketPath(), fi.Mode())
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("socket mode = %#o, want 0600", got)
		}
		uid, err := fileUID(fi)
		if err != nil {
			t.Fatalf("socket owner: %v", err)
		}
		if want := after.grafanaSocketOwnerUID(); uid != want {
			t.Errorf("socket uid = %d, want %d", uid, want)
		}
	})

	t.Run("the api's dashboards still work", func(t *testing.T) {
		if code, _ := grafanaGet(t, after, "/api/health", ""); code != http.StatusOK {
			t.Fatalf("/api/health over the socket = %d", code)
		}
		// No header: still refused. The socket says who may call; the
		// header still says who they are.
		if code, _ := grafanaGet(t, after, "/api/user", ""); code != http.StatusUnauthorized {
			t.Errorf("/api/user with no header = %d, want 401", code)
		}
		waitForStarterDashboard(t, after, "alice")
		// The provisioned datasources survived the switch.
		code, body := grafanaGet(t, after, "/api/datasources", "alice")
		// A Viewer cannot list datasources (403) — that is expected and
		// is not what this asserts; it asserts Grafana answers rather
		// than failing to route.
		if code != http.StatusOK && code != http.StatusForbidden {
			t.Errorf("/api/datasources = %d body=%s", code, body)
		}
	})

	t.Run("naming admin no longer yields server admin", func(t *testing.T) {
		code, body := grafanaGet(t, after, "/api/user", "admin")
		if code != http.StatusOK {
			t.Fatalf("/api/user as admin = %d", code)
		}
		if strings.Contains(body, `"isGrafanaAdmin":true`) {
			t.Errorf("admin is still a Grafana server admin: %s", body)
		}
		if code, _ := grafanaGet(t, after, "/api/admin/settings", "admin"); code == http.StatusOK {
			t.Error("/api/admin/settings answered 200 to the header value admin")
		}
	})

	t.Run("a non-owner cannot reach it, by any header value", func(t *testing.T) {
		dir := after.cfg.GrafanaSocketDir
		owner := after.grafanaSocketOwnerUID()
		stranger := 65534
		if owner == stranger {
			stranger = 65533
		}
		if err := dialAsUID(stranger, dir); err == nil {
			t.Fatalf("uid %d reached the socket through a 0700 directory", stranger)
		}
		// And with the directory deliberately opened up, the 0600 socket
		// alone still holds — so the refusal above is not resting on one
		// control.
		if err := os.Chmod(dir, 0o711); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		if err := dialAsUID(stranger, dir); err == nil {
			t.Fatalf("uid %d reached the socket with the directory at 0711", stranger)
		}
		// Positive control: the owning uid gets in through the same
		// helper, so the two refusals above are permissions and not a
		// broken harness.
		if err := dialAsUID(owner, dir); err != nil {
			t.Fatalf("positive control failed — uid %d could not reach the socket: %v",
				owner, err)
		}
	})

	t.Run("a restart re-tightens a loosened directory", func(t *testing.T) {
		dir := after.cfg.GrafanaSocketDir
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if err := after.Start(ctx); err != nil {
			t.Fatalf("re-Start: %v", err)
		}
		assertMode(t, dir, 0o700)
		if code, _ := grafanaGet(t, after, "/api/health", ""); code != http.StatusOK {
			t.Errorf("/api/health after re-Start = %d", code)
		}
	})
}

// TestGrafanaSocket_FreshInstall is the other half of zero-touch: a node that
// has never run the obs stack comes up on the socket directly, with no
// published-port phase in between.
func TestGrafanaSocket_FreshInstall(t *testing.T) {
	requireDocker(t)
	stateDir := funcStateDir(t)
	composeDown()
	t.Cleanup(composeDown)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	sup := grafanaFuncSupervisor(t, stateDir, true)
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(sup.cfg.GrafanaSocketDir, grafanaSocketFile)); err != nil {
		t.Fatalf("socket not created: %v", err)
	}
	conn, err := net.DialTimeout("tcp", grafanaFuncLegacyAddr, 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Errorf("a fresh install published %s", grafanaFuncLegacyAddr)
	}
	waitForStarterDashboard(t, sup, "alice")
}
