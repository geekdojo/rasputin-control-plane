package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// fakeDocker — programmable CmdRunner that models container state
// ============================================================================

// fakeDocker is a state machine that mimics enough of the docker CLI for
// supervisor tests:
//
//   - Tracks container existence + running/stopped
//   - Tracks whether the image is locally present
//   - Records every CLI invocation (name + args) for assertion
//   - Allows per-command error injection
//
// Tests own the post-condition state explicitly (e.g. "Start should leave
// the container in state=running") which keeps assertions black-box.
type fakeDocker struct {
	mu              sync.Mutex
	imagePresent    bool
	containerExists bool
	containerState  string // "running" | "exited" | "created"
	calls           []dockerCall
	errOnCmd        map[string]error // keyed by first arg (e.g. "pull")
}

type dockerCall struct {
	Name string
	Args []string
}

func newFakeDocker() *fakeDocker {
	return &fakeDocker{errOnCmd: map[string]error{}}
}

func (f *fakeDocker) record(args []string) {
	f.calls = append(f.calls, dockerCall{Name: "docker", Args: append([]string(nil), args...)})
}

func (f *fakeDocker) snapshot() []dockerCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]dockerCall, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeDocker) cmdNames() []string {
	out := []string{}
	for _, c := range f.snapshot() {
		if len(c.Args) > 0 {
			out = append(out, c.Args[0])
		}
	}
	return out
}

func (f *fakeDocker) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(args)
	if len(args) == 0 {
		return nil, errors.New("fakeDocker: empty args")
	}
	if injected, ok := f.errOnCmd[args[0]+"/"+sub(args)]; ok {
		return []byte("injected error"), injected
	}
	if injected, ok := f.errOnCmd[args[0]]; ok {
		return []byte("injected error"), injected
	}
	switch args[0] {
	case "inspect":
		// args: inspect --type container [--format ...] <name>
		if !f.containerExists {
			return []byte("Error: No such object: rasputin-headscale"),
				errors.New("exit status 1")
		}
		// If --format is present, return the formatted value; otherwise
		// return a minimal JSON array shaped like docker inspect.
		for i := 0; i < len(args); i++ {
			if args[i] == "--format" && i+1 < len(args) {
				if args[i+1] == "{{.State.Status}}" {
					return []byte(f.containerState + "\n"), nil
				}
			}
		}
		// Plain inspect (used by ContainerInfo).
		body := fmt.Sprintf(`[{"Name":"/rasputin-headscale","State":{"Status":%q,"StartedAt":"2026-06-01T18:00:00Z"},"Config":{"Image":%q},"NetworkSettings":{"Ports":{"8080/tcp":[{"HostPort":"18080"}]}}}]`,
			f.containerState, defaultImage)
		return []byte(body), nil
	case "image":
		// args: image inspect <ref>
		if len(args) >= 2 && args[1] == "inspect" {
			if f.imagePresent {
				return []byte(`[{"Id":"sha256:abc"}]`), nil
			}
			return []byte("Error: No such image"), errors.New("exit status 1")
		}
	case "pull":
		f.imagePresent = true
		return []byte("Status: Downloaded newer image\n"), nil
	case "run":
		f.containerExists = true
		f.containerState = "running"
		return []byte("0123abc\n"), nil
	case "start":
		if !f.containerExists {
			return nil, errors.New("no such container")
		}
		f.containerState = "running"
		return []byte("rasputin-headscale\n"), nil
	case "stop":
		if !f.containerExists {
			return nil, errors.New("no such container")
		}
		f.containerState = "exited"
		return []byte("rasputin-headscale\n"), nil
	}
	return nil, fmt.Errorf("fakeDocker: unhandled command: %v", args)
}

// sub returns "<second-arg>" for compound commands ("image inspect", etc.)
// so error-injection keys can target sub-commands like "image/inspect".
func sub(args []string) string {
	if len(args) >= 2 {
		return args[1]
	}
	return ""
}

// alwaysHealthy is a dialer that succeeds immediately — short-circuits the
// supervisor's waitHealthy poll when the test doesn't care about TCP.
func alwaysHealthy() func(network, address string, timeout time.Duration) (net.Conn, error) {
	return func(network, address string, timeout time.Duration) (net.Conn, error) {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
}

// alwaysUnhealthy fails every dial — drives waitHealthy through its
// time-out branch.
func alwaysUnhealthy() func(network, address string, timeout time.Duration) (net.Conn, error) {
	return func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
}

func newTestSupervisor(t *testing.T, fd *fakeDocker, opts ...func(*DockerSupervisorConfig)) *DockerSupervisor {
	t.Helper()
	cfg := DockerSupervisorConfig{
		StateDir:      t.TempDir(),
		ListenAddr:    "127.0.0.1:0",
		Runner:        fd.run,
		HealthTimeout: 2 * time.Second,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	s, err := NewDockerSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewDockerSupervisor: %v", err)
	}
	s.dialer = alwaysHealthy()
	return s
}

// ============================================================================
// Constructor + defaults
// ============================================================================

func TestDockerSupervisor_Constructor_RequiresStateDir(t *testing.T) {
	if _, err := NewDockerSupervisor(DockerSupervisorConfig{}); err == nil {
		t.Fatal("expected error for missing StateDir")
	}
}

func TestDockerSupervisor_Constructor_AppliesDefaults(t *testing.T) {
	s, err := NewDockerSupervisor(DockerSupervisorConfig{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDockerSupervisor: %v", err)
	}
	if s.cfg.ContainerName != defaultContainerName {
		t.Errorf("ContainerName: %q", s.cfg.ContainerName)
	}
	if s.cfg.Image != defaultImage {
		t.Errorf("Image: %q", s.cfg.Image)
	}
	if s.cfg.ListenAddr != defaultListenAddr {
		t.Errorf("ListenAddr: %q", s.cfg.ListenAddr)
	}
	// ServerURL is derived from the resolved server host, not a literal
	// "http://0.0.0.0:18080" — the wildcard wouldn't be navigable. Just
	// assert it's non-empty + parses; the exact value depends on the
	// host's network (and may differ in CI vs dev).
	if s.cfg.ServerURL == "" {
		t.Error("ServerURL: empty")
	}
	if !strings.HasPrefix(s.cfg.ServerURL, "http://") {
		t.Errorf("ServerURL: want http:// prefix, got %q", s.cfg.ServerURL)
	}
	if strings.Contains(s.cfg.ServerURL, "0.0.0.0") {
		t.Errorf("ServerURL: 0.0.0.0 leaked into URL: %q", s.cfg.ServerURL)
	}
	if s.cfg.DockerBin != "docker" {
		t.Errorf("DockerBin: %q", s.cfg.DockerBin)
	}
	if s.cfg.HealthTimeout != defaultHealthTimeout || s.cfg.PullTimeout != defaultPullTimeout {
		t.Errorf("timeouts: health=%v pull=%v", s.cfg.HealthTimeout, s.cfg.PullTimeout)
	}
}

func TestResolveServerHost(t *testing.T) {
	// Explicit IP passes through unchanged — operator's choice wins.
	if got := resolveServerHost("127.0.0.1:18080"); got != "127.0.0.1" {
		t.Errorf("loopback should pass through; got %q", got)
	}
	if got := resolveServerHost("192.168.1.10:18080"); got != "192.168.1.10" {
		t.Errorf("specific IP should pass through; got %q", got)
	}
	// Wildcards resolve to something else — exact value depends on host
	// network state, but it must NOT be "0.0.0.0" / "::" / "" (any of
	// those would produce an unnavigable URL).
	for _, listen := range []string{"0.0.0.0:18080", "[::]:18080"} {
		got := resolveServerHost(listen)
		if got == "" || got == "0.0.0.0" || got == "::" {
			t.Errorf("resolveServerHost(%q) must not return wildcard / empty; got %q", listen, got)
		}
	}
}

func TestPortOf(t *testing.T) {
	if got := portOf("127.0.0.1:18080"); got != "18080" {
		t.Errorf("got %q", got)
	}
	if got := portOf("0.0.0.0:9999"); got != "9999" {
		t.Errorf("got %q", got)
	}
	// Malformed → safe default; never blank, never panic.
	if got := portOf("garbage"); got != "18080" {
		t.Errorf("malformed addr should fall back to 18080; got %q", got)
	}
}

// ============================================================================
// Lifecycle
// ============================================================================

func TestDockerSupervisor_Start_CreatesWhenMissing(t *testing.T) {
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got := fd.cmdNames()
	// Expected sequence: inspect (missing) → image inspect (missing) →
	// pull → run. waitHealthy uses dialer, not the runner.
	want := []string{"inspect", "image", "pull", "run"}
	if !equalStringSlices(got, want) {
		t.Errorf("docker calls: got %v want %v", got, want)
	}
	// Config file written?
	if _, err := os.Stat(filepath.Join(s.cfg.StateDir, "config", "config.yaml")); err != nil {
		t.Errorf("config.yaml missing: %v", err)
	}
}

func TestDockerSupervisor_Start_NoPullWhenImagePresent(t *testing.T) {
	fd := newFakeDocker()
	fd.imagePresent = true
	s := newTestSupervisor(t, fd)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for _, c := range fd.snapshot() {
		if len(c.Args) > 0 && c.Args[0] == "pull" {
			t.Errorf("unexpected pull call when image present: %v", c.Args)
		}
	}
}

func TestDockerSupervisor_Start_RestartsWhenStopped(t *testing.T) {
	fd := newFakeDocker()
	fd.imagePresent = true
	fd.containerExists = true
	fd.containerState = "exited"
	s := newTestSupervisor(t, fd)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got := fd.cmdNames()
	// Expected: inspect (exited) → start. No image inspect, no pull, no run.
	want := []string{"inspect", "start"}
	if !equalStringSlices(got, want) {
		t.Errorf("docker calls: got %v want %v", got, want)
	}
}

func TestDockerSupervisor_Start_NoopWhenRunning(t *testing.T) {
	fd := newFakeDocker()
	fd.imagePresent = true
	fd.containerExists = true
	fd.containerState = "running"
	s := newTestSupervisor(t, fd)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got := fd.cmdNames()
	want := []string{"inspect"}
	if !equalStringSlices(got, want) {
		t.Errorf("running case should be inspect-only; got %v", got)
	}
}

func TestDockerSupervisor_Start_RunArgsIncludePortAndMounts(t *testing.T) {
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) {
		c.ListenAddr = "127.0.0.1:19999"
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	var runCall *dockerCall
	for _, c := range fd.snapshot() {
		if len(c.Args) > 0 && c.Args[0] == "run" {
			runCall = &c
			break
		}
	}
	if runCall == nil {
		t.Fatal("no docker run call recorded")
	}
	joined := strings.Join(runCall.Args, " ")
	for _, want := range []string{
		"--name " + defaultContainerName,
		"--restart unless-stopped",
		"-p 127.0.0.1:19999:8080",
		"/etc/headscale:ro",
		"/var/lib/headscale",
		defaultImage,
		"serve",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("run args missing %q: %v", want, runCall.Args)
		}
	}
}

func TestDockerSupervisor_Start_FailsWhenHealthTimesOut(t *testing.T) {
	fd := newFakeDocker()
	fd.imagePresent = true
	fd.containerExists = true
	fd.containerState = "running"
	s := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) {
		c.HealthTimeout = 300 * time.Millisecond
	})
	s.dialer = alwaysUnhealthy()
	start := time.Now()
	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("expected timeout error from Start")
	}
	if !strings.Contains(err.Error(), "not healthy") {
		t.Errorf("error should mention health timeout; got %v", err)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Errorf("waitHealthy returned too quickly: %v", elapsed)
	}
}

func TestDockerSupervisor_Stop_RunningContainer(t *testing.T) {
	fd := newFakeDocker()
	fd.containerExists = true
	fd.containerState = "running"
	s := newTestSupervisor(t, fd)
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	got := fd.cmdNames()
	want := []string{"inspect", "stop"}
	if !equalStringSlices(got, want) {
		t.Errorf("docker calls: got %v want %v", got, want)
	}
}

func TestDockerSupervisor_Stop_NoopWhenStopped(t *testing.T) {
	fd := newFakeDocker()
	fd.containerExists = true
	fd.containerState = "exited"
	s := newTestSupervisor(t, fd)
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for _, c := range fd.snapshot() {
		if len(c.Args) > 0 && c.Args[0] == "stop" {
			t.Errorf("unexpected stop call: %v", c.Args)
		}
	}
}

func TestDockerSupervisor_Stop_MissingContainerIsNoop(t *testing.T) {
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd)
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop on missing container should be a no-op, got %v", err)
	}
}

// ============================================================================
// Healthy
// ============================================================================

func TestDockerSupervisor_Healthy_RunningAndPortOpen(t *testing.T) {
	fd := newFakeDocker()
	fd.containerExists = true
	fd.containerState = "running"
	s := newTestSupervisor(t, fd)
	ok, err := s.Healthy(context.Background())
	if err != nil {
		t.Fatalf("Healthy: %v", err)
	}
	if !ok {
		t.Error("expected healthy=true")
	}
}

func TestDockerSupervisor_Healthy_RunningButPortClosed(t *testing.T) {
	fd := newFakeDocker()
	fd.containerExists = true
	fd.containerState = "running"
	s := newTestSupervisor(t, fd)
	s.dialer = alwaysUnhealthy()
	ok, err := s.Healthy(context.Background())
	if err != nil {
		t.Fatalf("Healthy: %v", err)
	}
	if ok {
		t.Error("expected healthy=false when port refuses connections")
	}
}

func TestDockerSupervisor_Healthy_NotRunning(t *testing.T) {
	fd := newFakeDocker()
	fd.containerExists = true
	fd.containerState = "exited"
	s := newTestSupervisor(t, fd)
	ok, err := s.Healthy(context.Background())
	if err != nil {
		t.Fatalf("Healthy: %v", err)
	}
	if ok {
		t.Error("expected healthy=false when container is exited")
	}
}

func TestDockerSupervisor_Healthy_MissingContainer(t *testing.T) {
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd)
	ok, err := s.Healthy(context.Background())
	if err != nil {
		t.Fatalf("Healthy: %v", err)
	}
	if ok {
		t.Error("expected healthy=false when container is missing")
	}
}

// ============================================================================
// Config rendering
// ============================================================================

// ============================================================================
// TLS / HTTPS mode
// ============================================================================

func TestDockerSupervisor_TLSMode_DefaultsServerURLToHTTPS(t *testing.T) {
	ca, err := EnsureMeshCA(t.TempDir(), "x")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	s, err := NewDockerSupervisor(DockerSupervisorConfig{
		StateDir: t.TempDir(),
		MeshCA:   ca,
	})
	if err != nil {
		t.Fatalf("NewDockerSupervisor: %v", err)
	}
	if !strings.HasPrefix(s.cfg.ServerURL, "https://") {
		t.Errorf("ServerURL should be https:// in TLS mode; got %q", s.cfg.ServerURL)
	}
}

func TestDockerSupervisor_TLSMode_RenderedConfigPointsAtLeaf(t *testing.T) {
	ca, err := EnsureMeshCA(t.TempDir(), "x")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) {
		c.MeshCA = ca
		c.ListenAddr = "127.0.0.1:18080" // pinned so leaf SAN check is deterministic
	})
	body, err := s.renderConfig()
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	rendered := string(body)
	if !strings.Contains(rendered, `tls_cert_path: "/etc/headscale-certs/leaf.pem"`) {
		t.Errorf("config missing tls_cert_path; got:\n%s", rendered)
	}
	if !strings.Contains(rendered, `tls_key_path: "/etc/headscale-certs/leaf.key"`) {
		t.Errorf("config missing tls_key_path; got:\n%s", rendered)
	}
}

func TestDockerSupervisor_TLSMode_StartMintsLeafAndMountsIt(t *testing.T) {
	ca, err := EnsureMeshCA(t.TempDir(), "x")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) {
		c.MeshCA = ca
		c.ListenAddr = "127.0.0.1:18080"
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Leaf files written under <state>/certs.
	certPath := filepath.Join(s.cfg.StateDir, "certs", "leaf.pem")
	keyPath := filepath.Join(s.cfg.StateDir, "certs", "leaf.key")
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("leaf cert not minted: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("leaf key not minted: %v", err)
	}
	// docker run args include the certs bind mount.
	var runCall *dockerCall
	for _, c := range fd.snapshot() {
		if len(c.Args) > 0 && c.Args[0] == "run" {
			rc := c
			runCall = &rc
			break
		}
	}
	if runCall == nil {
		t.Fatal("no docker run call")
	}
	if !strings.Contains(strings.Join(runCall.Args, " "), "/etc/headscale-certs:ro") {
		t.Errorf("run args missing certs mount: %v", runCall.Args)
	}
}

// HTTP mode (no MeshCA) must NOT touch the certs dir or render TLS
// paths — keeps the bring-up / test path lightweight.
func TestDockerSupervisor_HTTPMode_NoLeafNoMount(t *testing.T) {
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd) // MeshCA nil by default
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.cfg.StateDir, "certs")); err == nil {
		t.Error("certs dir was created in HTTP mode (should be skipped)")
	}
	for _, c := range fd.snapshot() {
		if len(c.Args) > 0 && c.Args[0] == "run" {
			joined := strings.Join(c.Args, " ")
			if strings.Contains(joined, "headscale-certs") {
				t.Errorf("HTTP-mode run args leaked TLS mount: %v", c.Args)
			}
		}
	}
	body, err := s.renderConfig()
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if !strings.Contains(string(body), `tls_cert_path: ""`) {
		t.Errorf("HTTP-mode config should have empty tls_cert_path; got:\n%s", body)
	}
}

func TestDockerSupervisor_RenderConfig_IncludesKeyFields(t *testing.T) {
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) {
		c.ServerURL = "http://mesh.rasputin.local:18080"
		c.ListenAddr = "127.0.0.1:18080"
	})
	body, err := s.renderConfig()
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	got := string(body)
	for _, want := range []string{
		"server_url: http://mesh.rasputin.local:18080",
		"listen_addr: 0.0.0.0:8080", // bound inside the container
		"/var/lib/headscale/noise_private.key",
		"/var/lib/headscale/db.sqlite",
		"magic_dns: false",
		"disable_check_updates: true",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered config missing %q\n---\n%s", want, got)
		}
	}
}

// Surprise-net: if the operator stops and restarts Rasputin while the
// container is still running externally, Start must NOT touch it
// destructively. We rely on writeConfig being safe to re-execute (atomic
// rename) and on inspect short-circuiting to no-op.
func TestDockerSupervisor_Start_DoesNotDestroyExistingState(t *testing.T) {
	fd := newFakeDocker()
	fd.imagePresent = true
	fd.containerExists = true
	fd.containerState = "running"
	s := newTestSupervisor(t, fd)
	// Seed an existing config.yaml that's "newer" than the template
	// would produce; Start should still overwrite (idempotent), but it
	// MUST NOT touch the data dir.
	if err := os.MkdirAll(filepath.Join(s.cfg.StateDir, "data"), 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	canary := filepath.Join(s.cfg.StateDir, "data", "db.sqlite")
	if err := os.WriteFile(canary, []byte("DO NOT DELETE"), 0o644); err != nil {
		t.Fatalf("seed canary: %v", err)
	}

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got, err := os.ReadFile(canary)
	if err != nil {
		t.Fatalf("read canary: %v", err)
	}
	if string(got) != "DO NOT DELETE" {
		t.Errorf("supervisor touched data dir: %q", got)
	}
}

// ============================================================================
// inspect parsing
// ============================================================================

func TestDockerSupervisor_Inspect_DistinguishesMissing(t *testing.T) {
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd)
	state, err := s.inspect(context.Background())
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if state != containerMissing {
		t.Errorf("state: got %v want containerMissing", state)
	}
}

func TestDockerSupervisor_Inspect_ExitedTreatedAsStopped(t *testing.T) {
	fd := newFakeDocker()
	fd.containerExists = true
	fd.containerState = "exited"
	s := newTestSupervisor(t, fd)
	state, err := s.inspect(context.Background())
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if state != containerStopped {
		t.Errorf("state: got %v want containerStopped", state)
	}
}

// ============================================================================
// ContainerInfo
// ============================================================================

func TestDockerSupervisor_ContainerInfo(t *testing.T) {
	fd := newFakeDocker()
	fd.containerExists = true
	fd.containerState = "running"
	s := newTestSupervisor(t, fd)
	info, err := s.ContainerInfo(context.Background())
	if err != nil {
		t.Fatalf("ContainerInfo: %v", err)
	}
	if info.Name != "rasputin-headscale" {
		t.Errorf("Name: %q", info.Name)
	}
	if info.Status != "running" {
		t.Errorf("Status: %q", info.Status)
	}
	if !strings.Contains(info.Ports, "18080→8080/tcp") {
		t.Errorf("Ports: %q", info.Ports)
	}
	if info.Image != defaultImage {
		t.Errorf("Image: %q", info.Image)
	}
}

// ============================================================================
// Concurrency sanity — Start under context cancel returns the ctx error
// ============================================================================

func TestDockerSupervisor_Start_RespectsContextCancellation(t *testing.T) {
	fd := newFakeDocker()
	fd.imagePresent = true
	fd.containerExists = true
	fd.containerState = "running"
	s := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) {
		c.HealthTimeout = 10 * time.Second
	})
	s.dialer = alwaysUnhealthy()
	ctx, cancel := context.WithCancel(context.Background())
	var got atomic.Pointer[error]
	done := make(chan struct{})
	go func() {
		err := s.Start(ctx)
		got.Store(&err)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
	if got.Load() == nil || !errors.Is(*got.Load(), context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", got.Load())
	}
}

// ============================================================================
// helpers
// ============================================================================

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
