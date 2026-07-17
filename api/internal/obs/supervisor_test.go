package obs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// ============================================================================
// fakeCompose — programmable CmdRunner for the docker-compose supervisor
// ============================================================================

// fakeCompose records every `docker compose ...` invocation and lets a
// test inject errors per subcommand (the verb that appears AFTER `-p
// <project> -f <file>`).
type fakeCompose struct {
	mu       sync.Mutex
	calls    [][]string
	errOnSub map[string]error
}

func newFakeCompose() *fakeCompose {
	return &fakeCompose{errOnSub: map[string]error{}}
}

func (f *fakeCompose) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	full := append([]string{name}, args...)
	f.calls = append(f.calls, append([]string(nil), full...))
	// Expect: docker compose -p <project> -f <path> <verb> [...]
	verb := ""
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-f" {
			if i+2 < len(args) {
				verb = args[i+2]
			}
			break
		}
	}
	if err, ok := f.errOnSub[verb]; ok && err != nil {
		return []byte("injected"), err
	}
	return []byte("ok"), nil
}

func (f *fakeCompose) subcommands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		for i := 0; i < len(c)-1; i++ {
			if c[i] == "-f" && i+2 < len(c) {
				out = append(out, c[i+2])
				break
			}
		}
	}
	return out
}

// ============================================================================
// stubVM — minimal /health server that flips healthy after N calls
// ============================================================================

// stubVM responds 200 on /health after `becomeHealthyAfter` calls,
// 503 before. Models VictoriaMetrics' boot window where /health is
// answering but not yet ready.
type stubVM struct {
	mu                 sync.Mutex
	healthCalls        int
	becomeHealthyAfter int
	importCalls        atomic.Int32
	lastImportBody     atomic.Value // string
	importStatus       atomic.Int32 // overridable; 0 → 204
}

func newStubVM() *stubVM { return &stubVM{} }

func (v *stubVM) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		v.mu.Lock()
		v.healthCalls++
		ok := v.healthCalls > v.becomeHealthyAfter
		v.mu.Unlock()
		if ok {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/api/v1/import/prometheus", func(w http.ResponseWriter, r *http.Request) {
		v.importCalls.Add(1)
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		v.lastImportBody.Store(string(buf[:n]))
		status := int(v.importStatus.Load())
		if status == 0 {
			status = http.StatusNoContent
		}
		w.WriteHeader(status)
	})
	return mux
}

// ============================================================================
// DockerComposeSupervisor tests
// ============================================================================

func TestNewDockerComposeSupervisor_RequiresStateDir(t *testing.T) {
	if _, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{}); err == nil {
		t.Fatal("expected error when StateDir empty")
	}
}

func TestNewDockerComposeSupervisor_AppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: dir})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	if got, want := sup.cfg.ProjectName, defaultProjectName; got != want {
		t.Errorf("ProjectName = %q, want %q", got, want)
	}
	if got, want := sup.cfg.VMImage, defaultVMImage; got != want {
		t.Errorf("VMImage = %q, want %q", got, want)
	}
	if got, want := sup.cfg.VMListenAddr, defaultVMListenAddr; got != want {
		t.Errorf("VMListenAddr = %q, want %q", got, want)
	}
	if sup.cfg.HealthTimeout != defaultHealthTimeout {
		t.Errorf("HealthTimeout = %v, want %v", sup.cfg.HealthTimeout, defaultHealthTimeout)
	}
}

func TestStart_HappyPath(t *testing.T) {
	vm := newStubVM()
	srv := httptest.NewServer(vm.handler())
	defer srv.Close()

	dir := t.TempDir()
	fake := newFakeCompose()
	host, port := splitHostPort(t, srv.URL)
	f := false
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:      dir,
		VMListenAddr:  host + ":" + port,
		Runner:        fake.run,
		HTTPClient:    srv.Client(),
		HealthTimeout: 2 * time.Second,
		PullTimeout:   time.Second,
		EnableLoki:    &f, // unit tests don't stub Loki; gated off
		EnableGrafana: &f, // same — no Grafana stub here
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Compose file exists.
	if _, err := os.Stat(filepath.Join(dir, composeFileName)); err != nil {
		t.Fatalf("compose file: %v", err)
	}
	// VM data dir exists.
	if _, err := os.Stat(filepath.Join(dir, vmDataDir)); err != nil {
		t.Fatalf("vm data dir: %v", err)
	}
	// We called pull then up.
	subs := fake.subcommands()
	if len(subs) < 2 || subs[0] != "pull" || subs[1] != "up" {
		t.Fatalf("unexpected subcommands: %v", subs)
	}
}

func TestStart_PullFailureIsRecoverable(t *testing.T) {
	vm := newStubVM()
	srv := httptest.NewServer(vm.handler())
	defer srv.Close()

	dir := t.TempDir()
	fake := newFakeCompose()
	// pull errors → we should continue to `up` anyway (image may be cached).
	fake.errOnSub["pull"] = errors.New("registry unreachable")

	host, port := splitHostPort(t, srv.URL)
	f := false
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:      dir,
		VMListenAddr:  host + ":" + port,
		Runner:        fake.run,
		HTTPClient:    srv.Client(),
		HealthTimeout: 2 * time.Second,
		PullTimeout:   time.Second,
		EnableLoki:    &f,
		EnableGrafana: &f,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start tolerated pull failure but Start itself failed: %v", err)
	}
	subs := fake.subcommands()
	hasUp := false
	for _, s := range subs {
		if s == "up" {
			hasUp = true
		}
	}
	if !hasUp {
		t.Fatalf("expected `up` after failed `pull`, got %v", subs)
	}
}

func TestStart_UpFailurePropagates(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeCompose()
	fake.errOnSub["up"] = errors.New("compose error")

	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir: dir,
		Runner:   fake.run,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if err := sup.Start(context.Background()); err == nil {
		t.Fatal("expected Start to fail when `compose up` fails")
	}
}

func TestStart_HealthTimeout(t *testing.T) {
	vm := newStubVM()
	vm.becomeHealthyAfter = 1000 // never within the test window
	srv := httptest.NewServer(vm.handler())
	defer srv.Close()

	dir := t.TempDir()
	fake := newFakeCompose()
	host, port := splitHostPort(t, srv.URL)
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:      dir,
		VMListenAddr:  host + ":" + port,
		Runner:        fake.run,
		HTTPClient:    srv.Client(),
		HealthTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	err = sup.Start(context.Background())
	if err == nil {
		t.Fatal("expected health-timeout error")
	}
	if !strings.Contains(err.Error(), "not healthy") {
		t.Fatalf("error should mention `not healthy`, got: %v", err)
	}
}

func TestStop_InvokesComposeStop(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeCompose()
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir: dir, Runner: fake.run,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if err := sup.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if subs := fake.subcommands(); len(subs) != 1 || subs[0] != "stop" {
		t.Fatalf("expected single `stop` call, got %v", subs)
	}
}

func TestHealthy(t *testing.T) {
	vm := newStubVM()
	srv := httptest.NewServer(vm.handler())
	defer srv.Close()

	dir := t.TempDir()
	host, port := splitHostPort(t, srv.URL)
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:     dir,
		VMListenAddr: host + ":" + port,
		Runner:       newFakeCompose().run,
		HTTPClient:   srv.Client(),
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	ok, err := sup.Healthy(context.Background())
	if err != nil {
		t.Fatalf("Healthy err: %v", err)
	}
	if !ok {
		t.Fatal("expected Healthy=true against stub returning 200")
	}
}

func TestRenderCompose_ContainsExpectedServices(t *testing.T) {
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:    t.TempDir(),
		VMRetention: "30d",
	})
	body, err := sup.renderCompose()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(body)
	for _, want := range []string{
		"services:",
		"victoriametrics:",
		defaultVMImage,
		"-storageDataPath=/storage",
		"-retentionPeriod=30d",
		"-search.latencyOffset=0s",
		"127.0.0.1:8428:8428",
		"./vm-data:/storage",
		"alloy:",
		defaultAlloyImage,
		"127.0.0.1:12345:12345",
		"./alloy-config:/etc/alloy:ro",
		"/var/run/docker.sock:/var/run/docker.sock:ro",
		"depends_on:",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("compose missing %q\n--- compose ---\n%s", want, s)
		}
	}
}

func TestRenderCompose_CadvisorDisabledOmitsMounts(t *testing.T) {
	f := false
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:       t.TempDir(),
		EnableCadvisor: &f,
	})
	body, _ := sup.renderCompose()
	s := string(body)
	if strings.Contains(s, "/var/run/docker.sock") {
		t.Error("docker socket mount should be absent when cadvisor disabled")
	}
	if strings.Contains(s, "/sys:/sys") {
		t.Error("/sys mount should be absent when cadvisor disabled")
	}
}

func TestRenderAlloyConfig_DefaultIncludesCadvisor(t *testing.T) {
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: t.TempDir()})
	body, err := sup.renderAlloyConfig()
	if err != nil {
		t.Fatalf("render alloy: %v", err)
	}
	s := string(body)
	for _, want := range []string{
		`prometheus.remote_write "vm"`,
		`url = "http://victoriametrics:8428/api/v1/write"`,
		`prometheus.exporter.self "alloy"`,
		`prometheus.exporter.cadvisor "containers"`,
		`docker_only = true`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("alloy config missing %q\n--- alloy ---\n%s", want, s)
		}
	}
}

func TestRenderAlloyConfig_CadvisorDisabled(t *testing.T) {
	f := false
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:       t.TempDir(),
		EnableCadvisor: &f,
	})
	body, _ := sup.renderAlloyConfig()
	if strings.Contains(string(body), "cadvisor") {
		t.Errorf("cadvisor component should be absent\n%s", body)
	}
}

func TestRenderCompose_IDSMountPresentWhenEnabled(t *testing.T) {
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:  t.TempDir(),
		IDSLogDir: "/var/lib/rasputin/obs/ids-alerts",
	})
	body, err := sup.renderCompose()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "/var/lib/rasputin/obs/ids-alerts:/var/log/rasputin:ro") {
		t.Errorf("compose missing IDS log mount\n--- compose ---\n%s", s)
	}
}

func TestRenderCompose_IDSMountAbsentWithoutLogDir(t *testing.T) {
	// IDSLogDir empty (the default) → no mount, even if EnableIDSPipe is
	// explicitly true. The pipe is meaningless without a source path.
	tr := true
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:      t.TempDir(),
		EnableIDSPipe: &tr,
	})
	body, _ := sup.renderCompose()
	if strings.Contains(string(body), "/var/log/rasputin:ro") {
		t.Errorf("compose should NOT have IDS mount when IDSLogDir empty\n%s", body)
	}
}

func TestRenderAlloyConfig_IDSPipePresentWhenEnabled(t *testing.T) {
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:  t.TempDir(),
		IDSLogDir: "/var/lib/rasputin/obs/ids-alerts",
	})
	body, err := sup.renderAlloyConfig()
	if err != nil {
		t.Fatalf("render alloy: %v", err)
	}
	s := string(body)
	for _, want := range []string{
		`loki.source.file "ids_alerts"`,
		`"__path__" = "/var/log/rasputin/alerts.jsonl"`,
		`"job" = "rasputin-ids"`,
		`loki.process "ids_alerts"`,
		`nodeId = "nodeId"`,
		`node_id = "nodeId"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("alloy config missing IDS-pipe fragment %q\n--- alloy ---\n%s", want, s)
		}
	}
}

func TestRenderAlloyConfig_IDSPipeAbsentWhenLokiOff(t *testing.T) {
	// EnableIDSPipe defaults on when Loki is on AND IDSLogDir is set.
	// Forcing Loki off must also turn the IDS pipe off — Alloy can't
	// write to a non-running Loki.
	f := false
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:   t.TempDir(),
		EnableLoki: &f,
		IDSLogDir:  "/var/lib/rasputin/obs/ids-alerts",
	})
	body, _ := sup.renderAlloyConfig()
	if strings.Contains(string(body), "ids_alerts") {
		t.Errorf("IDS pipe should be off when Loki is off\n%s", body)
	}
}

func TestStart_WritesAlloyConfig(t *testing.T) {
	vm := newStubVM()
	srv := httptest.NewServer(vm.handler())
	defer srv.Close()
	dir := t.TempDir()
	host, port := splitHostPort(t, srv.URL)
	f := false
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:      dir,
		VMListenAddr:  host + ":" + port,
		Runner:        newFakeCompose().run,
		HTTPClient:    srv.Client(),
		HealthTimeout: 2 * time.Second,
		EnableLoki:    &f, // disable so test doesn't have to stub Loki too
		EnableGrafana: &f,
	})
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, alloyConfigSubdir, alloyConfigFile)); err != nil {
		t.Fatalf("alloy config not written: %v", err)
	}
}

func TestVMBaseURL(t *testing.T) {
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:     t.TempDir(),
		VMListenAddr: "192.0.2.1:9000",
	})
	if got, want := sup.VMBaseURL(), "http://192.0.2.1:9000"; got != want {
		t.Errorf("VMBaseURL = %q, want %q", got, want)
	}
}

// ============================================================================
// VMSink tests
// ============================================================================

// fakeSupervisor is a Supervisor stub for VMSink tests.
type fakeSupervisor struct {
	healthy    bool
	baseURL    string
	lokiURL    string
	grafanaURL string
}

func (f *fakeSupervisor) Start(context.Context) error           { return nil }
func (f *fakeSupervisor) Stop(context.Context) error            { return nil }
func (f *fakeSupervisor) Healthy(context.Context) (bool, error) { return f.healthy, nil }
func (f *fakeSupervisor) VMBaseURL() string                     { return f.baseURL }
func (f *fakeSupervisor) LokiBaseURL() string                   { return f.lokiURL }
func (f *fakeSupervisor) GrafanaBaseURL() string                { return f.grafanaURL }

func TestVMSink_RequiresSupervisor(t *testing.T) {
	if _, err := NewVMSink(VMSinkConfig{}); err == nil {
		t.Fatal("expected error when Supervisor nil")
	}
}

func TestVMSink_SkipsWhenUnhealthy(t *testing.T) {
	sink, _ := NewVMSink(VMSinkConfig{
		Supervisor: &fakeSupervisor{healthy: false, baseURL: "http://x"},
	})
	err := sink.Write(context.Background(), &proto.MetricsEvt{
		NodeID: "n1", Ts: time.Now(), Metrics: map[string]float64{"cpu_percent": 12},
	})
	if err == nil {
		t.Fatal("expected error when supervisor unhealthy")
	}
	_, lastErr := sink.LastWrite()
	if lastErr == nil {
		t.Fatal("expected LastWrite to record err")
	}
}

func TestVMSink_HappyPath_RecordsBodyAndLastOK(t *testing.T) {
	vm := newStubVM()
	srv := httptest.NewServer(vm.handler())
	defer srv.Close()

	sink, _ := NewVMSink(VMSinkConfig{
		Supervisor: &fakeSupervisor{healthy: true, baseURL: srv.URL},
		HTTPClient: srv.Client(),
	})
	ts := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	if err := sink.Write(context.Background(), &proto.MetricsEvt{
		NodeID: "node-dev",
		Ts:     ts,
		Metrics: map[string]float64{
			proto.MetricCPUPercent:   37.5,
			proto.MetricMemUsedBytes: 1024,
		},
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if vm.importCalls.Load() != 1 {
		t.Fatalf("expected 1 import call, got %d", vm.importCalls.Load())
	}
	body, _ := vm.lastImportBody.Load().(string)
	for _, want := range []string{
		`rasputin_cpu_percent{nodeId="node-dev"} 37.5`,
		`rasputin_mem_used_bytes{nodeId="node-dev"} 1024`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
	// Sorted by name → cpu_percent comes before mem_used_bytes.
	if i, j := strings.Index(body, "rasputin_cpu_percent"), strings.Index(body, "rasputin_mem_used_bytes"); i < 0 || j < 0 || i > j {
		t.Errorf("body not sorted by metric name:\n%s", body)
	}
	ok, lastErr := sink.LastWrite()
	if lastErr != nil {
		t.Fatalf("LastWrite err: %v", lastErr)
	}
	if ok.IsZero() {
		t.Fatal("LastWrite ok should be non-zero on success")
	}
}

func TestVMSink_PropagatesHTTPError(t *testing.T) {
	vm := newStubVM()
	vm.importStatus.Store(http.StatusInternalServerError)
	srv := httptest.NewServer(vm.handler())
	defer srv.Close()

	sink, _ := NewVMSink(VMSinkConfig{
		Supervisor: &fakeSupervisor{healthy: true, baseURL: srv.URL},
		HTTPClient: srv.Client(),
	})
	err := sink.Write(context.Background(), &proto.MetricsEvt{
		NodeID: "n", Ts: time.Now(), Metrics: map[string]float64{"x": 1},
	})
	if err == nil {
		t.Fatal("expected error on 500 from VM")
	}
}

func TestVMSink_NilEventIsNoop(t *testing.T) {
	sink, _ := NewVMSink(VMSinkConfig{
		Supervisor: &fakeSupervisor{healthy: true, baseURL: "http://x"},
	})
	if err := sink.Write(context.Background(), nil); err != nil {
		t.Fatalf("nil evt: %v", err)
	}
	if err := sink.Write(context.Background(), &proto.MetricsEvt{}); err != nil {
		t.Fatalf("empty evt: %v", err)
	}
}

// ============================================================================
// encodePromText tests
// ============================================================================

func TestEncodePromText_SanitizesNames(t *testing.T) {
	out := string(encodePromText(&proto.MetricsEvt{
		NodeID: "n", Ts: time.UnixMilli(1_700_000_000_000),
		Metrics: map[string]float64{"foo-bar.baz": 1},
	}))
	if !strings.Contains(out, "rasputin_foo_bar_baz{") {
		t.Fatalf("name not sanitized: %s", out)
	}
}

func TestEncodePromText_IncludesTimestampMillis(t *testing.T) {
	ts := time.UnixMilli(1_700_000_000_000)
	out := string(encodePromText(&proto.MetricsEvt{
		NodeID: "n", Ts: ts, Metrics: map[string]float64{"x": 1},
	}))
	if !strings.Contains(out, " 1700000000000\n") {
		t.Fatalf("missing/wrong ts: %s", out)
	}
}

// ============================================================================
// Status snapshot tests
// ============================================================================

func TestStatus_NilReturnsDisabled(t *testing.T) {
	var s *Status
	snap := s.Snapshot(context.Background())
	if snap.Enabled {
		t.Error("nil status should be Enabled=false")
	}
}

func TestStatus_NoopSupervisorIsDisabled(t *testing.T) {
	sink, _ := NewVMSink(VMSinkConfig{Supervisor: &fakeSupervisor{}})
	s := NewStatus(NoopSupervisor{}, sink, nil)
	if snap := s.Snapshot(context.Background()); snap.Enabled {
		t.Error("noop supervisor should be Enabled=false")
	}
}

func TestStatus_HealthyReportsTrue(t *testing.T) {
	vm := newStubVM()
	srv := httptest.NewServer(vm.handler())
	defer srv.Close()

	fakeSup := &fakeSupervisor{healthy: true, baseURL: srv.URL}
	sink, _ := NewVMSink(VMSinkConfig{Supervisor: fakeSup, HTTPClient: srv.Client()})
	_ = sink.Write(context.Background(), &proto.MetricsEvt{
		NodeID: "n", Ts: time.Now(), Metrics: map[string]float64{"x": 1},
	})

	s := NewStatus(fakeSup, sink, nil)
	snap := s.Snapshot(context.Background())
	if !snap.Enabled {
		t.Fatal("Enabled should be true")
	}
	if !snap.Healthy {
		t.Fatal("Healthy should be true")
	}
	if snap.VMBaseURL != srv.URL {
		t.Errorf("VMBaseURL = %q, want %q", snap.VMBaseURL, srv.URL)
	}
	if snap.LastWriteOK.IsZero() {
		t.Error("LastWriteOK should be set after successful write")
	}
}

// ----- helpers ------------------------------------------------------------

func splitHostPort(t *testing.T, urlStr string) (string, string) {
	t.Helper()
	// urlStr is httptest's "http://127.0.0.1:NNNN"
	if !strings.HasPrefix(urlStr, "http://") {
		t.Fatalf("unexpected URL: %s", urlStr)
	}
	hostport := strings.TrimPrefix(urlStr, "http://")
	idx := strings.LastIndex(hostport, ":")
	if idx < 0 {
		t.Fatalf("no port in URL: %s", urlStr)
	}
	return hostport[:idx], hostport[idx+1:]
}

// A relative IDSLogDir must be normalized to an absolute path before it
// reaches the compose template. Compose reads a bare relative volume source
// as a *named volume* rather than a bind mount and rejects the project with
// "refers to undefined volume data/obs/ids-alerts" — which is exactly what a
// dev run (dataDir = ./data) produced the first time the UI toggle made obs
// reachable. Appliances pass an absolute dataDir, so only dev ever hit it.
func TestNewDockerComposeSupervisor_MakesIDSLogDirAbsolute(t *testing.T) {
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:  t.TempDir(),
		IDSLogDir: "data/obs/ids-alerts",
	})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	if !filepath.IsAbs(sup.cfg.IDSLogDir) {
		t.Errorf("IDSLogDir = %q; want an absolute path — compose reads a relative source as a named volume and rejects the project", sup.cfg.IDSLogDir)
	}
	if !strings.HasSuffix(sup.cfg.IDSLogDir, filepath.Join("data", "obs", "ids-alerts")) {
		t.Errorf("IDSLogDir = %q; want it to still point at the configured dir", sup.cfg.IDSLogDir)
	}
}

func TestNewDockerComposeSupervisor_EmptyIDSLogDirStaysEmpty(t *testing.T) {
	// Empty means "no IDS pipe" — Abs("") would turn it into the cwd and
	// silently mount the whole working directory into Alloy.
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	if sup.cfg.IDSLogDir != "" {
		t.Errorf("IDSLogDir = %q; want empty", sup.cfg.IDSLogDir)
	}
	if *sup.cfg.EnableIDSPipe {
		t.Error("EnableIDSPipe = true with no IDS log dir; want false")
	}
}
