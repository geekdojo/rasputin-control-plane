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

func TestRenderAlloyConfig_NodeIDLabel(t *testing.T) {
	// With ControlPlaneNodeID set, the controlplane's own remote-write stamps
	// external_labels{node_id} so its containers filter uniformly (§3.10 p5).
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:           t.TempDir(),
		ControlPlaneNodeID: "cp-1",
	})
	body, err := sup.renderAlloyConfig()
	if err != nil {
		t.Fatalf("render alloy: %v", err)
	}
	for _, want := range []string{"external_labels = {", `node_id = "cp-1"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("alloy config missing %q\n--- alloy ---\n%s", want, body)
		}
	}
}

func TestRenderAlloyConfig_NoNodeIDLabelWhenUnset(t *testing.T) {
	// Empty ControlPlaneNodeID (dev / no self-id) omits the block entirely,
	// rather than tagging every sample with node_id="".
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: t.TempDir()})
	body, _ := sup.renderAlloyConfig()
	if strings.Contains(string(body), "external_labels") {
		t.Errorf("expected no external_labels when node id unset\n%s", body)
	}
}

func TestRenderAlloyConfig_LokiWriteCarriesNodeID(t *testing.T) {
	// With Loki enabled, loki.write must also carry external_labels{node_id} —
	// otherwise the Logs tab's {node_id="…"} filter matches nothing (Slice 1.2c;
	// this was the "empty for every node" bug).
	tr := true
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:           t.TempDir(),
		ControlPlaneNodeID: "cp-1",
		EnableLoki:         &tr,
	})
	body, err := sup.renderAlloyConfig()
	if err != nil {
		t.Fatalf("render alloy: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, `loki.write "local"`) {
		t.Fatalf("expected loki.write block when Loki enabled\n%s", s)
	}
	// node_id must appear in BOTH remote_write (metrics) and loki.write (logs).
	if n := strings.Count(s, `node_id = "cp-1"`); n < 2 {
		t.Errorf("node_id label count = %d, want >= 2 (remote_write + loki.write)\n%s", n, s)
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
	stackReady *bool // nil → mirror `healthy` (most tests only care about VM)
	baseURL    string
	lokiURL    string
	grafanaURL string
}

func (f *fakeSupervisor) Start(context.Context) error           { return nil }
func (f *fakeSupervisor) Stop(context.Context) error            { return nil }
func (f *fakeSupervisor) Healthy(context.Context) (bool, error) { return f.healthy, nil }
func (f *fakeSupervisor) StackReady(context.Context) (bool, error) {
	if f.stackReady != nil {
		return *f.stackReady, nil
	}
	return f.healthy, nil
}
func (f *fakeSupervisor) VMBaseURL() string      { return f.baseURL }
func (f *fakeSupervisor) LokiBaseURL() string    { return f.lokiURL }
func (f *fakeSupervisor) GrafanaBaseURL() string { return f.grafanaURL }

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

// ----- storage size-caps (storage.md §5) ----------------------------------

// VM must reserve free space on the shared partition. Without it VM's default
// is 10 MB — effectively nothing — and a growing metrics store can fill the
// partition it shares with the SQLite DB, whose writes then fail. That's the
// wedge class the 2026-06-21 growpart incident proved.
func TestRenderCompose_VMReservesFreeDiskSpace(t *testing.T) {
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	raw, err := sup.renderCompose()
	if err != nil {
		t.Fatalf("renderCompose: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "-storage.minFreeDiskSpaceBytes=2GB") {
		t.Errorf("compose missing the default free-space reservation:\n%s", body)
	}
	// The time bound stays — the reservation is a backstop, not a replacement.
	if !strings.Contains(body, "-retentionPeriod=1y") {
		t.Errorf("compose lost -retentionPeriod:\n%s", body)
	}
}

func TestRenderCompose_VMFreeDiskSpaceOverride(t *testing.T) {
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:           t.TempDir(),
		VMMinFreeDiskSpace: "512MB",
	})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	raw, _ := sup.renderCompose()
	if !strings.Contains(string(raw), "-storage.minFreeDiskSpaceBytes=512MB") {
		t.Errorf("override not honored:\n%s", raw)
	}
}

// Loki shipped with no retention at all — no compactor, no retention_period —
// so it kept every log line forever and was the largest unbounded tenant on
// the controlplane's partition. retention_period alone is NOT enough:
// compactor.retention_enabled is off by default and a period set without it
// is silently ignored, which is exactly how this stays broken.
func TestWriteLokiConfig_HasRetentionAndCompactor(t *testing.T) {
	dir := t.TempDir()
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: dir})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	if err := sup.prepareHostDirs(); err != nil {
		t.Fatalf("prepareHostDirs: %v", err)
	}
	if err := sup.writeLokiConfig(); err != nil {
		t.Fatalf("writeLokiConfig: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, lokiConfigSubdir, lokiConfigFile))
	if err != nil {
		t.Fatalf("read rendered config: %v", err)
	}
	body := string(raw)
	for _, want := range []string{
		"retention_period: 720h",
		"retention_enabled: true",
		"delete_request_store: filesystem",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered loki config missing %q:\n%s", want, body)
		}
	}
}

func TestWriteLokiConfig_RetentionOverride(t *testing.T) {
	dir := t.TempDir()
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:      dir,
		LokiRetention: "168h",
	})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	if err := sup.prepareHostDirs(); err != nil {
		t.Fatalf("prepareHostDirs: %v", err)
	}
	if err := sup.writeLokiConfig(); err != nil {
		t.Fatalf("writeLokiConfig: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, lokiConfigSubdir, lokiConfigFile))
	if !strings.Contains(string(raw), "retention_period: 168h") {
		t.Errorf("override not honored:\n%s", raw)
	}
}

func TestNewDockerComposeSupervisor_SizeCapDefaults(t *testing.T) {
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	if sup.cfg.VMMinFreeDiskSpace != defaultVMMinFreeDiskSpace {
		t.Errorf("VMMinFreeDiskSpace = %q; want %q", sup.cfg.VMMinFreeDiskSpace, defaultVMMinFreeDiskSpace)
	}
	if sup.cfg.LokiRetention != defaultLokiRetention {
		t.Errorf("LokiRetention = %q; want %q", sup.cfg.LokiRetention, defaultLokiRetention)
	}
}

// Compose recreates a container only when its service *definition* changes —
// never when a bind-mounted file's contents change. Verified live 2026-07-16:
// editing loki-config.yaml and re-running `compose up -d` left the same
// container id running with the previous retention still live. So the rendered
// config's digest has to ride in the definition, or a changed config silently
// never applies (Loki retention, and more alarmingly the vmalert RULES file).
func TestRenderCompose_ConfigDigestChangesWithConfig(t *testing.T) {
	render := func(retention string) string {
		dir := t.TempDir()
		sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
			StateDir:      dir,
			LokiRetention: retention,
		})
		if err != nil {
			t.Fatalf("NewDockerComposeSupervisor: %v", err)
		}
		if err := sup.prepareHostDirs(); err != nil {
			t.Fatalf("prepareHostDirs: %v", err)
		}
		// Start renders configs before compose; mirror that ordering.
		if err := sup.writeLokiConfig(); err != nil {
			t.Fatalf("writeLokiConfig: %v", err)
		}
		raw, err := sup.renderCompose()
		if err != nil {
			t.Fatalf("renderCompose: %v", err)
		}
		return string(raw)
	}

	a, b := render("720h"), render("168h")
	// Scope to the loki service — every config-mounting service carries a
	// digest, and grabbing the first one finds alloy's, which has no reason to
	// change when only loki's retention does.
	digestOf := func(body, service string) string {
		lines := strings.Split(body, "\n")
		for i, line := range lines {
			if strings.TrimSpace(line) != service+":" {
				continue
			}
			for _, l := range lines[i:min(i+12, len(lines))] {
				if strings.Contains(l, "RASPUTIN_OBS_CONFIG_DIGEST") {
					return strings.TrimSpace(l)
				}
			}
		}
		return ""
	}
	da, db := digestOf(a, "loki"), digestOf(b, "loki")
	if da == "" || db == "" {
		t.Fatalf("no config digest rendered into compose:\n%s", a)
	}
	if da == db {
		t.Errorf("digest %q unchanged across differing loki retention — compose would not recreate the container, so the new retention would never apply", da)
	}
}

func TestConfigHash_MissingFilesYieldEmpty(t *testing.T) {
	// A disabled service renders no config; an empty digest keeps its service
	// definition stable rather than churning the container every Start.
	if got := configHash(filepath.Join(t.TempDir(), "nope.yaml")); got != "" {
		t.Errorf("configHash(missing) = %q; want empty", got)
	}
}

func TestConfigHash_StableForSameContent(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(f, []byte("retention: 720h"), 0o644); err != nil {
		t.Fatal(err)
	}
	first := configHash(f)
	second := configHash(f)
	if first == "" || first != second {
		t.Errorf("configHash unstable: %q vs %q — an unstable digest would recreate every container on every Start", first, second)
	}
	if err := os.WriteFile(f, []byte("retention: 168h"), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed := configHash(f); changed == first {
		t.Error("configHash did not change when content changed")
	}
}

// Loki runs as uid 10001 and must write its bind-mounted /loki dir. The api
// creates that dir as root at 0755, so on a real appliance (native Docker,
// real uid enforcement) Loki can't write it and dies before binding :3100 —
// a bare "connection refused" on the health check. Docker/Rancher Desktop
// mask this via VM uid remapping, so it only surfaced on the bench. Grafana
// (uid 472) had the 0o777 workaround since Slice 1.4; Loki (Slice 1.3) was
// missed. Assert BOTH non-root data dirs are world-writable.
func TestPrepareHostDirs_NonRootDataDirsAreWritable(t *testing.T) {
	dir := t.TempDir()
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: dir})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	if err := sup.prepareHostDirs(); err != nil {
		t.Fatalf("prepareHostDirs: %v", err)
	}
	for _, d := range []string{lokiDataDir, grafanaDataDir} {
		info, err := os.Stat(filepath.Join(dir, d))
		if err != nil {
			t.Fatalf("stat %s: %v", d, err)
		}
		// Other-write is the bit that lets a non-root container uid write a
		// root-owned host mount.
		if info.Mode().Perm()&0o002 == 0 {
			t.Errorf("%s mode = %o; want other-writable (0o002 set) so a non-root container user can write it", d, info.Mode().Perm())
		}
	}
}

// When Loki is disabled there's no loki-data dir to loosen — don't create or
// chmod one (it would be dead state, and the chmod would fail on a missing
// path now that the error is checked).
func TestPrepareHostDirs_NoLokiDirWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	f := false
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:   dir,
		EnableLoki: &f,
	})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	if err := sup.prepareHostDirs(); err != nil {
		t.Fatalf("prepareHostDirs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, lokiDataDir)); !os.IsNotExist(err) {
		t.Errorf("loki-data dir exists with Loki disabled (err=%v); want absent", err)
	}
}

// cAdvisor resolves each container's read-write layer from the daemon's
// reported DockerRootDir. On a Rasputin appliance that's /var/lib/rasputin/
// docker (state on the persistent partition), not the default — so the Alloy
// sidecar must bind-mount THAT path 1:1 or cAdvisor sees only the root cgroup
// and the Containers tab is empty. Bench-observed 2026-07-17. Masked on dev
// because Docker/Rancher Desktop keep the default data-root.
func TestRenderCompose_MountsDiscoveredDockerDataRoot(t *testing.T) {
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	// Simulate what Start's discovery would set on a real appliance.
	sup.dockerDataRoot = "/var/lib/rasputin/docker"
	body, err := sup.renderCompose()
	if err != nil {
		t.Fatalf("renderCompose: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "/var/lib/rasputin/docker:/var/lib/rasputin/docker:ro") {
		t.Errorf("compose does not mount the discovered data-root 1:1:\n%s", s)
	}
	// The stale hardcoded default must be gone once a real root is known.
	if strings.Contains(s, "/var/lib/docker:/var/lib/docker:ro") {
		t.Errorf("compose still mounts the default /var/lib/docker after discovery:\n%s", s)
	}
}

func TestRenderCompose_DockerDataRootFallsBackToDefault(t *testing.T) {
	// No Start / no discovery → the previous behavior (default path) so dev
	// and CI are unchanged.
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: t.TempDir()})
	body, _ := sup.renderCompose()
	if !strings.Contains(string(body), "/var/lib/docker:/var/lib/docker:ro") {
		t.Errorf("expected default data-root mount when undiscovered:\n%s", body)
	}
}

func TestDiscoverDockerDataRoot(t *testing.T) {
	cases := []struct {
		name   string
		out    string
		err    error
		expect string
	}{
		{"appliance", "/var/lib/rasputin/docker\n", nil, "/var/lib/rasputin/docker"},
		{"default", "/var/lib/docker", nil, "/var/lib/docker"},
		{"error falls back", "", errShim, "/var/lib/docker"},
		{"empty falls back", "  \n", nil, "/var/lib/docker"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotArgs []string
			sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
				StateDir: t.TempDir(),
				Runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
					gotArgs = args
					return []byte(tc.out), tc.err
				},
			})
			got := sup.discoverDockerDataRoot(context.Background())
			if got != tc.expect {
				t.Errorf("data-root = %q; want %q", got, tc.expect)
			}
			if tc.err == nil && (len(gotArgs) < 2 || gotArgs[0] != "info") {
				t.Errorf("expected a `docker info` call, got args %v", gotArgs)
			}
		})
	}
}

var errShim = errShimT("docker daemon down")

type errShimT string

func (e errShimT) Error() string { return string(e) }
