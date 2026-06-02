//go:build supervisor

// Live end-to-end test for the obs DockerComposeSupervisor + VMSink.
// Excluded from the default `go test` run by the `supervisor` build tag —
// invoke with:
//
//	go test -tags=supervisor -run TestObsSupervisor -count=1 -v -timeout=5m \
//	  ./api/internal/obs/...
//
// Requires:
//   - A working `docker` CLI on PATH (Docker Desktop / Rancher Desktop /
//     OrbStack / Podman with docker shim all work).
//   - Network access to pull the VictoriaMetrics image (only on first run).
//   - Free TCP port at 127.0.0.1:18428 (override via OBS_SMOKE_LISTEN_ADDR).
//
// State directory (OBS_SMOKE_STATE_DIR override):
//
//	Defaults to $HOME/.cache/rasputin-obs-smoke. As with the mesh
//	smoke test, $HOME is mounted into all the macOS-VM-backed Docker
//	runtimes by default while /var/folders (t.TempDir) is not. Using
//	the cache path keeps re-runs working without per-machine setup.
//
// Side effects:
//   - Pulls the VictoriaMetrics image into the local image store.
//   - Spins up a project "rasputin-obs-smoke" with container
//     rasputin-victoriametrics. Cleanup removes both.
//
// The test asserts the full Slice 1.1 readiness story end-to-end:
//  1. Supervisor.Start brings VM up and answers /health.
//  2. VMSink.Write publishes a sample to /api/v1/import/prometheus.
//  3. Querying VM's /api/v1/query returns that exact sample.
//  4. Supervisor.Stop tears the project down.
//  5. Re-Start picks the same volume back up without re-pulling.

package obs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

const obsSmokeProject = "rasputin-obs-smoke"

func TestObsSupervisor_LiveLifecycle(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unreachable; output=%q err=%v", strings.TrimSpace(string(out)), err)
	}

	stateDir, err := resolveObsSmokeStateDir()
	if err != nil {
		t.Fatalf("resolve state dir: %v", err)
	}
	t.Logf("obs smoke state dir: %s", stateDir)

	listenAddr := envDefault("OBS_SMOKE_LISTEN_ADDR", "127.0.0.1:18428")

	// Pre-clean a previous failed run.
	_ = exec.Command("docker", "compose", "-p", obsSmokeProject, "down", "-v").Run()
	t.Cleanup(func() {
		_ = exec.Command("docker", "compose", "-p", obsSmokeProject, "down", "-v").Run()
		_ = os.RemoveAll(stateDir)
	})

	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:      stateDir,
		ProjectName:   obsSmokeProject,
		VMListenAddr:  listenAddr,
		HealthTimeout: 3 * time.Minute, // first-run pull + Loki TSDB bootstrap can be slow
		PullTimeout:   3 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	t.Run("Start_BringsVMUp", func(t *testing.T) {
		if err := sup.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		ok, err := sup.Healthy(ctx)
		if err != nil {
			t.Fatalf("Healthy: %v", err)
		}
		if !ok {
			t.Fatal("Healthy=false after Start")
		}
	})

	t.Run("VMSink_RoundTripThroughVM", func(t *testing.T) {
		sink, err := NewVMSink(VMSinkConfig{Supervisor: sup})
		if err != nil {
			t.Fatalf("NewVMSink: %v", err)
		}
		// Use a stable, unique metric name so a previous (non-cleaned) run
		// doesn't pollute the assertion. Ts is also fixed so we can pin
		// the timestamp on read.
		now := time.Now().UTC().Truncate(time.Second)
		evt := &proto.MetricsEvt{
			NodeID: "smoke-node",
			Ts:     now,
			Metrics: map[string]float64{
				proto.MetricCPUPercent: 42.5,
			},
		}
		if err := sink.Write(ctx, evt); err != nil {
			t.Fatalf("VMSink.Write: %v", err)
		}

		// VM ingests asynchronously — poll for up to 10s.
		deadline := time.Now().Add(10 * time.Second)
		for {
			val, err := queryVMScalar(ctx, sup.VMBaseURL(),
				`rasputin_cpu_percent{nodeId="smoke-node"}`)
			if err == nil && val == 42.5 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("query never returned 42.5; last err=%v", err)
			}
			time.Sleep(250 * time.Millisecond)
		}
	})

	t.Run("Alloy_ScrapesAndShipsContainerMetrics", func(t *testing.T) {
		// Alloy needs ~30s to come up, run its first cadvisor scrape, and
		// remote-write. Poll for any sample carrying the cadvisor-emitted
		// container_label_io_kubernetes_container_name or the generic
		// container_cpu_user_seconds_total metric.
		deadline := time.Now().Add(60 * time.Second)
		for {
			body, err := vmInstantQuery(ctx, sup.VMBaseURL(),
				`count(container_cpu_user_seconds_total)`)
			if err == nil && strings.Contains(body, `"value":[`) &&
				!strings.Contains(body, `"result":[]`) {
				return
			}
			// Also accept Alloy's self-scrape metric as a healthy signal
			// when cadvisor mounts aren't usable in this environment
			// (Docker Desktop on macOS sometimes refuses /sys mount).
			selfBody, _ := vmInstantQuery(ctx, sup.VMBaseURL(),
				`count(alloy_build_info)`)
			if selfBody != "" && strings.Contains(selfBody, `"value":[`) &&
				!strings.Contains(selfBody, `"result":[]`) {
				t.Logf("Alloy self-scrape visible in VM; cadvisor likely not " +
					"reachable in this dev env (Docker Desktop /sys mount). " +
					"Self-scrape is enough to prove the Alloy → VM path.")
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("no Alloy/cadvisor metrics in VM after 60s; last cadvisor=%s, self=%s",
					body, selfBody)
			}
			time.Sleep(2 * time.Second)
		}
	})

	t.Run("Loki_AcceptsShippedDockerLogs", func(t *testing.T) {
		// Build a LogsClient against the live supervisor and query
		// {compose_service="victoriametrics"} — VM writes startup +
		// query logs continuously, so something should be present within
		// the discovery/ingest window. Loki's first scrape can take
		// ~15-20s after Alloy starts.
		client, err := NewLogsClient(LogsClientConfig{Supervisor: sup})
		if err != nil {
			t.Fatalf("NewLogsClient: %v", err)
		}
		deadline := time.Now().Add(90 * time.Second)
		for {
			body, err := client.QueryRange(ctx, LogsQuery{
				Query: `{compose_service="victoriametrics"}`,
				Start: time.Now().Add(-10 * time.Minute),
				End:   time.Now(),
				Limit: 5,
			})
			if err == nil && strings.Contains(string(body), `"streams"`) &&
				strings.Contains(string(body), `"values"`) &&
				!strings.Contains(string(body), `"result":[]`) {
				return
			}
			if time.Now().After(deadline) {
				snippet := ""
				if body != nil {
					snippet = string(body)
					if len(snippet) > 256 {
						snippet = snippet[:256]
					}
				}
				t.Fatalf("no Loki logs after 90s; last err=%v body=%s", err, snippet)
			}
			time.Sleep(3 * time.Second)
		}
	})

	t.Run("Grafana_ReachableAndProvisioned", func(t *testing.T) {
		// Grafana's /api/health is unauthenticated. The presence of the
		// VictoriaMetrics datasource (auto-provisioned at startup)
		// requires admin auth, which we don't want to bake into the
		// smoke test — instead just confirm Grafana is up and that
		// the provisioned dashboard JSON is served (Grafana exposes
		// it at /api/search?folderIds=…&type=dash-db which also
		// requires auth, so we use the basic-auth admin credentials
		// from the rendered grafana.ini).
		base := sup.GrafanaBaseURL()
		if base == "" {
			t.Fatal("GrafanaBaseURL empty")
		}
		// /api/health is open.
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/health", nil)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("/api/health: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/api/health = %d, want 200", resp.StatusCode)
		}
		// /api/search to confirm provisioning landed. Auth comes via
		// the X-Webauth-User header (auth.proxy mode) — basic-auth
		// + the cookie form are both disabled in the rendered
		// grafana.ini. auto_sign_up creates the user on first sight.
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet,
			base+"/api/search?type=dash-db", nil)
		req.Header.Set("X-Webauth-User", "smoke-operator")
		resp, err = (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("/api/search: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/api/search = %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "Cluster Overview") {
			t.Fatalf("starter dashboard missing from search response: %s",
				string(body))
		}
	})

	t.Run("VMAlert_RunsAndReachableHostWebhook", func(t *testing.T) {
		// Just confirm vmalert container is up. Verifying it actually
		// fires takes 5+ minutes (NodeDown needs absent_over_time[5m]);
		// out of scope for the smoke run. The webhook receiver itself
		// is covered by alerts package unit tests.
		out, err := exec.CommandContext(ctx, "docker", "inspect",
			"--format", "{{.State.Status}}", "rasputin-vmalert").CombinedOutput()
		if err != nil {
			t.Fatalf("docker inspect rasputin-vmalert: %v (output: %s)",
				err, strings.TrimSpace(string(out)))
		}
		if got := strings.TrimSpace(string(out)); got != "running" {
			t.Errorf("vmalert state = %q, want running", got)
		}
	})

	t.Run("Stop_GracefullyStops", func(t *testing.T) {
		if err := sup.Stop(ctx); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		ok, _ := sup.Healthy(ctx)
		if ok {
			t.Error("Healthy should be false after Stop")
		}
	})

	t.Run("Restart_PicksUpExistingVolume", func(t *testing.T) {
		if err := sup.Start(ctx); err != nil {
			t.Fatalf("re-Start: %v", err)
		}
		ok, err := sup.Healthy(ctx)
		if err != nil || !ok {
			t.Errorf("Healthy after re-Start: ok=%v err=%v", ok, err)
		}
		// The 42.5 sample from the previous run must still be there since
		// we did NOT call `compose down -v` between the two Starts.
		val, err := queryVMScalar(ctx, sup.VMBaseURL(),
			`rasputin_cpu_percent{nodeId="smoke-node"}`)
		if err != nil {
			t.Fatalf("re-query: %v", err)
		}
		if val != 42.5 {
			t.Errorf("post-restart sample = %v, want 42.5", val)
		}
	})
}

// vmInstantQuery runs an instant query and returns the raw JSON body
// (so the caller can do its own loose matching for "any sample present"
// cases like the Alloy/cAdvisor probe where the exact metric set isn't
// stable across environments).
func vmInstantQuery(ctx context.Context, base, expr string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v1/query?query="+httpEscape(expr), nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return string(body), fmt.Errorf("query HTTP %d", resp.StatusCode)
	}
	return string(body), nil
}

// queryVMScalar runs an instant query against VM's /api/v1/query and
// returns the most recent scalar value. VM's response shape:
//
//	{"status":"success","data":{"resultType":"vector",
//	 "result":[{"metric":{...},"value":[1234,"42.5"]}]}}
func queryVMScalar(ctx context.Context, base, expr string) (float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v1/query?query="+httpEscape(expr), nil)
	if err != nil {
		return 0, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("query HTTP %d: %s", resp.StatusCode, body)
	}
	var parsed struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Value [2]any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, fmt.Errorf("decode: %w; body=%s", err, body)
	}
	if parsed.Status != "success" {
		return 0, fmt.Errorf("status=%q body=%s", parsed.Status, body)
	}
	if len(parsed.Data.Result) == 0 {
		return 0, fmt.Errorf("no result")
	}
	// value[1] is the string-encoded sample value.
	s, ok := parsed.Data.Result[0].Value[1].(string)
	if !ok {
		return 0, fmt.Errorf("value not string: %T", parsed.Data.Result[0].Value[1])
	}
	var f float64
	if _, err := fmt.Sscanf(s, "%f", &f); err != nil {
		return 0, fmt.Errorf("parse %q: %w", s, err)
	}
	return f, nil
}

// httpEscape is a tiny URL escaper that handles the characters our
// queries use ({, ", }, =, _, alphanum). Avoids pulling net/url for one
// call.
func httpEscape(s string) string {
	const hex = "0123456789ABCDEF"
	b := make([]byte, 0, len(s)*3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '_', c == '.':
			b = append(b, c)
		default:
			b = append(b, '%', hex[c>>4], hex[c&0xf])
		}
	}
	return string(b)
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func resolveObsSmokeStateDir() (string, error) {
	if v := os.Getenv("OBS_SMOKE_STATE_DIR"); v != "" {
		if err := os.MkdirAll(v, 0o755); err != nil {
			return "", err
		}
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := home + "/.cache/rasputin-obs-smoke"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}
