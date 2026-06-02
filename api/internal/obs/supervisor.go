package obs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// Supervisor owns the observability sidecar stack's lifecycle on the
// controlplane node. Tier 2 (per design/control-plane/observability-stack.md)
// runs VictoriaMetrics, Loki, Grafana, and Alloy as Docker containers; this
// supervisor brings them up via `docker compose up -d`, waits for VM to
// answer /health, and tears them down on shutdown.
//
// Why compose (not per-container `docker run` like mesh/supervisor_docker.go):
// the obs stack is multi-container by definition — VM, Loki, Grafana, Alloy.
// `docker compose` handles the shared network, named volumes, restart
// policies, and dependency ordering uniformly. The supervisor still shells
// out to the CLI (not the SDK) for the same portability reasons the mesh
// supervisor does — Docker Desktop, Rancher Desktop, OrbStack, Colima all
// ship a compatible `docker compose` subcommand.
//
// Slice 1.1 scope: VictoriaMetrics only. Loki/Grafana/Alloy land in
// subsequent slices; the compose template adds services without changing
// the supervisor's surface.
type Supervisor interface {
	// Start brings the stack up. Idempotent: a running stack is a no-op
	// (still re-checks health), a stopped stack is started, a missing
	// stack is pulled + created + started. Returns once VM answers /health
	// or HealthTimeout fires.
	Start(ctx context.Context) error
	// Stop issues `docker compose stop` but deliberately leaves volumes
	// in place so VM's on-disk samples survive across restarts. Re-Start
	// re-attaches.
	Stop(ctx context.Context) error
	// Healthy is true when the VM container is running AND /health
	// answers 2xx. Used by /api/obs/status and the metrics fan-out's
	// "is it worth trying to remote-write?" gate.
	Healthy(ctx context.Context) (bool, error)
	// VMBaseURL is the host-side base URL the api uses for remote-write
	// (POST /api/v1/import/prometheus) and queries (GET /api/v1/query).
	// Empty until Start has succeeded at least once.
	VMBaseURL() string
	// LokiBaseURL is the host-side base URL for Loki's HTTP API.
	// Empty when Loki is disabled OR Start hasn't succeeded yet.
	// Used by the api's /api/obs/logs handler to proxy LogQL queries.
	LokiBaseURL() string
	// GrafanaBaseURL is the host-side base URL for Grafana. Empty
	// when Grafana is disabled. The api's /observability/* reverse
	// proxy uses it.
	GrafanaBaseURL() string
}

// NoopSupervisor is the default when obs is disabled. Healthy always
// reports false; VMBaseURL is empty. Start/Stop are no-ops. Lets callers
// unconditionally hold a Supervisor reference without nil-guarding every
// call site.
type NoopSupervisor struct{}

// NewNoopSupervisor returns a supervisor that does nothing. Use this when
// RASPUTIN_OBS_ENABLED is unset — the rest of the api keeps working
// (Tier 1 SQLite metrics, alerts aggregator, etc.) and the fan-out sink
// stays inert.
func NewNoopSupervisor() Supervisor                          { return NoopSupervisor{} }
func (NoopSupervisor) Start(context.Context) error           { return nil }
func (NoopSupervisor) Stop(context.Context) error            { return nil }
func (NoopSupervisor) Healthy(context.Context) (bool, error) { return false, nil }
func (NoopSupervisor) VMBaseURL() string                     { return "" }
func (NoopSupervisor) LokiBaseURL() string                   { return "" }
func (NoopSupervisor) GrafanaBaseURL() string                { return "" }

// CmdRunner runs a binary and returns its combined output. Injected so
// tests can drive lifecycle decisions without a real Docker daemon.
// Identical signature to mesh.CmdRunner; duplicated here to keep the
// packages decoupled.
type CmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// DockerComposeSupervisorConfig is the constructor input.
type DockerComposeSupervisorConfig struct {
	// StateDir is the host directory that holds the rendered
	// docker-compose.yml plus per-service config and data subdirectories.
	// The supervisor creates <StateDir>/{compose.yaml,vm-data} on Start.
	StateDir string

	// ProjectName becomes `docker compose -p <name>`. Defaults to
	// "rasputin-obs". Docker uses it to namespace networks and volumes,
	// which is what keeps a co-tenanted compose stack on the same host
	// (e.g. someone else's `obs` project) from colliding.
	ProjectName string

	// VMImage overrides the VictoriaMetrics image reference. Defaults to
	// the pinned upstream tag — bump deliberately, not via @latest.
	VMImage string

	// VMListenAddr is the host bind for VM's HTTP listener. Defaults to
	// "127.0.0.1:8428" — VM doesn't need to be LAN-reachable in Tier 2
	// (the api fans out from inside the same host); we'll open it up if
	// a future slice demands cross-node scrape. The container listens on
	// 8428 internally; we publish that to VMListenAddr on the host.
	VMListenAddr string

	// VMRetention is the `-retentionPeriod` flag passed to VM. Defaults
	// to "1y" — sparse homelab metrics + VM's compression ratio means a
	// year of 10s samples is still small.
	VMRetention string

	// AlloyImage overrides the Grafana Alloy image reference. Defaults
	// to the pinned upstream tag. Alloy lives in the same compose stack
	// as VM (Slice 1.2 onward) and remote-writes container + self
	// metrics to victoriametrics over the project network.
	AlloyImage string

	// AlloyListenAddr is the host bind for Alloy's UI / debug listener.
	// Defaults to "127.0.0.1:12345"; the container listens on 12345
	// internally. Loopback-only on purpose — Alloy's debug UI exposes
	// component state and shouldn't be LAN-reachable.
	AlloyListenAddr string

	// EnableCadvisor toggles the prometheus.exporter.cadvisor component
	// inside Alloy. Default true. cAdvisor scrapes per-container CPU /
	// mem / network / disk. Off lets dev / CI runs skip the privileged
	// mounts cAdvisor needs (Docker socket, host /sys, host /); turn
	// off if those mounts aren't permitted in your environment.
	EnableCadvisor *bool

	// LokiImage overrides the Loki image reference. Defaults to the
	// pinned upstream tag. Loki joins the compose stack at Slice 1.3
	// and receives container-log pushes from Alloy's loki.source.docker
	// component.
	LokiImage string

	// LokiListenAddr is the host bind for Loki's HTTP listener
	// (push + query). Defaults to "127.0.0.1:3100"; container listens
	// on 3100 internally.
	LokiListenAddr string

	// EnableLoki toggles the Loki service + Alloy's log-shipping
	// components. Default true. Off lets operators run a metrics-only
	// obs stack — useful when an external log aggregator is already
	// in play.
	EnableLoki *bool

	// GrafanaImage overrides the Grafana image reference. Defaults to
	// the pinned upstream tag. Grafana joins the stack at Slice 1.4
	// and is reached via the api's auth-proxy at /observability/*.
	GrafanaImage string

	// GrafanaListenAddr is the host bind for Grafana's HTTP listener.
	// Defaults to "127.0.0.1:3000"; container listens on 3000. Loopback
	// only because the auth-proxy is what makes Grafana safe to expose
	// — direct access bypasses Rasputin's session auth.
	GrafanaListenAddr string

	// EnableGrafana toggles the Grafana service. Default true. Off
	// gives a metrics + logs stack without the dashboard UI — useful
	// for operators using an existing Grafana elsewhere.
	EnableGrafana *bool

	// DockerBin overrides the docker binary path; useful when the runtime's
	// CLI lives somewhere unexpected. Defaults to "docker".
	DockerBin string

	// Runner overrides the command runner. Defaults to exec.CommandContext.
	Runner CmdRunner

	// HTTPClient is used to probe VM's /health endpoint. Tests inject a
	// stub; production gets a 2s-timeout client.
	HTTPClient *http.Client

	// HealthTimeout caps how long Start waits for VM to answer /health
	// after the stack starts. Defaults to 30s.
	HealthTimeout time.Duration

	// PullTimeout caps how long `docker compose pull` is allowed to run.
	// Defaults to 5 minutes.
	PullTimeout time.Duration
}

const (
	defaultProjectName       = "rasputin-obs"
	defaultVMImage           = "victoriametrics/victoria-metrics:v1.103.0"
	defaultVMListenAddr      = "127.0.0.1:8428"
	defaultVMRetention       = "1y"
	defaultAlloyImage        = "grafana/alloy:v1.4.2"
	defaultAlloyListenAddr   = "127.0.0.1:12345"
	defaultLokiImage         = "grafana/loki:3.4.1"
	defaultLokiListenAddr    = "127.0.0.1:3100"
	defaultGrafanaImage      = "grafana/grafana:11.5.1"
	defaultGrafanaListenAddr = "127.0.0.1:3000"
	defaultDockerBin         = "docker"

	// 90s covers Loki's cold-start window. VM alone is up in <5s;
	// Loki's TSDB schema bootstrap on a fresh data dir can take 30-60s.
	// Operators who run VM-only (EnableLoki=false) won't notice the
	// difference because waitHealthy short-circuits the moment VM is
	// ready in that mode.
	defaultHealthTimeout = 90 * time.Second
	defaultPullTimeout   = 5 * time.Minute

	composeFileName   = "docker-compose.yaml"
	vmDataDir         = "vm-data"
	alloyConfigSubdir = "alloy-config"
	alloyConfigFile   = "config.alloy"
	lokiConfigSubdir  = "loki-config"
	lokiConfigFile    = "loki-config.yaml"
	lokiDataDir       = "loki-data"

	grafanaConfigSubdir = "grafana-config"
	grafanaIniFile      = "grafana.ini"
	grafanaDataDir      = "grafana-data"
)

// DockerComposeSupervisor manages the obs stack via `docker compose`.
type DockerComposeSupervisor struct {
	cfg    DockerComposeSupervisorConfig
	runner CmdRunner
	httpc  *http.Client
}

// NewDockerComposeSupervisor constructs the supervisor. StateDir is
// required; everything else has sensible defaults.
func NewDockerComposeSupervisor(cfg DockerComposeSupervisorConfig) (*DockerComposeSupervisor, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("obs supervisor: StateDir required")
	}
	if cfg.ProjectName == "" {
		cfg.ProjectName = defaultProjectName
	}
	if cfg.VMImage == "" {
		cfg.VMImage = defaultVMImage
	}
	if cfg.VMListenAddr == "" {
		cfg.VMListenAddr = defaultVMListenAddr
	}
	if cfg.VMRetention == "" {
		cfg.VMRetention = defaultVMRetention
	}
	if cfg.AlloyImage == "" {
		cfg.AlloyImage = defaultAlloyImage
	}
	if cfg.AlloyListenAddr == "" {
		cfg.AlloyListenAddr = defaultAlloyListenAddr
	}
	if cfg.EnableCadvisor == nil {
		t := true
		cfg.EnableCadvisor = &t
	}
	if cfg.LokiImage == "" {
		cfg.LokiImage = defaultLokiImage
	}
	if cfg.LokiListenAddr == "" {
		cfg.LokiListenAddr = defaultLokiListenAddr
	}
	if cfg.EnableLoki == nil {
		t := true
		cfg.EnableLoki = &t
	}
	if cfg.GrafanaImage == "" {
		cfg.GrafanaImage = defaultGrafanaImage
	}
	if cfg.GrafanaListenAddr == "" {
		cfg.GrafanaListenAddr = defaultGrafanaListenAddr
	}
	if cfg.EnableGrafana == nil {
		t := true
		cfg.EnableGrafana = &t
	}
	if cfg.DockerBin == "" {
		cfg.DockerBin = defaultDockerBin
	}
	if cfg.HealthTimeout == 0 {
		cfg.HealthTimeout = defaultHealthTimeout
	}
	if cfg.PullTimeout == 0 {
		cfg.PullTimeout = defaultPullTimeout
	}
	runner := cfg.Runner
	if runner == nil {
		runner = execRunner
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	return &DockerComposeSupervisor{cfg: cfg, runner: runner, httpc: client}, nil
}

// execRunner is the default CmdRunner — runs the binary and returns its
// combined output. Errors include the captured output so logs surface why
// docker rejected an invocation.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// ----- Lifecycle ----------------------------------------------------------

// Start brings the obs stack up. Order of operations:
//
//  1. Render compose.yaml + ensure data subdirs exist.
//  2. `docker compose pull` to bring images down (idempotent — no-op if
//     local cache satisfies).
//  3. `docker compose up -d` to create + start every service.
//  4. Poll VM's /health until 2xx or HealthTimeout.
func (s *DockerComposeSupervisor) Start(ctx context.Context) error {
	if err := s.prepareHostDirs(); err != nil {
		return err
	}
	if err := s.writeAlloyConfig(); err != nil {
		return err
	}
	if s.lokiEnabled() {
		if err := s.writeLokiConfig(); err != nil {
			return err
		}
	}
	if s.grafanaEnabled() {
		if err := s.writeGrafanaConfig(); err != nil {
			return err
		}
	}
	if err := s.writeCompose(); err != nil {
		return err
	}
	pullCtx, pullCancel := context.WithTimeout(ctx, s.cfg.PullTimeout)
	if _, err := s.compose(pullCtx, "pull"); err != nil {
		pullCancel()
		// `compose pull` failure on a private registry / offline host is
		// recoverable if the image is already cached — `up -d` will
		// succeed. Log and continue; if `up` then fails, that's the real
		// signal.
		log.Printf("obs supervisor: compose pull failed (continuing): %v", err)
	} else {
		pullCancel()
	}
	if _, err := s.compose(ctx, "up", "-d", "--remove-orphans"); err != nil {
		return fmt.Errorf("docker compose up: %w", err)
	}
	return s.waitHealthy(ctx)
}

// Stop issues `docker compose stop`. Volumes / data persist.
func (s *DockerComposeSupervisor) Stop(ctx context.Context) error {
	if _, err := s.compose(ctx, "stop"); err != nil {
		return fmt.Errorf("docker compose stop: %w", err)
	}
	return nil
}

// Healthy probes VM's /health. Returns (false, nil) — not an error — when
// VM is unreachable or unhealthy, so callers can treat "not healthy" as a
// data state rather than a failure mode.
func (s *DockerComposeSupervisor) Healthy(ctx context.Context) (bool, error) {
	ok, err := s.vmHealth(ctx)
	if err != nil {
		return false, nil
	}
	return ok, nil
}

// VMBaseURL returns the host-side base URL VM is reachable at — e.g.
// "http://127.0.0.1:8428". Used by the metrics fan-out sink to construct
// the remote-write URL.
func (s *DockerComposeSupervisor) VMBaseURL() string {
	return "http://" + s.cfg.VMListenAddr
}

// LokiBaseURL returns the host-side base URL Loki is reachable at, or
// "" when Loki is disabled. Used by /api/obs/logs to proxy LogQL.
func (s *DockerComposeSupervisor) LokiBaseURL() string {
	if !s.lokiEnabled() {
		return ""
	}
	return "http://" + s.cfg.LokiListenAddr
}

// GrafanaBaseURL returns the host-side base URL Grafana is reachable
// at, or "" when Grafana is disabled. Used by the api's
// /observability/* reverse proxy.
func (s *DockerComposeSupervisor) GrafanaBaseURL() string {
	if !s.grafanaEnabled() {
		return ""
	}
	return "http://" + s.cfg.GrafanaListenAddr
}

// ----- Compose invocations ------------------------------------------------

// compose invokes `docker compose -p <project> -f <file> <args...>`.
// Centralised so the project + file flags are consistent everywhere.
func (s *DockerComposeSupervisor) compose(ctx context.Context, args ...string) ([]byte, error) {
	composePath := filepath.Join(s.cfg.StateDir, composeFileName)
	full := append([]string{"compose", "-p", s.cfg.ProjectName, "-f", composePath}, args...)
	return s.runner(ctx, s.cfg.DockerBin, full...)
}

// ----- Host state + config ------------------------------------------------

func (s *DockerComposeSupervisor) prepareHostDirs() error {
	subs := []string{vmDataDir, alloyConfigSubdir}
	if s.lokiEnabled() {
		subs = append(subs, lokiConfigSubdir, lokiDataDir)
	}
	if s.grafanaEnabled() {
		subs = append(subs,
			grafanaConfigSubdir,
			filepath.Join(grafanaConfigSubdir, "provisioning", "datasources"),
			filepath.Join(grafanaConfigSubdir, "provisioning", "dashboards"),
			filepath.Join(grafanaConfigSubdir, "dashboards"),
			grafanaDataDir,
		)
	}
	for _, sub := range subs {
		p := filepath.Join(s.cfg.StateDir, sub)
		if err := os.MkdirAll(p, 0o755); err != nil {
			return fmt.Errorf("obs supervisor: mkdir %s: %w", p, err)
		}
	}
	// Grafana wants the data dir owned by uid 472 (grafana user). Trying
	// to chown to a specific uid would break tests + cross-platform; we
	// chmod 0o777 instead, which is fine for a homelab-scope dir that's
	// never on a shared filesystem.
	if s.grafanaEnabled() {
		_ = os.Chmod(filepath.Join(s.cfg.StateDir, grafanaDataDir), 0o777)
	}
	return nil
}

// lokiEnabled is a small accessor so the rest of the package doesn't
// have to chase the (nil-vs-pointer)? shape of EnableLoki everywhere.
func (s *DockerComposeSupervisor) lokiEnabled() bool {
	return s.cfg.EnableLoki != nil && *s.cfg.EnableLoki
}

// cadvisorEnabled mirrors lokiEnabled — single-source-of-truth for the
// "is this optional component on" question.
func (s *DockerComposeSupervisor) cadvisorEnabled() bool {
	return s.cfg.EnableCadvisor != nil && *s.cfg.EnableCadvisor
}

// grafanaEnabled — single-source-of-truth for the dashboard service.
func (s *DockerComposeSupervisor) grafanaEnabled() bool {
	return s.cfg.EnableGrafana != nil && *s.cfg.EnableGrafana
}

// writeLokiConfig renders Loki's YAML config into <StateDir>/loki-config/.
// Loki picks up config-file changes on reload (SIGHUP) only; the simpler
// path is to let `docker compose up -d` recreate the container when the
// file content changes, which the next Start does for free.
func (s *DockerComposeSupervisor) writeLokiConfig() error {
	out := filepath.Join(s.cfg.StateDir, lokiConfigSubdir, lokiConfigFile)
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, []byte(lokiConfigYAML), 0o644); err != nil {
		return fmt.Errorf("obs supervisor: write %s: %w", tmp, err)
	}
	return os.Rename(tmp, out)
}

// lokiConfigYAML is a minimal single-instance Loki config — filesystem
// storage, no replication, no auth, TSDB index. Fine for homelab scale
// (think MB/day, not TB/day); when a real Loki cluster is needed, the
// shape switches to k3s + the Loki distributed chart and this file
// goes away.
//
// Why ship it as a static string instead of a template: every field
// here is fixed — paths inside the container, schema version, listen
// port. No per-installation knobs to interpolate. If that changes
// (custom retention, S3 backend, etc.) it'll become a template.
// writeGrafanaConfig lays down grafana.ini, datasource provisioning,
// dashboard provisioning, and the starter dashboard JSON.
//
// Grafana's "provisioning" feature reads YAML/JSON at startup; the api
// owning the lifecycle of these files (regenerating on Start) keeps
// Grafana stateless from the operator's perspective — no point-and-click
// setup the first time obs is enabled.
func (s *DockerComposeSupervisor) writeGrafanaConfig() error {
	pairs := []struct {
		path string
		body string
	}{
		{filepath.Join(grafanaConfigSubdir, grafanaIniFile), grafanaIni},
		{filepath.Join(grafanaConfigSubdir, "provisioning", "datasources", "all.yaml"), grafanaDatasourcesYAML},
		{filepath.Join(grafanaConfigSubdir, "provisioning", "dashboards", "all.yaml"), grafanaDashboardsYAML},
		{filepath.Join(grafanaConfigSubdir, "dashboards", "cluster-overview.json"), starterDashboardJSON},
	}
	for _, p := range pairs {
		full := filepath.Join(s.cfg.StateDir, p.path)
		tmp := full + ".tmp"
		if err := os.WriteFile(tmp, []byte(p.body), 0o644); err != nil {
			return fmt.Errorf("obs supervisor: write %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, full); err != nil {
			return fmt.Errorf("obs supervisor: rename %s: %w", tmp, err)
		}
	}
	return nil
}

// grafanaIni — Slice 1.4 main Grafana config. Two non-default knobs:
//
//   - [server] serve_from_sub_path = true + root_url path so the
//     api's /observability/* reverse proxy mounts cleanly.
//   - [auth.proxy] enabled = true + header_name = X-Webauth-User.
//     The api validates the operator's session cookie, then forwards
//     the request to Grafana with the user's name in this header.
//     auto_sign_up creates the Grafana user on first sight.
//
// allow_sign_up = false everywhere else — we don't want a sneak path
// past the api's auth via Grafana's own login form.
const grafanaIni = `# Generated by rasputin-api obs.DockerComposeSupervisor — do not hand-edit.
# Edits get clobbered on the next supervisor Start.

[server]
http_port = 3000
domain = localhost
root_url = %(protocol)s://%(domain)s/observability/
serve_from_sub_path = true

[security]
admin_user = admin
admin_password = rasputin-admin

[users]
allow_sign_up = false
auto_assign_org = true
auto_assign_org_role = Viewer

[auth]
disable_login_form = true
disable_signout_menu = true

[auth.anonymous]
enabled = false

[auth.basic]
enabled = false

[auth.proxy]
enabled = true
header_name = X-Webauth-User
header_property = username
auto_sign_up = true
sync_ttl = 60
whitelist =
headers =
enable_login_token = false

[log]
mode = console
level = warn
`

const grafanaDatasourcesYAML = `# Generated by rasputin-api obs.DockerComposeSupervisor — do not hand-edit.
apiVersion: 1
datasources:
  - name: VictoriaMetrics
    type: prometheus
    access: proxy
    url: http://victoriametrics:8428
    isDefault: true
    editable: false
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    editable: false
`

const grafanaDashboardsYAML = `# Generated by rasputin-api obs.DockerComposeSupervisor — do not hand-edit.
apiVersion: 1
providers:
  - name: rasputin
    orgId: 1
    folder: Rasputin
    type: file
    disableDeletion: false
    editable: true
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
`

// starterDashboardJSON is the "Cluster Overview" dashboard — three
// stat panels backed by the rasputin_* metrics that VMSink writes.
// Intentionally minimal: the goal is "operator sees something useful
// the first time they open /observability", not "comprehensive
// dashboard suite". The folder-provisioning hook (allowUiUpdates =
// true) lets them edit and save without our overwriting their changes.
const starterDashboardJSON = `{
  "title": "Cluster Overview",
  "uid": "rasputin-cluster-overview",
  "schemaVersion": 39,
  "version": 1,
  "refresh": "30s",
  "tags": ["rasputin"],
  "panels": [
    {
      "type": "timeseries",
      "title": "CPU % per node",
      "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
      "targets": [{"expr": "rasputin_cpu_percent", "legendFormat": "{{nodeId}}"}],
      "gridPos": {"x": 0, "y": 0, "w": 12, "h": 8}
    },
    {
      "type": "timeseries",
      "title": "Memory used (bytes) per node",
      "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
      "targets": [{"expr": "rasputin_mem_used_bytes", "legendFormat": "{{nodeId}}"}],
      "gridPos": {"x": 12, "y": 0, "w": 12, "h": 8}
    },
    {
      "type": "stat",
      "title": "Nodes reporting",
      "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
      "targets": [{"expr": "count(rasputin_cpu_percent)"}],
      "gridPos": {"x": 0, "y": 8, "w": 6, "h": 4}
    }
  ]
}
`

const lokiConfigYAML = `# Generated by rasputin-api obs.DockerComposeSupervisor — do not hand-edit.
# Edits get clobbered on the next supervisor Start.

auth_enabled: false

server:
  http_listen_port: 3100
  log_level: warn

common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    instance_addr: 127.0.0.1
    kvstore:
      store: inmemory

schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

limits_config:
  allow_structured_metadata: true
  reject_old_samples: true
  reject_old_samples_max_age: 168h
`

// writeAlloyConfig renders config.alloy into <StateDir>/alloy-config/.
// Alloy auto-reloads on file change (no SIGHUP needed) so subsequent
// supervisor Starts pick up template changes without container restarts.
func (s *DockerComposeSupervisor) writeAlloyConfig() error {
	rendered, err := s.renderAlloyConfig()
	if err != nil {
		return err
	}
	out := filepath.Join(s.cfg.StateDir, alloyConfigSubdir, alloyConfigFile)
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, rendered, 0o644); err != nil {
		return fmt.Errorf("obs supervisor: write %s: %w", tmp, err)
	}
	return os.Rename(tmp, out)
}

func (s *DockerComposeSupervisor) renderAlloyConfig() ([]byte, error) {
	data := alloyConfigData{
		EnableCadvisor: s.cadvisorEnabled(),
		EnableLoki:     s.lokiEnabled(),
	}
	var buf bytes.Buffer
	if err := alloyConfigTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render alloy config: %w", err)
	}
	return buf.Bytes(), nil
}

type alloyConfigData struct {
	EnableCadvisor bool
	EnableLoki     bool
}

// alloyConfigTmpl is the Slice 1.2 Alloy config in River syntax. It does
// two things in production:
//
//  1. Scrapes its own /metrics so Alloy's health (memory, components in
//     error state, samples in/out) lives in VM next to everything else.
//  2. Runs the prometheus.exporter.cadvisor component (embedded inside
//     Alloy — no extra container) and scrapes its targets. cAdvisor's
//     output is the per-container CPU / mem / network / disk that Slice
//     1.2 promises. Off when EnableCadvisor=false (env: RASPUTIN_OBS_ALLOY_CADVISOR=0).
//
// Slice 1.3 adds Loki components (loki.source.docker, loki.write); the
// template will grow in place rather than fork into a second file.
//
// Remote-write target is the in-network DNS name `victoriametrics` from
// the compose project network — works across runtimes without resolving
// the host's IP from inside the container.
var alloyConfigTmpl = template.Must(template.New("alloy-config").Parse(`// Generated by rasputin-api obs.DockerComposeSupervisor — do not hand-edit.
// Edits get clobbered on the next supervisor Start.

prometheus.remote_write "vm" {
  endpoint {
    url = "http://victoriametrics:8428/api/v1/write"
  }
}

prometheus.exporter.self "alloy" {}

prometheus.scrape "alloy_self" {
  targets    = prometheus.exporter.self.alloy.targets
  forward_to = [prometheus.remote_write.vm.receiver]
  scrape_interval = "15s"
}
{{- if .EnableCadvisor }}

prometheus.exporter.cadvisor "containers" {
  docker_only = true
}

prometheus.scrape "cadvisor" {
  targets    = prometheus.exporter.cadvisor.containers.targets
  forward_to = [prometheus.remote_write.vm.receiver]
  scrape_interval = "15s"
}
{{- end }}
{{- if .EnableLoki }}

// ----- Loki log shipping (Slice 1.3) -----
// loki.write hands every entry to Loki over the compose network. URL
// is the in-network DNS name so the operator's host-port mapping
// stays invisible to Alloy.
loki.write "local" {
  endpoint {
    url = "http://loki:3100/loki/api/v1/push"
  }
}

// Discover every running Docker container on the host. The result is a
// dynamic target list — new containers get tailed automatically, gone
// ones drop out. refresh_interval controls how often the discovery
// re-scans; 30s matches the agent's own poll cadence.
discovery.docker "containers" {
  host             = "unix:///var/run/docker.sock"
  refresh_interval = "30s"
}

// Relabel the discovery targets so each log stream carries useful
// labels in Loki: container name, image, and the project's compose
// service name. Keeps log search ergonomic ("{container=...}" instead
// of looking up container IDs).
discovery.relabel "containers" {
  targets = discovery.docker.containers.targets
  rule {
    source_labels = ["__meta_docker_container_name"]
    regex         = "/(.*)"
    target_label  = "container"
  }
  rule {
    source_labels = ["__meta_docker_container_log_stream"]
    target_label  = "stream"
  }
  rule {
    source_labels = ["__meta_docker_container_label_com_docker_compose_service"]
    target_label  = "compose_service"
  }
}

loki.source.docker "containers" {
  host       = "unix:///var/run/docker.sock"
  targets    = discovery.relabel.containers.output
  forward_to = [loki.write.local.receiver]
}
{{- end }}
`))

// writeCompose renders the compose YAML and writes it atomically. Re-runs
// overwrite — VM picks up flag changes on the next `compose up`.
func (s *DockerComposeSupervisor) writeCompose() error {
	rendered, err := s.renderCompose()
	if err != nil {
		return err
	}
	out := filepath.Join(s.cfg.StateDir, composeFileName)
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, rendered, 0o644); err != nil {
		return fmt.Errorf("obs supervisor: write %s: %w", tmp, err)
	}
	return os.Rename(tmp, out)
}

func (s *DockerComposeSupervisor) renderCompose() ([]byte, error) {
	vmHost, vmPort, err := net.SplitHostPort(s.cfg.VMListenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid VMListenAddr %q: %w", s.cfg.VMListenAddr, err)
	}
	if vmPort == "" {
		return nil, fmt.Errorf("invalid VMListenAddr %q: port required", s.cfg.VMListenAddr)
	}
	alloyHost, alloyPort, err := net.SplitHostPort(s.cfg.AlloyListenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid AlloyListenAddr %q: %w", s.cfg.AlloyListenAddr, err)
	}
	if alloyPort == "" {
		return nil, fmt.Errorf("invalid AlloyListenAddr %q: port required", s.cfg.AlloyListenAddr)
	}
	lokiHost, lokiPort, err := net.SplitHostPort(s.cfg.LokiListenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid LokiListenAddr %q: %w", s.cfg.LokiListenAddr, err)
	}
	if lokiPort == "" {
		return nil, fmt.Errorf("invalid LokiListenAddr %q: port required", s.cfg.LokiListenAddr)
	}
	grafanaHost, grafanaPort, err := net.SplitHostPort(s.cfg.GrafanaListenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid GrafanaListenAddr %q: %w", s.cfg.GrafanaListenAddr, err)
	}
	if grafanaPort == "" {
		return nil, fmt.Errorf("invalid GrafanaListenAddr %q: port required", s.cfg.GrafanaListenAddr)
	}
	data := composeData{
		VMImage:          s.cfg.VMImage,
		VMHost:           vmHost,
		VMPort:           vmPort,
		VMRetention:      s.cfg.VMRetention,
		VMDataDir:        "./" + vmDataDir,
		AlloyImage:       s.cfg.AlloyImage,
		AlloyHost:        alloyHost,
		AlloyPort:        alloyPort,
		AlloyConfigDir:   "./" + alloyConfigSubdir,
		AlloyConfigFile:  alloyConfigFile,
		EnableCadvisor:   s.cadvisorEnabled(),
		EnableLoki:       s.lokiEnabled(),
		LokiImage:        s.cfg.LokiImage,
		LokiHost:         lokiHost,
		LokiPort:         lokiPort,
		LokiConfigDir:    "./" + lokiConfigSubdir,
		LokiConfigFile:   lokiConfigFile,
		LokiDataDir:      "./" + lokiDataDir,
		EnableGrafana:    s.grafanaEnabled(),
		GrafanaImage:     s.cfg.GrafanaImage,
		GrafanaHost:      grafanaHost,
		GrafanaPort:      grafanaPort,
		GrafanaConfigDir: "./" + grafanaConfigSubdir,
		GrafanaDataDir:   "./" + grafanaDataDir,
	}
	var buf bytes.Buffer
	if err := composeTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render compose: %w", err)
	}
	return buf.Bytes(), nil
}

type composeData struct {
	VMImage          string
	VMHost           string
	VMPort           string
	VMRetention      string
	VMDataDir        string
	AlloyImage       string
	AlloyHost        string
	AlloyPort        string
	AlloyConfigDir   string
	AlloyConfigFile  string
	EnableCadvisor   bool
	EnableLoki       bool
	LokiImage        string
	LokiHost         string
	LokiPort         string
	LokiConfigDir    string
	LokiConfigFile   string
	LokiDataDir      string
	EnableGrafana    bool
	GrafanaImage     string
	GrafanaHost      string
	GrafanaPort      string
	GrafanaConfigDir string
	GrafanaDataDir   string
}

// composeTmpl is the Slice 1.1 compose YAML — VictoriaMetrics only.
// Subsequent slices add `loki`, `grafana`, and `alloy` services to this
// template under the same `services:` key. The shared bridge network is
// implicit (compose creates `<project>_default`).
//
// VM's flag set:
//   - storageDataPath: where the time-series live inside the container.
//   - retentionPeriod: how long to keep samples.
//   - httpListenAddr: bind inside the container. Always 0.0.0.0:port so
//     the host port mapping reaches it regardless of which interface the
//     daemon's bridge ends up using.
//   - search.latencyOffset=0s: VM defaults this to 30s to hide samples
//     mid-flight on scrape-style ingestion (Prometheus scrape windows can
//     produce partial reads inside their cycle). Rasputin pushes single
//     samples on the agent's 10s tick — each is fully committed at POST
//     time, so the offset only hurts: a `time=now()` query right after a
//     write returns empty for 30 seconds. Setting it to 0 makes PromQL
//     return data as soon as it's stored.
//
// `restart: unless-stopped` lets the Docker daemon (not us) handle crash
// recovery — simpler than reinventing it.
// VM listens on a FIXED internal port (8428) and Alloy listens on a
// FIXED internal port (12345). Only the host-side bind (VMListenAddr /
// AlloyListenAddr) varies per install — so peers inside the compose
// network can hard-code `victoriametrics:8428` and `alloy:12345` in
// their config without seeing the operator's host-port choice. Mirrors
// Headscale's "container always listens on 8080 internally" pattern in
// mesh/supervisor_docker.go.
var composeTmpl = template.Must(template.New("obs-compose").Parse(`# Generated by rasputin-api obs.DockerComposeSupervisor — do not hand-edit.
# Edits get clobbered on the next supervisor Start.
services:
  victoriametrics:
    image: {{.VMImage}}
    container_name: rasputin-victoriametrics
    restart: unless-stopped
    command:
      - "-storageDataPath=/storage"
      - "-retentionPeriod={{.VMRetention}}"
      - "-httpListenAddr=0.0.0.0:8428"
      - "-search.latencyOffset=0s"
    ports:
      - "{{.VMHost}}:{{.VMPort}}:8428"
    volumes:
      - {{.VMDataDir}}:/storage

  alloy:
    image: {{.AlloyImage}}
    container_name: rasputin-alloy
    restart: unless-stopped
    command:
      - run
      - --server.http.listen-addr=0.0.0.0:12345
      - /etc/alloy/{{.AlloyConfigFile}}
    ports:
      - "{{.AlloyHost}}:{{.AlloyPort}}:12345"
    volumes:
      - {{.AlloyConfigDir}}:/etc/alloy:ro
{{- if .EnableCadvisor }}
      # cAdvisor needs read access to the host's cgroup tree and the
      # Docker socket to enumerate containers. These are Linux paths;
      # Docker Desktop / OrbStack / Rancher Desktop expose the VM's
      # equivalents transparently on macOS / Windows.
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /sys:/sys:ro
      - /var/lib/docker:/var/lib/docker:ro
{{- end }}
    depends_on:
      - victoriametrics
{{- if .EnableLoki }}
      - loki

  loki:
    image: {{.LokiImage}}
    container_name: rasputin-loki
    restart: unless-stopped
    command:
      - "-config.file=/etc/loki/{{.LokiConfigFile}}"
    ports:
      - "{{.LokiHost}}:{{.LokiPort}}:3100"
    volumes:
      - {{.LokiConfigDir}}:/etc/loki:ro
      - {{.LokiDataDir}}:/loki
{{- end }}
{{- if .EnableGrafana }}

  grafana:
    image: {{.GrafanaImage}}
    container_name: rasputin-grafana
    restart: unless-stopped
    ports:
      - "{{.GrafanaHost}}:{{.GrafanaPort}}:3000"
    volumes:
      - {{.GrafanaConfigDir}}/grafana.ini:/etc/grafana/grafana.ini:ro
      - {{.GrafanaConfigDir}}/provisioning:/etc/grafana/provisioning:ro
      - {{.GrafanaConfigDir}}/dashboards:/var/lib/grafana/dashboards:ro
      - {{.GrafanaDataDir}}:/var/lib/grafana
    depends_on:
      - victoriametrics
{{- if .EnableLoki }}
      - loki
{{- end }}
{{- end }}
`))

// ----- Health -------------------------------------------------------------

// waitHealthy polls VM's /health (and Loki's /ready when enabled) every
// 500 ms until both are healthy or HealthTimeout fires. Loki added
// here so the supervisor doesn't claim "ready" while Loki is still
// booting — log-side consumers (Alloy's loki.write, /api/obs/logs)
// would otherwise see connection refused.
func (s *DockerComposeSupervisor) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(s.cfg.HealthTimeout)
	var lastErr error
	for {
		vmOK, vmErr := s.vmHealth(ctx)
		lokiOK := true
		var lokiErr error
		if s.lokiEnabled() {
			lokiOK, lokiErr = s.lokiReady(ctx)
		}
		grafanaOK := true
		var grafanaErr error
		if s.grafanaEnabled() {
			grafanaOK, grafanaErr = s.grafanaReady(ctx)
		}
		if vmOK && lokiOK && grafanaOK {
			return nil
		}
		switch {
		case !vmOK && vmErr != nil:
			lastErr = vmErr
		case !vmOK:
			lastErr = errors.New("vm /health returned non-2xx")
		case !lokiOK && lokiErr != nil:
			lastErr = fmt.Errorf("loki: %w", lokiErr)
		case !lokiOK:
			lastErr = errors.New("loki /ready returned non-2xx")
		case !grafanaOK && grafanaErr != nil:
			lastErr = fmt.Errorf("grafana: %w", grafanaErr)
		case !grafanaOK:
			lastErr = errors.New("grafana /api/health returned non-2xx")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("obs supervisor: stack not healthy after %s (last error: %w)",
				s.cfg.HealthTimeout, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// vmHealth does a single GET on VM's /health. VM answers 200 + plaintext
// "OK" once it's ready to accept queries / writes. A non-2xx is a "not
// ready yet" signal, not an error.
func (s *DockerComposeSupervisor) vmHealth(ctx context.Context) (bool, error) {
	return httpGet2xx(ctx, s.httpc, s.VMBaseURL()+"/health")
}

// lokiReady polls Loki's /ready endpoint, which returns 200 when the
// ingester is ready to accept writes. /ready is the canonical Loki
// readiness gate; /metrics responds even when the ingester isn't ready
// yet (so it's a worse choice).
func (s *DockerComposeSupervisor) lokiReady(ctx context.Context) (bool, error) {
	return httpGet2xx(ctx, s.httpc, s.LokiBaseURL()+"/ready")
}

// grafanaReady polls Grafana's /api/health. Returns 200 + JSON body
// {"database":"ok","version":"..."} once it's accepting requests.
func (s *DockerComposeSupervisor) grafanaReady(ctx context.Context) (bool, error) {
	return httpGet2xx(ctx, s.httpc, s.GrafanaBaseURL()+"/api/health")
}

func httpGet2xx(ctx context.Context, client *http.Client, url string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}
