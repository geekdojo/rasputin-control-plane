package obs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// answers 2xx. This is VICTORIAMETRICS-ONLY on purpose: it gates the
	// metrics fan-out ("is it worth trying to remote-write?"), and metrics
	// must keep flowing to VM even when Loki or Grafana are down — they're
	// independent stores. Do NOT widen this to the whole stack; use
	// StackReady for "is everything up?".
	Healthy(ctx context.Context) (bool, error)

	// StackReady is a one-shot check that EVERY enabled service is ready
	// (VM /health + Loki /ready if enabled + Grafana /api/health if
	// enabled). Unlike Healthy it reflects the whole stack, and unlike
	// waitHealthy it doesn't poll — it answers "right now, is the operator's
	// obs actually working end to end?" for /api/obs/status. A partial
	// failure (VM up, Loki dead) returns false here while Healthy stays
	// true, which is exactly the distinction that keeps the UI from showing
	// a green "recording" while a sidecar is crash-looping.
	StackReady(ctx context.Context) (bool, error)
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
func NewNoopSupervisor() Supervisor                             { return NoopSupervisor{} }
func (NoopSupervisor) Start(context.Context) error              { return nil }
func (NoopSupervisor) Stop(context.Context) error               { return nil }
func (NoopSupervisor) Healthy(context.Context) (bool, error)    { return false, nil }
func (NoopSupervisor) StackReady(context.Context) (bool, error) { return false, nil }
func (NoopSupervisor) VMBaseURL() string                        { return "" }
func (NoopSupervisor) LokiBaseURL() string                      { return "" }
func (NoopSupervisor) GrafanaBaseURL() string                   { return "" }

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

	// VMMinFreeDiskSpace is the `-storage.minFreeDiskSpaceBytes` flag.
	// Once free space on the partition drops below it, VM stops accepting
	// new samples rather than filling the disk. Defaults to "2GB"; accepts
	// VM's size suffixes (KB/MB/GB/TB, KiB/MiB/GiB/TiB).
	//
	// This is *back-pressure, not eviction* — old samples are kept and new
	// ones are refused. That's the deliberate trade: a blind metrics store
	// is recoverable, a wedged SQLite DB is an outage.
	//
	// Note this is NOT the size-cap storage.md §5 originally specified. That
	// policy called for `-retentionSize`, which does not exist in
	// VictoriaMetrics OSS at any version (it's Prometheus's
	// --storage.tsdb.retention.size). Free-space reservation turns out to be
	// the better fit anyway: a per-directory cap would only bound VM's own
	// footprint, whereas this watches the whole shared partition — so
	// bundles, app volumes and Docker images all count toward the headroom
	// it defends.
	VMMinFreeDiskSpace string

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

	// LokiRetention is how long log lines are kept — rendered into
	// limits_config.retention_period and enforced by the compactor.
	// Defaults to "720h" (30d). Must be a Go duration in hours or larger;
	// Loki rejects retention below 24h.
	//
	// Before this existed Loki ran with no retention at all and kept every
	// line forever, which made it the largest unbounded tenant on the
	// controlplane's shared partition. Loki has no free-space guard (no
	// equivalent of VM's -storage.minFreeDiskSpaceBytes), so this plus the
	// 85% DiskAlmostFull alert is the entire defense — see storage.md §5.
	LokiRetention string

	// EnableLoki toggles the Loki service + Alloy's log-shipping
	// components. Default true. Off lets operators run a metrics-only
	// obs stack — useful when an external log aggregator is already
	// in play.
	EnableLoki *bool

	// IDSLogDir is the host directory containing the api's IDS-alert
	// JSONL (api/internal/ids.Writer's parent dir). The Alloy container
	// mounts it read-only at /var/log/rasputin/ so loki.source.file can
	// tail the alert stream and ship to Loki with labels {job=rasputin-ids,
	// node_id=...}. Empty (default) disables the IDS pipe.
	//
	// Convention: <dataDir>/obs/ids-alerts. The api wires it; the
	// supervisor just mounts it.
	IDSLogDir string

	// EnableIDSPipe toggles Alloy's loki.source.file → loki.process →
	// loki.write chain for the IDS-alert JSONL. Implicitly requires
	// EnableLoki. Default true when both EnableLoki=true AND IDSLogDir
	// is non-empty — operators get the IDS pipe automatically as soon
	// as they wire the api side. Forced off by setting *EnableIDSPipe=false
	// or leaving IDSLogDir empty.
	EnableIDSPipe *bool

	// GrafanaImage overrides the Grafana image reference. Defaults to
	// the pinned upstream tag. Grafana joins the stack at Slice 1.4
	// and is reached via the api's auth-proxy at /observability/*.
	GrafanaImage string

	// GrafanaListenAddr is the host bind for Grafana's HTTP listener.
	// Defaults to "127.0.0.1:13000"; container listens on 3000
	// internally regardless of the host bind (see renderCompose's
	// fixed in-container ports). Loopback only because the auth-proxy
	// is what makes Grafana safe to expose — direct access bypasses
	// Rasputin's session auth. The host port avoids 3000 deliberately
	// because every JS dev server defaults to it.
	GrafanaListenAddr string

	// EnableGrafana toggles the Grafana service. Default true. Off
	// gives a metrics + logs stack without the dashboard UI — useful
	// for operators using an existing Grafana elsewhere.
	EnableGrafana *bool

	// VMAlertImage overrides the vmalert image reference. Defaults to
	// the pinned upstream tag. vmalert evaluates the Slice 1.5
	// starter-rules YAML against VM and POSTs Alertmanager-format
	// notifications to AlertsWebhookURL.
	VMAlertImage string

	// AlertsWebhookURL is where vmalert POSTs alerts. Defaults to
	// http://host.docker.internal:8080/api/alerts/webhook — the api
	// running on the controlplane host. Operators on Linux without
	// host.docker.internal can set this to the controlplane's LAN IP.
	AlertsWebhookURL string

	// AlertsWebhookSecret is sent in the X-Webhook-Secret header on
	// every vmalert POST. Empty (default) disables the header. Must
	// match RASPUTIN_ALERTS_WEBHOOK_SECRET on the api side.
	AlertsWebhookSecret string

	// EnableVMAlert toggles the vmalert service. Default true. Off
	// gives a metrics + logs + dashboards stack without alerting —
	// useful while operators are tuning rules.
	EnableVMAlert *bool

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
	defaultProjectName  = "rasputin-obs"
	defaultVMImage      = "victoriametrics/victoria-metrics:v1.103.0"
	defaultVMListenAddr = "127.0.0.1:8428"
	defaultVMRetention  = "1y"
	// defaultVMMinFreeDiskSpace reserves 2 GB of the controlplane's single
	// writable partition. VM refuses new samples once free space drops below
	// this, which is what keeps a growing metrics store from taking the
	// SQLite DB down with it — see storage.md §5. VM's own default is 10 MB,
	// i.e. effectively no protection at all on a shared partition.
	//
	// 2 GB against the documented 64 GB floor (~3%) is enough headroom for
	// SQLite to keep committing, a job ledger to keep writing, and the
	// operator to delete a staged bundle. It sits far below the 85%
	// DiskAlmostFull alert, so the alert always fires first and this is a
	// backstop, not the primary signal.
	defaultVMMinFreeDiskSpace = "2GB"
	defaultAlloyImage         = "grafana/alloy:v1.4.2"
	defaultAlloyListenAddr    = "127.0.0.1:12345"
	defaultLokiImage          = "grafana/loki:3.4.1"
	defaultLokiListenAddr     = "127.0.0.1:3100"
	// defaultLokiRetention bounds how far back logs are kept. Loki shipped
	// with NO retention configured at all — no compactor, no
	// retention_period — so it kept every log line forever. On the
	// controlplane's shared partition that is the single largest unbounded
	// tenant: log volume dwarfs metrics.
	//
	// 30d (720h) covers "what happened last month" without unbounded growth.
	// Unlike VM there is no free-space guard available — Loki has no
	// equivalent of -storage.minFreeDiskSpaceBytes — so time retention plus
	// the 85% alert is the whole defense. See storage.md §5.
	defaultLokiRetention = "720h"
	defaultGrafanaImage  = "grafana/grafana:11.5.1"
	// 3000 is the most contended port on a dev box — Next.js, CRA,
	// Vite, every common JS framework defaults to it. Grafana's
	// own internal port stays 3000 (handled in renderCompose's
	// fixed container-port map); only the HOST bind moves. 13000 is
	// outside the registered-port range and well clear of the
	// stack's other ports (VM 8428, Loki 3100, Alloy 12345).
	defaultGrafanaListenAddr = "127.0.0.1:13000"
	defaultVMAlertImage      = "victoriametrics/vmalert:v1.103.0"
	defaultAlertsWebhookURL  = "http://host.docker.internal:8080/api/alerts/webhook"
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

	vmalertConfigSubdir = "vmalert-config"
	vmalertRulesFile    = "rules.yml"
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
	if cfg.VMMinFreeDiskSpace == "" {
		cfg.VMMinFreeDiskSpace = defaultVMMinFreeDiskSpace
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
	if cfg.LokiRetention == "" {
		cfg.LokiRetention = defaultLokiRetention
	}
	if cfg.EnableLoki == nil {
		t := true
		cfg.EnableLoki = &t
	}
	if cfg.IDSLogDir != "" {
		// Compose only reads a volume source as a BIND MOUNT when it's an
		// absolute path (or starts with ./ — which then resolves against the
		// project dir, not our cwd, so it'd be wrong here anyway). A bare
		// relative source like "data/obs/ids-alerts" is parsed as a *named
		// volume* and the whole project is rejected:
		//
		//   service "alloy" refers to undefined volume data/obs/ids-alerts
		//
		// dataDir is relative in dev (./data) and absolute on an appliance
		// (/var/lib/rasputin), so this only ever bit dev — and dev couldn't
		// reach obs at all until it became UI-toggleable. Normalize here
		// rather than trusting every caller to pass an absolute path.
		abs, err := filepath.Abs(cfg.IDSLogDir)
		if err != nil {
			return nil, fmt.Errorf("obs supervisor: resolve IDSLogDir: %w", err)
		}
		cfg.IDSLogDir = abs
	}
	if cfg.EnableIDSPipe == nil {
		// Implicit-on when both Loki and an IDS log dir are configured.
		// Off otherwise — there's nothing to ship.
		on := *cfg.EnableLoki && cfg.IDSLogDir != ""
		cfg.EnableIDSPipe = &on
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
	if cfg.VMAlertImage == "" {
		cfg.VMAlertImage = defaultVMAlertImage
	}
	if cfg.AlertsWebhookURL == "" {
		cfg.AlertsWebhookURL = defaultAlertsWebhookURL
	}
	if cfg.EnableVMAlert == nil {
		t := true
		cfg.EnableVMAlert = &t
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
	if s.vmalertEnabled() {
		if err := s.writeVMAlertConfig(); err != nil {
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

// StackReady checks every enabled service once (no polling) and reports
// whether all are ready. It's the one-shot sibling of waitHealthy — same
// per-service probes (vmHealth / lokiReady / grafanaReady), gated on the same
// enable flags — used by /api/obs/status to answer "is obs actually working
// right now?". A probe error is treated as not-ready (false, nil), never a
// hard error, so the status handler renders a data state rather than a 500.
func (s *DockerComposeSupervisor) StackReady(ctx context.Context) (bool, error) {
	if ok, err := s.vmHealth(ctx); err != nil || !ok {
		return false, nil
	}
	if s.lokiEnabled() {
		if ok, err := s.lokiReady(ctx); err != nil || !ok {
			return false, nil
		}
	}
	if s.grafanaEnabled() {
		if ok, err := s.grafanaReady(ctx); err != nil || !ok {
			return false, nil
		}
	}
	return true, nil
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
	if s.vmalertEnabled() {
		subs = append(subs, vmalertConfigSubdir)
	}
	for _, sub := range subs {
		p := filepath.Join(s.cfg.StateDir, sub)
		if err := os.MkdirAll(p, 0o755); err != nil {
			return fmt.Errorf("obs supervisor: mkdir %s: %w", p, err)
		}
	}
	// Data dirs a NON-ROOT container user must write to.
	//
	// Docker bind-mounts preserve host ownership. The api creates these dirs
	// as its own user (root on the appliance) at 0755, but these images run
	// as fixed non-root uids — grafana=472, loki=10001 — so a root-owned 0755
	// dir denies them write and the container crashes at boot. Loki's failure
	// mode is a bare "connection refused" on :3100 because it dies before
	// binding.
	//
	// This only bites on a REAL appliance: Docker/Rancher Desktop mask it via
	// the VM's uid remapping, so a dev box (and CI) never sees it. It cost a
	// bench cycle 2026-07-17 — Loki was the one obs service that had never run
	// on real hardware until the UI toggle made obs reachable, and it went
	// straight into this. Grafana had the workaround since Slice 1.4; Loki
	// (Slice 1.3) was missed because nothing exercised it on native Docker.
	//
	// chmod 0o777 rather than chown to a specific uid: chown would break tests
	// and differ per platform, and this is a homelab-scope local dir that's
	// never on a shared filesystem. Any future sidecar with a writable data
	// dir and a non-root user belongs in this list.
	nonRootDataDirs := []string{}
	if s.grafanaEnabled() {
		nonRootDataDirs = append(nonRootDataDirs, grafanaDataDir)
	}
	if s.lokiEnabled() {
		nonRootDataDirs = append(nonRootDataDirs, lokiDataDir)
	}
	for _, d := range nonRootDataDirs {
		if err := os.Chmod(filepath.Join(s.cfg.StateDir, d), 0o777); err != nil {
			return fmt.Errorf("obs supervisor: chmod %s writable for non-root container: %w", d, err)
		}
	}
	return nil
}

// lokiEnabled is a small accessor so the rest of the package doesn't
// have to chase the (nil-vs-pointer)? shape of EnableLoki everywhere.
func (s *DockerComposeSupervisor) lokiEnabled() bool {
	return s.cfg.EnableLoki != nil && *s.cfg.EnableLoki
}

// idsPipeEnabled reports whether Alloy should tail+ship the IDS-alert
// JSONL. Requires Loki on AND a non-empty IDSLogDir — the dir is what
// gets mounted into Alloy at /var/log/rasputin.
func (s *DockerComposeSupervisor) idsPipeEnabled() bool {
	if s.cfg.EnableIDSPipe == nil || !*s.cfg.EnableIDSPipe {
		return false
	}
	return s.lokiEnabled() && s.cfg.IDSLogDir != ""
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

// vmalertEnabled — single-source-of-truth for the alerting service.
func (s *DockerComposeSupervisor) vmalertEnabled() bool {
	return s.cfg.EnableVMAlert != nil && *s.cfg.EnableVMAlert
}

// writeLokiConfig renders Loki's YAML config into <StateDir>/loki-config/.
// Loki picks up config-file changes on reload (SIGHUP) only; the simpler
// path is to let `docker compose up -d` recreate the container when the
// file content changes, which the next Start does for free.
func (s *DockerComposeSupervisor) writeLokiConfig() error {
	var buf bytes.Buffer
	if err := lokiConfigTmpl.Execute(&buf, struct{ Retention string }{
		Retention: s.cfg.LokiRetention,
	}); err != nil {
		return fmt.Errorf("obs supervisor: render loki config: %w", err)
	}
	out := filepath.Join(s.cfg.StateDir, lokiConfigSubdir, lokiConfigFile)
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("obs supervisor: write %s: %w", tmp, err)
	}
	return os.Rename(tmp, out)
}

// lokiConfigTmpl is a minimal single-instance Loki config — filesystem
// storage, no replication, no auth, TSDB index. Fine for homelab scale
// (think MB/day, not TB/day); when a real Loki cluster is needed, the
// shape switches to k3s + the Loki distributed chart and this file
// goes away.
//
// This was a static string until retention landed — the old comment here
// said it would "become a template" if custom retention ever arrived. It
// did, so it is.
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
# allow_embedding lets the UI's <iframe src="/observability/..."> render
# the dashboards. Default is X-Frame-Options=DENY which kills the embed.
# The auth-proxy is what makes this safe — only session-authenticated
# requests ever reach Grafana, regardless of which origin's frame.
allow_embedding = true

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

// writeVMAlertConfig lays down the rules YAML into
// <StateDir>/vmalert-config/. vmalert reloads on SIGHUP; the simpler
// path (matching every other config we manage) is to re-deploy on
// supervisor Start.
func (s *DockerComposeSupervisor) writeVMAlertConfig() error {
	out := filepath.Join(s.cfg.StateDir, vmalertConfigSubdir, vmalertRulesFile)
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, []byte(vmalertRulesYAML), 0o644); err != nil {
		return fmt.Errorf("obs supervisor: write %s: %w", tmp, err)
	}
	return os.Rename(tmp, out)
}

// vmalertRulesYAML is the Slice 1.5 starter rule set. Three rules,
// each scoped to homelab thresholds:
//
//   - NodeDown — node hasn't reported metrics in 5m. absent_over_time
//     fires when the series goes silent, which matches the agent's
//     "stale > 2m, offline > 30s" heartbeat semantics.
//   - HighCPU  — sustained CPU > 90% for 5m. Tuned for a homelab
//     where short spikes (apt-get update, docker pull) are normal
//     but a sustained burn means something's wrong.
//   - DiskAlmostFull — root disk > 85%. Below the 90% mark Linux
//     starts losing performance on ext4, gives the operator time to
//     clean up.
//
// All three carry severity: warning except NodeDown which is
// critical. The aggregator-derived "node-offline" alert and the
// rule's NodeDown will both fire for the same condition — Slice 1.5
// ships dedup as a future item; the wire shape carries enough labels
// for the UI to dedup client-side if needed.
const vmalertRulesYAML = `# Generated by rasputin-api obs.DockerComposeSupervisor — do not hand-edit.
groups:
  - name: rasputin-default
    interval: 30s
    rules:
      - alert: NodeDown
        expr: absent_over_time(rasputin_cpu_percent[5m])
        for: 5m
        labels:
          severity: critical
          source: vmalert
        annotations:
          summary: "Node has not reported metrics in 5 minutes"
          description: "rasputin_cpu_percent absent for >5m — check the agent on the affected node."

      - alert: HighCPU
        expr: rasputin_cpu_percent > 90
        for: 5m
        labels:
          severity: warning
          source: vmalert
        annotations:
          summary: "Sustained CPU > 90% on {{$labels.nodeId}}"
          description: "rasputin_cpu_percent has been above 90% for 5+ minutes (current value: {{$value}})."

      - alert: DiskAlmostFull
        expr: (rasputin_disk_used_bytes / rasputin_disk_total_bytes) > 0.85
        for: 5m
        labels:
          severity: warning
          source: vmalert
        annotations:
          summary: "Root disk above 85% on {{$labels.nodeId}}"
          description: "rasputin_disk_used_bytes / rasputin_disk_total_bytes > 0.85 for 5+ minutes."
`

var lokiConfigTmpl = template.Must(template.New("loki-config").Parse(`# Generated by rasputin-api obs.DockerComposeSupervisor — do not hand-edit.
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
  # How far back logs are kept. Enforced by the compactor below; without
  # BOTH of these Loki keeps every line forever, which is how it shipped.
  retention_period: {{.Retention}}

compactor:
  working_directory: /loki/compactor
  # retention_enabled is the switch that makes retention_period real. It is
  # off by default, and a retention_period set without it is silently
  # ignored — the trap that let logs accumulate unbounded.
  retention_enabled: true
  # Required once retention is on: where deletion requests are journaled.
  # Loki refuses to start with retention_enabled and no store configured.
  delete_request_store: filesystem
  compaction_interval: 10m
  # Grace window between a chunk falling out of retention and its deletion,
  # so an in-flight query doesn't lose its chunks mid-read.
  retention_delete_delay: 2h
  retention_delete_worker_count: 50
`))

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
		EnableIDSPipe:  s.idsPipeEnabled(),
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
	EnableIDSPipe  bool
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
{{- if .EnableIDSPipe }}

// ----- IDS alert pipe (snort3 → bus → api JSONL → here → Loki) -----
// The api's ids.Writer appends one JSON line per snort alert to
// /var/log/rasputin/alerts.jsonl (the supervisor mounts the host dir
// read-only). loki.process pulls nodeId out of the JSON so the UI
// can query {job="rasputin-ids", node_id="fw-1"} without scanning
// every node's alerts.
loki.source.file "ids_alerts" {
  targets = [
    {"__path__" = "/var/log/rasputin/alerts.jsonl", "job" = "rasputin-ids"},
  ]
  forward_to = [loki.process.ids_alerts.receiver]
}

loki.process "ids_alerts" {
  forward_to = [loki.write.local.receiver]

  stage.json {
    expressions = {nodeId = "nodeId", sid = "sid", priority = "priority"}
  }

  stage.labels {
    values = {node_id = "nodeId"}
  }
}
{{- end }}
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

// configHash returns a short digest of the given rendered config files, or ""
// if none are readable. It exists to force `docker compose up -d` to actually
// recreate a container when its config changes.
//
// Compose decides whether to recreate a service by hashing its *definition*
// (image, command, env, volume declarations) — NOT the contents of the files
// those volumes bind-mount. So editing loki-config.yaml and re-running
// `compose up -d` leaves the old container running with the old config, and
// the change silently does nothing. Verified 2026-07-16 on Rancher Desktop:
// same container id, uptime uninterrupted, live /config still serving the
// previous retention while the file on disk said otherwise.
//
// The api normally papers over this because a graceful shutdown stops the
// stack, so the next Start's `up` boots a fresh process that re-reads the
// file. But that's luck, not mechanism: kill the api ungracefully (crash,
// OOM, SIGKILL) and the containers keep running, so the next Start silently
// keeps the stale config. Feeding this digest into each service's
// environment makes the definition change with the file, which is what
// Kubernetes does with checksum/config annotations for the same reason.
func configHash(paths ...string) string {
	h := sha256.New()
	any := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue // not rendered (service disabled) — contributes nothing
		}
		any = true
		_, _ = h.Write([]byte(p))
		_, _ = h.Write(b)
	}
	if !any {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
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
		VMImage:            s.cfg.VMImage,
		VMHost:             vmHost,
		VMPort:             vmPort,
		VMRetention:        s.cfg.VMRetention,
		VMMinFreeDiskSpace: s.cfg.VMMinFreeDiskSpace,
		VMDataDir:          "./" + vmDataDir,
		// Digests of the configs each service bind-mounts. Start renders every
		// config file before calling renderCompose, so these read back what was
		// just written. VictoriaMetrics needs none — all of its knobs are
		// command-line flags, which compose already hashes as part of the
		// service definition.
		AlloyConfigHash: configHash(
			filepath.Join(s.cfg.StateDir, alloyConfigSubdir, alloyConfigFile)),
		LokiConfigHash: configHash(
			filepath.Join(s.cfg.StateDir, lokiConfigSubdir, lokiConfigFile)),
		GrafanaConfigHash: configHash(
			filepath.Join(s.cfg.StateDir, grafanaConfigSubdir, grafanaIniFile)),
		VMAlertConfigHash: configHash(
			filepath.Join(s.cfg.StateDir, vmalertConfigSubdir, vmalertRulesFile)),
		AlloyImage:          s.cfg.AlloyImage,
		AlloyHost:           alloyHost,
		AlloyPort:           alloyPort,
		AlloyConfigDir:      "./" + alloyConfigSubdir,
		AlloyConfigFile:     alloyConfigFile,
		EnableCadvisor:      s.cadvisorEnabled(),
		EnableLoki:          s.lokiEnabled(),
		EnableIDSPipe:       s.idsPipeEnabled(),
		IDSLogHostDir:       s.cfg.IDSLogDir,
		LokiImage:           s.cfg.LokiImage,
		LokiHost:            lokiHost,
		LokiPort:            lokiPort,
		LokiConfigDir:       "./" + lokiConfigSubdir,
		LokiConfigFile:      lokiConfigFile,
		LokiDataDir:         "./" + lokiDataDir,
		EnableGrafana:       s.grafanaEnabled(),
		GrafanaImage:        s.cfg.GrafanaImage,
		GrafanaHost:         grafanaHost,
		GrafanaPort:         grafanaPort,
		GrafanaConfigDir:    "./" + grafanaConfigSubdir,
		GrafanaDataDir:      "./" + grafanaDataDir,
		EnableVMAlert:       s.vmalertEnabled(),
		VMAlertImage:        s.cfg.VMAlertImage,
		VMAlertConfigDir:    "./" + vmalertConfigSubdir,
		VMAlertRulesFile:    vmalertRulesFile,
		AlertsWebhookURL:    s.cfg.AlertsWebhookURL,
		AlertsWebhookSecret: s.cfg.AlertsWebhookSecret,
	}
	var buf bytes.Buffer
	if err := composeTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render compose: %w", err)
	}
	return buf.Bytes(), nil
}

type composeData struct {
	VMImage             string
	VMHost              string
	VMPort              string
	VMRetention         string
	VMMinFreeDiskSpace  string
	AlloyConfigHash     string
	LokiConfigHash      string
	GrafanaConfigHash   string
	VMAlertConfigHash   string
	VMDataDir           string
	AlloyImage          string
	AlloyHost           string
	AlloyPort           string
	AlloyConfigDir      string
	AlloyConfigFile     string
	EnableCadvisor      bool
	EnableLoki          bool
	EnableIDSPipe       bool
	IDSLogHostDir       string // absolute host path, mounted into Alloy at /var/log/rasputin
	LokiImage           string
	LokiHost            string
	LokiPort            string
	LokiConfigDir       string
	LokiConfigFile      string
	LokiDataDir         string
	EnableGrafana       bool
	GrafanaImage        string
	GrafanaHost         string
	GrafanaPort         string
	GrafanaConfigDir    string
	GrafanaDataDir      string
	EnableVMAlert       bool
	VMAlertImage        string
	VMAlertConfigDir    string
	VMAlertRulesFile    string
	AlertsWebhookURL    string
	AlertsWebhookSecret string
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
      # Stop accepting samples once the partition has less than this free,
      # rather than filling it and taking the SQLite DB down too. VM has no
      # size-based retention (see DockerComposeSupervisorConfig), so this
      # reservation is the actual guard. storage.md §5.
      - "-storage.minFreeDiskSpaceBytes={{.VMMinFreeDiskSpace}}"
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
    # Digest of the rendered config. Compose only recreates a container when
    # its *definition* changes, never when a bind-mounted file's contents do —
    # so without this an edited config silently keeps the old one running.
    environment:
      RASPUTIN_OBS_CONFIG_DIGEST: "{{.AlloyConfigHash}}"
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
{{- if .EnableIDSPipe }}
      # IDS alert JSONL the api writes — Alloy tails it via
      # loki.source.file (see alloyConfigTmpl). Read-only because the
      # api owns the file lifecycle (open/rotate/close); Alloy just
      # follows it.
      - {{.IDSLogHostDir}}:/var/log/rasputin:ro
{{- end }}
    depends_on:
      - victoriametrics
{{- if .EnableLoki }}
      - loki

  loki:
    image: {{.LokiImage}}
    container_name: rasputin-loki
    restart: unless-stopped
    # See the alloy service — compose ignores bind-mounted file contents, so
    # the retention window would otherwise never take effect on a restart.
    environment:
      RASPUTIN_OBS_CONFIG_DIGEST: "{{.LokiConfigHash}}"
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
    # See the alloy service. Covers grafana.ini + the provisioned datasources
    # and dashboards, so a re-provision actually reaches the container.
    environment:
      RASPUTIN_OBS_CONFIG_DIGEST: "{{.GrafanaConfigHash}}"
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
{{- if .EnableVMAlert }}

  vmalert:
    image: {{.VMAlertImage}}
    container_name: rasputin-vmalert
    restart: unless-stopped
    # See the alloy service. This one covers the alerting RULES file — without
    # it an edited rule set silently never loads, which would be a quiet way to
    # stop alerting.
    environment:
      RASPUTIN_OBS_CONFIG_DIGEST: "{{.VMAlertConfigHash}}"
    command:
      - "-rule=/etc/vmalert/{{.VMAlertRulesFile}}"
      - "-datasource.url=http://victoriametrics:8428"
      - "-remoteWrite.url=http://victoriametrics:8428"
      - "-remoteRead.url=http://victoriametrics:8428"
      - "-notifier.url={{.AlertsWebhookURL}}"
      - "-evaluationInterval=30s"
{{- if .AlertsWebhookSecret }}
      - "-notifier.basicAuth.password=" # placeholder; secret goes via header below
      - '-notifier.headers=X-Webhook-Secret:{{.AlertsWebhookSecret}}'
{{- end }}
    volumes:
      - {{.VMAlertConfigDir}}:/etc/vmalert:ro
    extra_hosts:
      - "host.docker.internal:host-gateway"
    depends_on:
      - victoriametrics
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
