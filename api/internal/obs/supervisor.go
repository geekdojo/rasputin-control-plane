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
func NewNoopSupervisor() Supervisor                              { return NoopSupervisor{} }
func (NoopSupervisor) Start(context.Context) error               { return nil }
func (NoopSupervisor) Stop(context.Context) error                { return nil }
func (NoopSupervisor) Healthy(context.Context) (bool, error)     { return false, nil }
func (NoopSupervisor) VMBaseURL() string                         { return "" }

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
	defaultDockerBin    = "docker"

	defaultHealthTimeout = 30 * time.Second
	defaultPullTimeout   = 5 * time.Minute

	composeFileName = "docker-compose.yaml"
	vmDataDir       = "vm-data"
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
	for _, sub := range []string{vmDataDir} {
		p := filepath.Join(s.cfg.StateDir, sub)
		if err := os.MkdirAll(p, 0o755); err != nil {
			return fmt.Errorf("obs supervisor: mkdir %s: %w", p, err)
		}
	}
	return nil
}

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
	host, port, err := net.SplitHostPort(s.cfg.VMListenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid VMListenAddr %q: %w", s.cfg.VMListenAddr, err)
	}
	if port == "" {
		return nil, fmt.Errorf("invalid VMListenAddr %q: port required", s.cfg.VMListenAddr)
	}
	data := composeData{
		VMImage:     s.cfg.VMImage,
		VMHost:      host,
		VMPort:      port,
		VMRetention: s.cfg.VMRetention,
		VMDataDir:   "./" + vmDataDir,
	}
	var buf bytes.Buffer
	if err := composeTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render compose: %w", err)
	}
	return buf.Bytes(), nil
}

type composeData struct {
	VMImage     string
	VMHost      string
	VMPort      string
	VMRetention string
	VMDataDir   string
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
      - "-httpListenAddr=0.0.0.0:{{.VMPort}}"
      - "-search.latencyOffset=0s"
    ports:
      - "{{.VMHost}}:{{.VMPort}}:{{.VMPort}}"
    volumes:
      - {{.VMDataDir}}:/storage
`))

// ----- Health -------------------------------------------------------------

// waitHealthy polls vmHealth every 500 ms until success or HealthTimeout.
func (s *DockerComposeSupervisor) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(s.cfg.HealthTimeout)
	var lastErr error
	for {
		ok, err := s.vmHealth(ctx)
		if err == nil && ok {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New("vm /health returned non-2xx")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("obs supervisor: victoriametrics not healthy after %s (last error: %w)",
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
	url := s.VMBaseURL() + "/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := s.httpc.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}
