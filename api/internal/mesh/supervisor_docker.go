package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"
)

// DockerSupervisor manages a single Headscale container via the local
// docker CLI. Talking to the daemon via the CLI (rather than the SDK)
// keeps the deployment story portable across Docker Desktop, Rancher
// Desktop, OrbStack, Podman (with docker shim), and Colima — anything
// that drops a `docker` binary on PATH. The trade-off is wire format /
// flag-string compatibility, which is stable across those runtimes.
//
// Lifecycle (Start):
//
//  1. Ensure image present locally (`docker image inspect`; pull on miss).
//  2. Render config.yaml into the host state directory.
//  3. Inspect the container:
//     - missing       → create + start
//     - exists/stopped → start
//     - exists/running → no-op
//  4. Poll the listen port until healthy (or context deadline).
//
// Stop issues `docker stop` but deliberately leaves the container in
// place so on-disk state (sqlite db, noise key) survives across restarts.
// Re-running Start picks the container back up.
type DockerSupervisor struct {
	cfg    DockerSupervisorConfig
	runner CmdRunner
	dialer func(network, address string, timeout time.Duration) (net.Conn, error)
}

// CmdRunner runs a binary and returns its combined output. Injected so
// tests can drive lifecycle decisions without a real Docker daemon.
type CmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// DockerSupervisorConfig is the constructor input.
type DockerSupervisorConfig struct {
	// StateDir is the host directory that holds the container's config and
	// data subdirectories. The supervisor creates <StateDir>/{config,data}
	// on Start and bind-mounts them into the container.
	StateDir string

	// ContainerName is the docker container name. Defaults to "rasputin-headscale".
	ContainerName string

	// Image is the headscale image reference. Defaults to "headscale/headscale:0.28.0".
	Image string

	// ListenAddr is the host bind for Headscale's HTTP listener. Defaults
	// to "0.0.0.0:18080" — all LAN interfaces on the controlplane node,
	// which is the right default since the controlplane is behind Node N
	// on a real chassis and never has a WAN interface. Override to
	// "127.0.0.1:18080" for single-host dev. The container listens on
	// 8080 internally; we publish that to ListenAddr on the host.
	ListenAddr string

	// ServerURL is what gets written into Headscale's `server_url` field —
	// what Tailscale clients will connect to. Defaults to "http://" + ListenAddr.
	ServerURL string

	// DockerBin overrides the docker binary path; useful when the runtime's
	// CLI lives somewhere unexpected. Defaults to "docker".
	DockerBin string

	// Runner overrides the command runner. Defaults to exec.CommandContext.
	Runner CmdRunner

	// HealthTimeout caps how long Start waits for the listen port to
	// accept TCP connections after the container starts. Defaults to 30s.
	HealthTimeout time.Duration

	// PullTimeout caps how long `docker pull` is allowed to run.
	// Defaults to 5 minutes (the image is ~30 MB but first-pull bandwidth
	// is highly variable).
	PullTimeout time.Duration

	// MeshCA, when non-nil, switches the supervisor into HTTPS mode:
	// Start mints a server-auth leaf signed by this CA, mounts it into
	// the container, and renders a Headscale config that points at it
	// via tls_cert_path / tls_key_path. ServerURL is also forced to
	// https:// in that mode. Leave nil for HTTP-only (useful for tests
	// and bring-up before the wizard's PKI step runs).
	MeshCA *MeshCA

	// ExtraLeafDNSNames are appended to the leaf's SAN list — useful if
	// the operator wants the cert to also validate for a custom hostname
	// they advertise via mDNS or local DNS. The resolved listen host is
	// included automatically.
	ExtraLeafDNSNames []string
}

const (
	defaultContainerName = "rasputin-headscale"
	defaultImage         = "headscale/headscale:0.28.0"
	// Bind to all interfaces by default. On a real Rasputin chassis the
	// controlplane sits behind Node N (the firewall) on a LAN-only
	// interface — there is no WAN-facing NIC to accidentally expose, so
	// "all interfaces" means "all LAN interfaces". Loopback would prevent
	// any LAN client (laptop, phone) from reaching Headscale, which is
	// the whole point. Dev setups on multi-homed hosts can pin this to
	// 127.0.0.1 via RASPUTIN_HEADSCALE_LISTEN_ADDR.
	defaultListenAddr    = "0.0.0.0:18080"
	defaultHealthTimeout = 30 * time.Second
	defaultPullTimeout   = 5 * time.Minute
)

// NewDockerSupervisor constructs the supervisor. StateDir is required;
// everything else has sensible defaults.
func NewDockerSupervisor(cfg DockerSupervisorConfig) (*DockerSupervisor, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("mesh supervisor: StateDir required")
	}
	if cfg.ContainerName == "" {
		cfg.ContainerName = defaultContainerName
	}
	if cfg.Image == "" {
		cfg.Image = defaultImage
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultListenAddr
	}
	if cfg.ServerURL == "" {
		scheme := "http"
		if cfg.MeshCA != nil {
			// HTTPS-mode default — the Tailscale client refuses plaintext
			// HTTP, so a configured MeshCA implies the operator wants a
			// real TLS endpoint.
			scheme = "https"
		}
		cfg.ServerURL = scheme + "://" + resolveServerHost(cfg.ListenAddr) + ":" + portOf(cfg.ListenAddr)
	}
	if cfg.DockerBin == "" {
		cfg.DockerBin = "docker"
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
	return &DockerSupervisor{
		cfg:    cfg,
		runner: runner,
		dialer: net.DialTimeout,
	}, nil
}

// resolveServerHost picks the hostname that goes into Headscale's
// server_url when the operator hasn't set RASPUTIN_HEADSCALE_URL. If
// ListenAddr is a wildcard ("0.0.0.0" or "::") we can't use it as a URL
// hostname — Tailscale clients would try to literally navigate there —
// so we detect the controlplane's primary LAN IP via the dial-trick.
// Loopback / specific binds are passed through verbatim; the operator
// chose them deliberately.
//
// Fallback chain (in order of preference): host part of ListenAddr if
// it's a real IP → primary LAN IP via dial-trick → "localhost". The
// final fallback is only useful for same-host dev; production setups
// hit the dial-trick branch.
func resolveServerHost(listenAddr string) string {
	host, _, err := net.SplitHostPort(listenAddr)
	if err == nil && host != "" && host != "0.0.0.0" && host != "::" {
		return host
	}
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		if local, ok := conn.LocalAddr().(*net.UDPAddr); ok && local.IP != nil {
			return local.IP.String()
		}
	}
	return "localhost"
}

func portOf(listenAddr string) string {
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return "18080"
	}
	return port
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

// Start brings the container up. Idempotent: a running container is a no-op
// (still re-checks health), a stopped container is started, a missing
// container is pulled + created + started.
//
// When MeshCA is set, Start also ensures a Headscale TLS leaf exists at
// <state>/certs/{leaf.pem,leaf.key} and the config points at it. The
// leaf is re-minted silently on SAN drift (e.g. controlplane moved
// subnets) or near expiry — operators never see a "wrong cert" error
// as long as they're trusting the CA the wizard installed on their
// devices.
func (s *DockerSupervisor) Start(ctx context.Context) error {
	if err := s.prepareHostDirs(); err != nil {
		return err
	}
	if s.cfg.MeshCA != nil {
		if err := s.ensureLeaf(); err != nil {
			return err
		}
	}
	if err := s.writeConfig(); err != nil {
		return err
	}
	state, err := s.inspect(ctx)
	if err != nil {
		return err
	}
	switch state {
	case containerMissing:
		if err := s.ensureImage(ctx); err != nil {
			return err
		}
		if err := s.createAndStart(ctx); err != nil {
			return err
		}
	case containerStopped:
		log.Printf("mesh supervisor: starting existing container %q", s.cfg.ContainerName)
		if _, err := s.runner(ctx, s.cfg.DockerBin, "start", s.cfg.ContainerName); err != nil {
			return fmt.Errorf("docker start %s: %w", s.cfg.ContainerName, err)
		}
	case containerRunning:
		// no-op
	}
	return s.waitHealthy(ctx)
}

// Stop gracefully stops the container but leaves the on-disk state intact.
// Re-Start re-attaches to the same container row.
func (s *DockerSupervisor) Stop(ctx context.Context) error {
	state, err := s.inspect(ctx)
	if err != nil {
		return err
	}
	if state != containerRunning {
		return nil
	}
	_, err = s.runner(ctx, s.cfg.DockerBin, "stop", s.cfg.ContainerName)
	if err != nil {
		return fmt.Errorf("docker stop %s: %w", s.cfg.ContainerName, err)
	}
	return nil
}

// Healthy is true when the container is running AND the listen port
// accepts a TCP connection.
func (s *DockerSupervisor) Healthy(ctx context.Context) (bool, error) {
	state, err := s.inspect(ctx)
	if err != nil {
		return false, err
	}
	if state != containerRunning {
		return false, nil
	}
	if err := s.tcpPing(ctx); err != nil {
		return false, nil
	}
	return true, nil
}

// ----- API key bootstrap --------------------------------------------------

// apiKeyExpiration is the lifetime of the admin API key the supervisor mints
// for the api to talk to its own Headscale. This is an appliance-internal
// credential on a single-owner box, so it's set effectively permanent
// (~10 years) — re-minting is a recovery action (delete the file + restart),
// not a routine rotation. Headscale parses this as a Go duration.
const apiKeyExpiration = "87600h"

// ServerURL returns the resolved Headscale URL that clients should dial. This
// is what the RealClient uses as its BaseURL and what agents pass to
// `tailscale up --login-server`. Set explicitly via RASPUTIN_HEADSCALE_URL or
// derived from the listen address (dial-trick for the primary LAN IP).
func (s *DockerSupervisor) ServerURL() string { return s.cfg.ServerURL }

// apiKeyPath is where the bootstrapped admin API key is persisted so it
// survives api restarts without minting (and accumulating) a new key each
// boot.
func (s *DockerSupervisor) apiKeyPath() string {
	return filepath.Join(s.cfg.StateDir, "apikey")
}

// EnsureAPIKey returns a Headscale admin API key for the supervised
// container, minting one via `headscale apikeys create` on first call and
// persisting it to <StateDir>/apikey (0600) for reuse across restarts. The
// container must be running — call Start first.
//
// This is the step that closes the self-bootstrap loop. Because the
// supervisor owns the container, it can mint the very credential the
// RealClient needs — so a controlplane with Docker comes up on real mesh
// with zero operator input and zero provision-time secret injection. (The
// chicken-and-egg the env-var-only path couldn't solve: there's no Headscale
// to mint a key from until first boot, so the key can't be baked into a
// seed.)
func (s *DockerSupervisor) EnsureAPIKey(ctx context.Context) (string, error) {
	if b, err := os.ReadFile(s.apiKeyPath()); err == nil {
		if key := strings.TrimSpace(string(b)); key != "" {
			return key, nil
		}
	}
	key, err := s.mintAPIKey(ctx)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(s.apiKeyPath(), []byte(key+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("mesh supervisor: persist api key: %w", err)
	}
	log.Printf("mesh supervisor: minted Headscale admin API key (persisted at %s)", s.apiKeyPath())
	return key, nil
}

// mintAPIKey runs `headscale apikeys create` inside the container and returns
// the resulting token.
func (s *DockerSupervisor) mintAPIKey(ctx context.Context) (string, error) {
	out, err := s.runner(ctx, s.cfg.DockerBin, "exec", s.cfg.ContainerName,
		"headscale", "apikeys", "create", "--expiration", apiKeyExpiration)
	if err != nil {
		return "", fmt.Errorf("mesh supervisor: create api key: %w", err)
	}
	key := parseAPIKey(out)
	if key == "" {
		return "", fmt.Errorf("mesh supervisor: could not parse api key from headscale output: %q",
			strings.TrimSpace(string(out)))
	}
	return key, nil
}

// parseAPIKey extracts the key token from `headscale apikeys create` output.
// The CLI prints human-readable lines plus the key itself on its own line;
// the key is the trailing whitespace-free token. Prefix-agnostic so it
// survives Headscale formatting changes across the 0.2x line.
func parseAPIKey(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.ContainsAny(line, " \t") || len(line) < 16 {
			continue
		}
		return line
	}
	return ""
}

// ----- Container introspection -------------------------------------------

type containerState int

const (
	containerMissing containerState = iota
	containerStopped
	containerRunning
)

// inspect uses `docker inspect --type container --format '{{.State.Status}}'`
// to determine the container's lifecycle state. A non-zero exit (e.g.
// "No such object") is treated as missing.
func (s *DockerSupervisor) inspect(ctx context.Context) (containerState, error) {
	out, err := s.runner(ctx, s.cfg.DockerBin,
		"inspect", "--type", "container", "--format", "{{.State.Status}}",
		s.cfg.ContainerName)
	if err != nil {
		// docker inspect non-zero on missing — distinguish from real
		// failures (daemon unreachable, permission denied) by checking
		// the output for "No such object" / "no such container".
		low := strings.ToLower(string(out) + err.Error())
		if strings.Contains(low, "no such") {
			return containerMissing, nil
		}
		return containerMissing, fmt.Errorf("docker inspect %s: %w", s.cfg.ContainerName, err)
	}
	status := strings.TrimSpace(string(out))
	switch status {
	case "running":
		return containerRunning, nil
	case "created", "exited", "dead", "paused", "restarting":
		return containerStopped, nil
	default:
		return containerStopped, nil
	}
}

// ensureImage runs `docker image inspect`; on miss, `docker pull`.
func (s *DockerSupervisor) ensureImage(ctx context.Context) error {
	if _, err := s.runner(ctx, s.cfg.DockerBin, "image", "inspect", s.cfg.Image); err == nil {
		return nil
	}
	log.Printf("mesh supervisor: pulling image %s", s.cfg.Image)
	pullCtx, cancel := context.WithTimeout(ctx, s.cfg.PullTimeout)
	defer cancel()
	if _, err := s.runner(pullCtx, s.cfg.DockerBin, "pull", s.cfg.Image); err != nil {
		return fmt.Errorf("docker pull %s: %w", s.cfg.Image, err)
	}
	return nil
}

// createAndStart issues `docker run` with the standardised flag set. We
// use --restart=unless-stopped so the Docker daemon (not us) handles
// crash recovery — simpler than reinventing it.
func (s *DockerSupervisor) createAndStart(ctx context.Context) error {
	confDir := filepath.Join(s.cfg.StateDir, "config")
	dataDir := filepath.Join(s.cfg.StateDir, "data")
	args := []string{
		"run", "-d",
		"--name", s.cfg.ContainerName,
		"--restart", "unless-stopped",
		"-p", s.cfg.ListenAddr + ":8080",
		"-v", confDir + ":/etc/headscale:ro",
		"-v", dataDir + ":/var/lib/headscale",
	}
	if s.cfg.MeshCA != nil {
		certsDir := filepath.Join(s.cfg.StateDir, "certs")
		args = append(args, "-v", certsDir+":/etc/headscale-certs:ro")
	}
	args = append(args, s.cfg.Image, "serve")

	log.Printf("mesh supervisor: creating container %q (image=%s listen=%s tls=%v)",
		s.cfg.ContainerName, s.cfg.Image, s.cfg.ListenAddr, s.cfg.MeshCA != nil)
	if _, err := s.runner(ctx, s.cfg.DockerBin, args...); err != nil {
		return fmt.Errorf("docker run %s: %w", s.cfg.ContainerName, err)
	}
	return nil
}

// ----- Host state + config ------------------------------------------------

func (s *DockerSupervisor) prepareHostDirs() error {
	subs := []string{"config", "data"}
	if s.cfg.MeshCA != nil {
		subs = append(subs, "certs")
	}
	for _, sub := range subs {
		p := filepath.Join(s.cfg.StateDir, sub)
		if err := os.MkdirAll(p, 0o755); err != nil {
			return fmt.Errorf("mesh supervisor: mkdir %s: %w", p, err)
		}
	}
	return nil
}

// ensureLeaf mints (or reuses) the TLS leaf cert the container will
// serve from. SANs include the resolved server host, 127.0.0.1 (for
// same-host probes), localhost (same-host dev), and any ExtraLeafDNSNames
// the caller wanted to advertise.
func (s *DockerSupervisor) ensureLeaf() error {
	host := resolveServerHost(s.cfg.ListenAddr)
	spec := LeafSpec{
		CommonName:  host,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	if ip := net.ParseIP(host); ip != nil {
		spec.IPAddresses = append(spec.IPAddresses, ip)
	} else {
		spec.DNSNames = []string{host}
	}
	spec.DNSNames = append(spec.DNSNames, "localhost")
	spec.DNSNames = append(spec.DNSNames, s.cfg.ExtraLeafDNSNames...)
	certsDir := filepath.Join(s.cfg.StateDir, "certs")
	if _, err := MintLeafToDisk(s.cfg.MeshCA, certsDir, spec); err != nil {
		return fmt.Errorf("mesh supervisor: mint leaf: %w", err)
	}
	return nil
}

// writeConfig renders and writes config.yaml. Idempotent — overwrite is
// safe; Headscale re-reads on container start, not per-request.
func (s *DockerSupervisor) writeConfig() error {
	rendered, err := s.renderConfig()
	if err != nil {
		return err
	}
	out := filepath.Join(s.cfg.StateDir, "config", "config.yaml")
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, rendered, 0o644); err != nil {
		return fmt.Errorf("mesh supervisor: write %s: %w", tmp, err)
	}
	return os.Rename(tmp, out)
}

// renderConfig builds the YAML body. The template is deliberately compact —
// only the fields Headscale actually requires plus the ones we override
// (paths, listen, server_url, optional TLS). Operators who need to tune
// anything else can edit the rendered file; subsequent writes will
// overwrite, so the proper escape hatch (post-MVS) is a per-field
// config override map.
//
// Notable choice: the unix socket lives at /tmp/headscale.sock inside the
// container, NOT under /var/lib/headscale. Headscale chmods the socket
// on create; chmod on a socket inside a macOS-bind-mounted directory
// fails with "invalid argument" under Rancher Desktop / OrbStack / Docker
// Desktop, which crashes the process ~2s after Start. Production Linux
// nodes don't see this — bind mounts there behave normally — but using
// the ephemeral /tmp inside the container costs nothing and keeps the
// macOS dev story working out of the box. The CLI (`headscale users ...`)
// resolves its socket from the same config file, so it finds it there.
func (s *DockerSupervisor) renderConfig() ([]byte, error) {
	data := configData{
		ServerURL:  s.cfg.ServerURL,
		ListenAddr: "0.0.0.0:8080", // inside the container
	}
	if s.cfg.MeshCA != nil {
		// Paths inside the container — the host's <state>/certs is
		// bind-mounted at /etc/headscale-certs by createAndStart.
		data.TLSCertPath = "/etc/headscale-certs/leaf.pem"
		data.TLSKeyPath = "/etc/headscale-certs/leaf.key"
	}
	var buf bytes.Buffer
	if err := configTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render headscale config: %w", err)
	}
	return buf.Bytes(), nil
}

type configData struct {
	ServerURL   string
	ListenAddr  string
	TLSCertPath string // empty in HTTP mode
	TLSKeyPath  string // empty in HTTP mode
}

var configTmpl = template.Must(template.New("headscale-config").Parse(`server_url: {{.ServerURL}}
listen_addr: {{.ListenAddr}}
metrics_listen_addr: 0.0.0.0:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false

noise:
  private_key_path: /var/lib/headscale/noise_private.key

prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential

derp:
  server:
    enabled: false
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  paths: []
  auto_update_enabled: false
  update_frequency: 24h

disable_check_updates: true
ephemeral_node_inactivity_timeout: 30m

database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
    wal_autocheckpoint: 1000

acme_url: https://acme-v02.api.letsencrypt.org/directory
acme_email: ""
tls_letsencrypt_hostname: ""
tls_letsencrypt_cache_dir: /var/lib/headscale/cache
tls_letsencrypt_challenge_type: HTTP-01
tls_letsencrypt_listen: ":http"
tls_cert_path: "{{.TLSCertPath}}"
tls_key_path: "{{.TLSKeyPath}}"

log:
  level: info
  format: text

policy:
  mode: file
  path: ""

dns:
  magic_dns: false
  base_domain: rasputin.invalid
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []
  extra_records: []

unix_socket: /tmp/headscale.sock
unix_socket_permission: "0770"
`))

// ----- Health -------------------------------------------------------------

// waitHealthy polls tcpPing every 500ms until success or HealthTimeout.
func (s *DockerSupervisor) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(s.cfg.HealthTimeout)
	var lastErr error
	for {
		if err := s.tcpPing(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("mesh supervisor: %s not healthy after %s (last error: %w)",
				s.cfg.ContainerName, s.cfg.HealthTimeout, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// tcpPing dials the host listen addr. A successful TCP handshake is
// sufficient — anything richer (HTTP, Headscale's /api/v1/health) would
// require an API key, which the supervisor doesn't own.
func (s *DockerSupervisor) tcpPing(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	timeout := 2 * time.Second
	if ok {
		if rem := time.Until(deadline); rem < timeout && rem > 0 {
			timeout = rem
		}
	}
	conn, err := s.dialer("tcp", s.cfg.ListenAddr, timeout)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// ----- Diagnostics --------------------------------------------------------

// ContainerInfo returns a small JSON-friendly snapshot for log triage /
// future UI surfacing. Not in the Supervisor interface; callers that want
// it cast to *DockerSupervisor explicitly.
type ContainerInfo struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	Status  string `json:"status"`
	Ports   string `json:"ports,omitempty"`
	Started string `json:"started,omitempty"`
}

func (s *DockerSupervisor) ContainerInfo(ctx context.Context) (*ContainerInfo, error) {
	out, err := s.runner(ctx, s.cfg.DockerBin,
		"inspect", "--type", "container", s.cfg.ContainerName)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Name  string
		State struct {
			Status    string
			StartedAt string
		}
		Config struct {
			Image string
		}
		NetworkSettings struct {
			Ports map[string][]struct{ HostPort string }
		}
	}
	if err := json.Unmarshal(out, &raw); err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("parse docker inspect output: %w", err)
	}
	r := raw[0]
	info := &ContainerInfo{
		Name:    strings.TrimPrefix(r.Name, "/"),
		Image:   r.Config.Image,
		Status:  r.State.Status,
		Started: r.State.StartedAt,
	}
	if len(r.NetworkSettings.Ports) > 0 {
		var hostPorts []string
		for containerPort, bindings := range r.NetworkSettings.Ports {
			for _, b := range bindings {
				hostPorts = append(hostPorts, b.HostPort+"→"+containerPort)
			}
		}
		sort.Strings(hostPorts)
		info.Ports = strings.Join(hostPorts, ",")
	}
	return info, nil
}
