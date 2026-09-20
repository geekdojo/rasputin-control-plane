package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
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

	// apiKeyMu serialises MintSessionAPIKey: concurrent 401s must not race
	// two mints over the recorded prefixes.
	apiKeyMu sync.Mutex

	// runImage is the reference `docker run` is given, settled by ensureImage.
	// It is cfg.Image on a node that pulled, and the OS-baked image ID on an
	// appliance -- where the digest-pinned reference cannot be resolved
	// locally at all. See ensureImage.
	runImage string
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

	// Image is the headscale image reference. Defaults to the pin in
	// mesh-images.json. It must be digest-pinned (name:tag@sha256:...) whether
	// it came from the default or from RASPUTIN_HEADSCALE_IMAGE: an override
	// that skipped the rule would be a second, weaker rule for the same kind of
	// value, which is exactly the gap .github/image-sources.tsv was written to
	// count.
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

	// ClusterID is the bare cluster identity (RASPUTIN_CLUSTER_ID, e.g. "home1"),
	// used to derive the MagicDNS base domain "<cluster-id>.internal".
	// Empty on a dev box → the base domain falls back to "rasputin.internal".
	// Kept separate from ServerURL because an operator can override ServerURL
	// (RASPUTIN_HEADSCALE_URL) to a non-.local host, so it isn't a reliable
	// source for the cluster id. See renderConfig / baseDomainFor.
	ClusterID string

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

// defaultImage is the pinned Headscale reference, read from the embedded
// mesh-images.json rather than written twice. The OS build reads the same file
// out of the control-plane release, so the ref the image bakes and the ref the
// api runs cannot drift.
var defaultImage = func() string {
	ref, ok := BakedImageRef("headscale")
	if !ok {
		panic("mesh: mesh-images.json has no \"headscale\" image; names present: " + strings.Join(bakedImageNames(), ", "))
	}
	return ref
}()

const (
	defaultContainerName = "rasputin-headscale"
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
	// Fail closed on an unpinned reference, from either source. A tag is
	// mutable at the registry, so `docker pull` of one does not describe a
	// fixed image no matter how specific the tag looks -- and the mesh server
	// is the component that mints the credentials every node joins with.
	if err := tileschema.ValidateImagePin(cfg.Image); err != nil {
		return nil, fmt.Errorf("mesh supervisor: image %q: %w (set %s to a name:tag@sha256:... reference)",
			cfg.Image, err, "RASPUTIN_HEADSCALE_IMAGE")
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
// stunPublish maps the HTTP listen address onto the STUN port, preserving the
// host bind: "0.0.0.0:18080" -> "0.0.0.0:3478", "127.0.0.1:18080" ->
// "127.0.0.1:3478". Keeping the bind identical means narrowing ListenAddr for
// dev narrows STUN with it, instead of quietly opening a LAN listener.
func stunPublish(listenAddr string) string {
	host := listenAddr
	if i := strings.LastIndex(listenAddr, ":"); i >= 0 {
		host = listenAddr[:i]
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return host + ":3478"
}

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
	if err := s.ensureExtraRecordsFile(); err != nil {
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

// sessionAPIKeyExpiration is the Headscale-side lifetime of the admin API
// key each api process mints for itself. The key's real life is the api
// process that holds it in memory: the next start (or a 401) mints a
// replacement and expires this one by its recorded prefix. The expiration
// only bounds a key whose api died before it could be expired, and a 401
// after it simply re-mints. Parsed by Headscale (prometheus duration form).
const sessionAPIKeyExpiration = "24h"

// ServerURL returns the resolved Headscale URL that clients should dial. This
// is what the RealClient uses as its BaseURL and what agents pass to
// `tailscale up --login-server`. Set explicitly via RASPUTIN_HEADSCALE_URL or
// derived from the listen address (dial-trick for the primary LAN IP).
func (s *DockerSupervisor) ServerURL() string { return s.cfg.ServerURL }

// legacyAPIKeyPath is where api releases before the per-start key persisted
// a long-lived (10-year) admin API key. MintSessionAPIKey expires that key on
// Headscale by its prefix and then deletes the file.
func (s *DockerSupervisor) legacyAPIKeyPath() string {
	return filepath.Join(s.cfg.StateDir, "apikey")
}

// apiKeyPrefixesPath records the prefixes of admin API keys this supervisor
// minted and has not yet confirmed expired, one per line. A prefix is only
// Headscale's lookup id for a key, not a credential; it is recorded so the
// next api start can expire a key the previous process held only in memory.
func (s *DockerSupervisor) apiKeyPrefixesPath() string {
	return filepath.Join(s.cfg.StateDir, "apikey-prefixes")
}

// MintSessionAPIKey mints a fresh Headscale admin API key for this api
// process and returns it; the caller holds it in memory only. The container
// must be running — call Start first.
//
// Every key this supervisor minted earlier is expired (`headscale apikeys
// expire --prefix`), so at most one supervisor-minted key is live at a time:
// the one this process holds. Call it at each api start and again when
// Headscale answers 401. It also retires the legacy on-disk key (see
// retireLegacyAPIKey).
//
// Order matters for crash safety: the new key's prefix is recorded before
// any old key is expired, and an old prefix is dropped from the record only
// once Headscale confirms it expired. The one window left — dying between
// the mint and the record — leaves a key that sessionAPIKeyExpiration bounds.
//
// The supervisor owns the container, so it can mint the very credential the
// RealClient needs: a controlplane with Docker comes up on real mesh with
// zero operator input and zero provision-time secret injection. (There is no
// Headscale to mint a key from until first boot, so a key cannot be baked
// into a seed.)
func (s *DockerSupervisor) MintSessionAPIKey(ctx context.Context) (string, error) {
	s.apiKeyMu.Lock()
	defer s.apiKeyMu.Unlock()

	previous, err := s.readAPIKeyPrefixes()
	if err != nil {
		return "", err
	}
	key, err := s.mintAPIKey(ctx)
	if err != nil {
		return "", err
	}
	prefix, err := headscaleAPIKeyPrefix(key)
	if err != nil {
		// A key whose prefix cannot be read can never be expired by us, so
		// it is not used; it lapses at sessionAPIKeyExpiration.
		return "", fmt.Errorf("mesh supervisor: minted api key has no readable prefix: %w", err)
	}
	if err := s.writeAPIKeyPrefixes(appendUnique(previous, prefix)); err != nil {
		return "", err
	}
	remaining := []string{prefix}
	for _, old := range previous {
		if old == prefix {
			continue
		}
		known, err := s.expireAPIKeyPrefix(ctx, old)
		if err != nil {
			log.Printf("mesh supervisor: could not expire previous admin API key %s (will retry at the next mint): %v", old, err)
			remaining = append(remaining, old)
			continue
		}
		if known {
			log.Printf("mesh supervisor: expired previous admin API key %s", old)
		} else {
			log.Printf("mesh supervisor: previous admin API key %s is not on Headscale; nothing to expire", old)
		}
	}
	if err := s.writeAPIKeyPrefixes(remaining); err != nil {
		return "", err
	}
	s.retireLegacyAPIKey(ctx)
	log.Printf("mesh supervisor: minted this process's Headscale admin API key %s (held in memory)", prefix)
	return key, nil
}

// retireLegacyAPIKey expires the long-lived key an older api persisted at
// legacyAPIKeyPath, then deletes the file. The file stays in place when the
// expire fails, so the next mint retries; a file whose content is not a
// Headscale key is left alone and logged, because what it holds cannot be
// expired by prefix.
func (s *DockerSupervisor) retireLegacyAPIKey(ctx context.Context) {
	path := s.legacyAPIKeyPath()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("mesh supervisor: read legacy admin API key file %s: %v", path, err)
		return
	}
	legacy := strings.TrimSpace(string(b))
	if legacy != "" {
		prefix, perr := headscaleAPIKeyPrefix(legacy)
		if perr != nil {
			log.Printf("mesh supervisor: legacy admin API key file %s holds no recognisable Headscale key (%v); leaving it in place", path, perr)
			return
		}
		known, err := s.expireAPIKeyPrefix(ctx, prefix)
		if err != nil {
			log.Printf("mesh supervisor: could not expire legacy admin API key %s (will retry at the next mint): %v", prefix, err)
			return
		}
		if known {
			log.Printf("mesh supervisor: expired legacy admin API key %s", prefix)
		} else {
			log.Printf("mesh supervisor: legacy admin API key %s is not on Headscale; nothing to expire", prefix)
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("mesh supervisor: delete legacy admin API key file %s: %v", path, err)
		return
	}
	log.Printf("mesh supervisor: deleted legacy admin API key file %s", path)
}

// mintAPIKey runs `headscale apikeys create` inside the container and returns
// the resulting token.
func (s *DockerSupervisor) mintAPIKey(ctx context.Context) (string, error) {
	out, err := s.runner(ctx, s.cfg.DockerBin, "exec", s.cfg.ContainerName,
		"headscale", "apikeys", "create", "--expiration", sessionAPIKeyExpiration)
	if err != nil {
		return "", fmt.Errorf("mesh supervisor: create api key: %w", err)
	}
	key := parseAPIKey(out)
	if key == "" {
		// Never echo the output: it is where the key would be.
		return "", errors.New("mesh supervisor: could not parse api key from headscale output")
	}
	return key, nil
}

// expireAPIKeyPrefix runs `headscale apikeys expire --prefix <p>` inside the
// container (flag syntax checked against the pinned headscale 0.28.0) and
// reports whether Headscale had the key. A key Headscale does not have is
// already as unusable as it can be, so Headscale's "record not found" is
// done (known=false); every other failure (docker, the CLI, the daemon)
// is an error and keeps the prefix recorded for the next attempt.
func (s *DockerSupervisor) expireAPIKeyPrefix(ctx context.Context, prefix string) (known bool, err error) {
	out, err := s.runner(ctx, s.cfg.DockerBin, "exec", s.cfg.ContainerName,
		"headscale", "apikeys", "expire", "--prefix", prefix)
	if err != nil {
		if strings.Contains(strings.ToLower(string(out)), "record not found") {
			return false, nil
		}
		return false, fmt.Errorf("expire api key %s: %w", prefix, err)
	}
	return true, nil
}

func (s *DockerSupervisor) readAPIKeyPrefixes() ([]string, error) {
	b, err := os.ReadFile(s.apiKeyPrefixesPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mesh supervisor: read api key prefixes: %w", err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if p := strings.TrimSpace(line); p != "" {
			out = appendUnique(out, p)
		}
	}
	return out, nil
}

func (s *DockerSupervisor) writeAPIKeyPrefixes(prefixes []string) error {
	path := s.apiKeyPrefixesPath()
	tmp := path + ".tmp"
	body := strings.Join(prefixes, "\n")
	if body != "" {
		body += "\n"
	}
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return fmt.Errorf("mesh supervisor: record api key prefixes: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("mesh supervisor: record api key prefixes: %w", err)
	}
	return nil
}

func appendUnique(xs []string, x string) []string {
	for _, have := range xs {
		if have == x {
			return xs
		}
	}
	return append(xs, x)
}

// Headscale API key formats (headscale 0.28.0 hscontrol/db/api_key.go):
// current keys are "hskey-api-" + a 12-character URL-safe prefix + "-" +
// secret; legacy keys are a 7-character prefix + "." + secret.
const (
	headscaleAPIKeyTag          = "hskey-api-"
	headscaleAPIKeyPrefixLen    = 12
	headscaleLegacyKeyPrefixLen = 7
)

// headscaleAPIKeyPrefix returns the prefix Headscale identifies key by —
// what `headscale apikeys expire --prefix` takes.
func headscaleAPIKeyPrefix(key string) (string, error) {
	key = strings.TrimSpace(key)
	if rest, ok := strings.CutPrefix(key, headscaleAPIKeyTag); ok {
		if len(rest) < headscaleAPIKeyPrefixLen+2 || rest[headscaleAPIKeyPrefixLen] != '-' {
			return "", errors.New("malformed hskey-api key")
		}
		prefix := rest[:headscaleAPIKeyPrefixLen]
		if !urlSafe(prefix) {
			return "", errors.New("malformed hskey-api key prefix")
		}
		return prefix, nil
	}
	if prefix, secret, ok := strings.Cut(key, "."); ok && len(prefix) == headscaleLegacyKeyPrefixLen && secret != "" && urlSafe(prefix) {
		return prefix, nil
	}
	return "", errors.New("not a Headscale API key")
}

func urlSafe(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return s != ""
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

// ensureImage settles WHICH image this node will run, and makes it present.
//
// It returns nothing; the answer is s.runImage, read by createAndStart.
//
// TWO PATHS REACH THE SAME IMAGE, VERIFIED DIFFERENTLY.
//
//   - PULLED. The reference is digest-pinned, so the daemon verifies the
//     manifest digest itself and nothing further is needed. This is the dev
//     box, and any node whose baked tarball did not load.
//
//   - LOADED FROM THE OS-BAKED TARBALL. This is a Rasputin appliance forming
//     its mesh on a first boot with no internet. Here the digest cannot be
//     checked and the REFERENCE CANNOT EVEN BE RESOLVED: `docker save` of a
//     digest-pinned reference writes a tarball whose RepoTags is null, and
//     `docker load` records no RepoDigest in the classic image store because
//     there was no registry pull to record one from. So the loaded image has
//     no name at all -- `docker image inspect headscale/...@sha256:...` fails
//     on a node that is holding exactly the right bytes.
//
//     What survives `docker save`/`docker load` is the image ID, the digest of
//     the image config, and the OS build writes it beside the tarball at pull
//     time, when the digest pin still held. So on such a node the image is
//     both FOUND and PINNED by that ID: running it by ID is a stronger pin
//     than any name, because a name is a local label anyone with the daemon
//     can move and an ID is the content.
func (s *DockerSupervisor) ensureImage(ctx context.Context) error {
	path := bakedImageIDsPath()
	if id, ok := readBakedImageID(path, s.cfg.Image); ok {
		if _, err := s.runner(ctx, s.cfg.DockerBin, "image", "inspect", id); err == nil {
			log.Printf("mesh supervisor: running the OS-baked image %s (%s, recorded in %s)",
				id, s.cfg.Image, path)
			s.runImage = id
			return nil
		}
		// A record with no image behind it is the normal state on a node whose
		// tarball did not load -- rasputin-mesh-images.service is ordering-only
		// and a failed load does not block the api. Fall through to the pull,
		// which is still digest-verified; say so, because "it silently went to
		// the network" is exactly the failure the baked image exists to avoid
		// and it should be visible in a boot log.
		log.Printf("mesh supervisor: %s records image %s for %s, but no such image is loaded; falling back to a pull",
			path, id, s.cfg.Image)
	}

	s.runImage = s.cfg.Image
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
		// STUN for the embedded DERP relay. Same host bind as the HTTP
		// listener, so an operator who narrowed ListenAddr to loopback for dev
		// gets a loopback STUN too rather than an unexpected LAN listener.
		"-p", stunPublish(s.cfg.ListenAddr) + ":3478/udp",
		"-v", confDir + ":/etc/headscale:ro",
		"-v", dataDir + ":/var/lib/headscale",
	}
	if s.cfg.MeshCA != nil {
		certsDir := filepath.Join(s.cfg.StateDir, "certs")
		args = append(args, "-v", certsDir+":/etc/headscale-certs:ro")
	}
	// runImage, not cfg.Image: on an appliance the baked image has no resolvable
	// name and is addressed by its ID. ensureImage settled which one applies and
	// runs before every path that reaches here.
	img := s.runImage
	if img == "" {
		return fmt.Errorf("mesh supervisor: createAndStart before ensureImage settled an image")
	}
	args = append(args, img, "serve")

	log.Printf("mesh supervisor: creating container %q (image=%s listen=%s tls=%v)",
		s.cfg.ContainerName, img, s.cfg.ListenAddr, s.cfg.MeshCA != nil)
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

// headscaleLeafName is the leaf sweep's name for Headscale's TLS leaf.
const headscaleLeafName = "headscale"

// LeafConsumer registers Headscale's TLS leaf with the controlplane's one leaf
// sweep (sweep.go). Headscale reads its certificate once, when the container
// starts, so a renewed file on the host reaches no client until the container
// restarts — which is why this consumer has a reload hook, and why that hook
// restarts. Sweep calls it only when a fresh leaf was actually minted, so the
// restart follows real drift (near-expiry, a moved hostname) and never a tick.
func (s *DockerSupervisor) LeafConsumer() LeafConsumer {
	return LeafConsumer{
		Name:   headscaleLeafName,
		Dir:    s.certsDir(),
		Spec:   s.leafSpec,
		Reload: s.reloadLeaf,
	}
}

func (s *DockerSupervisor) certsDir() string { return filepath.Join(s.cfg.StateDir, "certs") }

// reloadLeaf restarts the Headscale container so it picks up the leaf now on
// disk. A container that is missing or stopped needs nothing: the next Start
// creates or starts it, and Start reads the current leaf.
func (s *DockerSupervisor) reloadLeaf(ctx context.Context, _ LeafPaths) error {
	state, err := s.inspect(ctx)
	if err != nil {
		return err
	}
	if state != containerRunning {
		return nil
	}
	log.Printf("mesh supervisor: restarting %q to serve the renewed TLS leaf", s.cfg.ContainerName)
	if _, err := s.runner(ctx, s.cfg.DockerBin, "restart", s.cfg.ContainerName); err != nil {
		return fmt.Errorf("docker restart %s: %w", s.cfg.ContainerName, err)
	}
	return s.waitHealthy(ctx)
}

// ensureLeaf mints (or reuses) the TLS leaf cert the container will
// serve from.
func (s *DockerSupervisor) ensureLeaf() error {
	spec, err := s.leafSpec()
	if err != nil {
		return err
	}
	if _, err := MintLeafToDisk(s.cfg.MeshCA, s.certsDir(), spec); err != nil {
		return fmt.Errorf("mesh supervisor: mint leaf: %w", err)
	}
	return nil
}

// leafSpec is the SAN set Headscale's leaf must carry. SANs include the
// resolved server host, 127.0.0.1 (for same-host probes), localhost (same-host
// dev), and any ExtraLeafDNSNames the caller wanted to advertise.
//
// Derived on every call rather than captured once, so the sweep re-checks the
// names as well as the dates: a controlplane that changed hostname or moved
// subnets gets a re-mint from the same check that catches near-expiry.
func (s *DockerSupervisor) leafSpec() (LeafSpec, error) {
	spec := LeafSpec{
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost"},
	}
	// The leaf MUST be valid for the host clients actually dial — the
	// ServerURL host (e.g. rasputin.local) — not just a re-resolved
	// ListenAddr. ensureLeaf used to derive the SAN solely from
	// resolveServerHost(ListenAddr), so pinning ServerURL to a name left the
	// leaf valid only for the LAN IP/localhost and the api's own client
	// rejected it ("x509: certificate is valid for localhost, not
	// rasputin.local" — bench 2026-06-18). Cover the ServerURL host AND the
	// resolved LAN IP (so same-LAN IP access still validates); fall back to
	// the resolved host when ServerURL is unset.
	var hosts []string
	if h := serverURLHost(s.cfg.ServerURL); h != "" {
		hosts = append(hosts, h)
	}
	if lan := resolveServerHost(s.cfg.ListenAddr); lan != "" {
		hosts = append(hosts, lan)
	}
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	spec.CommonName = hosts[0]
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			spec.IPAddresses = append(spec.IPAddresses, ip)
		} else {
			spec.DNSNames = append(spec.DNSNames, h)
		}
	}
	spec.DNSNames = append(spec.DNSNames, s.cfg.ExtraLeafDNSNames...)
	return spec, nil
}

// serverURLHost returns the hostname from a server URL like
// "https://rasputin.local:18080" (no scheme, no port). "" if unset/unparseable.
func serverURLHost(serverURL string) string {
	if serverURL == "" {
		return ""
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
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

// extraRecordsHostPath is where the api writes the Headscale `extra_records`
// JSON on the host. It's inside the config dir, which createAndStart bind-mounts
// read-only at /etc/headscale — so Headscale reads/watches it at the container
// path the config template points to (extra_records_path). ADR-0004 §9: this is
// the tailnet app-name projection (`<app>.<cluster-id>.internal → tailnet IP`);
// node tailnet names are MagicDNS-synthesized and are not written here.
func (s *DockerSupervisor) extraRecordsHostPath() string {
	return filepath.Join(s.cfg.StateDir, "config", "extra_records.json")
}

// ensureExtraRecordsFile writes an empty `[]` records file if none exists yet,
// so Headscale never starts against a missing extra_records_path (it reads the
// path early — juanfont/headscale#2753). An existing file (a projection written
// on a prior run) is left untouched; the next reconcile refreshes it.
func (s *DockerSupervisor) ensureExtraRecordsFile() error {
	path := s.extraRecordsHostPath()
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.WriteFile(path, []byte("[]\n"), 0o644); err != nil {
		return fmt.Errorf("mesh supervisor: seed extra_records: %w", err)
	}
	return nil
}

// extraRecord is one Headscale dns.extra_records entry. Only A records are used:
// the Tailscale client processes A/AAAA, and Rasputin is IPv4-only (LOCKED
// decision #9).
type extraRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// renderExtraRecords marshals fqdn→IPv4 to the Headscale extra_records JSON,
// **sorted by name** for stable output — Headscale checksums the file to detect
// real changes, so a stable byte-for-byte rendering avoids spurious reloads
// (headscale.net/ref/dns). Entries with an empty name or value are dropped.
func renderExtraRecords(fqdnToIP map[string]string) ([]byte, error) {
	names := make([]string, 0, len(fqdnToIP))
	for name, ip := range fqdnToIP {
		if name == "" || ip == "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	recs := make([]extraRecord, 0, len(names))
	for _, name := range names {
		recs = append(recs, extraRecord{Name: name, Type: "A", Value: fqdnToIP[name]})
	}
	// A non-nil empty slice renders as `[]`, never `null` — Headscale wants a
	// valid (possibly empty) array at all times.
	return json.MarshalIndent(recs, "", "  ")
}

// ReconcileAppRecords writes the current tailnet app-name projection to the
// Headscale extra_records file, which Headscale hot-reloads (no restart —
// ADR-0004 §9). fqdnToIP maps each app's tailnet FQDN to its target node's
// tailnet IPv4.
//
// The write is **in place** (truncate + write the same inode), deliberately
// NOT the temp-file+rename writeConfig uses: Headscale's filewatcher watches the
// path's inode, and a rename-over swaps the inode and drops the watch
// (juanfont/headscale#2289), silently stranding every later change. In-place
// keeps the watch; the cost is a sub-second window where a concurrent read could
// see a partial/empty file, which self-heals on the next change event (the file
// is tiny and written in one call). Runtime filewatcher behavior is validated on
// a real bench cluster, not in unit tests.
func (s *DockerSupervisor) ReconcileAppRecords(fqdnToIP map[string]string) error {
	data, err := renderExtraRecords(fqdnToIP)
	if err != nil {
		return fmt.Errorf("mesh supervisor: render extra_records: %w", err)
	}
	if err := os.WriteFile(s.extraRecordsHostPath(), data, 0o644); err != nil {
		return fmt.Errorf("mesh supervisor: write extra_records: %w", err)
	}
	return nil
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
		BaseDomain: baseDomainFor(s.cfg.ClusterID),
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
	BaseDomain  string // MagicDNS base domain, "<cluster-id>.internal"
	TLSCertPath string // empty in HTTP mode
	TLSKeyPath  string // empty in HTTP mode
}

// baseDomainFor builds the MagicDNS base domain from the cluster id:
// "<cluster-id>.internal" — the ICANN-reserved private-use `.internal` TLD, so
// it can never collide with a public zone. The cluster-id prefix means two
// clusters in one household don't collide on tailnet names, and compute/app
// names hang cleanly off it (`<node>.home1.internal`) — mesh.md §6. Empty/dev →
// "rasputin.internal". The cluster id is already a single DNS-safe label
// (ADR-0003), so no sanitisation is needed here.
func baseDomainFor(clusterID string) string {
	id := strings.TrimSpace(clusterID)
	if id == "" {
		id = "rasputin"
	}
	return id + ".internal"
}

var configTmpl = template.Must(template.New("headscale-config").Parse(`server_url: {{.ServerURL}}
listen_addr: {{.ListenAddr}}
# Empty disables Headscale's metrics and debug listener (headscale 0.28.0
# serves nothing on it when the address is empty). Nothing scrapes it.
metrics_listen_addr: ""
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
    enabled: true
    region_id: 999
    region_code: "rasputin"
    region_name: "Rasputin Embedded DERP"
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
    # Written explicitly rather than left to Headscale's default: the
    # embedded relay serves only clients this Headscale knows.
    verify_clients: true
  urls: []
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
  magic_dns: true
  base_domain: {{.BaseDomain}}
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []
  extra_records_path: /etc/headscale/extra_records.json

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
