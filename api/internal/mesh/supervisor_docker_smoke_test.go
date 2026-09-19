//go:build supervisor

// Live end-to-end test for DockerSupervisor + RealClient. Excluded from
// the default `go test` run by the `supervisor` build tag — invoke with:
//
//	go test -tags=supervisor -run TestSupervisor -count=1 -v -timeout=5m \
//	  ./api/internal/mesh/...
//
// Requires:
//   - A working `docker` CLI on PATH (Docker Desktop / Rancher Desktop /
//     OrbStack / Podman with docker shim all work).
//   - Network access to pull headscale/headscale:0.28.0 (only on first run).
//   - Free TCP port at 127.0.0.1:18080 (override via SUPERVISOR_LISTEN_ADDR).
//
// State directory (SUPERVISOR_STATE_DIR override):
//   Defaults to $HOME/.cache/rasputin-supervisor-smoke. We deliberately do
//   NOT use t.TempDir() because Rancher Desktop + OrbStack + Docker Desktop
//   on macOS only bind-mount paths that have been shared with their
//   underlying VM — and $HOME is always shared while /var/folders (where
//   t.TempDir lives) is NOT. A mount-but-empty directory is the classic
//   tell: container sees the mount point but no files. The default cache
//   path is well-known so re-runs can clean up; we also remove it at exit.
//
// Side effects:
//   - Pulls the headscale image into the local image store on first run.
//   - Starts a container named `rasputin-headscale-test` (NOT the
//     production "rasputin-headscale"; cleanup removes it).
//   - Writes state to the resolved SUPERVISOR_STATE_DIR.
//
// The test asserts the full Phase 2 readiness story end-to-end:
//   1. Supervisor.Start() creates and starts the container.
//   2. Supervisor.Healthy() returns true.
//   3. ContainerInfo reports the expected image and port mapping.
//   4. (After bootstrapping a user + apikey via docker exec) RealClient
//      can talk to the supervised Headscale instance.
//   5. Supervisor.Stop() gracefully stops it.
//   6. Re-Start() picks the container back up without re-pulling.
//   7. Cleanup removes the container.

package mesh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const supervisorTestContainer = "rasputin-headscale-test"

func TestSupervisor_LiveDockerLifecycle(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not on PATH: %v", err)
	}
	// Confirm the daemon is reachable; bail with a clear skip otherwise.
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unreachable; output=%q err=%v", strings.TrimSpace(string(out)), err)
	}

	stateDir, err := resolveSupervisorStateDir()
	if err != nil {
		t.Fatalf("resolve state dir: %v", err)
	}
	t.Logf("supervisor state dir: %s", stateDir)
	listenAddr := envDefault("SUPERVISOR_LISTEN_ADDR", "127.0.0.1:18080")

	// Pre-clean any leftover container from a previous failed run.
	_ = exec.Command("docker", "rm", "-f", supervisorTestContainer).Run()
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", supervisorTestContainer).Run()
		_ = os.RemoveAll(stateDir)
	})

	// Mint a Mesh TLS CA in the same state tree so the supervisor renders
	// an HTTPS-enabled Headscale config end-to-end. The CA lives outside
	// the per-container state dir so re-runs (which wipe stateDir) don't
	// invalidate it; in real deployment it'd be at <trustDir>/mesh-ca.*.
	caDir := filepath.Join(stateDir, "trust")
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		t.Fatalf("mkdir trust: %v", err)
	}
	ca, err := EnsureMeshCA(caDir, "supervisor-smoke")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}

	sup, err := NewDockerSupervisor(DockerSupervisorConfig{
		StateDir:      stateDir,
		ContainerName: supervisorTestContainer,
		ListenAddr:    listenAddr,
		ServerURL:     "https://" + listenAddr,
		HealthTimeout: 60 * time.Second, // first-run image pull can be slow
		PullTimeout:   3 * time.Minute,
		MeshCA:        ca,
	})
	if err != nil {
		t.Fatalf("NewDockerSupervisor: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	t.Run("Start_FromMissing", func(t *testing.T) {
		if err := sup.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
	})

	t.Run("Healthy", func(t *testing.T) {
		ok, err := sup.Healthy(ctx)
		if err != nil || !ok {
			t.Fatalf("Healthy: ok=%v err=%v", ok, err)
		}
	})

	t.Run("ContainerInfo", func(t *testing.T) {
		info, err := sup.ContainerInfo(ctx)
		if err != nil {
			t.Fatalf("ContainerInfo: %v", err)
		}
		t.Logf("container: %+v", info)
		if info.Status != "running" {
			t.Errorf("status: %q", info.Status)
		}
		if !strings.Contains(info.Image, "headscale") {
			t.Errorf("image: %q", info.Image)
		}
	})

	// Bootstrap a user + API key via docker exec, then drive RealClient
	// against the live container to prove the full Phase 2 chain works.
	t.Run("RealClient_FullChainAgainstSupervised", func(t *testing.T) {
		if out, err := exec.CommandContext(ctx, "docker", "exec", supervisorTestContainer,
			"headscale", "users", "create", "smoke-operator").CombinedOutput(); err != nil {
			// "already exists" is fine for a re-run scenario; anything else fails.
			low := strings.ToLower(string(out))
			if !strings.Contains(low, "already exists") {
				t.Fatalf("create user: %v\n%s", err, out)
			}
		}
		raw, err := exec.CommandContext(ctx, "docker", "exec", supervisorTestContainer,
			"headscale", "apikeys", "create", "--expiration", "10m").CombinedOutput()
		if err != nil {
			t.Fatalf("mint apikey: %v\n%s", err, raw)
		}
		// The CLI prints the key (one of the trailing lines). Take the
		// last hskey- prefixed line.
		var apiKey string
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "hskey-") {
				apiKey = line
			}
		}
		if apiKey == "" {
			t.Fatalf("could not parse API key from CLI output:\n%s", raw)
		}

		// Trust pool that ONLY contains our Mesh CA — proves the chain
		// works without falling back to system roots (which wouldn't
		// trust a per-installation CA anyway).
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca.CertPEM) {
			t.Fatal("failed to add mesh CA to trust pool")
		}
		c, err := NewRealClient(RealClientConfig{
			BaseURL:        "https://" + listenAddr,
			APIKey:         apiKey,
			RequestTimeout: 10 * time.Second,
			TLSConfig:      &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		})
		if err != nil {
			t.Fatalf("NewRealClient: %v", err)
		}
		if err := c.EnsureUser(ctx, "smoke-operator"); err != nil {
			t.Fatalf("EnsureUser: %v", err)
		}
		id, plaintext, err := c.CreatePreAuthKey(ctx, CreatePreAuthKeyInput{
			User:     "smoke-operator",
			Reusable: false,
			Expiry:   time.Now().Add(time.Hour),
			Tags:     []string{"tag:user-device"},
		})
		if err != nil {
			t.Fatalf("CreatePreAuthKey: %v", err)
		}
		if id == "" || plaintext == "" {
			t.Fatalf("empty id or plaintext: id=%q plaintext=%q", id, plaintext)
		}
		t.Logf("end-to-end via supervised container: key id=%s plaintext_prefix=%s",
			id, plaintext[:min(20, len(plaintext))])

		// The two pre-auth profiles against the real API: a user-device key
		// may not carry the node tag; a node key carries exactly the node
		// tag, is single-use, and is expired on demand (as the enrol dispatch
		// step does when it ends).
		svc := NewService(Config{DefaultUser: "smoke-operator"}, nil, c, NewNoopSupervisor())
		if _, err := svc.MintPreAuthKey(ctx, PreAuthUserDevice, PreAuthKeyRequest{Tags: []string{meshNodeTag}}); !errors.Is(err, ErrPreAuthRequest) {
			t.Errorf("user key with the node tag: %v", err)
		}
		uk, err := svc.MintPreAuthKey(ctx, PreAuthUserDevice, PreAuthKeyRequest{})
		if err != nil {
			t.Fatalf("user key: %v", err)
		}
		nk, err := svc.MintPreAuthKey(ctx, PreAuthNode, PreAuthKeyRequest{})
		if err != nil {
			t.Fatalf("node key: %v", err)
		}
		if err := c.ExpirePreAuthKey(ctx, nk.ID); err != nil {
			t.Fatalf("expire node key: %v", err)
		}
		keys, err := c.ListPreAuthKeys(ctx, "")
		if err != nil {
			t.Fatalf("list keys: %v", err)
		}
		seen := 0
		for _, k := range keys {
			t.Logf("preauth key id=%s tags=%v reusable=%v expires=%s", k.ID, k.Tags, k.Reusable, k.Expiration.Format(time.RFC3339))
			switch k.ID {
			case nk.ID:
				seen++
				if !slices.Equal(k.Tags, []string{meshNodeTag}) || k.Reusable || k.Expiration.After(time.Now()) {
					t.Errorf("node key on Headscale = %+v; want [%s], single-use, expired", k, meshNodeTag)
				}
			case uk.ID:
				seen++
				if !slices.Equal(k.Tags, []string{UserDeviceTag}) || k.Expiration.After(time.Now().Add(UserDeviceKeyDefaultExpiry+time.Minute)) {
					t.Errorf("user key on Headscale = %+v", k)
				}
			}
		}
		if seen != 2 {
			t.Errorf("found %d of the 2 minted keys on Headscale", seen)
		}
	})

	t.Run("Start_IsIdempotent", func(t *testing.T) {
		if err := sup.Start(ctx); err != nil {
			t.Fatalf("second Start: %v", err)
		}
	})

	t.Run("Stop_GracefullyStops", func(t *testing.T) {
		if err := sup.Stop(ctx); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		ok, err := sup.Healthy(ctx)
		if err != nil {
			t.Fatalf("Healthy after stop: %v", err)
		}
		if ok {
			t.Error("Healthy should be false after Stop")
		}
	})

	t.Run("Start_PicksUpExistingContainer", func(t *testing.T) {
		if err := sup.Start(ctx); err != nil {
			t.Fatalf("re-Start: %v", err)
		}
		ok, err := sup.Healthy(ctx)
		if err != nil || !ok {
			t.Errorf("Healthy after re-Start: ok=%v err=%v", ok, err)
		}
	})
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// resolveSupervisorStateDir returns the host path the supervisor will
// bind-mount into the Headscale container. Honor an explicit env override;
// otherwise default to a HOME-rooted path which works across the
// VM-backed macOS runtimes (Rancher Desktop, OrbStack, Docker Desktop)
// without extra config.
func resolveSupervisorStateDir() (string, error) {
	if v := os.Getenv("SUPERVISOR_STATE_DIR"); v != "" {
		if err := os.MkdirAll(v, 0o755); err != nil {
			return "", err
		}
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := home + "/.cache/rasputin-supervisor-smoke"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

const sessionKeyTestContainer = "rasputin-headscale-apikey-test"

// TestSupervisor_LiveSessionAPIKey drives the per-start admin key against a
// real headscale container (the pinned image):
//
//  1. a legacy long-lived key file (as older api releases persisted it) is
//     expired on Headscale by its prefix and then deleted;
//  2. an api restart (a new supervisor over the same state dir) mints a new
//     key and the previous process's key stops working (HTTP 401);
//  3. a client holding a key that has been expired re-mints on the 401 and
//     its request succeeds;
//  4. the metrics listener is off.
func TestSupervisor_LiveSessionAPIKey(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unreachable; output=%q err=%v", strings.TrimSpace(string(out)), err)
	}
	base, err := resolveSupervisorStateDir()
	if err != nil {
		t.Fatalf("resolve state dir: %v", err)
	}
	stateDir := filepath.Join(base, "session-key")
	listenAddr := envDefault("SUPERVISOR_APIKEY_LISTEN_ADDR", "127.0.0.1:18081")
	_ = exec.Command("docker", "rm", "-f", sessionKeyTestContainer).Run()
	_ = os.RemoveAll(stateDir)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", sessionKeyTestContainer).Run()
		_ = os.RemoveAll(stateDir)
	})
	if err := os.MkdirAll(filepath.Join(stateDir, "trust"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ca, err := EnsureMeshCA(filepath.Join(stateDir, "trust"), "apikey-smoke")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	newSup := func() *DockerSupervisor {
		s, err := NewDockerSupervisor(DockerSupervisorConfig{
			StateDir:      stateDir,
			ContainerName: sessionKeyTestContainer,
			ListenAddr:    listenAddr,
			ServerURL:     "https://" + listenAddr,
			HealthTimeout: 60 * time.Second,
			PullTimeout:   3 * time.Minute,
			MeshCA:        ca,
		})
		if err != nil {
			t.Fatalf("NewDockerSupervisor: %v", err)
		}
		return s
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	clientWith := func(key string, refresh func(context.Context) (string, error)) *RealClient {
		c, err := NewRealClient(RealClientConfig{
			BaseURL: "https://" + listenAddr, APIKey: key, RefreshAPIKey: refresh,
			RequestTimeout: 10 * time.Second,
			TLSConfig:      &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		})
		if err != nil {
			t.Fatalf("NewRealClient: %v", err)
		}
		return c
	}
	status := func(ctx context.Context, key string) int {
		_, err := clientWith(key, nil).ListNodes(ctx)
		if err == nil {
			return 200
		}
		var he *HTTPError
		if errors.As(err, &he) {
			return he.Status
		}
		t.Fatalf("ListNodes: %v", err)
		return 0
	}
	apikeysList := func(ctx context.Context) string {
		out, err := exec.CommandContext(ctx, "docker", "exec", sessionKeyTestContainer, "headscale", "apikeys", "list").CombinedOutput()
		if err != nil {
			t.Fatalf("apikeys list: %v\n%s", err, out)
		}
		return string(out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	sup1 := newSup()
	if err := sup1.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// An older api's persisted 10-year key.
	raw, err := exec.CommandContext(ctx, "docker", "exec", sessionKeyTestContainer,
		"headscale", "apikeys", "create", "--expiration", "87600h").CombinedOutput()
	if err != nil {
		t.Fatalf("mint legacy key: %v\n%s", err, raw)
	}
	legacy := parseAPIKey(raw)
	legacyPrefix, err := headscaleAPIKeyPrefix(legacy)
	if err != nil {
		t.Fatalf("legacy key from the real CLI has no readable prefix (%v); output shape: %d bytes", err, len(raw))
	}
	if err := os.WriteFile(sup1.legacyAPIKeyPath(), []byte(legacy+"\n"), 0o600); err != nil {
		t.Fatalf("seed legacy file: %v", err)
	}
	if got := status(ctx, legacy); got != 200 {
		t.Fatalf("legacy key before migration: HTTP %d, want 200", got)
	}

	key1, err := sup1.MintSessionAPIKey(ctx)
	if err != nil {
		t.Fatalf("MintSessionAPIKey (first start): %v", err)
	}
	p1, _ := headscaleAPIKeyPrefix(key1)
	t.Logf("first start: minted %s; legacy %s", p1, legacyPrefix)
	if got := status(ctx, legacy); got != 401 {
		t.Errorf("legacy key after migration: HTTP %d, want 401", got)
	}
	if _, err := os.Stat(sup1.legacyAPIKeyPath()); !os.IsNotExist(err) {
		t.Errorf("legacy key file still present: %v", err)
	}
	if got := status(ctx, key1); got != 200 {
		t.Fatalf("session key 1: HTTP %d, want 200", got)
	}

	// api restart: a new supervisor over the same state dir.
	sup2 := newSup()
	if err := sup2.Start(ctx); err != nil {
		t.Fatalf("re-Start: %v", err)
	}
	// A recorded prefix Headscale has never heard of (a restored Headscale
	// DB, say) must read as done, not be retried forever.
	f, err := os.OpenFile(sup2.apiKeyPrefixesPath(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open prefixes: %v", err)
	}
	_, _ = f.WriteString("NoSuchPrefx1\n")
	_ = f.Close()
	key2, err := sup2.MintSessionAPIKey(ctx)
	if err != nil {
		t.Fatalf("MintSessionAPIKey (restart): %v", err)
	}
	p2, _ := headscaleAPIKeyPrefix(key2)
	t.Logf("restart: minted %s", p2)
	if got := status(ctx, key1); got != 401 {
		t.Errorf("previous start's key after restart: HTTP %d, want 401", got)
	}
	if got := status(ctx, key2); got != 200 {
		t.Errorf("current key: HTTP %d, want 200", got)
	}
	if b, _ := os.ReadFile(sup2.apiKeyPrefixesPath()); strings.TrimSpace(string(b)) != p2 {
		t.Errorf("recorded prefixes = %q, want %q", b, p2)
	}
	t.Logf("headscale apikeys list after restart:\n%s", apikeysList(ctx))

	// A client still holding key1 (expired) re-mints on the 401.
	c := clientWith(key1, sup2.MintSessionAPIKey)
	if err := c.EnsureUser(ctx, "rasputin-operator"); err != nil {
		t.Fatalf("EnsureUser with an expired key and a re-mint: %v", err)
	}
	if got := status(ctx, key2); got != 401 {
		t.Errorf("the re-mint should have expired key2: HTTP %d", got)
	}

	// Metrics listener off.
	logs, _ := exec.CommandContext(ctx, "docker", "logs", sessionKeyTestContainer).CombinedOutput()
	if !strings.Contains(string(logs), "metrics server disabled") {
		t.Errorf("headscale did not report the metrics server disabled; logs:\n%s", logs)
	}
}
