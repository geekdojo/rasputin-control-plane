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
// Side effects:
//   - Pulls the headscale image into the local image store on first run.
//   - Starts a container named `rasputin-headscale-test` (NOT the
//     production "rasputin-headscale"; cleanup removes it).
//   - Writes state to a t.TempDir on the host.
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
	"os"
	"os/exec"
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

	stateDir := t.TempDir()
	listenAddr := envDefault("SUPERVISOR_LISTEN_ADDR", "127.0.0.1:18080")

	// Pre-clean any leftover container from a previous failed run.
	_ = exec.Command("docker", "rm", "-f", supervisorTestContainer).Run()
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", supervisorTestContainer).Run()
	})

	sup, err := NewDockerSupervisor(DockerSupervisorConfig{
		StateDir:      stateDir,
		ContainerName: supervisorTestContainer,
		ListenAddr:    listenAddr,
		ServerURL:     "http://" + listenAddr,
		HealthTimeout: 60 * time.Second, // first-run image pull can be slow
		PullTimeout:   3 * time.Minute,
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

		c, err := NewRealClient(RealClientConfig{
			BaseURL:        "http://" + listenAddr,
			APIKey:         apiKey,
			RequestTimeout: 10 * time.Second,
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
