package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// RealBackend shells out to the local tailscale CLI. tailscaled must
// already be running (systemd on Linux, the .app on macOS, the Tailscale
// service on Windows).
type RealBackend struct {
	binary   string
	caBundle string    // where the Mesh CA is installed for tailscaled to trust
	run      cmdRunner // restart hook; injectable for tests
}

// NewRealBackend resolves the tailscale binary path. Returns an error if
// not found.
func NewRealBackend() (*RealBackend, error) {
	bin, err := exec.LookPath("tailscale")
	if err != nil {
		return nil, fmt.Errorf("tailscale binary not on PATH: %w", err)
	}
	return &RealBackend{binary: bin, caBundle: caBundlePath(), run: execRun}, nil
}

// execRun is the default cmdRunner — runs a binary and returns combined output.
func execRun(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (b *RealBackend) Name() string { return "tailscale" }

func (b *RealBackend) Enroll(ctx context.Context, in EnrollInput) (Status, error) {
	if in.LoginServer == "" || in.AuthKey == "" {
		return Status{}, errors.New("tailscale: login server and auth key are required")
	}
	// Trust the self-hosted Headscale's HTTPS leaf before tailscaled dials it.
	// The Mesh CA isn't in any public store, so without this `tailscale up`
	// fails the TLS handshake. Only restart tailscaled when the CA actually
	// changed (first enroll); subsequent enrolls + post-reboot starts already
	// have it on the persistent bundle.
	if len(in.MeshCAPEM) > 0 {
		// Two trust mechanisms, run together so the agent doesn't need to know
		// its OS: (1) a dedicated bundle at b.caBundle that the tailscaled
		// service trusts via SSL_CERT_FILE (Buildroot, read-only /etc); (2)
		// appending to the system trust bundle (OpenWrt, writable /etc, whose
		// stock tailscale init has no env hook). Each no-ops where it doesn't
		// apply. tailscaled caches the cert pool at start, so restart it if
		// either mechanism changed something.
		changedFile, err := installMeshCA(in.MeshCAPEM, b.caBundle)
		if err != nil {
			return Status{}, fmt.Errorf("tailscale: install mesh CA: %w", err)
		}
		changedBundle, berr := ensureCAInSystemBundle(in.MeshCAPEM, defaultSystemBundles)
		if berr != nil && !changedBundle {
			log.Printf("rasputin-agent: mesh CA system-bundle append skipped (%v); relying on SSL_CERT_FILE=%s", berr, b.caBundle)
		}
		if changedFile || changedBundle {
			log.Printf("rasputin-agent: mesh CA installed (file=%v bundle=%v); restarting tailscaled", changedFile, changedBundle)
			if err := restartTailscaled(ctx, b.run); err != nil {
				return Status{}, fmt.Errorf("tailscale: %w", err)
			}
			b.waitForDaemon(ctx)
		}
	}
	args := []string{
		"up",
		"--login-server=" + in.LoginServer,
		"--auth-key=" + in.AuthKey,
		"--reset", // start from a clean state — matches the saga's intent
	}
	if in.Hostname != "" {
		args = append(args, "--hostname="+in.Hostname)
	}
	if len(in.AdvertiseRoutes) > 0 {
		args = append(args, "--advertise-routes="+strings.Join(in.AdvertiseRoutes, ","))
	}
	if in.AcceptDNS {
		args = append(args, "--accept-dns=true")
	}
	if in.AcceptRoutes {
		args = append(args, "--accept-routes=true")
	}
	cmd := exec.CommandContext(ctx, b.binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return Status{}, fmt.Errorf("tailscale up: %w (stderr=%s)", err, stderr.String())
	}
	return b.Status(ctx)
}

// waitForDaemon polls `tailscale status` until the daemon's socket answers
// (or ~10s elapses) so the subsequent `tailscale up` doesn't race a
// just-restarted tailscaled. Best-effort: a slow daemon just means `up`
// retries the connection itself.
func (b *RealBackend) waitForDaemon(ctx context.Context) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := b.run(ctx, b.binary, "status", "--json"); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func (b *RealBackend) Leave(ctx context.Context) error {
	// `tailscale logout` removes the key; `tailscale down` brings the
	// interface down. We do both for a clean leave.
	if out, err := exec.CommandContext(ctx, b.binary, "logout").CombinedOutput(); err != nil {
		return fmt.Errorf("tailscale logout: %w (out=%s)", err, string(out))
	}
	if out, err := exec.CommandContext(ctx, b.binary, "down").CombinedOutput(); err != nil {
		return fmt.Errorf("tailscale down: %w (out=%s)", err, string(out))
	}
	return nil
}

// tsStatusJSON is the subset of `tailscale status --json` the agent needs.
// The CLI returns a much larger struct; we ignore the rest.
type tsStatusJSON struct {
	Self struct {
		ID            string   `json:"ID"`
		HostName      string   `json:"HostName"`
		TailscaleIPs  []string `json:"TailscaleIPs"`
		PrimaryRoutes []string `json:"PrimaryRoutes"`
		Online        bool     `json:"Online"`
	} `json:"Self"`
	Peer map[string]struct {
		Online bool `json:"Online"`
	} `json:"Peer"`
	BackendState string `json:"BackendState"` // "NeedsLogin", "Running", "Stopped", ...
}

func (b *RealBackend) Status(ctx context.Context) (Status, error) {
	out, err := exec.CommandContext(ctx, b.binary, "status", "--json").Output()
	if err != nil {
		return Status{}, fmt.Errorf("tailscale status: %w", err)
	}
	var s tsStatusJSON
	if err := json.Unmarshal(out, &s); err != nil {
		return Status{}, fmt.Errorf("decode status: %w", err)
	}
	enrolled := s.BackendState == "Running"
	ip := ""
	if len(s.Self.TailscaleIPs) > 0 {
		ip = s.Self.TailscaleIPs[0]
	}
	return Status{
		Enrolled:  enrolled,
		TailnetID: s.Self.ID,
		TailnetIP: ip,
		Hostname:  s.Self.HostName,
		Routes:    s.Self.PrimaryRoutes,
		PeerCount: len(s.Peer),
	}, nil
}
