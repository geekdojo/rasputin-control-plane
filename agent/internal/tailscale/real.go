package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// RealBackend shells out to the local tailscale CLI. tailscaled must
// already be running (systemd on Linux, the .app on macOS, the Tailscale
// service on Windows).
type RealBackend struct {
	binary string
}

// NewRealBackend resolves the tailscale binary path. Returns an error if
// not found.
func NewRealBackend() (*RealBackend, error) {
	bin, err := exec.LookPath("tailscale")
	if err != nil {
		return nil, fmt.Errorf("tailscale binary not on PATH: %w", err)
	}
	return &RealBackend{binary: bin}, nil
}

func (b *RealBackend) Name() string { return "tailscale" }

func (b *RealBackend) Enroll(ctx context.Context, in EnrollInput) (Status, error) {
	if in.LoginServer == "" || in.AuthKey == "" {
		return Status{}, errors.New("tailscale: login server and auth key are required")
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
