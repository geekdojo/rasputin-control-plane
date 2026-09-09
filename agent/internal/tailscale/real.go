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

// TrustFingerprint is the fingerprint of the bundle at b.caBundle — the one
// SSL_CERT_FILE points tailscaled at and the agent's own HTTPS clients read.
func (b *RealBackend) TrustFingerprint() string { return InstalledCAFingerprint(b.caBundle) }

func (b *RealBackend) Enroll(ctx context.Context, in EnrollInput) (Status, error) {
	if in.LoginServer == "" || in.AuthKey == "" {
		return Status{}, errors.New("tailscale: login server and auth key are required")
	}
	started := time.Now()
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
				if ctx.Err() != nil {
					return Status{}, fmt.Errorf("tailscale: restarting tailscaled had not finished when the enroll deadline expired, %s after the enroll began: %w",
						tidyDuration(time.Since(started)), err)
				}
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
	// `tailscale up --auth-key` blocks until tailscaled reports Running —
	// i.e. until Headscale has answered the login — and says nothing while
	// it waits. When ctx expires first, CommandContext kills it (SIGKILL: the
	// default Cancel is Process.Kill) and Run returns the bare "signal:
	// killed" with an empty stderr, which is all e3bench-compute1 had to say
	// for itself on 2026-09-05 (geekdojo/geekdojo-brain#402). ctx.Err() is
	// the tell — the ExitError wins over the context error in Run's return
	// value — so it is checked explicitly and the kill is named for what it
	// is: which command, after how long, under what deadline, and what
	// tailscaled says now.
	cmd := exec.CommandContext(ctx, b.binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Once killed, do not sit on the stderr pipe waiting for EOF: the CLI
	// forks nothing, but a hung one is exactly the case being handled.
	cmd.WaitDelay = 2 * time.Second
	upStarted := time.Now()
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return Status{}, b.enrollKilledByDeadline(ctx, in.LoginServer, started, upStarted)
		}
		return Status{}, fmt.Errorf("tailscale up: %w (stderr=%s)", err, redactAuthKey(stderr.String(), in.AuthKey))
	}
	return b.Status(ctx)
}

// enrollKilledByDeadline is the error for a `tailscale up` that the enroll
// deadline killed while it was still waiting on the login. It carries what
// an operator needs without the agent log: how long the CLI ran, the
// deadline that ended it, how much of that deadline the mesh CA install and
// tailscaled restart had already used, which Headscale it was waiting on,
// and what tailscaled reports now — on a fresh, short context, since the
// one that fired can run nothing.
func (b *RealBackend) enrollKilledByDeadline(ctx context.Context, loginServer string, started, upStarted time.Time) error {
	ran := tidyDuration(time.Since(upStarted))
	deadline := "the enroll deadline"
	if dl, ok := ctx.Deadline(); ok {
		deadline = fmt.Sprintf("the %s enroll deadline", tidyDuration(dl.Sub(started)))
	}
	prep := ""
	if spent := upStarted.Sub(started); spent >= time.Second {
		prep = fmt.Sprintf(" (%s of it had gone to installing the mesh CA and restarting tailscaled)", tidyDuration(spent))
	}
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	state := "tailscaled's state could not be read afterwards"
	if s, err := b.statusJSON(probeCtx); err == nil && s.BackendState != "" {
		state = "tailscaled reports " + s.BackendState
	}
	if strings.HasPrefix(state, "tailscaled reports Running") {
		// The login landed as the CLI was being killed. Say so rather than
		// claim Headscale never answered; the retry finds the node enrolled.
		return fmt.Errorf("tailscale up killed after %s by %s while still running%s; headscale at %s answered the login only as the CLI was killed — %s, so a retry will find the node enrolled",
			ran, deadline, prep, loginServer, state)
	}
	return fmt.Errorf("tailscale up killed after %s by %s while still running%s; headscale at %s had not answered the login (%s)",
		ran, deadline, prep, loginServer, state)
}

// tidyDuration renders a duration the way a log reader counts: whole seconds
// once it is a second or more, else to the ten-millisecond.
func tidyDuration(d time.Duration) time.Duration {
	if d >= time.Second {
		return d.Round(time.Second)
	}
	return d.Round(10 * time.Millisecond)
}

// redactAuthKey keeps the pre-auth key out of anything the CLI echoed back.
// tailscale does not print its --auth-key today; this is the guard for the
// day it does, because the error travels into the job ledger and the log.
func redactAuthKey(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "<auth key>")
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

// statusJSON runs `tailscale status --json` and decodes the subset above.
func (b *RealBackend) statusJSON(ctx context.Context) (tsStatusJSON, error) {
	out, err := exec.CommandContext(ctx, b.binary, "status", "--json").Output()
	if err != nil {
		return tsStatusJSON{}, fmt.Errorf("tailscale status: %w", err)
	}
	var s tsStatusJSON
	if err := json.Unmarshal(out, &s); err != nil {
		return tsStatusJSON{}, fmt.Errorf("decode status: %w", err)
	}
	return s, nil
}

func (b *RealBackend) Status(ctx context.Context) (Status, error) {
	s, err := b.statusJSON(ctx)
	if err != nil {
		return Status{}, err
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
