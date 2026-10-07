package tailscale

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// The trust bundle is NOT appended to the box's global trust bundle any more
// (geekdojo/geekdojo-brain#542). The agent used to do that on images whose
// tailscaled service could not take an SSL_CERT_FILE env — the OpenWrt
// firewall, whose stock tailscale init forwards no env to the daemon. It made
// a CA with no name constraints an anchor for every TLS client on the box, for
// every name, and an OpenWrt `ca-bundle` package upgrade silently dropped it
// again, so it was not even a durable way to be too trusting.
//
// Both images now give tailscaled the bundle at nodetrust.BundlePath() through
// SSL_CERT_FILE: a systemd drop-in on rasputin-os, and the firewall's own
// procd service (files/etc/init.d/rasputin-tailscale) on OpenWrt. Go reads
// SSL_CERT_FILE in place of its built-in bundle list but still walks its
// certificate directories, so public roots keep loading either way. The
// firewall's init strips a block a previous agent appended.

// cmdRunner runs a command and returns combined output. Injected so tests can
// drive restart logic without a real init system.
type cmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// initSystemPresent reports whether an init system's entrypoint exists. A var
// so tests can drive either platform without a real filesystem.
var initSystemPresent = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// restartTailscaled bounces the daemon so it reloads the system cert pool
// (Go caches it at process start). Rasputin ships two init systems — systemd
// on the Buildroot OS, procd on the OpenWrt firewall — and only ever ONE of
// them exists on a given box.
//
// So probe before attempting, rather than trying both and joining the errors.
// The old version always tried both, which meant every systemd-node failure
// reported a guaranteed-useless second line:
//
//	restart tailscaled (tried systemctl + procd): exit status 1
//	fork/exec /etc/init.d/tailscale: no such file or directory
//
// The procd line reads as the cause and isn't — it can never exist there. On
// the 2026-08-03 bench that message produced a confident misdiagnosis
// ("wrong-platform bug") when the real cause was the first line: the node was
// mid-reboot, so systemctl exited 1. An error that names the wrong cause is
// worse than a terse one.
func restartTailscaled(ctx context.Context, run cmdRunner) error {
	// Ordered by specificity, not by platform: only one of these markers
	// exists on a given box, except on an OpenWrt firewall mid-upgrade, where
	// both init scripts are present and Rasputin's is the one that carries
	// SSL_CERT_FILE. Restarting the stock service there would start a second,
	// env-less daemon on the same state file and port, so it is tried only
	// when ours is absent — which is an image that predates
	// geekdojo/geekdojo-brain#542 and still has the appended-CA trust.
	attempts := []struct {
		probe string // init-system marker that must exist to bother trying
		argv  []string
	}{
		{"/run/systemd/system", []string{"systemctl", "restart", "tailscaled"}},
		{"/etc/init.d/rasputin-tailscale", []string{"/etc/init.d/rasputin-tailscale", "restart"}},
		{"/etc/init.d/tailscale", []string{"/etc/init.d/tailscale", "restart"}},
	}
	var errs []error
	var tried []string
	for _, a := range attempts {
		if !initSystemPresent(a.probe) {
			continue
		}
		tried = append(tried, a.argv[0])
		if _, err := run(ctx, a.argv[0], a.argv[1:]...); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}
	if len(tried) == 0 {
		return errors.New("restart tailscaled: no supported init system found (looked for systemd at /run/systemd/system and procd at /etc/init.d/rasputin-tailscale and /etc/init.d/tailscale)")
	}
	return fmt.Errorf("restart tailscaled (tried %s): %w", strings.Join(tried, ", "), errors.Join(errs...))
}
