package tailscale

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// defaultCABundlePath is where the agent writes the Mesh CA so tailscaled
// trusts the self-hosted Headscale's HTTPS leaf. tailscaled's service is
// configured (per OS image) with SSL_CERT_FILE pointing at this same path.
//
// Go's crypto/x509 reads SSL_CERT_FILE *in addition to* the default cert
// directories (/etc/ssl/certs, ...), so this file can hold only the Mesh CA
// while the public roots tailscaled needs for Tailscale's DERP relays still
// load from the system dirs. The path is overridable via
// RASPUTIN_MESH_CA_BUNDLE because the persistent location differs per image
// (Buildroot: /var/lib/rasputin/...; OpenWrt: /etc is the persistent fs).
const defaultCABundlePath = "/var/lib/rasputin/mesh/tailscaled-ca.pem"

func caBundlePath() string {
	if p := os.Getenv("RASPUTIN_MESH_CA_BUNDLE"); p != "" {
		return p
	}
	return defaultCABundlePath
}

// installMeshCA writes the Mesh CA PEM to path, atomically, and reports
// whether the on-disk content actually changed. Idempotent: a re-enroll with
// the same CA is a no-op (changed=false), so the caller skips the tailscaled
// restart. After a reboot the persistent file already holds the CA, so
// tailscaled trusts it from first start with no restart needed.
func installMeshCA(caPEM []byte, path string) (changed bool, err error) {
	if len(bytes.TrimSpace(caPEM)) == 0 {
		return false, nil
	}
	want := append(bytes.TrimSpace(caPEM), '\n')
	if existing, e := os.ReadFile(path); e == nil && bytes.Equal(existing, want) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, want, 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, fmt.Errorf("rename %s: %w", path, err)
	}
	return true, nil
}

// systemBundleMarker delimits the Mesh CA we append to a system trust bundle,
// so the append is idempotent and recognizable.
const systemBundleMarker = "# rasputin-mesh-ca (managed by rasputin-agent)"

// defaultSystemBundles are the trust-bundle files Go's crypto/x509 reads first
// on Linux. Appending the Mesh CA here is how nodes whose tailscaled service
// can't take an SSL_CERT_FILE env trust the self-hosted Headscale — notably
// the OpenWrt firewall, whose stock tailscale init script has no env hook. On
// images with a read-only /etc (Buildroot squashfs) the append fails and the
// SSL_CERT_FILE bundle (installMeshCA) is the mechanism instead. Running both
// means the agent doesn't need to know which OS it's on.
var defaultSystemBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Buildroot ca-certificates, OpenWrt ca-bundle — Go's first candidate
}

// ensureCAInSystemBundle appends the Mesh CA to the first writable system
// trust bundle that already exists, unless it's already present. Best-effort:
// a read-only or absent bundle returns (false, err) and the caller treats it
// as "not my mechanism here" rather than fatal. Idempotent via marker/content.
func ensureCAInSystemBundle(caPEM []byte, candidates []string) (changed bool, err error) {
	trimmed := bytes.TrimSpace(caPEM)
	if len(trimmed) == 0 {
		return false, nil
	}
	for _, path := range candidates {
		existing, e := os.ReadFile(path)
		if e != nil {
			err = e
			continue // bundle not present at this path
		}
		if bytes.Contains(existing, trimmed) {
			return false, nil // already trusted
		}
		f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if e != nil {
			err = e // read-only fs (Buildroot) or perms — not our mechanism here
			continue
		}
		_, werr := f.WriteString("\n" + systemBundleMarker + "\n" + string(trimmed) + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			err = werr
			continue
		}
		return true, nil
	}
	return false, err
}

// cmdRunner runs a command and returns combined output. Injected so tests can
// drive restart logic without a real init system.
type cmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// restartTailscaled bounces the daemon so it reloads the system cert pool
// (Go caches it at process start). Tries systemd first (Buildroot OS), then
// procd (OpenWrt firewall). Best-effort across the two init systems Rasputin
// images actually ship.
func restartTailscaled(ctx context.Context, run cmdRunner) error {
	var errs []error
	for _, attempt := range [][]string{
		{"systemctl", "restart", "tailscaled"},
		{"/etc/init.d/tailscale", "restart"},
	} {
		if _, err := run(ctx, attempt[0], attempt[1:]...); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}
	return fmt.Errorf("restart tailscaled (tried systemctl + procd): %w", errors.Join(errs...))
}
