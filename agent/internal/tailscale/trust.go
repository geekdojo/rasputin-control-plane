package tailscale

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// CABundlePath is the exported accessor for the resolved Mesh CA bundle path
// (env override RASPUTIN_MESH_CA_BUNDLE, else the per-image default). The
// updater's bundle-download HTTPS client uses it to trust the api's mesh-CA
// leaf — the api serves /api/bundles/{sha} over the mesh-CA HTTPS listener,
// and the agent's process (unlike tailscaled's) has no SSL_CERT_FILE, so its
// default client would otherwise reject that cert.
func CABundlePath() string { return caBundlePath() }

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
	attempts := []struct {
		probe string // init-system marker that must exist to bother trying
		argv  []string
	}{
		{"/run/systemd/system", []string{"systemctl", "restart", "tailscaled"}},
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
		return errors.New("restart tailscaled: no supported init system found (looked for systemd at /run/systemd/system and procd at /etc/init.d/tailscale)")
	}
	return fmt.Errorf("restart tailscaled (tried %s): %w", strings.Join(tried, ", "), errors.Join(errs...))
}
