package tailscale

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
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
	// Trimmed: an override that is only whitespace is a misconfiguration, and
	// honouring it would point tailscaled's trust file at a path that cannot
	// exist — which reads, from the outside, exactly like "no mesh CA is
	// installed". Falling back to the per-image default is the closed answer.
	if p := strings.TrimSpace(os.Getenv("RASPUTIN_MESH_CA_BUNDLE")); p != "" {
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

// InstalledCAFingerprint reports proto.MeshCAFingerprint of the mesh CA bundle
// at path, or proto.MeshCAFingerprintNone when there is no bundle there (or it
// is empty, or unreadable — every one of which means "this node trusts no
// mesh CA", which is what the api needs to know). Read fresh on every call:
// installMeshCA replaces the file atomically, so the answer is always the
// bundle tailscaled and the agent's HTTPS clients actually use.
func InstalledCAFingerprint(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return proto.MeshCAFingerprintNone
	}
	if fp := proto.MeshCAFingerprint(b); fp != "" {
		return fp
	}
	return proto.MeshCAFingerprintNone
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
	// 0700, tightening an existing install's 0755 (geekdojo/geekdojo-brain#144).
	// On a controlplane this is the same /var/lib/rasputin/mesh the api keeps
	// its mesh state in — pre-auth keys among it — and the agent created it
	// world-listable. Everything that reads what is in here (tailscaled via
	// SSL_CERT_FILE, the agent's own updater client, the api) runs as root.
	if err := atrest.EnsureSecretDir(filepath.Dir(path)); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	// 0644, set explicitly: a CA certificate is public by construction, it is
	// what every node is told to trust, and the mode is stated here rather
	// than left to the umask so it cannot drift either way.
	if err := atrest.WritePublicFile(path, want); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

// The Mesh CA is NOT appended to the box's global trust bundle any more
// (geekdojo/geekdojo-brain#542). The agent used to do that on images whose
// tailscaled service could not take an SSL_CERT_FILE env — the OpenWrt
// firewall, whose stock tailscale init forwards no env to the daemon. It made
// a CA with no name constraints an anchor for every TLS client on the box, for
// every name, and an OpenWrt `ca-bundle` package upgrade silently dropped it
// again, so it was not even a durable way to be too trusting.
//
// Both images now give tailscaled the bundle at caBundlePath() through
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
