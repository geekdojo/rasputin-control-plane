// Package nodetrust is the agent's half of node trust delivery: the one trust
// bundle this node holds (the controlplane CA, plus the operator's CA when
// Headscale is theirs), how it is installed, what this node reports it
// trusts, and the trust.install handler that receives it.
//
// The bundle is what the agent's own HTTPS clients (the OS update download,
// the backup transfer, the restore fetch) verify the api against, and what
// tailscaled is pointed at with SSL_CERT_FILE. It is not a mesh concern, so it
// lives here and not in agent/internal/tailscale; the tailscale backend is one
// of its consumers (a Reloader), and installs through it only for a legacy
// mesh.enroll from an api that predates trust.install.
package nodetrust

import (
	"os"
	"strings"
)

// defaultBundlePath is where the agent writes the trust bundle so tailscaled
// trusts the self-hosted Headscale's HTTPS leaf. tailscaled's service is
// configured (per OS image) with SSL_CERT_FILE pointing at this same path.
//
// Go's crypto/x509 reads SSL_CERT_FILE *in addition to* the default cert
// directories (/etc/ssl/certs, ...), so this file can hold only the bundle
// while the public roots tailscaled needs for Tailscale's DERP relays still
// load from the system dirs. The path is overridable via
// RASPUTIN_MESH_CA_BUNDLE because the persistent location differs per image
// (Buildroot: /var/lib/rasputin/...; OpenWrt: /etc is the persistent fs).
// Both the path and the variable are compatibility names: the OS images and
// the OpenWrt init script name them.
const defaultBundlePath = "/var/lib/rasputin/mesh/tailscaled-ca.pem"

// BundlePath is the resolved trust bundle path: RASPUTIN_MESH_CA_BUNDLE when
// it is set, else the per-image default.
//
// Trimmed: an override that is only whitespace is a misconfiguration, and
// honouring it would point tailscaled's trust file at a path that cannot
// exist — which reads, from the outside, exactly like "no bundle is
// installed". Falling back to the per-image default is the closed answer.
func BundlePath() string {
	if p := strings.TrimSpace(os.Getenv("RASPUTIN_MESH_CA_BUNDLE")); p != "" {
		return p
	}
	return defaultBundlePath
}
