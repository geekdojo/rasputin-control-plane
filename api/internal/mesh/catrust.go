package mesh

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// One trust source for api→Headscale, and one bundle for the nodes
// (geekdojo/geekdojo-brain#506).
//
// # api → Headscale
//
// The api reaches Headscale over HTTPS in two shapes. Self-hosted, the
// supervisor runs the container and its leaf is signed by this installation's
// Mesh CA. External, the operator runs Headscale and its leaf is signed by
// whatever they use — a public CA, or their own root, which they name with
// RASPUTIN_HEADSCALE_CA_FILE. The two shapes differ only in WHICH root signs
// the leaf, so they get one helper and not two code paths: CATLSConfig builds
// the client config, with RootCAs holding exactly the PEM it is handed. An
// unparseable PEM is an error, never a silent fall back to the system pool.
//
// # Nodes
//
// A node needs the same trust through a different mechanism: tailscaled reads
// SSL_CERT_FILE (Go's only hook, the OS unit's drop-in), which the agent
// writes from the bundle mesh.enroll carries. That bundle is NodeTrustBundle.
//
// The Mesh CA is always in it. It signs more than Headscale: the api's own
// HTTPS leaf and the per-app leaves a node serves are minted from it, so a
// node that does not hold it cannot verify its own controlplane, whoever runs
// Headscale. Until this change the operator's CA was shipped INSTEAD on the
// external path, so those nodes trusted the operator's root and not their own
// cluster's.
//
// The operator's CA is appended when there is one. A bundle is a
// concatenation of PEM blocks — both the SSL_CERT_FILE path and the
// system-bundle append the agent already does take one as readily as they
// take a single certificate — so this needs no new node-side mechanism, and
// the existing convergence delivers it: the bundle's fingerprint
// (proto.MeshCAFingerprint) changes, converge_trust sees every enrolled node
// reporting a stale one, and re-delivers.

// CATLSConfig is the TLS client config that trusts exactly caPEM and nothing
// else. source names where the PEM came from, so a parse failure says which
// input to fix.
func CATLSConfig(caPEM []byte, source string) (*tls.Config, error) {
	if len(bytes.TrimSpace(caPEM)) == 0 {
		return nil, fmt.Errorf("mesh: %s: no CA PEM to trust", source)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mesh: %s: no certificates parsed from the CA PEM", source)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// NodeTrustBundle concatenates the PEM blobs a node must trust, in the order
// given and without duplicates: the Mesh CA first, then the operator's CA
// when Headscale is theirs. Empty inputs are skipped, and the result is empty
// when everything was.
func NodeTrustBundle(pems ...[]byte) []byte {
	var out [][]byte
	for _, p := range pems {
		p = bytes.TrimSpace(p)
		if len(p) == 0 {
			continue
		}
		dup := false
		for _, have := range out {
			if bytes.Equal(have, p) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return append(bytes.Join(out, []byte("\n")), '\n')
}
