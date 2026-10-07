package tlsca

import "bytes"

// Bundle concatenates the PEM blobs a node must trust, in the order given and
// without duplicates: the controlplane CA first, then the operator's CA when
// Headscale is theirs. Empty inputs are skipped, and the result is empty when
// everything was.
//
// A bundle is a concatenation of PEM blocks. Both tailscaled's SSL_CERT_FILE
// and the agent's own HTTPS clients take one as readily as a single
// certificate, so adding the operator's root needs no node-side mechanism, and
// the existing convergence delivers it: the bundle's fingerprint
// (proto.TrustFingerprint) changes, trust.converge sees every node reporting a
// stale one, and installs the new bundle (geekdojo/geekdojo-brain#506).
//
// The store CA never goes in a bundle: no node, browser or collector verifies
// anything it signs.
func Bundle(pems ...[]byte) []byte {
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
