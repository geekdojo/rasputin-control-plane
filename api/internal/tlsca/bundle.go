package tlsca

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

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

// CertificatesOnly parses a CA file into its certificates and returns them
// re-encoded as CERTIFICATE blocks, and nothing else. It is how the api reads
// the operator's CA file (RASPUTIN_HEADSCALE_CA_FILE) before any of it reaches
// a node (SEC-INPUT): text outside the blocks — openssl's "Bag Attributes",
// "subject=" and "issuer=" lines — is dropped, because every node refuses a
// bundle that carries it (proto.ValidateTrustBundle). A standard PEM file
// comes back byte-identical, so a node's fingerprint does not move on upgrade.
//
// A block of any other type is refused, naming its position and type and
// nothing of its content: a private key in a CA file is the operator's
// mistake to fix, not something to ship to every node or quietly drop. So is
// a certificate that does not parse, and a file with no certificate at all.
func CertificatesOnly(data []byte) ([]byte, error) {
	var out []byte
	rest := data
	for i := 1; ; i++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block %d is a %q block; only CERTIFICATE blocks belong in a CA file", i, block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("PEM block %d is a certificate that does not parse: %w", i, err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
	}
	if len(out) == 0 {
		return nil, errors.New("no CERTIFICATE block")
	}
	return out, nil
}
