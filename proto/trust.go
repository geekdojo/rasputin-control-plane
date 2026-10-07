package proto

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// What a node trusts, as a fingerprint.
//
// A node holds one trust bundle: the controlplane CA (and the operator's CA
// when Headscale is theirs), which tailscaled and the agent's own HTTPS clients
// verify the api, Headscale and the app leaves against. When the controlplane's
// CA changes under a node — an identity restore put the ORIGINAL CA back on
// e3bench 2026-09-04 while compute1, enrolled in the interim, kept the fresh
// one — the node is silently unable to reach anything the api serves: backup
// transfer, bundle downloads, restore egress all fail with "certificate signed
// by unknown authority".
//
// Convergence needs one fact from the node: which bundle it trusts. The agent
// reports it here, as a fingerprint, on every registration — never the PEM
// (the api already has the PEM; the fingerprint is all the comparison needs
// and all a log or ledger row should carry). The api compares it with its own
// bundle and sends trust.install to any node that differs (api/internal/
// nodetrust, trust.converge).

// MetadataTrustFingerprint is the registration-metadata key under which an
// agent reports the fingerprint of the trust bundle it has installed for
// tailscaled and its own HTTPS clients (TrustFingerprint of the file at the
// agent's bundle path), TrustFingerprintNone when no bundle is installed, or
// TrustFingerprintReloadPending while a changed bundle has not yet reached
// tailscaled. Absent from a pre-fingerprint agent's registration; consumers
// must treat absence as "unknown" — never as "stale" — and leave that node
// alone rather than guess.
//
// The wire value is a compatibility name and keeps the mesh prefix it was
// born with: mixed fleets send it.
const MetadataTrustFingerprint = "meshCaFingerprint"

// TrustFingerprintNone is the value an agent reports when it has no trust
// bundle installed at all. Distinct from an absent key: "none" is a report.
const TrustFingerprintNone = "none"

// TrustFingerprintReloadPending is the value an agent reports when it has
// installed a changed bundle but could not make tailscaled reload it. It is
// not a fingerprint, so it matches no api's bundle and the node reads as
// stale — to this api and to an older one — and the next trust.install
// retries the reload. Reported until a reload succeeds.
const TrustFingerprintReloadPending = "reload-pending"

// TrustFingerprint is the canonical fingerprint of a trust bundle: the
// lowercase hex SHA-256 of the PEM with surrounding whitespace trimmed, so
// the api's in-memory copy and the file the agent wrote (which the agent
// terminates with exactly one newline) fingerprint identically. Empty input
// fingerprints to "" — there is nothing to fingerprint, and "" never
// compares equal to a report.
func TrustFingerprint(pem []byte) string {
	trimmed := bytes.TrimSpace(pem)
	if len(trimmed) == 0 {
		return ""
	}
	sum := sha256.Sum256(trimmed)
	return hex.EncodeToString(sum[:])
}

// ValidateTrustBundle refuses anything that is not a bundle of CA certificates: no PEM
// at all, a block that is not a CERTIFICATE (a private key, say — this file is
// written 0644), a CERTIFICATE that does not parse, or non-whitespace bytes
// outside the blocks. The agent's trust.install refuses on it, and the api's
// node bundle is built to pass it (geekdojo/geekdojo-brain#741).
func ValidateTrustBundle(bundle []byte) error {
	rest := bundle
	sawCert := false
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return errors.New("trust bundle carries bytes outside a PEM block")
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return errors.New("trust bundle carries a malformed PEM block")
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("trust bundle carries a %q block; only certificates belong in it", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("trust bundle carries a certificate that does not parse: %w", err)
		}
		sawCert = true
	}
	if !sawCert {
		return errors.New("trust bundle carries no certificate")
	}
	return nil
}

// ShortFingerprint is the leading 12 hex characters of a fingerprint, for
// logs and UI where the whole digest is noise. A short or empty input is
// returned as it is.
func ShortFingerprint(fp string) string {
	return fp[:min(len(fp), 12)]
}

// CATLSConfig is the TLS client config that trusts exactly caPEM and nothing
// else: no system roots, no pin. source names where the PEM came from, so a
// parse failure says which input to fix.
//
// It lives here, not in the api, because the api (its Headscale clients) and
// the agent (its HTTPS clients to the api, geekdojo/geekdojo-brain#590) need
// the same answer and are separate modules; proto is the one both import. An
// empty or unparseable PEM is an error, never a silent fall back to the
// system pool — a nil RootCAs would mean exactly that.
func CATLSConfig(caPEM []byte, source string) (*tls.Config, error) {
	if len(bytes.TrimSpace(caPEM)) == 0 {
		return nil, fmt.Errorf("tls: %s: no CA PEM to trust", source)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("tls: %s: no certificates parsed from the CA PEM", source)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}
