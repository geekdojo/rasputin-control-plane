package proto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

// What a node trusts, as a fingerprint.
//
// The mesh CA is delivered to a node exactly once, inside mesh.enroll, and the
// node keeps whatever it was handed. Nothing in the product re-delivers it,
// and nothing reports which CA a node holds — so when the control plane's CA
// changes under an enrolled node, the node is silently unable to reach
// anything the api serves over the mesh-CA listener: backup transfer, bundle
// downloads, restore egress. Found on e3bench 2026-09-04: an identity restore
// (#291) put the ORIGINAL mesh CA back on the controlplane while compute1,
// enrolled during the interim against the fresh one, kept the fresh one, and
// every node→api TLS client on it failed with "certificate signed by unknown
// authority" until the CA was re-delivered by hand.
//
// Convergence needs one fact from the node: which CA it trusts. The agent
// reports it here, as a fingerprint, on every registration — never the PEM
// (the api already has the PEM; the fingerprint is all the comparison needs
// and all a log or ledger row should carry). The api compares it with its own
// mesh-ca.pem on every mesh.reconcile and re-runs mesh.enroll for any node
// that differs. See api/internal/mesh (converge_trust).

// MetadataMeshCAFingerprint is the registration-metadata key under which an
// agent reports the fingerprint of the mesh CA bundle it has installed for
// tailscaled and its own HTTPS clients (MeshCAFingerprint of the file at the
// agent's CA bundle path), or MeshCAFingerprintNone when no bundle is
// installed. Absent from a pre-fingerprint agent's registration; consumers
// must treat absence as "unknown" — never as "stale" — and leave that node
// alone rather than guess.
const MetadataMeshCAFingerprint = "meshCaFingerprint"

// MeshCAFingerprintNone is the value an agent reports when it has no mesh CA
// bundle installed at all. Distinct from an absent key: "none" is a report.
const MeshCAFingerprintNone = "none"

// MeshCAFingerprint is the canonical fingerprint of a mesh CA bundle: the
// lowercase hex SHA-256 of the PEM with surrounding whitespace trimmed, so
// the api's in-memory copy and the file the agent wrote (which the agent
// terminates with exactly one newline) fingerprint identically. Empty input
// fingerprints to "" — there is nothing to fingerprint, and "" never
// compares equal to a report.
func MeshCAFingerprint(pem []byte) string {
	trimmed := bytes.TrimSpace(pem)
	if len(trimmed) == 0 {
		return ""
	}
	sum := sha256.Sum256(trimmed)
	return hex.EncodeToString(sum[:])
}

// ShortFingerprint is the leading 12 hex characters of a fingerprint, for
// logs and UI where the whole digest is noise. A short or empty input is
// returned as it is.
func ShortFingerprint(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}
