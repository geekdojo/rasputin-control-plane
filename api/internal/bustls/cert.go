package bustls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// CertFileName is the bus certificate under the api's bus directory
// (<dataDir>/bus/bus.crt, /var/lib/rasputin/bus/bus.crt on an appliance) —
// beside the key it wraps.
//
// Format: one PEM CERTIFICATE block. It is PUBLIC: it carries the bus public
// key, which is already published as the pin, and nothing else, so it is
// 0644 (see mintAndWrite).
const CertFileName = "bus.crt"

// BusDNSName is the certificate's one Subject Alternative Name, and it is
// FIXED: the same value on every cluster, forever.
//
// Nothing resolves it. A node reaches the bus by address and verifies the
// server by the pin — the SHA-256 of the key's SubjectPublicKeyInfo — checking
// no chain, no name and no dates. The SAN exists for clients that cannot be
// told to do that:
//
//   - Go's crypto/tls verifies the name against SANs only. It does not fall
//     back to the Common Name, so a certificate with `CN=rasputin-bus` and no
//     SAN is rejected as "not valid for any names" by anything that verifies
//     it at all. Measured on grafana/alloy v1.4.2 against a certificate of
//     exactly today's shape (geekdojo/geekdojo-brain#467).
//   - No Rasputin client verifies this certificate by chain or pins its
//     bytes. The collectors trust the api's controlplane-CA-signed leaf, which the
//     node listener serves in place of this certificate
//     (geekdojo/geekdojo-brain#672).
//
// It is fixed rather than derived from the cluster name because it is not a
// name anyone looks up: deriving it would make the certificate change when a
// cluster is renamed, for no gain.
const BusDNSName = "rasputin-bus"

// EnsureCert loads dir/bus.crt, minting and persisting one around key when
// there is none it can use. generated reports which happened.
//
// Before geekdojo/geekdojo-brain#508 nothing persisted a bus certificate: the
// api minted a fresh one, with a fresh random serial, every time it started.
// That is invisible to a node, which pins the key. It was persisted for a
// collector that pinned the certificate's bytes; since
// geekdojo/geekdojo-brain#672 no client does, so the file is kept only as a
// stable certificate around the key.
//
// A persisted certificate is reused only when all three hold:
//
//  1. it parses;
//  2. it wraps THIS key — its public key hashes to the same pin;
//  3. it carries BusDNSName and the no-expiry NotAfter this package mints.
//
// Anything else is re-minted and the log line says which condition failed.
// None of this reads a clock: a certificate is not judged by whether it has
// expired, only by whether it is one this package would have written. Nothing
// is lost by re-minting — the pin is the key, so every node keeps verifying the
// bus across the change, and no client pins the certificate's bytes — while a
// stale certificate that no longer matches the key cannot be served with it.
func EnsureCert(dir string, key *Key) (cert tls.Certificate, generated bool, err error) {
	if key == nil {
		return tls.Certificate{}, false, errors.New("bustls: EnsureCert: key required")
	}
	if err := atrest.EnsureSecretDir(dir); err != nil {
		return tls.Certificate{}, false, fmt.Errorf("bustls: %w", err)
	}
	path := filepath.Join(dir, CertFileName)
	data, rerr := os.ReadFile(path)
	switch {
	case rerr == nil:
		leaf, why := usableCert(data, key)
		if why == "" {
			return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key.signer, Leaf: leaf}, false, nil
		}
		// Re-minted, not refused: unlike the key, this file holds nothing that
		// cannot be made again from the key beside it.
		cert, err = mintAndWrite(path, key)
		if err != nil {
			return tls.Certificate{}, false, err
		}
		return cert, true, fmt.Errorf("bustls: %s was replaced: %s", path, why)
	case errors.Is(rerr, os.ErrNotExist):
		cert, err = mintAndWrite(path, key)
		return cert, true, err
	default:
		return tls.Certificate{}, false, fmt.Errorf("bustls: read %s: %w", path, rerr)
	}
}

// usableCert parses a persisted certificate and reports why it cannot be
// reused, "" when it can.
func usableCert(data []byte, key *Key) (*x509.Certificate, string) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "it is not a PEM CERTIFICATE block"
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "it does not parse: " + err.Error()
	}
	pin, err := proto.BusPinForPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, "its public key is not one this bus can serve: " + err.Error()
	}
	if pin != key.Pin() {
		return nil, fmt.Sprintf("it wraps the key pinned %s, and this controlplane's bus key is pinned %s — the key was replaced or restored", pin, key.Pin())
	}
	if !slices.Contains(leaf.DNSNames, BusDNSName) {
		return nil, fmt.Sprintf("it carries no %q DNS name, which a client that verifies the name at all requires", BusDNSName)
	}
	if !leaf.NotAfter.Equal(certNotAfter) {
		return nil, fmt.Sprintf("it expires at %s rather than %s, so a client that checks dates would one day refuse a bus every node accepts",
			leaf.NotAfter.Format("2006-01-02"), certNotAfter.Format("2006-01-02"))
	}
	return leaf, ""
}

func mintAndWrite(path string, key *Key) (tls.Certificate, error) {
	cert, err := SelfSignedCert(key.signer, certNotBefore, certNotAfter)
	if err != nil {
		return tls.Certificate{}, err
	}
	// 0644: the certificate is public — it carries the public key, already
	// published as the pin, and nothing else. The bus directory around it
	// stays 0700.
	if err := atrest.WritePublicFile(path, encodeCertPEM(cert)); err != nil {
		return tls.Certificate{}, fmt.Errorf("bustls: write %s: %w", path, err)
	}
	return cert, nil
}

// encodeCertPEM renders a minted certificate in the persisted form: one PEM
// CERTIFICATE block.
func encodeCertPEM(cert tls.Certificate) []byte {
	var buf bytes.Buffer
	for _, der := range cert.Certificate {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return buf.Bytes()
}
