// Package nodekeytest builds the client identity a node presents to the api:
// a key the node made, in a certificate the node signed itself, made the way
// the agent makes it (agent/internal/nodekeys). Tests import it; nothing in a
// shipped binary does.
//
// It is the one copy of what several packages' tests each built by hand
// (geekdojo/geekdojo-brain#672). The parameters below are the agent's, and a
// test that claims "a client the way the agent makes it" — the node listener's
// handshake, the Alloy probe — is only as true as they are, so they live in
// one place: ECDSA P-256, a PKCS#8 "PRIVATE KEY" PEM, a random 128-bit serial,
// the clientAuth EKU, and dates from 1970 to 9999 so no clock can refuse it.
package nodekeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// NotBefore and NotAfter are the agent's certificate dates
// (agent/internal/nodekeys certNotBefore / certNotAfter).
var (
	NotBefore = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	NotAfter  = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

// Pair is one node client identity.
type Pair struct {
	// Key is the node's private key.
	Key *ecdsa.PrivateKey
	// Leaf is the self-signed certificate around Key.
	Leaf *x509.Certificate
}

// New returns a fresh Pair with cn as the certificate's Common Name, failing
// the test if one cannot be made.
func New(t testing.TB, cn string) Pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             NotBefore,
		NotAfter:              NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Pair{Key: key, Leaf: leaf}
}

// TLS returns the pair as a crypto/tls client certificate.
func (p Pair) TLS() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{p.Leaf.Raw}, PrivateKey: p.Key, Leaf: p.Leaf}
}

// CertPEM returns the certificate as one PEM CERTIFICATE block, the form the
// agent writes to disk.
func (p Pair) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Leaf.Raw})
}

// KeyPEM returns the key as a PKCS#8 "PRIVATE KEY" PEM block, the form the
// agent writes to disk and Alloy reads.
func (p Pair) KeyPEM(t testing.TB) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(p.Key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
