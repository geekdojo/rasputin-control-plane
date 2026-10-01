package nodekeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// The pair carries the agent's parameters, because tests that use it claim to
// stand in for the agent's collector key.
func TestNew_MakesTheAgentsShape(t *testing.T) {
	p := New(t, "collector")

	if p.Key.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256", p.Key.Curve.Params().Name)
	}
	if p.Leaf.Subject.CommonName != "collector" {
		t.Errorf("CN = %q, want collector", p.Leaf.Subject.CommonName)
	}
	if !p.Leaf.NotBefore.Equal(NotBefore) || !p.Leaf.NotAfter.Equal(NotAfter) {
		t.Errorf("dates = %s..%s, want %s..%s", p.Leaf.NotBefore, p.Leaf.NotAfter, NotBefore, NotAfter)
	}
	if len(p.Leaf.ExtKeyUsage) != 1 || p.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("EKU = %v, want [clientAuth]", p.Leaf.ExtKeyUsage)
	}
	if p.Leaf.SerialNumber.BitLen() < 64 {
		t.Errorf("serial %s is not a random 128-bit value", p.Leaf.SerialNumber)
	}
	if err := p.Leaf.CheckSignature(p.Leaf.SignatureAlgorithm, p.Leaf.RawTBSCertificate, p.Leaf.Signature); err != nil {
		t.Errorf("the certificate is not self-signed: %v", err)
	}
	if !p.Key.PublicKey.Equal(p.Leaf.PublicKey) {
		t.Error("the certificate does not wrap the key")
	}
	if New(t, "collector").Leaf.SerialNumber.Cmp(p.Leaf.SerialNumber) == 0 {
		t.Error("two pairs share a serial")
	}
}

func TestPair_Encodings(t *testing.T) {
	p := New(t, "c02")

	tc := p.TLS()
	if len(tc.Certificate) != 1 || string(tc.Certificate[0]) != string(p.Leaf.Raw) || tc.PrivateKey != p.Key || tc.Leaf != p.Leaf {
		t.Error("TLS() is not the pair")
	}

	block, rest := pem.Decode(p.CertPEM())
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 || string(block.Bytes) != string(p.Leaf.Raw) {
		t.Errorf("CertPEM() is not one CERTIFICATE block of the leaf")
	}

	block, rest = pem.Decode(p.KeyPEM(t))
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatalf("KeyPEM() is not one PRIVATE KEY block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("KeyPEM() is not PKCS#8: %v", err)
	}
	if ek, ok := k.(*ecdsa.PrivateKey); !ok || !ek.Equal(p.Key) {
		t.Error("KeyPEM() does not round-trip the key")
	}
}
