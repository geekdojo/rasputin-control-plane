package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TC-1065-01: SignLeaf signs a server leaf over a key the caller supplies. The
// leaf carries that key, exactly the ServerAuth EKU, is not a CA, and verifies
// for its name with the CA as the only root.
func TestSignLeaf_OverASuppliedKey(t *testing.T) {
	ca := newCAForTest(t)
	key := newP256(t)
	const name = "rasputin-bmc-0123456789ab.local"
	certPEM, err := ca.SignLeaf(serverSpec(name), &key.PublicKey)
	if err != nil {
		t.Fatalf("SignLeaf: %v", err)
	}
	cert := mustParseCert(t, certPEM)
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("leaf public key is not the supplied key")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v, want exactly [ServerAuth]", cert.ExtKeyUsage)
	}
	if cert.IsCA {
		t.Error("leaf is a CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: name, Roots: roots}); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// TC-1065-02: a set NotAfter is stamped exactly, whatever Lifetime says; a zero
// NotAfter keeps the default lifetime.
func TestSignLeaf_NotAfter(t *testing.T) {
	ca := newCAForTest(t)
	key := newP256(t)

	spec := serverSpec("x")
	spec.NotAfter = ca.Cert.NotAfter
	spec.Lifetime = 24 * time.Hour
	cert := mustParseCert(t, mustSign(t, ca, spec, key))
	if !cert.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Errorf("NotAfter = %v, want the CA's %v", cert.NotAfter, ca.Cert.NotAfter)
	}

	cert = mustParseCert(t, mustSign(t, ca, serverSpec("x"), key))
	if got, want := cert.NotAfter.Sub(cert.NotBefore), defaultLeafLifetime+time.Hour; got != want {
		t.Errorf("default lifetime: got %v, want %v", got, want)
	}
}

func mustSign(t *testing.T, ca *CA, spec LeafSpec, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	certPEM, err := ca.SignLeaf(spec, &key.PublicKey)
	if err != nil {
		t.Fatalf("SignLeaf: %v", err)
	}
	return certPEM
}

// TC-1065-03: SignLeaf fails closed on a NotAfter past the CA's, a nil key,
// and a spec checkSpec refuses.
func TestSignLeaf_Refusals(t *testing.T) {
	ca := newCAForTest(t)
	key := newP256(t)

	late := serverSpec("x")
	late.NotAfter = ca.Cert.NotAfter.Add(time.Second)
	noCN := serverSpec("x")
	noCN.CommonName = ""

	cases := []struct {
		name string
		spec LeafSpec
		pub  any
	}{
		{"NotAfter past the CA's", late, &key.PublicKey},
		{"nil public key", serverSpec("x"), nil},
		{"empty CommonName", noCN, &key.PublicKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, err := ca.SignLeaf(tc.spec, tc.pub)
			if err == nil {
				t.Fatal("SignLeaf accepted the spec")
			}
			if certPEM != nil {
				t.Errorf("certificate bytes returned with the error: %d bytes", len(certPEM))
			}
		})
	}

	var nilCA *CA
	if certPEM, err := nilCA.SignLeaf(serverSpec("x"), &key.PublicKey); err == nil || certPEM != nil {
		t.Errorf("nil CA: got %d bytes, err %v", len(certPEM), err)
	}
}
