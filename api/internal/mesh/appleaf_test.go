package mesh

import (
	"crypto/x509"
	"encoding/pem"
	"slices"
	"testing"
)

func TestAppLeafDNSNames(t *testing.T) {
	// Tailnet-only: just the bare name.
	got := AppLeafDNSNames("home1", "jellyfin", false)
	if want := []string{"jellyfin.home1.internal"}; !slices.Equal(got, want) {
		t.Errorf("tailnet-only SANs = %v, want %v", got, want)
	}
	// LAN-exposed: bare name first (CommonName), then the .lan name.
	got = AppLeafDNSNames("home1", "jellyfin", true)
	if want := []string{"jellyfin.home1.internal", "jellyfin.lan.home1.internal"}; !slices.Equal(got, want) {
		t.Errorf("LAN-exposed SANs = %v, want %v", got, want)
	}
	// Empty cluster id → the baseDomainFor dev fallback.
	if got := AppLeafDNSNames("", "app", false); got[0] != "app.rasputin.internal" {
		t.Errorf("dev-fallback SAN = %v", got)
	}
}

func TestMintAppLeaf_SANsMatchExposure(t *testing.T) {
	ca := newCAForTest(t)

	for _, tc := range []struct {
		name      string
		exposeLAN bool
		wantSANs  []string
	}{
		{"tailnet-only", false, []string{"jellyfin.home1.internal"}},
		{"lan-exposed", true, []string{"jellyfin.home1.internal", "jellyfin.lan.home1.internal"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, keyPEM, err := MintAppLeaf(ca, "home1", "jellyfin", tc.exposeLAN)
			if err != nil {
				t.Fatalf("MintAppLeaf: %v", err)
			}
			if len(keyPEM) == 0 {
				t.Error("empty key PEM")
			}
			cert := parseLeaf(t, certPEM)
			if !slices.Equal(cert.DNSNames, tc.wantSANs) {
				t.Errorf("cert DNSNames = %v, want %v", cert.DNSNames, tc.wantSANs)
			}
			if cert.Subject.CommonName != tc.wantSANs[0] {
				t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, tc.wantSANs[0])
			}
			// It's a server-auth leaf, and it chains to the Mesh CA.
			if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
				t.Errorf("leaf missing serverAuth EKU: %v", cert.ExtKeyUsage)
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca.Cert)
			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				t.Errorf("leaf does not verify against the Mesh CA: %v", err)
			}
		})
	}
}

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("cert PEM did not decode")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}
