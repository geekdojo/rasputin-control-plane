package mesh

import (
	"bytes"
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

// TestPrepareAppLeaf_RenewsUntilCommitted proves the commit-on-delivery
// contract: a freshly-prepared leaf is not persisted, so it keeps renewing
// until CommitAppLeaf runs — after which it's returned unchanged (renewed=false).
func TestPrepareAppLeaf_RenewsUntilCommitted(t *testing.T) {
	ca := newCAForTest(t)
	dir := t.TempDir()

	certPEM, keyPEM, renewed, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", false)
	if err != nil {
		t.Fatalf("PrepareAppLeaf: %v", err)
	}
	if !renewed {
		t.Fatal("first prepare (no disk leaf) must mint fresh: renewed=true")
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("empty PEM from fresh mint")
	}

	// Uncommitted → a second prepare must STILL renew (offline-retry safety).
	if _, _, renewed2, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", false); err != nil || !renewed2 {
		t.Fatalf("uncommitted leaf must keep renewing: renewed=%v err=%v", renewed2, err)
	}

	// Commit, then the same still-valid leaf comes back with renewed=false.
	if err := CommitAppLeaf(dir, certPEM, keyPEM); err != nil {
		t.Fatalf("CommitAppLeaf: %v", err)
	}
	got, _, renewed3, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", false)
	if err != nil {
		t.Fatalf("PrepareAppLeaf after commit: %v", err)
	}
	if renewed3 {
		t.Error("committed, still-valid leaf must not renew")
	}
	if !bytes.Equal(got, certPEM) {
		t.Error("prepare returned a different cert than was committed")
	}
}

// TestPrepareAppLeaf_RenewsOnSANDrift: toggling exposeLAN changes the SANs, so
// even a committed, far-from-expiry leaf must be re-minted.
func TestPrepareAppLeaf_RenewsOnSANDrift(t *testing.T) {
	ca := newCAForTest(t)
	dir := t.TempDir()

	certPEM, keyPEM, _, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", false)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := CommitAppLeaf(dir, certPEM, keyPEM); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, _, renewed, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", true); err != nil || !renewed {
		t.Errorf("exposeLAN toggle (SAN drift) must renew: renewed=%v err=%v", renewed, err)
	}
}

func TestPrepareAppLeaf_NilCA(t *testing.T) {
	if _, _, _, err := PrepareAppLeaf(nil, t.TempDir(), "home1", "app", false); err == nil {
		t.Error("nil CA must error")
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
