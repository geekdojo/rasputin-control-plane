package main

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
)

func TestAPILeafSpec_SANs(t *testing.T) {
	spec := apiLeafSpec("nodex", net.ParseIP("192.168.7.2"))

	wantDNS := []string{"rasputin.local", "localhost", "nodex", "nodex.local"}
	if !slices.Equal(spec.DNSNames, wantDNS) {
		t.Errorf("DNSNames = %v, want %v", spec.DNSNames, wantDNS)
	}
	if len(spec.IPAddresses) != 2 {
		t.Fatalf("IPAddresses = %v, want 127.0.0.1 + LAN IP", spec.IPAddresses)
	}
	if !spec.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("first IP SAN = %v, want 127.0.0.1", spec.IPAddresses[0])
	}
	if !spec.IPAddresses[1].Equal(net.ParseIP("192.168.7.2")) {
		t.Errorf("second IP SAN = %v, want 192.168.7.2", spec.IPAddresses[1])
	}
}

func TestAPILeafSpec_FQDNHostnameNoDoubleLocal(t *testing.T) {
	// Hostname already carries a dot → no "<host>.local" appended on top.
	spec := apiLeafSpec("nodex.local", nil)
	want := []string{"rasputin.local", "localhost", "nodex.local"}
	if !slices.Equal(spec.DNSNames, want) {
		t.Errorf("DNSNames = %v, want %v", spec.DNSNames, want)
	}
	if len(spec.IPAddresses) != 1 { // air-gapped: just loopback
		t.Errorf("IPAddresses = %v, want only 127.0.0.1", spec.IPAddresses)
	}
}

func TestAPILeafSpec_HostnameIsRasputinLocal_NoDup(t *testing.T) {
	spec := apiLeafSpec("rasputin.local", nil)
	want := []string{"rasputin.local", "localhost"}
	if !slices.Equal(spec.DNSNames, want) {
		t.Errorf("DNSNames = %v, want %v", spec.DNSNames, want)
	}
}

// End-to-end: mint the api leaf via ensureAPILeaf's underlying path and
// assert the SANs survive onto the actual certificate.
func TestEnsureAPILeaf_CertCarriesSANs(t *testing.T) {
	dir := t.TempDir()
	ca, err := mesh.EnsureMeshCA(dir, "test")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}

	spec := apiLeafSpec("nodex", net.ParseIP("10.0.0.5"))
	certPEM, _, err := mesh.MintLeaf(ca, spec)
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("leaf is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	for _, dns := range []string{"rasputin.local", "localhost", "nodex", "nodex.local"} {
		if !slices.Contains(cert.DNSNames, dns) {
			t.Errorf("leaf missing DNS SAN %q (have %v)", dns, cert.DNSNames)
		}
	}
	wantIPs := []string{"127.0.0.1", "10.0.0.5"}
	for _, want := range wantIPs {
		found := false
		for _, ip := range cert.IPAddresses {
			if ip.String() == want {
				found = true
			}
		}
		if !found {
			t.Errorf("leaf missing IP SAN %s (have %v)", want, cert.IPAddresses)
		}
	}
	// And the browser-facing check that actually matters:
	if err := cert.VerifyHostname("rasputin.local"); err != nil {
		t.Errorf("VerifyHostname(rasputin.local): %v", err)
	}
}
