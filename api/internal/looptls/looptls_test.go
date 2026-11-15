package looptls

import (
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
)

// TC-978-18: the extracted address rule accepts only https to a loopback IP
// literal with an explicit port, and returns scheme and host alone.
func TestParseAddr(t *testing.T) {
	for _, ok := range []string{"https://127.0.0.1:8543", "https://[::1]:8544", "https://127.0.0.2:1"} {
		u, err := ParseAddr(ok)
		if err != nil || u.Scheme != "https" || u.Path != "" {
			t.Errorf("ParseAddr(%q) = %v, %v", ok, u, err)
		}
	}
	for _, bad := range []string{"http://127.0.0.1:8543", "https://localhost:8543", "https://127.0.0.1", "https://127.0.0.1:0",
		"https://127.0.0.1:65536", "https://10.0.0.1:8543", "https://127.0.0.1:8543/x", "https://127.0.0.1:8543?q=1",
		"https://u:p@127.0.0.1:8543", "https://127.0.0.1:8543#f", "https:opaque", "https://127.0.0.1:08543", "%zz"} {
		if _, err := ParseAddr(bad); err == nil || !strings.HasPrefix(err.Error(), "address ") {
			t.Errorf("ParseAddr(%q) = %v, want a refusal naming the address", bad, err)
		}
	}
}

// TC-978-18: the client config trusts the CA alone at TLS 1.3, reads the leaf
// at each handshake (a missing leaf is a *LeafError, not a construction
// error), and refuses an empty path, a PEM with no certificate and a nil
// mint.
func TestClientTLS(t *testing.T) {
	dir := t.TempDir()
	ca, err := tlsca.Ensure(tlsca.IdentityConfig(), dir, "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := NewClientTLS(ca.CertPEM, filepath.Join(dir, "none.pem"), filepath.Join(dir, "none.key"))
	if err != nil || cfg.MinVersion != tls.VersionTLS13 || cfg.RootCAs == nil {
		t.Fatalf("NewClientTLS = %+v, %v", cfg, err)
	}
	_, err = cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if !IsLeafError(err) || !strings.HasPrefix(err.Error(), "client leaf unusable: ") {
		t.Errorf("a missing leaf: %v, want a *LeafError", err)
	}
	paths, err := ca.MintLeafToDisk(filepath.Join(dir, "client"), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "x"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ = NewClientTLS(ca.CertPEM, paths.CertPath, paths.KeyPath)
	if c, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{}); err != nil || c == nil {
		t.Errorf("a leaf on disk: %v, %v", c, err)
	}
	if _, err := NewClientTLS(ca.CertPEM, "", paths.KeyPath); err == nil {
		t.Error("an empty leaf path was accepted")
	}
	if _, err := NewClientTLS([]byte("not a pem"), paths.CertPath, paths.KeyPath); err == nil {
		t.Error("a CA PEM with no certificate was accepted")
	}
	if _, err := NewMintedClientTLS(ca.CertPEM, nil); err == nil {
		t.Error("a nil mint was accepted")
	}
	minted, err := NewMintedClientTLS(ca.CertPEM, func() (*tls.Certificate, error) { return nil, errors.New("mint failed") })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := minted.GetClientCertificate(&tls.CertificateRequestInfo{}); !IsLeafError(err) {
		t.Errorf("a failed mint: %v, want a *LeafError", err)
	}
}

// TC-978-18: the four refusal alerts classify as a refused client
// certificate, by the peer's alert text or by tls.AlertError; anything else
// does not.
func TestClientCertRefused(t *testing.T) {
	for _, a := range []tls.AlertError{42, 46, 48, 116} {
		if !ClientCertRefused(&net.OpError{Op: "remote error", Err: a}) || !ClientCertRefused(a) {
			t.Errorf("alert %d not classified as refused", a)
		}
	}
	for _, err := range []error{
		&net.OpError{Op: "remote error", Err: tls.AlertError(40)},
		&net.OpError{Op: "remote error"},
		errors.New("bad certificate"),
	} {
		if ClientCertRefused(err) {
			t.Errorf("%v classified as refused", err)
		}
	}
}
