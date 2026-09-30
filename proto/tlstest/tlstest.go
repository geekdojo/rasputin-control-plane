// Package tlstest mints throwaway certificate authorities and HTTPS servers
// whose leaf they sign. FOR TESTS ONLY: neither binary imports it.
//
// It exists because the agent's HTTPS clients trust exactly the node's mesh
// CA bundle (geekdojo/geekdojo-brain#590), and proving that takes more than
// httptest.NewTLSServer offers: every httptest server presents the SAME
// built-in certificate, so "a server under an unrelated CA" cannot be built
// from it. The tests of proto, the agent's tailscale, updater and quiesce
// packages and backupxfer all need that server, so it is written once, here,
// in the module they all import.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// CA is a self-signed certificate authority.
type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// PEM is the CA certificate, PEM-encoded: what a trust bundle holds.
	PEM []byte
}

// NewCA mints a CA named name.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tlstest: CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("tlstest: CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("tlstest: parse CA certificate: %v", err)
	}
	return &CA{Cert: cert, key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Pool is a certificate pool holding this CA alone.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// NewServer starts an HTTPS server on 127.0.0.1 whose leaf this CA signed,
// and closes it when the test ends.
func (ca *CA) NewServer(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	// A refused handshake is what most callers are testing for; the
	// server's own log line about it is noise.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t)}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func (ca *CA) leaf(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tlstest: leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("tlstest: leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// KeyOnlyPEM is a PEM file that holds a private key and no certificate: a
// well-formed PEM that nothing can trust.
func KeyOnlyPEM(t testing.TB) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tlstest: key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("tlstest: marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("tlstest: serial: %v", err)
	}
	return n
}

// Get fetches url through a client whose TLS config is cfg and nothing else,
// and returns the error (nil on any response, whatever its status).
func Get(cfg *tls.Config, url string) error {
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// IsUnknownAuthority reports whether err is the X.509 verdict for a
// certificate that does not chain to any trusted root.
func IsUnknownAuthority(err error) bool {
	var ua x509.UnknownAuthorityError
	return errors.As(err, &ua)
}
