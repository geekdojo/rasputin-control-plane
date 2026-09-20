package mesh

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// One caTLSConfig for both Headscale backends, and one node trust bundle
// (geekdojo/geekdojo-brain#506).

// newCA mints a throwaway CA, standing in for this installation's Mesh CA or
// for the operator's own root.
func newCA(t *testing.T, name string) *MeshCA {
	t.Helper()
	ca, err := EnsureMeshCA(filepath.Join(t.TempDir(), name), name)
	if err != nil {
		t.Fatalf("EnsureMeshCA(%s): %v", name, err)
	}
	return ca
}

// tlsServerSignedBy starts an HTTPS server whose leaf ca signed, the shape
// either Headscale presents.
func tlsServerSignedBy(t *testing.T, ca *MeshCA, name string) *httptest.Server {
	t.Helper()
	certPEM, keyPEM, err := MintLeaf(ca, LeafSpec{
		CommonName:  name,
		DNSNames:    []string{name, "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		t.Fatalf("MintLeaf(%s): %v", name, err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair(%s): %v", name, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string, cfg *tls.Config) error {
	t.Helper()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	c := &http.Client{Transport: tr}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return nil
}

// The helper trusts exactly what it is handed: the self-hosted backend's Mesh
// CA and the external backend's operator CA go through the same function, and
// neither config trusts the other's leaf or the system pool.
func TestCATLSConfig_TrustsExactlyThePEMItIsGiven(t *testing.T) {
	meshCA := newCA(t, "mesh")
	operatorCA := newCA(t, "operator")
	selfHosted := tlsServerSignedBy(t, meshCA, "headscale-self")
	external := tlsServerSignedBy(t, operatorCA, "headscale-external")

	meshCfg, err := CATLSConfig(meshCA.CertPEM, "the Mesh CA")
	if err != nil {
		t.Fatalf("CATLSConfig(mesh): %v", err)
	}
	opCfg, err := CATLSConfig(operatorCA.CertPEM, "RASPUTIN_HEADSCALE_CA_FILE=/x")
	if err != nil {
		t.Fatalf("CATLSConfig(operator): %v", err)
	}

	if err := get(t, selfHosted.URL, meshCfg); err != nil {
		t.Errorf("the Mesh CA config did not trust the self-hosted leaf: %v", err)
	}
	if err := get(t, external.URL, opCfg); err != nil {
		t.Errorf("the operator CA config did not trust the external leaf: %v", err)
	}
	if err := get(t, external.URL, meshCfg); err == nil {
		t.Error("the Mesh CA config trusted a leaf it did not sign")
	}
	if err := get(t, selfHosted.URL, opCfg); err == nil {
		t.Error("the operator CA config trusted a leaf it did not sign")
	}
	if meshCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2 or better", meshCfg.MinVersion)
	}
}

// A PEM that parses to nothing is an error, never a silent fall back to the
// system pool — which would make the api trust any public CA for Headscale.
func TestCATLSConfig_RefusesUnusablePEM(t *testing.T) {
	for _, tc := range []struct{ name, pem string }{
		{"empty", ""},
		{"whitespace", "\n\n  \n"},
		{"not a pem", "hello, this is not a certificate"},
		{"pem-ish but undecodable", "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CATLSConfig([]byte(tc.pem), "RASPUTIN_HEADSCALE_CA_FILE=/x")
			if err == nil {
				t.Fatalf("CATLSConfig accepted %q and returned %+v", tc.name, cfg)
			}
			if !strings.Contains(err.Error(), "RASPUTIN_HEADSCALE_CA_FILE=/x") {
				t.Errorf("error does not name the source: %v", err)
			}
		})
	}
}

// The node bundle: the Mesh CA always, the operator's appended, no duplicates.
func TestNodeTrustBundle_Contents(t *testing.T) {
	meshCA := newCA(t, "mesh")
	operatorCA := newCA(t, "operator")

	only := NodeTrustBundle(meshCA.CertPEM)
	if !bytes.Contains(only, bytes.TrimSpace(meshCA.CertPEM)) {
		t.Fatal("the self-hosted bundle does not carry the Mesh CA")
	}
	if got := countCerts(t, only); got != 1 {
		t.Fatalf("the self-hosted bundle holds %d certificates, want 1", got)
	}

	both := NodeTrustBundle(meshCA.CertPEM, operatorCA.CertPEM)
	if got := countCerts(t, both); got != 2 {
		t.Fatalf("the external bundle holds %d certificates, want 2", got)
	}
	if !bytes.Contains(both, bytes.TrimSpace(meshCA.CertPEM)) {
		t.Error("the external bundle dropped the Mesh CA — a node must always get its own cluster's CA")
	}
	if !bytes.Contains(both, bytes.TrimSpace(operatorCA.CertPEM)) {
		t.Error("the external bundle dropped the operator's CA")
	}
	if i, j := bytes.Index(both, bytes.TrimSpace(meshCA.CertPEM)), bytes.Index(both, bytes.TrimSpace(operatorCA.CertPEM)); i > j {
		t.Error("the operator's CA is not appended after the Mesh CA")
	}

	// Idempotent inputs: the same CA twice (an operator who points
	// RASPUTIN_HEADSCALE_CA_FILE at the Mesh CA) is one certificate.
	if got := countCerts(t, NodeTrustBundle(meshCA.CertPEM, meshCA.CertPEM)); got != 1 {
		t.Errorf("a duplicated CA produced %d certificates, want 1", got)
	}
	if b := NodeTrustBundle(nil, []byte("  \n")); b != nil {
		t.Errorf("NodeTrustBundle with nothing to ship = %q, want nil", b)
	}
	// The bundle is what converge_trust compares, so it must be stable: the
	// same inputs produce the same fingerprint.
	if a, b := proto.MeshCAFingerprint(both), proto.MeshCAFingerprint(NodeTrustBundle(meshCA.CertPEM, operatorCA.CertPEM)); a != b {
		t.Errorf("the bundle's fingerprint is not stable: %s vs %s", a, b)
	}
	if proto.MeshCAFingerprint(both) == proto.MeshCAFingerprint(only) {
		t.Error("appending the operator's CA left the fingerprint unchanged; converge_trust would never re-deliver it")
	}
}

// A self-hosted cluster must see no change at all: the bundle for the Mesh CA
// alone is the Mesh CA's own PEM, byte for byte, so its fingerprint is the one
// every enrolled node already reports and converge_trust re-delivers nothing.
func TestNodeTrustBundle_SelfHostedBundleIsUnchangedBytes(t *testing.T) {
	meshCA := newCA(t, "mesh")
	if got := NodeTrustBundle(meshCA.CertPEM); !bytes.Equal(got, meshCA.CertPEM) {
		t.Fatalf("the self-hosted bundle is not the Mesh CA PEM byte for byte:\n got %q\nwant %q", got, meshCA.CertPEM)
	}
	if proto.MeshCAFingerprint(NodeTrustBundle(meshCA.CertPEM)) != proto.MeshCAFingerprint(meshCA.CertPEM) {
		t.Error("the self-hosted bundle's fingerprint moved; every node would be re-enrolled for nothing")
	}
}

// Functional: a node that holds the bundle — read the way tailscaled reads
// SSL_CERT_FILE, as a pool of PEM blocks — trusts BOTH the Headscale the
// operator runs and its own cluster's services.
func TestNodeTrustBundle_TrustsBothServersFromOneFile(t *testing.T) {
	meshCA := newCA(t, "mesh")
	operatorCA := newCA(t, "operator")
	clusterService := tlsServerSignedBy(t, meshCA, "api-https") // the node's own api / app leaves
	headscale := tlsServerSignedBy(t, operatorCA, "headscale-external")

	bundlePath := filepath.Join(t.TempDir(), "mesh-ca.pem")
	if err := os.WriteFile(bundlePath, NodeTrustBundle(meshCA.CertPEM, operatorCA.CertPEM), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	onDisk, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(onDisk) {
		t.Fatal("the written bundle parsed as no certificates at all")
	}
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	if err := get(t, headscale.URL, cfg); err != nil {
		t.Errorf("a node holding the bundle did not trust the operator's Headscale: %v", err)
	}
	if err := get(t, clusterService.URL, cfg); err != nil {
		t.Errorf("a node holding the bundle did not trust its own cluster's CA: %v", err)
	}
}

// countCerts is how many certificates parse out of a PEM bundle.
func countCerts(t *testing.T, bundle []byte) int {
	t.Helper()
	n := 0
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("bundle carries a %q block; only certificates belong in a trust bundle", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Fatalf("bundle carries an unparseable certificate: %v", err)
		}
		n++
	}
	return n
}
