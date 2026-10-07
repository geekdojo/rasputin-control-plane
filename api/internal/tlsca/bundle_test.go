package tlsca

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

// One proto.CATLSConfig for both Headscale backends, and one node trust bundle
// (geekdojo/geekdojo-brain#506).

// newCA mints a throwaway CA, standing in for this installation's controlplane CA or
// for the operator's own root.
func newCA(t *testing.T, name string) *CA {
	t.Helper()
	return mustEnsure(t, ControlplaneConfig(), filepath.Join(t.TempDir(), name), testDeps())
}

// tlsServerSignedBy starts an HTTPS server whose leaf ca signed, the shape
// either Headscale presents.
func tlsServerSignedBy(t *testing.T, ca *CA, name string) *httptest.Server {
	t.Helper()
	certPEM, keyPEM, err := ca.MintLeaf(LeafSpec{
		Usage:       UsageServer,
		CommonName:  name,
		DNSNames:    []string{name, "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		t.Fatalf("MintLeaf(%s): %v", name, err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM.Reveal())
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

	meshCfg, err := proto.CATLSConfig(meshCA.CertPEM, "the controlplane CA")
	if err != nil {
		t.Fatalf("proto.CATLSConfig(mesh): %v", err)
	}
	opCfg, err := proto.CATLSConfig(operatorCA.CertPEM, "RASPUTIN_HEADSCALE_CA_FILE=/x")
	if err != nil {
		t.Fatalf("proto.CATLSConfig(operator): %v", err)
	}

	if err := get(t, selfHosted.URL, meshCfg); err != nil {
		t.Errorf("the controlplane CA config did not trust the self-hosted leaf: %v", err)
	}
	if err := get(t, external.URL, opCfg); err != nil {
		t.Errorf("the operator CA config did not trust the external leaf: %v", err)
	}
	if err := get(t, external.URL, meshCfg); err == nil {
		t.Error("the controlplane CA config trusted a leaf it did not sign")
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
			cfg, err := proto.CATLSConfig([]byte(tc.pem), "RASPUTIN_HEADSCALE_CA_FILE=/x")
			if err == nil {
				t.Fatalf("CATLSConfig accepted %q and returned %+v", tc.name, cfg)
			}
			if !strings.Contains(err.Error(), "RASPUTIN_HEADSCALE_CA_FILE=/x") {
				t.Errorf("error does not name the source: %v", err)
			}
		})
	}
}

// The node bundle: the controlplane CA always, the operator's appended, no duplicates.
func TestBundle_Contents(t *testing.T) {
	meshCA := newCA(t, "mesh")
	operatorCA := newCA(t, "operator")

	only := Bundle(meshCA.CertPEM)
	if !bytes.Contains(only, bytes.TrimSpace(meshCA.CertPEM)) {
		t.Fatal("the self-hosted bundle does not carry the controlplane CA")
	}
	if got := countCerts(t, only); got != 1 {
		t.Fatalf("the self-hosted bundle holds %d certificates, want 1", got)
	}

	both := Bundle(meshCA.CertPEM, operatorCA.CertPEM)
	if got := countCerts(t, both); got != 2 {
		t.Fatalf("the external bundle holds %d certificates, want 2", got)
	}
	if !bytes.Contains(both, bytes.TrimSpace(meshCA.CertPEM)) {
		t.Error("the external bundle dropped the controlplane CA — a node must always get its own cluster's CA")
	}
	if !bytes.Contains(both, bytes.TrimSpace(operatorCA.CertPEM)) {
		t.Error("the external bundle dropped the operator's CA")
	}
	if i, j := bytes.Index(both, bytes.TrimSpace(meshCA.CertPEM)), bytes.Index(both, bytes.TrimSpace(operatorCA.CertPEM)); i > j {
		t.Error("the operator's CA is not appended after the controlplane CA")
	}

	// Idempotent inputs: the same CA twice (an operator who points
	// RASPUTIN_HEADSCALE_CA_FILE at the controlplane CA) is one certificate.
	if got := countCerts(t, Bundle(meshCA.CertPEM, meshCA.CertPEM)); got != 1 {
		t.Errorf("a duplicated CA produced %d certificates, want 1", got)
	}
	if b := Bundle(nil, []byte("  \n")); b != nil {
		t.Errorf("Bundle with nothing to ship = %q, want nil", b)
	}
	// The bundle is what converge_trust compares, so it must be stable: the
	// same inputs produce the same fingerprint.
	if a, b := proto.TrustFingerprint(both), proto.TrustFingerprint(Bundle(meshCA.CertPEM, operatorCA.CertPEM)); a != b {
		t.Errorf("the bundle's fingerprint is not stable: %s vs %s", a, b)
	}
	if proto.TrustFingerprint(both) == proto.TrustFingerprint(only) {
		t.Error("appending the operator's CA left the fingerprint unchanged; converge_trust would never re-deliver it")
	}
}

// A self-hosted cluster must see no change at all: the bundle for the controlplane CA
// alone is the controlplane CA's own PEM, byte for byte, so its fingerprint is the one
// every enrolled node already reports and converge_trust re-delivers nothing.
func TestBundle_SelfHostedBundleIsUnchangedBytes(t *testing.T) {
	meshCA := newCA(t, "mesh")
	if got := Bundle(meshCA.CertPEM); !bytes.Equal(got, meshCA.CertPEM) {
		t.Fatalf("the self-hosted bundle is not the controlplane CA PEM byte for byte:\n got %q\nwant %q", got, meshCA.CertPEM)
	}
	if proto.TrustFingerprint(Bundle(meshCA.CertPEM)) != proto.TrustFingerprint(meshCA.CertPEM) {
		t.Error("the self-hosted bundle's fingerprint moved; every node would be re-enrolled for nothing")
	}
}

// Functional: a node that holds the bundle — read the way tailscaled reads
// SSL_CERT_FILE, as a pool of PEM blocks — trusts BOTH the Headscale the
// operator runs and its own cluster's services.
func TestBundle_TrustsBothServersFromOneFile(t *testing.T) {
	meshCA := newCA(t, "mesh")
	operatorCA := newCA(t, "operator")
	clusterService := tlsServerSignedBy(t, meshCA, "api-https") // the node's own api / app leaves
	headscale := tlsServerSignedBy(t, operatorCA, "headscale-external")

	bundlePath := filepath.Join(t.TempDir(), "mesh-ca.pem")
	if err := os.WriteFile(bundlePath, Bundle(meshCA.CertPEM, operatorCA.CertPEM), 0o644); err != nil {
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

// TC-741-11 (bundle half): the bundle and its fingerprint are byte-identical
// to what the release before tlsca produced. The fixtures in testdata were
// written by mesh.NodeTrustBundle and proto.TrustFingerprint at
// origin/main b2522ff, from two fixed CA certificates, so an upgrade changes
// no node's reported fingerprint and trust.converge re-sends nothing.
func TestBundle_GoldenAgainstThePreTLSCARelease(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cp, op := read("controlplane-ca.pem"), read("operator-ca.pem")
	fps := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(read("fingerprints.txt"))), "\n") {
		k, v, _ := strings.Cut(line, " ")
		fps[k] = v
	}
	for _, tc := range []struct {
		name, golden, fpKey string
		got                 []byte
	}{
		{"controlplane only", "bundle-controlplane.pem", "controlplane", Bundle(cp)},
		{"controlplane and operator", "bundle-controlplane-operator.pem", "controlplane+operator", Bundle(cp, op)},
		// TC-741-32 (b): the api now parses the operator's file before
		// bundling it; a standard PEM file must not move the fingerprint.
		{"controlplane and the parsed operator file", "bundle-controlplane-operator.pem", "controlplane+operator", Bundle(cp, mustCertificatesOnly(t, op))},
	} {
		if want := read(tc.golden); !bytes.Equal(tc.got, want) {
			t.Errorf("%s: bundle bytes differ from the golden", tc.name)
		}
		if got := proto.TrustFingerprint(tc.got); got != fps[tc.fpKey] {
			t.Errorf("%s: fingerprint %s, want %s", tc.name, got, fps[tc.fpKey])
		}
	}
}

func mustCertificatesOnly(t *testing.T, data []byte) []byte {
	t.Helper()
	out, err := CertificatesOnly(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TC-741-32 (F-741-18): CertificatesOnly keeps the certificates in a CA file
// and nothing else. A standard file comes back byte-identical, openssl's text
// around the blocks is dropped, and a key, an unparseable certificate or a
// certificate-less file is refused naming the block, never its content.
func TestCertificatesOnly(t *testing.T) {
	a, b := newCA(t, "a").CertPEM, newCA(t, "b").CertPEM
	two := append(append([]byte{}, a...), b...)
	if got := mustCertificatesOnly(t, two); !bytes.Equal(got, two) {
		t.Error("a standard two-certificate file did not come back byte-identical")
	}
	annotated := "Bag Attributes\n    localKeyID: 01 02\nsubject=/CN=a\nissuer=/CN=a\n" + string(a) +
		"Bag Attributes\nsubject=/CN=b\nissuer=/CN=b\n" + string(b) + "trailing words\n"
	got := mustCertificatesOnly(t, []byte(annotated))
	if !bytes.Equal(got, two) {
		t.Errorf("openssl text was not dropped:\n%s", got)
	}
	if err := proto.ValidateTrustBundle(Bundle(got)); err != nil {
		t.Errorf("a node would refuse the parsed file: %v", err)
	}

	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-key-material")})
	for name, tc := range map[string]struct {
		in   []byte
		want string
	}{
		"a private key after a certificate": {append(append([]byte{}, a...), key...), `PEM block 2 is a "PRIVATE KEY" block`},
		"an unparseable certificate":        {[]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), "PEM block 1 is a certificate that does not parse"},
		"no certificate":                    {[]byte("subject=/CN=a\n"), "no CERTIFICATE block"},
		"empty":                             {nil, "no CERTIFICATE block"},
	} {
		out, err := CertificatesOnly(tc.in)
		if err == nil || out != nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: out %q err %v, want a refusal saying %q", name, out, err, tc.want)
			continue
		}
		if b64 := strings.Split(string(key), "\n")[1]; strings.Contains(err.Error(), b64) || strings.Contains(err.Error(), "secret-key-material") {
			t.Errorf("%s: the refusal carries block content: %v", name, err)
		}
	}
}
