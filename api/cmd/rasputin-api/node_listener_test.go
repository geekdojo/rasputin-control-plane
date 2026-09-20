package main

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
)

// The node listener serves two certificates on one port, and SNI is the only
// thing that tells its two kinds of client apart. A client that asks for the
// bus certificate's name gets the bus certificate; anything else — and that
// means the cluster name a legacy collector asks for — gets the api's mesh
// leaf. A client that sends no SNI at all gets the bus certificate, because
// that is the path everything new is on.
func TestNodeListenerCert_SelectsBySNI(t *testing.T) {
	key, err := bustls.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	busCert, err := bustls.SelfSignedCert(key, timeZero(), timeMax())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mesh.EnsureMeshCA(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := mesh.MintLeaf(ca, mesh.LeafSpec{CommonName: "api", DNSNames: []string{"rasputin.local"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}})
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &apiLeaf{}
	leaf.cert.Store(&leafCert)

	get := nodeListenerCert(&busCert, func() *apiLeaf { return leaf })
	for name, tc := range map[string]struct {
		sni  string
		want *tls.Certificate
	}{
		"the bus certificate's name": {bustls.CertDNSName, &busCert},
		"no SNI at all":              {"", &busCert},
		"the cluster name":           {"rasputin.local", &leafCert},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := get(&tls.ClientHelloInfo{ServerName: tc.sni})
			if err != nil {
				t.Fatalf("SNI %q: %v", tc.sni, err)
			}
			if got != tc.want {
				t.Errorf("SNI %q served the wrong certificate", tc.sni)
			}
		})
	}

	// The bus certificate carries that name and nothing else, so a client
	// pinning it by name cannot be handed the mesh leaf by mistake.
	if got := busCert.Leaf.DNSNames; len(got) != 1 || got[0] != bustls.CertDNSName {
		t.Errorf("bus certificate DNS names = %v, want [%s]", got, bustls.CertDNSName)
	}
}

// With HTTPS off there is no mesh leaf at all, and a legacy client asking for
// the cluster name is told why rather than handed something it cannot verify.
// The listener itself still serves registered-key clients.
func TestNodeListenerCert_NoLeafNamesTheReason(t *testing.T) {
	key, err := bustls.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	busCert, err := bustls.SelfSignedCert(key, timeZero(), timeMax())
	if err != nil {
		t.Fatal(err)
	}
	get := nodeListenerCert(&busCert, func() *apiLeaf { return nil })
	if _, err := get(&tls.ClientHelloInfo{ServerName: "rasputin.local"}); err == nil {
		t.Error("a legacy client was served a certificate with no leaf loaded")
	}
	if got, err := get(&tls.ClientHelloInfo{ServerName: bustls.CertDNSName}); err != nil || got != &busCert {
		t.Errorf("a key client with no leaf loaded = (%v, %v), want the bus certificate", got, err)
	}
}

func timeZero() time.Time { return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC) }
func timeMax() time.Time  { return time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC) }
