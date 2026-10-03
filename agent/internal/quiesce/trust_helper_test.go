package quiesce

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/nodekeys"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// trustNoTLS is the TrustSource for tests whose endpoint is plain http: it
// trusts no certificate, so a test that reaches for HTTPS by mistake fails
// the handshake instead of passing on a system root.
func trustNoTLS() (*tls.Config, error) {
	return &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}, nil
}

// testNodeKeys is a node's key set made the way the agent makes it
// (nodekeys.Ensure), and its agent key as the client certificate the stager
// presents.
func testNodeKeys(t *testing.T) (*nodekeys.Keys, *tls.Certificate) {
	t.Helper()
	keys, _, err := nodekeys.Ensure(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := keys.ClientCertificate(proto.NodeKeyAgent)
	if err != nil {
		t.Fatal(err)
	}
	return keys, cert
}

// testAgentCert is testNodeKeys' certificate alone.
func testAgentCert(t *testing.T) *tls.Certificate {
	t.Helper()
	_, cert := testNodeKeys(t)
	return cert
}
