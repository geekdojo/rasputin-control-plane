package quiesce

import (
	"crypto/tls"
	"crypto/x509"
)

// trustNoTLS is the TrustSource for tests whose endpoint is plain http: it
// trusts no certificate, so a test that reaches for HTTPS by mistake fails
// the handshake instead of passing on a system root.
func trustNoTLS() (*tls.Config, error) {
	return &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}, nil
}
