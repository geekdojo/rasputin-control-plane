package secretstore

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// NewTLSConfig is the client side of S8's transport: trust the store CA and
// nothing else, speak TLS 1.3 only, and present the store-CA client leaf at
// certPath and keyPath.
//
// The leaf is read from disk at each handshake, never at construction. So a
// leaf that does not exist yet (every first boot, until the startup sweep
// mints it) is not a construction error, a call made while it is missing or
// unreadable fails that handshake as ErrUnreachable with no request sent, and
// a renewed leaf is presented on the next new connection with no rebuild
// (geekdojo/geekdojo-brain#758, F-758-01).
func NewTLSConfig(storeCAPEM []byte, certPath, keyPath string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(storeCAPEM) {
		return nil, errors.New("secretstore: store CA PEM holds no certificate")
	}
	if certPath == "" || keyPath == "" {
		return nil, errors.New("secretstore: client leaf path is empty")
	}
	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, &leafError{err: err}
			}
			return &cert, nil
		},
	}, nil
}

// leafError is a client leaf that could not be loaded for a handshake.
type leafError struct{ err error }

func (e *leafError) Error() string { return fmt.Sprintf("client leaf unusable: %v", e.err) }
func (e *leafError) Unwrap() error { return e.err }
