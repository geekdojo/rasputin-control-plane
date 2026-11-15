// Package looptls is the client side of a loopback service reached over
// mutually authenticated TLS: the address rule, the client TLS config that
// trusts one CA and presents a client leaf read at each handshake, and the
// classification of a handshake that failed because of that leaf or because
// the server refused it.
//
// The secret store's client was its first user (geekdojo/geekdojo-brain#758);
// the identity service's client is its second (#978), so the code lives here
// once and each client wraps its errors in its own kinds.
package looptls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
)

// ParseAddr checks a loopback service's address and returns it as a URL
// holding only the scheme and host. It accepts https, a loopback IP literal
// and an explicit port in 1-65535, and nothing else: no hostname (a name
// resolves through whatever the resolver says), no path, query, fragment or
// userinfo. Its error names the address and the reason, with no package
// prefix, so each client adds its own.
func ParseAddr(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("address %q: %w", s, err)
	}
	if err := checkAddr(u); err != nil {
		return nil, fmt.Errorf("address %q: %w", s, err)
	}
	return &url.URL{Scheme: "https", Host: u.Host}, nil
}

func checkAddr(u *url.URL) error {
	switch {
	case u.Scheme != "https":
		return errors.New("scheme is not https")
	case u.Opaque != "":
		return errors.New("is not an absolute https URL")
	case u.User != nil:
		return errors.New("carries userinfo")
	case u.Path != "" || u.RawPath != "":
		return errors.New("carries a path")
	case u.RawQuery != "" || u.ForceQuery:
		return errors.New("carries a query")
	case u.Fragment != "" || u.RawFragment != "":
		return errors.New("carries a fragment")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil {
		return errors.New("host is not an IP literal")
	}
	if !ip.IsLoopback() {
		return errors.New("host is not a loopback address")
	}
	port := u.Port()
	if port == "" {
		return errors.New("has no explicit port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return fmt.Errorf("port %q is not in 1-65535", port)
	}
	return nil
}

// NewClientTLS trusts the CA in caPEM and nothing else, speaks TLS 1.3 only,
// and presents the client leaf at certPath and keyPath.
//
// The leaf is read from disk at each handshake, never at construction. So a
// leaf that does not exist yet (every first boot, until the startup sweep
// mints it) is not a construction error, a call made while it is missing or
// unreadable fails that handshake with a *LeafError and no request sent, and
// a renewed leaf is presented on the next new connection with no rebuild.
func NewClientTLS(caPEM []byte, certPath, keyPath string) (*tls.Config, error) {
	cfg, err := clientTLS(caPEM, func() (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	})
	if err != nil {
		return nil, err
	}
	if certPath == "" || keyPath == "" {
		return nil, errors.New("client leaf path is empty")
	}
	return cfg, nil
}

// NewMintedClientTLS is NewClientTLS for a client leaf that never touches
// the disk: mint is called at each handshake and its certificate presented,
// so every new connection carries a new leaf. A mint error fails that
// handshake with a *LeafError and no request sent.
func NewMintedClientTLS(caPEM []byte, mint func() (*tls.Certificate, error)) (*tls.Config, error) {
	if mint == nil {
		return nil, errors.New("the client leaf mint is nil")
	}
	return clientTLS(caPEM, mint)
}

// clientTLS is the one client config: the CA alone as roots, TLS 1.3, and
// get's leaf at each handshake, its error a *LeafError.
func clientTLS(caPEM []byte, get func() (*tls.Certificate, error)) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the CA PEM holds no certificate")
	}
	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := get()
			if err != nil {
				return nil, &LeafError{Err: err}
			}
			return cert, nil
		},
	}, nil
}

// LeafError is a client leaf that could not be loaded for a handshake.
type LeafError struct{ Err error }

func (e *LeafError) Error() string { return fmt.Sprintf("client leaf unusable: %v", e.Err) }
func (e *LeafError) Unwrap() error { return e.Err }

// IsLeafError reports whether err holds a *LeafError: the handshake failed
// on our own client leaf, before anything was sent.
func IsLeafError(err error) bool {
	var lerr *LeafError
	return errors.As(err, &lerr)
}

// refusalAlerts are the TLS alerts a server sends about the client's
// certificate: bad_certificate (42), certificate_unknown (46), unknown_ca
// (48) and certificate_required (116).
var refusalAlerts = []tls.AlertError{42, 46, 48, 116}

// ClientCertRefused reports whether err is the server refusing our client
// certificate.
//
// crypto/tls reports an alert the PEER sent as a *net.OpError with Op
// "remote error" wrapping its unexported alert type, never as tls.AlertError
// (which it uses for QUIC). The unexported alert and tls.AlertError render the
// same text for the same code, so the code is matched through that text, read
// from the standard library itself rather than written here
// (geekdojo/geekdojo-brain#758, F-758-07). tls.AlertError is matched too, so a
// future crypto/tls that returns it still classifies.
func ClientCertRefused(err error) bool {
	var ae tls.AlertError
	if errors.As(err, &ae) && slices.Contains(refusalAlerts, ae) {
		return true
	}
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "remote error" || op.Err == nil {
		return false
	}
	text := op.Err.Error()
	return slices.ContainsFunc(refusalAlerts, func(a tls.AlertError) bool { return a.Error() == text })
}
