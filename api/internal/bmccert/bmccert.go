// Package bmccert signs a Super4C BMC's certificate request under the
// controlplane CA (geekdojo/geekdojo-brain#1065).
//
// The board generates its P-256 key itself and sends a certificate request
// naming one host, rasputin-bmc-<12 lowercase hex>.local. Signer checks that
// request against a fixed policy and asks the CA for a server leaf over the
// request's key. The leaf names the board inside the cluster's own zone,
// bmc-<the same 12 hex>.<cluster id>.internal (geekdojo/geekdojo-brain#1142):
// only the key and the 12 hex of the validated name come from the request,
// and its subject and any extension it asks for never reach the certificate.
//
// The leaf expires with the CA. The board can be re-seeded only over its J47
// header, so a leaf with a shorter life would leave it serving an expired
// certificate with no path to renew it.
package bmccert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The refusals. Each is a reason the request itself is wrong, and Sign signs
// nothing when it returns one.
var (
	// ErrNoUser: no operator is named for the record.
	ErrNoUser = errors.New("bmccert: a signed-in operator is required")
	// ErrSignature: the request's own signature does not verify.
	ErrSignature = errors.New("bmccert: the certificate request's signature does not verify")
	// ErrKeyType: the request's key is not ECDSA P-256.
	ErrKeyType = errors.New("bmccert: the certificate request's key is not ECDSA P-256")
	// ErrExtension: the request asks for an extension other than its name.
	ErrExtension = errors.New("bmccert: the certificate request carries an extension other than subjectAltName")
	// ErrName: the request does not name exactly one BMC host and nothing else.
	ErrName = errors.New("bmccert: the certificate request does not name exactly one rasputin-bmc host")
)

// oidSubjectAltName is the only extension a BMC request may carry.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// bmcName is the name the firmware writes: the board's MAC as lowercase hex,
// captured for the leaf's name.
var bmcName = regexp.MustCompile(`^rasputin-bmc-([0-9a-f]{12})\.local$`)

// Issuer signs a leaf over a supplied public key (*tlsca.CA).
type Issuer interface {
	SignLeaf(spec tlsca.LeafSpec, pub crypto.PublicKey) ([]byte, error)
}

// Signed is a signed BMC leaf and the CA certificate that vouches for it.
type Signed struct {
	// Name is the host the leaf names, as both its CN and its only SAN:
	// bmc-<12 hex>.<cluster id>.internal.
	Name string
	// LeafPEM is the leaf certificate.
	LeafPEM []byte
	// CAPEM is the controlplane CA's certificate.
	CAPEM []byte
	// NotAfter is the leaf's expiry, which is the CA's.
	NotAfter time.Time
}

// Signer checks a BMC certificate request and has the CA sign it.
type Signer struct {
	issuer Issuer
	zone   string
	caCert *x509.Certificate
	caPEM  []byte
	log    *slog.Logger
}

// New builds a Signer. issuer signs, caCert is its certificate (whose expiry
// the leaf takes), caPEM is that certificate as PEM for the response, and log
// records each signing. clusterID names the zone the leaf is named in,
// proto.BaseDomain(clusterID), so an empty id is the rasputin zone, as for
// the app leaves. Every other argument is required.
func New(issuer Issuer, caCert *x509.Certificate, caPEM []byte, clusterID string, log *slog.Logger) (*Signer, error) {
	switch {
	case issuer == nil:
		return nil, errors.New("bmccert: New: an issuer is required")
	case caCert == nil:
		return nil, errors.New("bmccert: New: the CA certificate is required")
	case len(caPEM) == 0:
		return nil, errors.New("bmccert: New: the CA certificate PEM is required")
	case log == nil:
		return nil, errors.New("bmccert: New: a logger is required")
	}
	return &Signer{issuer: issuer, zone: proto.BaseDomain(clusterID), caCert: caCert, caPEM: append([]byte(nil), caPEM...), log: log}, nil
}

// Sign checks csr and returns a server leaf over its key, named
// bmc-<the 12 hex of the request's name>.<the cluster's zone>. user is the operator the record names. A policy refusal wraps one
// of the Err values above; any other error is the issuer's, and is logged at
// ERROR here.
func (s *Signer) Sign(ctx context.Context, user string, csr *x509.CertificateRequest) (Signed, error) {
	mac, err := check(user, csr)
	if err != nil {
		return Signed{}, err
	}
	name := "bmc-" + mac + "." + s.zone
	spec := tlsca.LeafSpec{
		Usage:      tlsca.UsageServer,
		CommonName: name,
		DNSNames:   []string{name},
		NotAfter:   s.caCert.NotAfter,
	}
	leafPEM, err := s.issuer.SignLeaf(spec, csr.PublicKey)
	if err == nil {
		var leaf *x509.Certificate
		if leaf, err = parseLeaf(leafPEM); err == nil {
			s.log.LogAttrs(ctx, slog.LevelInfo, "bmc server leaf signed",
				slog.String("event", "bmccert.signed"),
				slog.String("name", name),
				slog.String("serial", leaf.SerialNumber.Text(16)),
				slog.Time("not_after", leaf.NotAfter),
				slog.String("user", user))
			return Signed{Name: name, LeafPEM: leafPEM, CAPEM: append([]byte(nil), s.caPEM...), NotAfter: leaf.NotAfter}, nil
		}
	}
	s.log.LogAttrs(ctx, slog.LevelError, "bmc server leaf not signed",
		slog.String("event", "bmccert.sign_failed"),
		slog.String("name", name),
		slog.String("user", user),
		slog.String("err", err.Error()))
	return Signed{}, fmt.Errorf("bmccert: sign %s: %w", name, err)
}

// check applies the policy in order and returns the 12 hex of the validated
// name.
func check(user string, csr *x509.CertificateRequest) (string, error) {
	if user == "" {
		return "", ErrNoUser
	}
	if csr == nil {
		return "", fmt.Errorf("%w: no request", ErrSignature)
	}
	// ParseCertificateRequest does not check the signature; this does.
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrSignature, err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return "", ErrKeyType
	}
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			return "", fmt.Errorf("%w: %s", ErrExtension, ext.Id)
		}
	}
	if len(csr.DNSNames) != 1 || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		return "", ErrName
	}
	m := bmcName.FindStringSubmatch(csr.DNSNames[0])
	if m == nil {
		return "", ErrName
	}
	return m[1], nil
}

// parseLeaf reads back the issuer's leaf, for the serial and expiry the
// record names.
func parseLeaf(leafPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(leafPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("issuer returned no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
