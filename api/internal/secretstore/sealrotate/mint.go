package sealrotate

import (
	"crypto/tls"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// MintRotationLeaf mints the rotation client's leaf under the store CA for one
// handshake; it is secretstore.NewMintedTLSConfig's mint. The leaf is never
// written to disk: a standing credential for a rare, privileged role is not
// kept (plan, Alternatives rejected). The key's PEM leaves its secret.Value
// only into tls.X509KeyPair. The leaf is clientAuth, with the CommonName the
// store's rasputin-seal-rotate cert role admits (#804).
func MintRotationLeaf(ca *tlsca.CA) func() (*tls.Certificate, error) {
	return func() (*tls.Certificate, error) {
		certPEM, key, err := ca.MintLeaf(tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: RotationRole})
		if err != nil {
			return nil, err
		}
		defer key.Destroy()
		cert, err := tls.X509KeyPair(certPEM, key.Reveal())
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
}
