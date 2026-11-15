package secretstore

import (
	"crypto/tls"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
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
// (geekdojo/geekdojo-brain#758, F-758-01). The config is looptls's, which the
// identity client shares (geekdojo/geekdojo-brain#978).
func NewTLSConfig(storeCAPEM []byte, certPath, keyPath string) (*tls.Config, error) {
	cfg, err := looptls.NewClientTLS(storeCAPEM, certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("secretstore: store TLS: %w", err)
	}
	return cfg, nil
}

// NewMintedTLSConfig is NewTLSConfig for a client leaf that never touches the
// disk: mint is called at each handshake and its certificate presented, so
// every new connection carries a new leaf (geekdojo/geekdojo-brain#830, the
// seal rotation's role). A mint error fails that handshake as ErrUnreachable
// with no request sent. The store CA trust and TLS 1.3 are NewTLSConfig's.
func NewMintedTLSConfig(storeCAPEM []byte, mint func() (*tls.Certificate, error)) (*tls.Config, error) {
	cfg, err := looptls.NewMintedClientTLS(storeCAPEM, mint)
	if err != nil {
		return nil, fmt.Errorf("secretstore: store TLS: %w", err)
	}
	return cfg, nil
}
