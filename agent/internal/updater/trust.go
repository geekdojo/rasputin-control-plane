package updater

import (
	"crypto/tls"
	"errors"
	"net/http"
)

// TrustSource returns the TLS client config the bundle download trusts: the
// node's mesh CA bundle and nothing else (geekdojo/geekdojo-brain#590). The
// download URL is always the api's /api/bundles/{sha} at <cluster>.local, a
// leaf the Mesh CA signs, so no system root belongs in it. The composition
// root passes tailscale.MeshTrust.ClientTLSConfig, which re-reads the bundle
// on every call.
type TrustSource func() (*tls.Config, error)

// errNoTrustSource is a backend constructed without a trust source. It is a
// constructor error rather than a nil check at download time, so a wiring
// mistake stops the agent at startup instead of surfacing as a failed update.
var errNoTrustSource = errors.New("no mesh trust source wired for the bundle download")

// errNoTrustRoots is a trust source that answered without error but with no
// root pool. A nil config, or a nil RootCAs, would make net/http verify
// against the system roots, so it is refused before any request is made.
var errNoTrustRoots = errors.New("mesh trust source returned no root pool; refusing to fall back to the system roots")

// trustedClient builds the download client from one call to trust. The
// client is per Download, so a CA re-delivered between updates is used by
// the next one without an agent restart. A config with no root pool is
// refused: it would mean the system roots.
func trustedClient(trust TrustSource) (*http.Client, error) {
	cfg, err := trust()
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.RootCAs == nil {
		return nil, errNoTrustRoots
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}, nil
}
