package secretstore

import (
	"fmt"
	"net/url"

	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
)

// ParseAddr checks the store's address and returns it as a URL holding only
// the scheme and host (S8). It accepts https, a loopback IP literal and an
// explicit port in 1-65535, and nothing else: no hostname (a name resolves
// through whatever the resolver says), no path, query, fragment or userinfo.
// The rule is looptls.ParseAddr's, which the identity client shares.
func ParseAddr(s string) (*url.URL, error) {
	u, err := looptls.ParseAddr(s)
	if err != nil {
		return nil, fmt.Errorf("secretstore: %w", err)
	}
	return u, nil
}
