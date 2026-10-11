package secretstore

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
)

// ParseAddr checks the store's address and returns it as a URL holding only
// the scheme and host (S8). It accepts https, a loopback IP literal and an
// explicit port in 1-65535, and nothing else: no hostname (a name resolves
// through whatever the resolver says), no path, query, fragment or userinfo.
func ParseAddr(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("secretstore: address %q: %w", s, err)
	}
	if err := checkAddr(u); err != nil {
		return nil, fmt.Errorf("secretstore: address %q: %w", s, err)
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
