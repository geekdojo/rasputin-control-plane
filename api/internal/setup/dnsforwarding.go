package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DNS forwarding — the optional AA-11 stub (ADR-0004 §10). The control-plane
// nameserver is authoritative for <cluster-id>.internal and REFUSEs everything
// else; enabling this lets it forward the everything-else to an upstream, so a
// Mode-B operator who points their router's DNS at the control plane gets both
// internal names and the public internet from one box. Persisted as a cluster
// setting; default disabled. The runtime forwarder + the loop-safe upstream
// resolution live in the nameserver package.
const KeyDNSForwarding = "dns.forwarding"

// DNSForwarding is the operator's forwarding choice. Upstream is the operator-
// picked resolver ("ip" or "ip:port"); empty means "auto" — the nameserver
// inherits the CP's own DHCP resolver, falling back to a public resolver when
// that would loop (detect-and-fall-back, decided with Bryce 2026-08-09).
type DNSForwarding struct {
	Enabled  bool   `json:"enabled"`
	Upstream string `json:"upstream"`
}

// ErrInvalidUpstream rejects an upstream that isn't a bare IPv4 or IPv4:port.
var ErrInvalidUpstream = errors.New("upstream must be an IPv4 address or IPv4:port (Rasputin is IPv4-only)")

// GetDNSForwarding returns the stored choice — the zero value (disabled, auto)
// when never set.
func (s *Service) GetDNSForwarding(ctx context.Context) (DNSForwarding, error) {
	raw, err := s.store.Get(ctx, KeyDNSForwarding)
	if err != nil {
		return DNSForwarding{}, err
	}
	if raw == "" {
		return DNSForwarding{}, nil
	}
	var v DNSForwarding
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return DNSForwarding{}, fmt.Errorf("setup: corrupt %s value: %w", KeyDNSForwarding, err)
	}
	return v, nil
}

// SetDNSForwarding validates and persists the choice, returning the stored form
// (upstream trimmed). A blank upstream is valid ("auto"); a non-blank one must
// be an IPv4 address, optionally with a port.
func (s *Service) SetDNSForwarding(ctx context.Context, v DNSForwarding) (DNSForwarding, error) {
	v.Upstream = strings.TrimSpace(v.Upstream)
	if v.Upstream != "" && !validUpstream(v.Upstream) {
		return DNSForwarding{}, ErrInvalidUpstream
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return DNSForwarding{}, err
	}
	if err := s.store.Set(ctx, KeyDNSForwarding, string(raw)); err != nil {
		return DNSForwarding{}, err
	}
	return v, nil
}

// validUpstream accepts a bare IPv4 or IPv4:port; IPv6 is rejected (decision #9).
func validUpstream(s string) bool {
	host := s
	if h, p, err := net.SplitHostPort(s); err == nil {
		host = h
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
}
