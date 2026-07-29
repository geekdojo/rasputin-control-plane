package bmc

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/mdns"
)

// mdnsDialContext resolves `.local` names over mDNS before dialling.
//
// This exists because a chassis BMC is addressed by NAME, deliberately:
// it takes DHCP, and a lease is not an identity, so every layer of this
// project tells the operator to enter `turingpi.local` rather than an
// address. That advice was broken until 2026-07-28 — the driver used a
// plain transport, `.local` is link-local mDNS and the appliance has no
// resolver for it, so the one address form we recommend was the one form
// that could not connect. It went unnoticed because the bench always
// used a literal IP.
//
// The bus client has always dialled this way (agent/internal/bus). This
// is the same behaviour for the BMC's HTTP client: intercept `.local`,
// resolve it over mDNS, fall through to the OS resolver otherwise — so a
// real DNS name or an IP keeps working untouched.
func mdnsDialContext(resolveTimeout, dialTimeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if host, port, err := net.SplitHostPort(address); err == nil &&
			strings.HasSuffix(strings.ToLower(host), ".local") {
			if ip, rerr := mdns.Resolve(host, resolveTimeout); rerr == nil && ip != "" {
				address = net.JoinHostPort(ip, port)
			} else if rerr != nil {
				log.Printf("bmc: mDNS resolve %s failed (%v); falling back to the OS resolver", host, rerr)
			}
		}
		d := net.Dialer{Timeout: dialTimeout}
		return d.DialContext(ctx, network, address)
	}
}
