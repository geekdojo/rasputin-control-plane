package bus

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/mdns"
	"github.com/nats-io/nats.go"
)

// mdnsDialer resolves *.local hostnames via multicast DNS before dialing, so a
// node can reach the control plane at rasputin.local on a LAN whose OS has no
// .local resolver (notably the OpenWrt firewall image). nats calls Dial on every
// (re)connect, so address churn is handled transparently — each reconnect
// re-resolves. Non-.local hosts and bare IPs dial normally.
type mdnsDialer struct {
	resolveTimeout time.Duration
	dialTimeout    time.Duration
}

func (d *mdnsDialer) Dial(network, address string) (net.Conn, error) {
	if host, port, err := net.SplitHostPort(address); err == nil &&
		strings.HasSuffix(strings.ToLower(host), ".local") {
		if ip, rerr := mdns.Resolve(host, d.resolveTimeout); rerr == nil && ip != "" {
			address = net.JoinHostPort(ip, port)
		} else if rerr != nil {
			log.Printf("agent/bus: mDNS resolve %s failed (%v); falling back to OS resolver", host, rerr)
		}
	}
	return net.DialTimeout(network, address, d.dialTimeout)
}

// Connect dials the api's NATS broker with infinite reconnect. onConnected,
// if non-nil, fires once for the initial connection AND on every successful
// reconnect — used by the agent to (re-)publish its registration event.
//
// token is the node's bus join credential (RASPUTIN_CP_JOIN_TOKEN). When set,
// it's presented as NATS username=nodeID, password=token, which the api's
// auth-callout responder validates to mint a per-node scoped JWT. It is
// harmless to pass when the server has no auth enabled (NATS ignores creds it
// doesn't require), so the agent always passes it; only the SERVER's
// RASPUTIN_BUS_AUTH flag gates enforcement. A controlplane's co-located agent
// has no token and is trusted via loopback.
func Connect(url, nodeID, token string, onConnected func(*nats.Conn)) (*nats.Conn, error) {
	if url == "" {
		url = nats.DefaultURL
	}
	connOpts := []nats.Option{
		nats.Name(fmt.Sprintf("rasputin-agent/%s", nodeID)),
		// Resolve rasputin.local via mDNS on every (re)connect (see mdnsDialer).
		nats.SetCustomDialer(&mdnsDialer{resolveTimeout: 2 * time.Second, dialTimeout: 5 * time.Second}),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.PingInterval(20 * time.Second),
		nats.MaxPingsOutstanding(3),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				log.Printf("agent/bus: disconnected: %v", err)
			}
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Printf("agent/bus: reconnected to %s", c.ConnectedUrl())
			if onConnected != nil {
				onConnected(c)
			}
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			log.Printf("agent/bus: connection closed")
		}),
		// Without this, nats.go installs its own default handler and the only
		// trace of an async failure is a bare, unprefixed line nobody greps for.
		// That matters most for permissions violations: Msg.Respond is an
		// ASYNCHRONOUS publish that returns nil, so an agent whose reply is
		// denied by the bus sees no error at all on the calling goroutine — the
		// denial arrives here, later, or nowhere. A dropped reply then surfaces
		// only on the api as "rpc: context deadline exceeded", which names the
		// wrong side of the connection. Say it loudly, with the fix.
		nats.ErrorHandler(func(_ *nats.Conn, sub *nats.Subscription, err error) {
			subject := "(no subscription)"
			if sub != nil {
				subject = sub.Subject
			}
			if errors.Is(err, nats.ErrPermissionViolation) {
				log.Printf("rasputin-agent: bus: PERMISSIONS VIOLATION on %s: %v — "+
					"this node's minted credential does not allow that subject. If it "+
					"names an _INBOX subject, a reply outlived its response grant "+
					"(see proto.BusReplyGrantTTL); otherwise the publish is outside "+
					"rasputin.node.%s.>", subject, err, nodeID)
				return
			}
			log.Printf("rasputin-agent: bus: async error on %s: %v", subject, err)
		}),
	}
	// Always present the node id as the NATS username (token as password, which
	// may be empty). The callout needs the id to scope the grant and to apply
	// loopback trust for a tokenless controlplane agent; an empty token from a
	// non-loopback node is correctly denied. Harmless when the server has no
	// auth — NATS ignores creds it doesn't require.
	connOpts = append(connOpts, nats.UserInfo(nodeID, token))
	nc, err := nats.Connect(url, connOpts...)
	if err != nil {
		return nil, fmt.Errorf("agent/bus: connect %s: %w", url, err)
	}
	log.Printf("agent/bus: connected to %s as %s", nc.ConnectedUrl(), nodeID)
	if onConnected != nil {
		onConnected(nc)
	}
	return nc, nil
}
