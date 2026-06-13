package bus

import (
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

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
