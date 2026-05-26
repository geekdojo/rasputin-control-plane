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
func Connect(url, nodeID string, onConnected func(*nats.Conn)) (*nats.Conn, error) {
	if url == "" {
		url = nats.DefaultURL
	}
	nc, err := nats.Connect(url,
		nats.Name(fmt.Sprintf("rasputin-agent/%s", nodeID)),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.PingInterval(20*time.Second),
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
	)
	if err != nil {
		return nil, fmt.Errorf("agent/bus: connect %s: %w", url, err)
	}
	log.Printf("agent/bus: connected to %s as %s", nc.ConnectedUrl(), nodeID)
	if onConnected != nil {
		onConnected(nc)
	}
	return nc, nil
}
