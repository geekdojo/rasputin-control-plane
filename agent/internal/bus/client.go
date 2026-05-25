package bus

import (
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

// Connect dials the api's NATS broker with infinite reconnect. The connection
// name shows the node id in `nats` CLI output.
func Connect(url, nodeID string) (*nats.Conn, error) {
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
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			log.Printf("agent/bus: connection closed")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("agent/bus: connect %s: %w", url, err)
	}
	log.Printf("agent/bus: connected to %s as %s", nc.ConnectedUrl(), nodeID)
	return nc, nil
}
