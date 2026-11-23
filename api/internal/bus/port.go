package bus

import (
	"strconv"

	"github.com/nats-io/nats-server/v2/server"
)

// DefaultPort is the bus's client port when none is configured.
const DefaultPort = 4222

// AnyPort asks the embedded server to listen on any free port the OS picks.
// The bound port is then readable from Server.ClientURL.
const AnyPort = server.RANDOM_PORT

// ParsePort maps a RASPUTIN_NATS_PORT value to a bus port. A positive number
// is that port and "-1" is AnyPort; anything else (empty, "0", any other
// negative number, or text that is not a number) is DefaultPort.
func ParsePort(v string) int {
	p, err := strconv.Atoi(v)
	switch {
	case err != nil:
		return DefaultPort
	case p > 0:
		return p
	case p == AnyPort:
		return AnyPort
	default:
		return DefaultPort
	}
}
