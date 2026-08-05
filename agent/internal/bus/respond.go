package bus

import (
	"encoding/json"
	"log"

	"github.com/nats-io/nats.go"
)

// Respond marshals body to JSON and sends it as the reply to m. Marshal and
// reply failures are logged and otherwise swallowed — an agent can't do
// anything useful with a reply it failed to send. Shared by the subsystem
// handlers so the reply encoding and log lines stay identical across them.
func Respond(m *nats.Msg, body any) {
	payload, err := json.Marshal(body)
	if err != nil {
		log.Printf("rasputin-agent: marshal response: %v", err)
		return
	}
	if err := m.Respond(payload); err != nil {
		log.Printf("rasputin-agent: respond: %v", err)
	}
}
