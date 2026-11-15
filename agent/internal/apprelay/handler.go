package apprelay

import (
	"encoding/json"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Sockets is what the app.relay verb needs of the Manager.
type Sockets interface {
	Prepare(appID string) ([]byte, error)
	Install(appID string, certPEM, caPEM []byte) error
	Remove(appID string) error
}

// RegisterHandlers subscribes nodeID's app.relay verb on nc, answered by s.
// main calls it on every bus connection, beside the docker handlers.
func RegisterHandlers(nc *nats.Conn, nodeID string, s Sockets) (*nats.Subscription, error) {
	subj := proto.AppRelaySubject(nodeID)
	sub, err := nc.Subscribe(subj, func(m *nats.Msg) {
		bus.Respond(m, handle(s, m.Data))
	})
	if err != nil {
		return nil, fmt.Errorf("subscribe %s: %w", subj, err)
	}
	return sub, nil
}

// handle answers one app.relay command.
func handle(s Sockets, data []byte) proto.AppRelayAck {
	var cmd proto.AppRelayCmd
	if err := json.Unmarshal(data, &cmd); err != nil {
		return proto.AppRelayAck{Detail: "The command is not an app.relay command."}
	}
	switch cmd.Op {
	case proto.AppRelayPrepare:
		der, err := s.Prepare(cmd.AppID)
		if err != nil {
			return proto.AppRelayAck{Detail: err.Error()}
		}
		return proto.AppRelayAck{OK: true, PublicKeyDER: der}
	case proto.AppRelayInstall:
		if err := s.Install(cmd.AppID, cmd.CertPEM, cmd.CAPEM); err != nil {
			return proto.AppRelayAck{Detail: err.Error()}
		}
		return proto.AppRelayAck{OK: true}
	case proto.AppRelayRemove:
		if err := s.Remove(cmd.AppID); err != nil {
			return proto.AppRelayAck{Detail: err.Error()}
		}
		return proto.AppRelayAck{OK: true}
	}
	return proto.AppRelayAck{Detail: fmt.Sprintf("The operation %q is not prepare, install or remove.", cmd.Op)}
}
