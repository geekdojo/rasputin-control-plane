package proxy

import (
	"encoding/json"
	"log"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// RegisterHandlers subscribes the agent to per-app leaf delivery for nodeID.
// Register only on app-hosting roles (compute / controlplane), alongside the
// docker handlers. Returns the subscription so the caller can unsubscribe at
// shutdown.
func RegisterHandlers(nc *nats.Conn, nodeID string, store *LeafStore) (*nats.Subscription, error) {
	subj := proto.AppLeafSubject(nodeID)
	sub, err := nc.Subscribe(subj, func(m *nats.Msg) { handleLeaf(store, m) })
	if err != nil {
		return nil, err
	}
	log.Printf("rasputin-agent: subscribed to %s", subj)
	return sub, nil
}

func handleLeaf(store *LeafStore, m *nats.Msg) {
	var cmd proto.AppLeafCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		bus.Respond(m, proto.AppLeafAck{OK: false, Detail: "bad cmd"})
		log.Printf("rasputin-agent: app.leaf: bad cmd: %v", err)
		return
	}
	if cmd.AppID == "" {
		bus.Respond(m, proto.AppLeafAck{OK: false, Detail: "empty appId"})
		return
	}

	if cmd.Remove {
		if err := store.Remove(cmd.AppID); err != nil {
			bus.Respond(m, proto.AppLeafAck{OK: false, Detail: err.Error()})
			log.Printf("rasputin-agent: app.leaf remove %s: %v", cmd.AppID, err)
			return
		}
		log.Printf("rasputin-agent: removed leaf for app %s", cmd.AppID)
		bus.Respond(m, proto.AppLeafAck{OK: true})
		return
	}

	if err := store.Write(cmd.AppID, cmd.CertPEM, cmd.KeyPEM); err != nil {
		bus.Respond(m, proto.AppLeafAck{OK: false, Detail: err.Error()})
		log.Printf("rasputin-agent: app.leaf write %s: %v", cmd.AppID, err)
		return
	}
	log.Printf("rasputin-agent: installed leaf for app %s (%s)", cmd.AppID, cmd.Name)
	bus.Respond(m, proto.AppLeafAck{OK: true})
}
