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
func RegisterHandlers(nc *nats.Conn, nodeID string, store *LeafStore, reconcile func() error) (*nats.Subscription, error) {
	subj := proto.AppLeafSubject(nodeID)
	sub, err := nc.Subscribe(subj, func(m *nats.Msg) { handleLeaf(store, reconcile, m) })
	if err != nil {
		return nil, err
	}
	log.Printf("rasputin-agent: subscribed to %s", subj)
	return sub, nil
}

func handleLeaf(store *LeafStore, reconcile func() error, m *nats.Msg) {
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
		reconcileBestEffort(reconcile, cmd.AppID)
		bus.Respond(m, proto.AppLeafAck{OK: true})
		return
	}

	if err := store.Write(cmd.AppID, cmd.CertPEM, cmd.KeyPEM, RouteMeta{
		TailnetFQDN:  cmd.TailnetFQDN,
		LANFQDN:      cmd.LANFQDN,
		UpstreamPort: cmd.UpstreamPort,
		UpstreamTLS:  cmd.UpstreamTLS,
	}); err != nil {
		bus.Respond(m, proto.AppLeafAck{OK: false, Detail: err.Error()})
		log.Printf("rasputin-agent: app.leaf write %s: %v", cmd.AppID, err)
		return
	}
	log.Printf("rasputin-agent: installed leaf for app %s (%s)", cmd.AppID, cmd.Name)
	// Ack reflects DELIVERY (leaf stored). Pushing Caddy config is best-effort:
	// a failure (e.g. Caddy not up yet) is logged, and startup + the next leaf
	// change re-reconcile — never fail the delivery on a transient proxy issue.
	reconcileBestEffort(reconcile, cmd.AppID)
	bus.Respond(m, proto.AppLeafAck{OK: true})
}

func reconcileBestEffort(reconcile func() error, appID string) {
	if reconcile == nil {
		return
	}
	if err := reconcile(); err != nil {
		log.Printf("rasputin-agent: proxy reconcile after %s: %v (will retry on next change / restart)", appID, err)
	}
}
