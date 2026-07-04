package openwrt

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// RegisterHandlers wires the agent's NATS subscriptions for the firewall
// command subjects, dispatching to the supplied UCIClient. Returns the two
// subscriptions; the caller must Unsubscribe them at shutdown.
//
// Only register-time-called on firewall-role agents — compute and storage
// nodes should never see these subjects on their own subspaces.
func RegisterHandlers(nc *nats.Conn, nodeID string, client UCIClient) ([]*nats.Subscription, error) {
	subs := make([]*nats.Subscription, 0, 2)

	applySubj := proto.NodeCmdSubject(nodeID, "firewall.apply")
	sub, err := nc.Subscribe(applySubj, func(m *nats.Msg) {
		handleApply(nc, client, m)
	})
	if err != nil {
		return nil, err
	}
	subs = append(subs, sub)
	log.Printf("rasputin-agent: subscribed to %s", applySubj)

	getSubj := proto.NodeCmdSubject(nodeID, "firewall.get")
	sub, err = nc.Subscribe(getSubj, func(m *nats.Msg) {
		handleGet(nc, client, m)
	})
	if err != nil {
		return subs, err
	}
	subs = append(subs, sub)
	log.Printf("rasputin-agent: subscribed to %s", getSubj)

	setActiveSubj := proto.FirewallSetActiveSubject(nodeID)
	sub, err = nc.Subscribe(setActiveSubj, func(m *nats.Msg) {
		handleSetActive(client, m)
	})
	if err != nil {
		return subs, err
	}
	subs = append(subs, sub)
	log.Printf("rasputin-agent: subscribed to %s", setActiveSubj)

	return subs, nil
}

func handleApply(_ *nats.Conn, client UCIClient, m *nats.Msg) {
	var cmd proto.FirewallApplyCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		respond(m, proto.FirewallApplyAck{OK: false})
		log.Printf("rasputin-agent: firewall.apply: bad cmd: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hash, err := client.Apply(ctx, cmd.State)
	if err != nil {
		respond(m, proto.FirewallApplyAck{OK: false})
		log.Printf("rasputin-agent: firewall.apply: %v", err)
		return
	}
	respond(m, proto.FirewallApplyAck{OK: true, Hash: hash})
}

func handleGet(_ *nats.Conn, client UCIClient, m *nats.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state, hash, err := client.Get(ctx)
	if err != nil {
		respond(m, proto.FirewallGetAck{State: map[string]any{}, Hash: ""})
		log.Printf("rasputin-agent: firewall.get: %v", err)
		return
	}
	respond(m, proto.FirewallGetAck{State: state, Hash: hash})
}

func handleSetActive(client UCIClient, m *nats.Msg) {
	var cmd proto.FirewallSetActiveCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		respond(m, proto.FirewallSetActiveAck{OK: false})
		log.Printf("rasputin-agent: firewall.set_active: bad cmd: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.SetActive(ctx, cmd.Active); err != nil {
		respond(m, proto.FirewallSetActiveAck{OK: false, Applied: cmd.Active})
		log.Printf("rasputin-agent: firewall.set_active(active=%v): %v", cmd.Active, err)
		return
	}
	log.Printf("rasputin-agent: firewall.set_active(active=%v) ok", cmd.Active)
	respond(m, proto.FirewallSetActiveAck{OK: true, Applied: cmd.Active})
}

func respond(m *nats.Msg, body any) {
	payload, err := json.Marshal(body)
	if err != nil {
		log.Printf("rasputin-agent: marshal response: %v", err)
		return
	}
	if err := m.Respond(payload); err != nil {
		log.Printf("rasputin-agent: respond: %v", err)
	}
}
