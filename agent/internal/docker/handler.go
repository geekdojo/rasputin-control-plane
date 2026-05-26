package docker

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// RegisterHandlers wires the agent's docker.deploy / docker.stop /
// docker.status subscriptions to the supplied Backend. Returns the
// subscriptions so the caller can unsubscribe at shutdown.
//
// Only register on compute (or controlplane) role agents. Firewall and
// storage nodes don't host user apps.
func RegisterHandlers(nc *nats.Conn, nodeID string, b Backend) ([]*nats.Subscription, error) {
	subs := make([]*nats.Subscription, 0, 3)

	deploySubj := proto.AppDeploySubject(nodeID)
	sub, err := nc.Subscribe(deploySubj, func(m *nats.Msg) {
		handleDeploy(b, m)
	})
	if err != nil {
		return nil, err
	}
	subs = append(subs, sub)
	log.Printf("rasputin-agent: subscribed to %s (backend=%s)", deploySubj, b.Name())

	stopSubj := proto.AppStopSubject(nodeID)
	sub, err = nc.Subscribe(stopSubj, func(m *nats.Msg) {
		handleStop(b, m)
	})
	if err != nil {
		return subs, err
	}
	subs = append(subs, sub)
	log.Printf("rasputin-agent: subscribed to %s", stopSubj)

	statusSubj := proto.AppStatusSubject(nodeID)
	sub, err = nc.Subscribe(statusSubj, func(m *nats.Msg) {
		handleStatus(b, m)
	})
	if err != nil {
		return subs, err
	}
	subs = append(subs, sub)
	log.Printf("rasputin-agent: subscribed to %s", statusSubj)

	return subs, nil
}

func handleDeploy(b Backend, m *nats.Msg) {
	var cmd proto.AppDeployCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		respond(m, proto.AppDeployAck{OK: false, Status: proto.AppStatusFailed, Detail: "bad cmd"})
		log.Printf("rasputin-agent: docker.deploy: bad cmd: %v", err)
		return
	}
	// Deploy can be slow (image pulls etc); give it a generous window.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	status, detail, err := b.Deploy(ctx, cmd.AppID, cmd.Name, cmd.ComposeYAML)
	if err != nil {
		respond(m, proto.AppDeployAck{OK: false, Status: status, Detail: detail})
		log.Printf("rasputin-agent: docker.deploy %s: %v", cmd.AppID, err)
		return
	}
	respond(m, proto.AppDeployAck{OK: status == proto.AppStatusRunning, Status: status, Detail: detail})
}

func handleStop(b Backend, m *nats.Msg) {
	var cmd proto.AppStopCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		respond(m, proto.AppStopAck{OK: false, Status: proto.AppStatusFailed, Detail: "bad cmd"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, detail, err := b.Stop(ctx, cmd.AppID)
	if err != nil {
		respond(m, proto.AppStopAck{OK: false, Status: status, Detail: detail})
		log.Printf("rasputin-agent: docker.stop %s: %v", cmd.AppID, err)
		return
	}
	respond(m, proto.AppStopAck{OK: status == proto.AppStatusStopped, Status: status, Detail: detail})
}

func handleStatus(b Backend, m *nats.Msg) {
	var cmd proto.AppStatusCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		respond(m, proto.AppStatusAck{Status: proto.AppStatusUnknown})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, services, err := b.Status(ctx, cmd.AppID)
	if err != nil {
		log.Printf("rasputin-agent: docker.status %s: %v", cmd.AppID, err)
	}
	respond(m, proto.AppStatusAck{AppID: cmd.AppID, Status: status, Services: services})
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
