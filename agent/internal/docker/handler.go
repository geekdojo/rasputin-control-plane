package docker

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
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

	// The orphan-volume verbs exist only where the backend can answer them
	// honestly. The mock has no volumes and does not implement the interface.
	if reaper, ok := b.(VolumeReaper); ok {
		listSubj := proto.AppVolumesListSubject(nodeID)
		sub, err = nc.Subscribe(listSubj, func(m *nats.Msg) {
			handleVolumesList(reaper, m)
		})
		if err != nil {
			return subs, err
		}
		subs = append(subs, sub)
		log.Printf("rasputin-agent: subscribed to %s", listSubj)

		removeSubj := proto.AppVolumesRemoveSubject(nodeID)
		sub, err = nc.Subscribe(removeSubj, func(m *nats.Msg) {
			handleVolumesRemove(reaper, m)
		})
		if err != nil {
			return subs, err
		}
		subs = append(subs, sub)
		log.Printf("rasputin-agent: subscribed to %s", removeSubj)
	}

	return subs, nil
}

func handleVolumesList(r VolumeReaper, m *nats.Msg) {
	// Sizing walks every managed volume's files; a node with a large bulk
	// volume needs longer than the other verbs get.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	vols, err := r.ListProjectVolumes(ctx)
	if err != nil {
		bus.Respond(m, proto.AppVolumesListAck{OK: false, Detail: err.Error(), Volumes: []proto.AppVolumeInfo{}})
		log.Printf("rasputin-agent: docker.volumes.list: %v", err)
		return
	}
	if vols == nil {
		vols = []proto.AppVolumeInfo{}
	}
	bus.Respond(m, proto.AppVolumesListAck{OK: true, Volumes: vols})
}

func handleVolumesRemove(r VolumeReaper, m *nats.Msg) {
	var cmd proto.AppVolumesRemoveCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		bus.Respond(m, proto.AppVolumesRemoveAck{OK: false, Detail: "bad cmd",
			Removed: []string{}, Refused: []proto.AppVolumeRefusal{}})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ack := r.RemoveProjectVolumes(ctx, cmd)
	for _, ref := range ack.Refused {
		log.Printf("rasputin-agent: docker.volumes.remove: refused %s: %s", ref.Name, ref.Reason)
	}
	for _, name := range ack.Removed {
		log.Printf("rasputin-agent: docker.volumes.remove: removed %s", name)
	}
	bus.Respond(m, ack)
}

func handleDeploy(b Backend, m *nats.Msg) {
	var cmd proto.AppDeployCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		bus.Respond(m, proto.AppDeployAck{OK: false, Status: proto.AppStatusFailed, Detail: "bad cmd"})
		log.Printf("rasputin-agent: docker.deploy: bad cmd: %v", err)
		return
	}
	// Deploy is slow because of the image pull. The window is proto's, shared
	// with the api's RPC deadline so the two cannot drift apart — see
	// proto.AppDeployWorkFor, which also clamps whatever the api sent. The api
	// takes the budget from the app's catalog tile; an api older than the field
	// sends nothing, which is zero, which is the default.
	budget := proto.AppDeployWorkFor(cmd.WorkBudgetSeconds)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	status, detail, err := b.Deploy(ctx, cmd.AppID, cmd.Name, cmd.ComposeYAML)
	if err != nil {
		bus.Respond(m, proto.AppDeployAck{OK: false, Status: status, Detail: detail})
		log.Printf("rasputin-agent: docker.deploy %s: %v", cmd.AppID, err)
		return
	}
	bus.Respond(m, proto.AppDeployAck{OK: status == proto.AppStatusRunning, Status: status, Detail: detail})
}

func handleStop(b Backend, m *nats.Msg) {
	var cmd proto.AppStopCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		bus.Respond(m, proto.AppStopAck{OK: false, Status: proto.AppStatusFailed, Detail: "bad cmd"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, detail, err := b.Stop(ctx, cmd.AppID, cmd.DeleteVolumes)
	if err != nil {
		bus.Respond(m, proto.AppStopAck{OK: false, Status: status, Detail: detail})
		log.Printf("rasputin-agent: docker.stop %s: %v", cmd.AppID, err)
		return
	}
	bus.Respond(m, proto.AppStopAck{OK: status == proto.AppStatusStopped, Status: status, Detail: detail})
}

func handleStatus(b Backend, m *nats.Msg) {
	var cmd proto.AppStatusCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		bus.Respond(m, proto.AppStatusAck{Status: proto.AppStatusUnknown})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, services, err := b.Status(ctx, cmd.AppID)
	if err != nil {
		log.Printf("rasputin-agent: docker.status %s: %v", cmd.AppID, err)
	}
	bus.Respond(m, proto.AppStatusAck{AppID: cmd.AppID, Status: status, Services: services})
}
