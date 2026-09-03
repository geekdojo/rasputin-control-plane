package quiesce

import (
	"context"
	"encoding/json"
	"log"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"github.com/nats-io/nats.go"
)

// RegisterHandlers wires the two staging verbs and returns the subscriptions.
// Registered wherever the docker handlers are — compute and controlplane
// agents — because those are the nodes that host app volumes; the
// backup-target storage verbs live on the controlplane and storage roles and
// are a different concern.
//
// Every handler acks synchronously, on the same connection, with the same
// reply-grant budget the other backup verbs use. There are no progress
// events: an operator cannot act on "60% copied", and the one thing they
// could act on — the app is down — is over before the ack goes out or is
// reported in it.
func RegisterHandlers(nc *nats.Conn, nodeID string, s *Stager) ([]*nats.Subscription, error) {
	subs := make([]*nats.Subscription, 0, 2)
	bind := func(subj string, fn nats.MsgHandler) error {
		sub, err := nc.Subscribe(subj, fn)
		if err != nil {
			return err
		}
		subs = append(subs, sub)
		log.Printf("rasputin-agent: subscribed to %s", subj)
		return nil
	}

	if err := bind(proto.BackupStageVolumeSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.BackupStageVolumeCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			bus.Respond(m, proto.BackupStageVolumeAck{
				OK: false, AppRestored: true, Refusal: proto.StorageRefusalBackendError, Detail: err.Error(),
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), proto.BackupStageWork)
		defer cancel()

		// Loud and BEFORE the call, like every other service-affecting verb
		// in this agent: if an app is ever found stopped, this line is the
		// evidence of what asked for it. Nothing sensitive — ids, a volume
		// name and a strategy.
		if cmd.Quiesce == tileschema.QuiesceStop {
			log.Printf("rasputin-agent: quiesce: STAGE (service-interrupting) app=%s name=%q volume=%s class=%s strategy=%s staging=%s backend=%s",
				cmd.AppID, cmd.AppName, cmd.Volume, cmd.Class, cmd.Quiesce, cmd.StagingName, s.rt.Name())
		} else {
			log.Printf("rasputin-agent: quiesce: STAGE app=%s name=%q volume=%s class=%s strategy=%s staging=%s backend=%s",
				cmd.AppID, cmd.AppName, cmd.Volume, cmd.Class, cmd.Quiesce, cmd.StagingName, s.rt.Name())
		}

		ack := s.Stage(ctx, cmd)
		switch {
		case !ack.OK:
			log.Printf("rasputin-agent: quiesce: stage REFUSED app=%s volume=%s refusal=%s restored=%t: %s",
				cmd.AppID, cmd.Volume, ack.Refusal, ack.AppRestored, ack.Detail)
		case ack.Stopped:
			log.Printf("rasputin-agent: quiesce: staged %s (%d bytes, %d files) as %s; app %s was down %dms, restored=%t by %s",
				cmd.Volume, ack.SizeBytes, ack.FileCount, ack.StagedPath, cmd.AppID, ack.DowntimeMillis, ack.AppRestored, ack.RestoredBy)
		default:
			log.Printf("rasputin-agent: quiesce: staged %s (%d bytes, %d files, %s) as %s",
				cmd.Volume, ack.SizeBytes, ack.FileCount, ack.Consistency, ack.StagedPath)
		}
		if !ack.AppRestored {
			log.Printf("rasputin-agent: quiesce: APP %s IS NOT BACK after staging %s: %s", cmd.AppID, cmd.Volume, ack.RestoreDetail)
		}
		bus.Respond(m, ack)
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.BackupUnstageSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.BackupUnstageCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			bus.Respond(m, proto.BackupUnstageAck{
				OK: false, Refusal: proto.StorageRefusalBackendError, Detail: err.Error(),
			})
			return
		}
		ack := s.Unstage(cmd)
		if ack.OK && ack.Existed {
			log.Printf("rasputin-agent: quiesce: unstaged %s (%d bytes)", cmd.StagingName, ack.FreedBytes)
		}
		bus.Respond(m, ack)
	}); err != nil {
		return subs, err
	}

	return subs, nil
}
