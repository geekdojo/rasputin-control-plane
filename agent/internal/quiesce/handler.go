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

// RegisterHandlers wires the staging verbs — stage, transfer, unstage — and
// the restore verb, and returns the subscriptions.
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
	subs := make([]*nats.Subscription, 0, 4)
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

	if err := bind(proto.BackupTransferSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.BackupTransferCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			bus.Respond(m, proto.BackupTransferAck{
				OK: false, Refusal: proto.StorageRefusalBackendError, Detail: err.Error(),
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), proto.BackupTransferWork)
		defer cancel()
		// The credential is NOT in this line, or any line. The destination
		// is: an operator debugging an upload needs to know where it went.
		log.Printf("rasputin-agent: transfer: SEAL+UPLOAD app=%s name=%q volume=%s staging=%s member=%s generation=%s destination=%s",
			cmd.AppID, cmd.AppName, cmd.Volume, cmd.StagingName, cmd.Member, cmd.GenerationID, cmd.Destination)
		ack := s.Transfer(ctx, cmd)
		if ack.OK {
			log.Printf("rasputin-agent: transfer: landed %s as %s (%d sealed bytes, sha256 %s)",
				cmd.StagingName, cmd.Member, ack.SealedBytes, ack.SealedDigest)
		} else {
			log.Printf("rasputin-agent: transfer: %s NOT landed refusal=%s destination-code=%s: %s",
				cmd.StagingName, ack.Refusal, ack.DestinationCode, ack.Detail)
		}
		bus.Respond(m, ack)
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.BackupRestoreVolumeSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.BackupRestoreVolumeCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			bus.Respond(m, proto.BackupRestoreVolumeAck{
				OK: false, AppRestored: true, Refusal: proto.StorageRefusalBackendError, Detail: err.Error(),
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), proto.BackupRestoreVolumeWork)
		defer cancel()
		// Loud and BEFORE the call, like the stage verb: this is the verb
		// that REPLACES an app's data. Identifiers, the member and the
		// source — the credential is NOT in this line, or any line.
		log.Printf("rasputin-agent: restore: RESTORE VOLUME (service-interrupting, REPLACES DATA) app=%s name=%q volume=%s class=%s generation=%s member=%s restore=%s source=%s backend=%s",
			cmd.AppID, cmd.AppName, cmd.Volume, cmd.Class, cmd.GenerationID, cmd.Member, cmd.RestoreID, cmd.Source, s.rt.Name())
		ack := s.RestoreVolume(ctx, cmd)
		switch {
		case !ack.OK:
			log.Printf("rasputin-agent: restore: REFUSED app=%s volume=%s refusal=%s source-code=%s restored=%t: %s",
				cmd.AppID, cmd.Volume, ack.Refusal, ack.SourceCode, ack.AppRestored, ack.Detail)
		case ack.Stopped:
			log.Printf("rasputin-agent: restore: replaced %s of app %s from %s (%d files, %d bytes; previous contents kept at %s); app was down %dms, restored=%t by %s",
				cmd.Volume, cmd.AppID, cmd.Member, ack.FileCount, ack.UnpackedBytes, ack.PreviousKept, ack.DowntimeMillis, ack.AppRestored, ack.RestoredBy)
		default:
			log.Printf("rasputin-agent: restore: replaced %s of app %s from %s (%d files, %d bytes; previous contents kept at %s); the app was not running and was not started",
				cmd.Volume, cmd.AppID, cmd.Member, ack.FileCount, ack.UnpackedBytes, ack.PreviousKept)
		}
		if !ack.AppRestored {
			log.Printf("rasputin-agent: restore: APP %s IS NOT BACK after restoring %s: %s", cmd.AppID, cmd.Volume, ack.RestoreDetail)
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
