package updater

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// RegisterHandlers wires NATS subscriptions for all six update verbs and
// returns the subscriptions. Caller unsubscribes on shutdown.
//
// On every command we ack synchronously. Long-running operations (download,
// install) stream progress on
// rasputin.node.<nodeID>.evt.update.{download,install}.progress.
func RegisterHandlers(nc *nats.Conn, nodeID string, backend Backend) ([]*nats.Subscription, error) {
	subs := make([]*nats.Subscription, 0, 6)

	bind := func(subj string, fn nats.MsgHandler) error {
		s, err := nc.Subscribe(subj, fn)
		if err != nil {
			return err
		}
		subs = append(subs, s)
		log.Printf("rasputin-agent: subscribed to %s", subj)
		return nil
	}

	if err := bind(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ack, err := backend.Precheck(ctx)
		if err != nil {
			respond(m, proto.UpdatePrecheckAck{OK: false, Detail: err.Error()})
			return
		}
		respond(m, ack)
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.UpdateDownloadSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.UpdateDownloadCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			respond(m, proto.UpdateDownloadAck{OK: false, Detail: err.Error()})
			return
		}
		// Long-running: 15-minute upper bound. The api's step timeout is
		// shorter (10m) so the saga will time out first if needed.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		progress := func(done, total int64) {
			ev := proto.UpdateDownloadProgressEvt{
				NodeID:         nodeID,
				BundleID:       cmd.BundleID,
				BytesCompleted: done,
				BytesTotal:     total,
				Ts:             time.Now().UTC(),
			}
			payload, _ := json.Marshal(ev)
			_ = nc.Publish(proto.UpdateDownloadProgressSubject(nodeID), payload)
		}
		localPath, sha, err := backend.Download(ctx, cmd.BundleID, cmd.URL, cmd.ExpectedSHA256, cmd.SizeBytes, progress)
		if err != nil {
			respond(m, proto.UpdateDownloadAck{OK: false, SHA256: sha, Detail: err.Error()})
			return
		}
		respond(m, proto.UpdateDownloadAck{
			OK: true, LocalPath: localPath, SHA256: sha,
		})
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.UpdateInstallSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.UpdateInstallCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			respond(m, proto.UpdateInstallAck{OK: false, Detail: err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		progress := func(phase string, percent int) {
			ev := proto.UpdateInstallProgressEvt{
				NodeID:   nodeID,
				BundleID: cmd.BundleID,
				Phase:    phase,
				Percent:  percent,
				Ts:       time.Now().UTC(),
			}
			payload, _ := json.Marshal(ev)
			_ = nc.Publish(proto.UpdateInstallProgressSubject(nodeID), payload)
		}
		newVer, err := backend.Install(ctx, cmd.BundleID, cmd.LocalPath, cmd.TargetSlot, progress)
		if err != nil {
			respond(m, proto.UpdateInstallAck{OK: false, TargetSlot: cmd.TargetSlot, Detail: err.Error()})
			return
		}
		respond(m, proto.UpdateInstallAck{
			OK: true, TargetSlot: cmd.TargetSlot, NewVersion: newVer,
		})
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.UpdateRebootSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.UpdateRebootCmd
		_ = json.Unmarshal(m.Data, &cmd)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		delay, err := backend.Reboot(ctx, cmd.BundleID, cmd.DelaySeconds)
		if err != nil {
			respond(m, proto.UpdateRebootAck{OK: false})
			return
		}
		respond(m, proto.UpdateRebootAck{OK: true, DelaySeconds: delay})
		// Publish the rebooting event so the saga's sub-before-RPC catches it.
		ev, _ := json.Marshal(proto.SystemRebootingEvt{
			NodeID:       nodeID,
			DelaySeconds: delay,
			Ts:           time.Now().UTC(),
		})
		_ = nc.Publish(proto.NodeEvtSubject(nodeID, "rebooting"), ev)
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.UpdateMarkGoodSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.UpdateMarkGoodCmd
		_ = json.Unmarshal(m.Data, &cmd)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := backend.MarkGood(ctx, cmd.BundleID); err != nil {
			respond(m, proto.UpdateMarkGoodAck{OK: false, Detail: err.Error()})
			return
		}
		respond(m, proto.UpdateMarkGoodAck{OK: true})
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.UpdateMarkBadSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.UpdateMarkBadCmd
		_ = json.Unmarshal(m.Data, &cmd)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := backend.MarkBad(ctx, cmd.BundleID, cmd.Reason); err != nil {
			respond(m, proto.UpdateMarkBadAck{OK: false, Detail: err.Error()})
			return
		}
		respond(m, proto.UpdateMarkBadAck{OK: true})
	}); err != nil {
		return subs, err
	}

	return subs, nil
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
