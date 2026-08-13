package updater

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/host"
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
	return RegisterHandlersWithFault(nc, nodeID, backend, FaultConfig{})
}

// RegisterHandlersWithFault is RegisterHandlers plus update-path fault
// injection (see fault.go). cfg is the zero FaultConfig in every non-bench
// path; it carries both the armed fault and the one directory its marker
// lives in, so this site cannot disagree with the startup site about where
// that is.
func RegisterHandlersWithFault(nc *nats.Conn, nodeID string, backend Backend, cfg FaultConfig) ([]*nats.Subscription, error) {
	fault := cfg.Fault
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
			bus.Respond(m, proto.UpdatePrecheckAck{OK: false, BootID: host.BootID(), Detail: err.Error()})
			return
		}
		// Boot identity is stamped here rather than inside each backend: a
		// Backend describes SLOT reality (rauc / openwrt-ab / mock), and which
		// boot is answering is a host fact that is identical for all three.
		// One place to stamp means a new backend cannot silently omit it.
		// ADR-0005 Decision 1.
		ack.BootID = host.BootID()
		// Same argument for the running version, and here it is not a nicety.
		//
		// RAUCBackend sources CurrentVersion from RAUC_SLOT_STATUS_N_BUNDLE_VERSION,
		// which the RAUC on our image NEVER emits: /etc/rauc/system.conf sets
		// neither data-directory nor statusfile, so RAUC falls back to per-slot
		// status and says "System status information not supported!". Bench-
		// confirmed on e3bench 2026-08-12 — the real `rauc status
		// --output-format=shell` output contains no version field at all. So
		// every Buildroot OS node reported an EMPTY CurrentVersion, which made
		// the verify path blind and inverted the inventory write-back: a
		// successful update took the no-version-in-hand branch and left the node
		// UNCONFIRMED, so the update check reported needs-attention forever.
		//
		// The running rootfs IS the booted slot, so /etc/rasputin/image-version
		// is the authoritative answer and the agent already reads it for
		// registration. Fall back to it whenever the backend has nothing —
		// never override a backend that does know, since a slot-aware value is
		// strictly better evidence than a file on the mounted rootfs.
		if ack.CurrentVersion == "" {
			ack.CurrentVersion = host.ImageVersion()
		}
		bus.Respond(m, ack)
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.UpdateDownloadSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.UpdateDownloadCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			bus.Respond(m, proto.UpdateDownloadAck{OK: false, Detail: err.Error()})
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
			bus.Respond(m, proto.UpdateDownloadAck{OK: false, SHA256: sha, Detail: err.Error()})
			return
		}
		bus.Respond(m, proto.UpdateDownloadAck{
			OK: true, LocalPath: localPath, SHA256: sha,
		})
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.UpdateInstallSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.UpdateInstallCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			bus.Respond(m, proto.UpdateInstallAck{OK: false, Detail: err.Error()})
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
			bus.Respond(m, proto.UpdateInstallAck{OK: false, TargetSlot: cmd.TargetSlot, Detail: err.Error()})
			return
		}
		bus.Respond(m, proto.UpdateInstallAck{
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

		// FaultNoReboot: ack and announce exactly as a healthy node does, then
		// simply do not reboot. From the api's side this is indistinguishable
		// from a node whose reboot silently failed — bench node c13 — and it is
		// the only way to reach the terminal bootSame verdict.
		if fault == FaultNoReboot {
			log.Printf("rasputin-agent: ⚠️  FAULT %s: acking the reboot and NOT rebooting", FaultNoReboot)
			bus.Respond(m, proto.UpdateRebootAck{OK: true, DelaySeconds: cmd.DelaySeconds})
			ev, _ := json.Marshal(proto.SystemRebootingEvt{
				NodeID:       nodeID,
				DelaySeconds: cmd.DelaySeconds,
				Ts:           time.Now().UTC(),
			})
			_ = nc.Publish(proto.NodeEvtSubject(nodeID, "rebooting"), ev)
			return
		}

		// FaultDieAfterReboot: reboot for real, but arm the marker FIRST so the
		// agent on the far side comes up mute. Arming before the reboot is the
		// whole trick — after it, this process is gone. A marker we could not
		// write is reported and the reboot proceeds normally, so the test fails
		// loudly rather than quietly passing as a healthy update.
		if fault == FaultDieAfterReboot {
			if err := cfg.ArmMuteAfterReboot(); err != nil {
				log.Printf("rasputin-agent: ⚠️  FAULT %s: could not arm marker: %v — rebooting NORMALLY, the fault will NOT fire", FaultDieAfterReboot, err)
			} else {
				log.Printf("rasputin-agent: ⚠️  FAULT %s: armed; this node will come back MUTE", FaultDieAfterReboot)
			}
		}

		delay, err := backend.Reboot(ctx, cmd.BundleID, cmd.DelaySeconds)
		if err != nil {
			bus.Respond(m, proto.UpdateRebootAck{OK: false})
			return
		}
		bus.Respond(m, proto.UpdateRebootAck{OK: true, DelaySeconds: delay})
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
			bus.Respond(m, proto.UpdateMarkGoodAck{OK: false, Detail: err.Error()})
			return
		}
		bus.Respond(m, proto.UpdateMarkGoodAck{OK: true})
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.UpdateMarkBadSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.UpdateMarkBadCmd
		_ = json.Unmarshal(m.Data, &cmd)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := backend.MarkBad(ctx, cmd.BundleID, cmd.Reason); err != nil {
			bus.Respond(m, proto.UpdateMarkBadAck{OK: false, Detail: err.Error()})
			return
		}
		bus.Respond(m, proto.UpdateMarkBadAck{OK: true})
	}); err != nil {
		return subs, err
	}

	return subs, nil
}
