package storage

import (
	"context"
	"encoding/json"
	"log"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// RegisterHandlers wires NATS subscriptions for the storage verbs and returns
// the subscriptions. Caller unsubscribes on shutdown.
//
// Four target-selection verbs (§4.8) and three backup-run verbs (§4.1). Every
// handler acks synchronously. There are no progress events: enumerate and
// inspect are quick, and a claim's phases are not something an operator can act
// on halfway through — the useful reporting boundary is the saga step, which the
// api already renders. The same holds for a backup write: an operator cannot act
// on "60% copied".
//
// Note what is NOT here. There is no "unclaim", no "reformat", and no verb that
// takes a device path other than Claim. There is no verb that READS an archive
// back, either — this node holds no §4.6 private key, so there is nothing it
// could do with one. Adding any of them is adding a way to destroy or exfiltrate
// a disk, and each would need its own copy of the guards.
//
// stagingRoot is where BackupWrite reads staged archives from; a caller that
// passes "" disables the write verb rather than defaulting it, because a
// default staging root is a default answer to "which files may this verb read".
// It is also what preflight reports back, so the api stages into the directory
// this node will actually read rather than into one it derived for itself —
// see StagingRoot for the failure that came of deriving it twice.
func RegisterHandlers(nc *nats.Conn, nodeID string, backend Backend, stagingRoot string) ([]*nats.Subscription, error) {
	subs := make([]*nats.Subscription, 0, 7)

	bind := func(subj string, fn nats.MsgHandler) error {
		s, err := nc.Subscribe(subj, fn)
		if err != nil {
			return err
		}
		subs = append(subs, s)
		log.Printf("rasputin-agent: subscribed to %s", subj)
		return nil
	}

	if err := bind(proto.StorageEnumerateSubject(nodeID), func(m *nats.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), proto.StorageEnumerateWork)
		defer cancel()
		ack, err := backend.Enumerate(ctx)
		if err != nil {
			bus.Respond(m, proto.StorageEnumerateAck{
				OK:      false,
				Backend: backend.Name(),
				Refusal: refusalFor(err),
				Detail:  err.Error(),
			})
			return
		}
		ack.Backend = backend.Name()
		bus.Respond(m, ack)
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.StorageClaimSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.StorageClaimCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			// An unparseable claim is refused rather than defaulted. A
			// zero-valued StorageClaimCmd has an empty device path and an empty
			// fingerprint, and while both would be refused downstream, the
			// place to stop a malformed destructive command is here.
			bus.Respond(m, proto.StorageClaimAck{
				OK: false, Refusal: proto.StorageRefusalBackendError, Detail: err.Error(),
			})
			return
		}
		// The budget is a proto constant because the bus reply grant is derived
		// from it — a budget the grant does not outlive is a reply the agent is
		// not allowed to send (proto.BusReplyGrantTTL).
		ctx, cancel := context.WithTimeout(context.Background(), proto.StorageClaimWork)
		defer cancel()

		// Deliberately loud, and deliberately BEFORE the call. This is the only
		// agent verb that can destroy the cluster it runs on; if a node is ever
		// found with an unexpectedly blank disk, this line is the evidence of
		// what asked for it. Nothing sensitive: a device path, a fingerprint and
		// an operator's label. §4.6's private key never comes near this handler.
		log.Printf("rasputin-agent: storage: CLAIM (destructive) device=%s fingerprint=%s label=%q backend=%s",
			cmd.DevicePath, short(cmd.Fingerprint), cmd.Label, backend.Name())

		ack, err := backend.Claim(ctx, cmd)
		if err != nil {
			log.Printf("rasputin-agent: storage: claim REFUSED device=%s: %v", cmd.DevicePath, err)
			bus.Respond(m, proto.StorageClaimAck{
				OK:         false,
				DevicePath: cmd.DevicePath,
				Refusal:    refusalFor(err),
				Detail:     err.Error(),
			})
			return
		}
		// The cluster id, the key id and the two wrapped key blobs are now
		// stamped by the BACKEND, into the marker file on the platter, because
		// that is where they have to be for the disk to be self-describing.
		// This handler used to set them on the ack afterwards, which decorated
		// the reply and left the disk carrying neither — see markerFrom. The
		// agent still invents none of them: it records what the api told it,
		// and none of it is key material in the clear.
		log.Printf("rasputin-agent: storage: claimed device=%s partuuid=%s mount=%s",
			ack.DevicePath, ack.PartUUID, ack.MountPath)
		bus.Respond(m, ack)
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.StorageMountSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.StorageMountCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			bus.Respond(m, proto.StorageMountAck{
				OK: false, Refusal: proto.StorageRefusalBackendError, Detail: err.Error(),
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), proto.StorageMountWork)
		defer cancel()
		path, err := backend.Mount(ctx, cmd.PartUUID)
		if err != nil {
			bus.Respond(m, proto.StorageMountAck{
				OK: false, PartUUID: cmd.PartUUID, Refusal: refusalFor(err), Detail: err.Error(),
			})
			return
		}
		bus.Respond(m, proto.StorageMountAck{OK: true, PartUUID: cmd.PartUUID, MountPath: path})
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.StorageInspectSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.StorageInspectCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			bus.Respond(m, proto.StorageInspectAck{
				OK: false, Refusal: proto.StorageRefusalBackendError, Detail: err.Error(),
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), proto.StorageInspectWork)
		defer cancel()
		ack, err := backend.Inspect(ctx, cmd.PartUUID)
		if err != nil {
			bus.Respond(m, proto.StorageInspectAck{
				OK: false, PartUUID: cmd.PartUUID, Refusal: refusalFor(err), Detail: err.Error(),
			})
			return
		}
		// The write probe (#398), only when asked for and only on a target
		// that is present and mounted: a probe of nothing would report the
		// absence twice. Presence is not health — the e3bench stick listed
		// fine while refusing writes — and this is the half of the check
		// that can tell.
		if cmd.Probe && ack.OK && ack.Present && ack.MountPath != "" {
			ack.WriteProbe = WriteProbe(ctx, ack.MountPath)
			if !ack.WriteProbe.OK {
				log.Printf("rasputin-agent: storage: write probe FAILED partuuid=%s mount=%s: %s",
					cmd.PartUUID, ack.MountPath, ack.WriteProbe.Detail)
			}
		}
		bus.Respond(m, ack)
	}); err != nil {
		return subs, err
	}

	// ----- the backup-run verbs (§4.1) -----------------------------------
	//
	// Preflight and prune are cheap and idempotent. Write is neither, and the
	// api declares its saga step Irreversible around it — see archive.go for
	// what that step is protecting and why prune deliberately is not.

	if err := bind(proto.BackupPreflightSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.BackupPreflightCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			bus.Respond(m, proto.BackupPreflightAck{
				OK: false, Refusal: proto.StorageRefusalBackendError, Detail: err.Error(),
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), proto.BackupPreflightWork)
		defer cancel()
		// stagingRoot goes out with the answer: the api has to know where to
		// stage before it seals, and this is the step that runs before it does.
		ack, err := BackupPreflight(ctx, backend, stagingRoot, cmd)
		if err != nil {
			bus.Respond(m, proto.BackupPreflightAck{
				OK: false, PartUUID: cmd.PartUUID, Refusal: refusalFor(err), Detail: err.Error(),
			})
			return
		}
		bus.Respond(m, ack)
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.BackupWriteSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.BackupWriteCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			bus.Respond(m, proto.BackupWriteAck{
				OK: false, Refusal: proto.StorageRefusalBackendError, Detail: err.Error(),
			})
			return
		}
		if stagingRoot == "" {
			// Not a default. A verb that reads a file off this node's disk and
			// copies it onto a removable one is not something to enable by
			// falling back to a guessed directory.
			bus.Respond(m, proto.BackupWriteAck{
				OK: false, PartUUID: cmd.PartUUID, Refusal: proto.BackupRefusalStagingMissing,
				Detail: "this agent has no backup staging root configured, so it can accept no archive",
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), proto.BackupWriteWork)
		defer cancel()

		// Loud and BEFORE the call, like the claim handler above: this is the
		// verb that puts a cluster's secrets onto a disk somebody can unplug.
		// Nothing sensitive in the line — a partition UUID, a generation id
		// that says its own scope, and a digest over ciphertext.
		log.Printf("rasputin-agent: storage: BACKUP WRITE partuuid=%s generation=%s digest=%s bytes=%d",
			cmd.PartUUID, cmd.GenerationID, short(cmd.Digest), cmd.SizeBytes)

		ack, err := BackupWrite(ctx, backend, stagingRoot, cmd)
		if err != nil {
			log.Printf("rasputin-agent: storage: backup write REFUSED generation=%s: %v", cmd.GenerationID, err)
			bus.Respond(m, proto.BackupWriteAck{
				OK: false, PartUUID: cmd.PartUUID, Refusal: refusalFor(err), Detail: err.Error(),
			})
			return
		}
		log.Printf("rasputin-agent: storage: wrote generation %s (%d bytes) to %s",
			ack.Generation.ID, ack.Generation.SizeBytes, ack.Generation.ArchivePath)
		bus.Respond(m, ack)
	}); err != nil {
		return subs, err
	}

	if err := bind(proto.BackupPruneSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.BackupPruneCmd
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			bus.Respond(m, proto.BackupPruneAck{
				OK: false, Refusal: proto.StorageRefusalBackendError, Detail: err.Error(),
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), proto.BackupPruneWork)
		defer cancel()
		ack, err := BackupPrune(ctx, backend, cmd)
		if err != nil {
			bus.Respond(m, proto.BackupPruneAck{
				OK: false, PartUUID: cmd.PartUUID, Refusal: refusalFor(err), Detail: err.Error(),
			})
			return
		}
		if len(ack.Pruned) > 0 {
			// Retention deletes archives. It is convergent and safe to repeat,
			// which is exactly why it must still leave a record of what it
			// removed on the node that removed it.
			log.Printf("rasputin-agent: storage: pruned %d generation(s) on %s, kept %d: %v",
				len(ack.Pruned), cmd.PartUUID, len(ack.Kept), ack.Pruned)
		}
		bus.Respond(m, ack)
	}); err != nil {
		return subs, err
	}

	return subs, nil
}
