package storage

import (
	"context"
	"encoding/json"
	"log"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// RegisterHandlers wires NATS subscriptions for the four storage verbs and
// returns the subscriptions. Caller unsubscribes on shutdown.
//
// Every handler acks synchronously. There are no progress events: enumerate and
// inspect are quick, and a claim's phases are not something an operator can act
// on halfway through — the useful reporting boundary is the saga step, which the
// api already renders.
//
// Note what is NOT here. There is no "unclaim", no "reformat", and no verb that
// takes a device path other than Claim. Adding one is adding a second way to
// destroy a disk, and it would need its own copy of both guards.
func RegisterHandlers(nc *nats.Conn, nodeID string, backend Backend) ([]*nats.Subscription, error) {
	subs := make([]*nats.Subscription, 0, 4)

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
		// an operator's label. §4.6's data key never comes near this handler.
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
		bus.Respond(m, ack)
	}); err != nil {
		return subs, err
	}

	return subs, nil
}
