package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// rpcSlack is the headroom the api allows on top of an agent work budget. The
// budget is what the AGENT may spend before it answers; the api must outwait it
// by the round trip plus the marshal, or it gives up on a handler that is about
// to reply correctly.
const rpcSlack = 15 * proto.StorageEnumerateWork / 100 // 15%

// Enumerate asks a node for its candidate disks. Read-only: it mutates
// nothing, on the agent or here.
//
// Two callers, both wanted and both correct:
//
//   - the UI picker, from an HTTP handler, before any job exists (the operator
//     cannot choose a disk from a list that only a running job could produce);
//   - step 2 of the claim saga, as the re-verify.
//
// The duplication is the point. The picker's answer is what the operator
// confirmed; step 2's answer is what is true now. Comparing the two is how the
// TOCTOU window between confirmation and mkfs gets closed.
func Enumerate(ctx context.Context, nc *nats.Conn, nodeID string) (*proto.StorageEnumerateAck, error) {
	if nc == nil {
		return nil, errors.New("no bus connection")
	}
	if nodeID == "" {
		return nil, errors.New("nodeId is required")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, proto.StorageEnumerateWork+rpcSlack)
		defer cancel()
	}
	cmd, err := json.Marshal(proto.StorageEnumerateCmd{})
	if err != nil {
		return nil, err
	}
	msg, err := nc.RequestWithContext(ctx, proto.StorageEnumerateSubject(nodeID), cmd)
	if err != nil {
		return nil, fmt.Errorf("storage enumerate rpc to %s: %w", nodeID, err)
	}
	var ack proto.StorageEnumerateAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return nil, fmt.Errorf("storage enumerate: unreadable reply from %s: %w", nodeID, err)
	}
	if !ack.OK {
		return &ack, refusalError("enumerate", ack.Refusal, ack.Detail)
	}
	return &ack, nil
}

// refusalError renders an agent refusal as an error an operator can act on. The
// machine-readable code is kept in the message rather than dropped: the UI
// branches on it, and "protected" and "device-absent" want different prompts.
func refusalError(verb string, refusal proto.StorageRefusal, detail string) error {
	if refusal == "" {
		refusal = proto.StorageRefusalBackendError
	}
	if detail == "" {
		detail = "no detail given"
	}
	return fmt.Errorf("%s refused [%s]: %s", verb, refusal, detail)
}

// findCandidate resolves the disk the operator confirmed out of a fresh
// enumeration, BY FINGERPRINT — never by device path.
//
// That direction is the whole of §4.8. The operator's consent is bound to a
// fingerprint (WWN/serial + size + partition-table hash); a device path is what
// the kernel happened to call that disk at the moment they looked. A disk that
// moved from /dev/sda to /dev/sdb between the picker and the confirmation is
// still the disk they chose, and a DIFFERENT disk that took over the old path is
// emphatically not.
//
// So a match is a fingerprint match, and the current device path comes FROM the
// match rather than being trusted into it.
func findCandidate(ack *proto.StorageEnumerateAck, spec *ClaimSpec) (*proto.StorageCandidate, error) {
	var matches []*proto.StorageCandidate
	var atPath *proto.StorageCandidate
	for i := range ack.Candidates {
		c := &ack.Candidates[i]
		if c.Fingerprint != "" && c.Fingerprint == spec.Fingerprint {
			matches = append(matches, c)
		}
		if c.DevicePath == spec.DevicePath {
			atPath = c
		}
	}

	switch {
	case len(matches) == 1:
		return matches[0], nil

	case len(matches) > 1:
		// Two candidates fingerprinting the same is precisely the collision the
		// fingerprint exists to catch — two identical blank USB sticks behind
		// cheap bridges that report neither WWN nor serial (proto's
		// IdentityWeak). There is no safe way to guess which one the operator
		// meant, so nothing is formatted.
		paths := make([]string, 0, len(matches))
		weak := false
		for _, m := range matches {
			paths = append(paths, m.DevicePath)
			weak = weak || m.IdentityWeak
		}
		hint := ""
		if weak {
			hint = " (the disks report neither WWN nor serial, so their fingerprints rest on model + size + partition table alone)"
		}
		return nil, fmt.Errorf("refusing to claim [%s]: %d attached disks carry the confirmed fingerprint — %v%s. Detach all but the one you mean and choose it again",
			proto.StorageRefusalFingerprintMismatch, len(matches), paths, hint)

	case atPath != nil:
		// A disk IS at the confirmed path, and it is not the confirmed disk.
		// This is the exact case the fingerprint exists for: proceeding here
		// formats a stranger.
		return nil, fmt.Errorf("refusing to claim [%s]: the disk now at %s is not the one confirmed (model %q, serial %q) — its partition table changed, or a different disk took the path. Re-run the picker and confirm again",
			proto.StorageRefusalFingerprintMismatch, spec.DevicePath, atPath.Model, atPath.Serial)

	default:
		return nil, fmt.Errorf("refusing to claim [%s]: no attached disk carries the confirmed fingerprint, and nothing is at %s — the disk was unplugged between the picker and now",
			proto.StorageRefusalDeviceAbsent, spec.DevicePath)
	}
}
