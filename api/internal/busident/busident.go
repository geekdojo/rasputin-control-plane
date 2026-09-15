// Package busident binds a node event to the node that published it.
//
// The bus scopes each node's credential to the subjects under
// "rasputin.node.<its-id>.>", so the node token in a message's SUBJECT is the
// authenticated identity of the publisher. The payload's nodeId field is just
// data the publisher chose. Every api consumer of a node-published event must
// therefore take the node id from the subject, and must not act on a payload
// that names a different node.
//
// The decode helpers here are pure (subject + bytes in, event or error out) so
// they are unit- and fuzz-testable without a bus.
package busident

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

var (
	// ErrBadSubject means the subject is not "rasputin.node.<id>.<rest>" with a
	// valid node id token.
	ErrBadSubject = errors.New("not a node subject")
	// ErrNodeIDMismatch means the payload carries a non-empty nodeId that
	// differs from the node id in the subject. Such a message is dropped, not
	// rewritten.
	ErrNodeIDMismatch = errors.New("payload node id does not match subject")
)

// NodeIDFromSubject extracts the node id from "rasputin.node.<id>.<rest>". The
// id must be a valid node id (a lowercase RFC 1123 DNS label, the rule the bus
// enforces when it mints a node credential); anything else is refused.
func NodeIDFromSubject(subject string) (string, bool) {
	parts := strings.SplitN(subject, ".", 4)
	if len(parts) < 4 || parts[0] != "rasputin" || parts[1] != "node" || parts[3] == "" {
		return "", false
	}
	if !tileschema.ValidDNSLabel(parts[2]) {
		return "", false
	}
	return parts[2], true
}

// subjectNodeID returns the node id of a subject that must be exactly
// want(id), or ErrBadSubject.
func subjectNodeID(subject string, want func(id string) bool) (string, error) {
	id, ok := NodeIDFromSubject(subject)
	if !ok || !want(id) {
		return "", fmt.Errorf("%w: %q", ErrBadSubject, subject)
	}
	return id, nil
}

// bind checks the payload's claimed id against the subject's id.
func bind(id, payloadNodeID string) error {
	if payloadNodeID != "" && payloadNodeID != id {
		return fmt.Errorf("%w: subject %q, payload %q", ErrNodeIDMismatch, id, payloadNodeID)
	}
	return nil
}

// DecodeRegistered decodes a message that must be on exactly
// rasputin.node.<id>.evt.registered, with its NodeID bound to the subject.
func DecodeRegistered(subject string, data []byte) (proto.NodeRegisteredEvt, error) {
	id, err := subjectNodeID(subject, func(id string) bool { return subject == proto.NodeRegisteredSubject(id) })
	if err != nil {
		return proto.NodeRegisteredEvt{}, err
	}
	var ev proto.NodeRegisteredEvt
	if err := json.Unmarshal(data, &ev); err != nil {
		return proto.NodeRegisteredEvt{}, fmt.Errorf("decode registered: %w", err)
	}
	if err := bind(id, ev.NodeID); err != nil {
		return proto.NodeRegisteredEvt{}, err
	}
	ev.NodeID = id
	return ev, nil
}

// DecodeIDSAlert decodes a message that must be on
// rasputin.node.<id>.evt.ids.<event>, with its NodeID bound to the subject.
func DecodeIDSAlert(subject string, data []byte) (proto.IDSAlertEvt, error) {
	id, err := subjectNodeID(subject, func(id string) bool {
		prefix := proto.NodeEvtSubject(id, "ids.")
		return strings.HasPrefix(subject, prefix) && len(subject) > len(prefix)
	})
	if err != nil {
		return proto.IDSAlertEvt{}, err
	}
	var ev proto.IDSAlertEvt
	if err := json.Unmarshal(data, &ev); err != nil {
		return proto.IDSAlertEvt{}, fmt.Errorf("decode ids alert: %w", err)
	}
	if err := bind(id, ev.NodeID); err != nil {
		return proto.IDSAlertEvt{}, err
	}
	ev.NodeID = id
	return ev, nil
}

// DecodeMetrics decodes a message that must be on exactly
// rasputin.node.<id>.metrics, with its NodeID bound to the subject.
func DecodeMetrics(subject string, data []byte) (proto.MetricsEvt, error) {
	id, err := subjectNodeID(subject, func(id string) bool { return subject == proto.NodeMetricsSubject(id) })
	if err != nil {
		return proto.MetricsEvt{}, err
	}
	var ev proto.MetricsEvt
	if err := json.Unmarshal(data, &ev); err != nil {
		return proto.MetricsEvt{}, fmt.Errorf("decode metrics: %w", err)
	}
	if err := bind(id, ev.NodeID); err != nil {
		return proto.MetricsEvt{}, err
	}
	ev.NodeID = id
	return ev, nil
}
