package apprelay

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// callBound bounds one call's round trip to the api, as deliverLeaf bounds
// the api's leaf delivery. It only bounds that I/O call: an api that has not
// answered within it is far outside normal bounds, and the app is told so.
const callBound = 15 * time.Second

// Relay carries an app's calls over the bus to the api. It is attached to
// each bus connection the agent makes; until the first, every call is
// answered unavailable.
type Relay struct {
	node  string
	bound time.Duration
	log   *slog.Logger
	mu    sync.Mutex
	nc    *nats.Conn
}

// NewRelay is the relay for node. bound is callBound in production
// (DefaultCallBound); a test passes a short one.
func NewRelay(node string, bound time.Duration, log *slog.Logger) (*Relay, error) {
	switch {
	case node == "":
		return nil, errors.New("apprelay: NewRelay: the node id is empty")
	case bound <= 0:
		return nil, errors.New("apprelay: NewRelay: the call bound is not positive")
	case log == nil:
		return nil, errors.New("apprelay: NewRelay: the logger is nil")
	}
	return &Relay{node: node, bound: bound, log: log}, nil
}

// DefaultCallBound is the bound main gives NewRelay.
const DefaultCallBound = callBound

// Attach makes nc the connection calls go out on. main calls it from the
// subscriber it runs on every bus connection.
func (r *Relay) Attach(nc *nats.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nc = nc
}

func (r *Relay) conn() *nats.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nc
}

// The sentences of the agent's own refusals.
const (
	msgNotConnected = "The node is not connected to the control plane; try again later."
	msgNoAnswer     = "The control plane did not answer; try again later."
)

// Forward publishes call, which the socket stamped with appID, on this node's
// relay subject, asking for the reply on a subject of its own under the
// node's command lane, and returns the api's reply. cid is the correlation
// id the agent's own refusal carries. A call that cannot reach the api, or
// that the api does not answer within the bound, is answered unavailable and
// logged at WARN.
func (r *Relay) Forward(appID string, call proto.AppSecretCall, cid string) proto.AppSecretReply {
	call.AppID = appID
	nc := r.conn()
	if nc == nil {
		return proto.AppSecretReply{Code: proto.AppSecretUnavailable, Message: msgNotConnected, CorrelationID: cid}
	}
	unreachable := func(err error) proto.AppSecretReply {
		r.log.Warn("app relay call did not reach the control plane", "component", "apprelay", "event", "apprelay.call_failed",
			"app_id", appID, "op", call.Op, "name", call.Name, "correlation_id", cid, "err", err.Error())
		return proto.AppSecretReply{Code: proto.AppSecretUnavailable, Message: msgNoAnswer, CorrelationID: cid}
	}
	reply := proto.AppSecretReplyPrefix(r.node) + cid
	sub, err := nc.SubscribeSync(reply)
	if err != nil {
		return unreachable(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	data, err := json.Marshal(call)
	if err != nil {
		return unreachable(err)
	}
	if err := nc.PublishRequest(proto.AppSecretCallSubject(r.node), reply, data); err != nil {
		return unreachable(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.bound)
	defer cancel()
	msg, err := sub.NextMsgWithContext(ctx)
	if err != nil {
		return unreachable(err)
	}
	var rep proto.AppSecretReply
	if err := json.Unmarshal(msg.Data, &rep); err != nil {
		return unreachable(err)
	}
	return rep
}
