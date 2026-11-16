package apprelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// Caller is the business service the handler calls. *Service satisfies it.
type Caller interface {
	Do(ctx context.Context, c Call) (secret.Value, error)
}

// Publisher publishes a reply. *nats.Conn satisfies it.
type Publisher interface {
	Publish(subj string, data []byte) error
}

// HandlerDeps is everything a Handler needs. IDs returns a fresh
// correlation id; main passes crypto/rand's Text, as the HTTP server's.
type HandlerDeps struct {
	Service Caller
	Log     *slog.Logger
	IDs     func() string
}

// Handler is the bus endpoint for an app's calls (SEC-INPUT, ERR-BOUNDARY).
type Handler struct {
	d HandlerDeps
}

// NewHandler refuses a HandlerDeps with a nil field.
func NewHandler(d HandlerDeps) (*Handler, error) {
	switch {
	case d.Service == nil:
		return nil, errors.New("apprelay: NewHandler: HandlerDeps.Service is nil")
	case d.Log == nil:
		return nil, errors.New("apprelay: NewHandler: HandlerDeps.Log is nil")
	case d.IDs == nil:
		return nil, errors.New("apprelay: NewHandler: HandlerDeps.IDs is nil")
	}
	return &Handler{d: d}, nil
}

// Subscribe subscribes the handler to every node's app calls on nc, the
// api's own connection, and answers on nc. main calls it before agents are
// admitted to the bus (geekdojo/geekdojo-brain#623).
func (h *Handler) Subscribe(nc *nats.Conn) (*nats.Subscription, error) {
	sub, err := nc.Subscribe(proto.AppSecretCallFilter, func(m *nats.Msg) {
		h.Handle(context.Background(), nc, m.Subject, m.Reply, m.Data)
	})
	if err != nil {
		return nil, fmt.Errorf("apprelay: subscribe %s: %w", proto.AppSecretCallFilter, err)
	}
	return sub, nil
}

// The safe sentences each code carries. None names the value or store text.
const (
	msgNotFound    = "The secret does not exist."
	msgExists      = "The secret already exists; replace it instead."
	msgConflict    = "The secret changed while it was being replaced; read it and try again."
	msgForbidden   = "The call was refused: an app may reach only its own runtime secrets, from the node it runs on."
	msgUnavailable = "The secret store could not complete the call; try again later."
)

// okMessage is the sentence a successful op's reply carries.
var okMessage = map[string]string{
	proto.AppSecretRead:    "The secret was read.",
	proto.AppSecretCreate:  "The secret was created.",
	proto.AppSecretReplace: "The secret was replaced.",
	proto.AppSecretDelete:  "The secret was deleted.",
}

// Handle answers one call that arrived on subject, asking for a reply on
// reply. The node is the one the subject names, which the broker lets only
// that node publish; a node the body names is never read. A reply subject
// outside that node's own reply prefix is refused and nothing is published,
// so no node can point the api's answer at another node's lane.
func (h *Handler) Handle(ctx context.Context, pub Publisher, subject, reply string, data []byte) {
	node, ok := proto.AppSecretCallNode(subject)
	if !ok || !validReply(node, reply) {
		h.d.Log.LogAttrs(ctx, slog.LevelWarn, "app relay call dropped: its reply subject is not the calling node's",
			slog.String("component", "apprelay"),
			slog.String("event", "apprelay.reply_refused"),
			slog.String("subject", subject),
			slog.String("reply", reply))
		return
	}
	cid := h.d.IDs()
	call, why := parseCall(node, data)
	defer call.Value.Destroy()
	if why != "" {
		h.refused(ctx, call, cid, "invalid: "+why)
		h.reply(ctx, pub, reply, proto.AppSecretReply{Code: proto.AppSecretInvalid,
			Message: "The call is not valid: " + why + ".", CorrelationID: cid})
		return
	}
	value, err := h.d.Service.Do(ctx, call)
	defer value.Destroy()
	if err != nil {
		h.reply(ctx, pub, reply, h.errorReply(ctx, call, cid, err))
		return
	}
	r := proto.AppSecretReply{Code: proto.AppSecretOK, Message: okMessage[call.Op], CorrelationID: cid}
	if call.Op == proto.AppSecretRead {
		r.Value = string(value.Reveal())
	}
	h.reply(ctx, pub, reply, r)
}

// validReply reports whether reply is a subject under node's own reply
// prefix, with a token and no wildcard.
func validReply(node, reply string) bool {
	prefix := proto.AppSecretReplyPrefix(node)
	token, ok := strings.CutPrefix(reply, prefix)
	return ok && token != "" && !strings.ContainsAny(token, "*> \t\r\n")
}

// parseCall parses data into a Call from node: a known op, a canonical app
// id, a runtime secret name and a bounded value. A field the call does not
// define, a node id among them, is never read. why is the reason a person
// reads when it does not parse, and empty when it does. The call is returned
// with whatever did parse, for the refusal record.
func parseCall(node string, data []byte) (Call, string) {
	c := Call{Node: node}
	var w proto.AppSecretCall
	if err := json.Unmarshal(data, &w); err != nil {
		return c, "the body is not a call"
	}
	c.AppID, c.Op, c.Name = w.AppID, w.Op, w.Name
	switch w.Op {
	case proto.AppSecretRead, proto.AppSecretCreate, proto.AppSecretReplace, proto.AppSecretDelete:
	default:
		return c, "the operation is not read, create, replace or delete"
	}
	ref, err := secrets.AppRuntimeSecret(w.AppID, w.Name)
	if err != nil {
		return c, "the app id or the secret name is not valid"
	}
	if len(w.Value) > proto.AppRelayMaxValueBytes {
		return c, fmt.Sprintf("the value is longer than %d bytes", proto.AppRelayMaxValueBytes)
	}
	c.Ref = ref
	if w.Op == proto.AppSecretCreate || w.Op == proto.AppSecretReplace {
		c.Value = secret.New([]byte(w.Value))
	}
	return c, ""
}

// errorReply maps the service's error to its code and sentence, and logs it
// under the correlation id: a refusal at WARN, a store failure at ERROR.
func (h *Handler) errorReply(ctx context.Context, c Call, cid string, err error) proto.AppSecretReply {
	r := proto.AppSecretReply{CorrelationID: cid}
	switch {
	case errors.Is(err, secretstore.ErrNotFound):
		r.Code, r.Message = proto.AppSecretNotFound, msgNotFound
	case errors.Is(err, secrets.ErrExists):
		r.Code, r.Message = proto.AppSecretExists, msgExists
	case errors.Is(err, secrets.ErrConflict):
		r.Code, r.Message = proto.AppSecretConflict, msgConflict
	case errors.Is(err, secrets.ErrForbidden), errors.Is(err, ErrNoApp), errors.Is(err, ErrNotGranted), errors.Is(err, ErrWrongNode):
		r.Code, r.Message = proto.AppSecretForbidden, msgForbidden
		h.refused(ctx, c, cid, err.Error())
	case errors.Is(err, secrets.ErrInvalidRef), errors.Is(err, secretstore.ErrInvalidValue):
		r.Code, r.Message = proto.AppSecretInvalid, "The call is not valid: the store does not accept the value."
		h.refused(ctx, c, cid, err.Error())
	default:
		r.Code, r.Message = proto.AppSecretUnavailable, msgUnavailable
		h.d.Log.LogAttrs(ctx, slog.LevelError, "app relay call failed at the secret store",
			append(h.attrs(c, cid, "apprelay.store_failed"), slog.String("err", err.Error()))...)
	}
	return r
}

// refused writes the one WARN record of a refused call.
func (h *Handler) refused(ctx context.Context, c Call, cid, reason string) {
	h.d.Log.LogAttrs(ctx, slog.LevelWarn, "app relay call refused",
		append(h.attrs(c, cid, "apprelay.refused"), slog.String("reason", reason))...)
}

// attrs are the fields every call record carries. Never the value.
func (h *Handler) attrs(c Call, cid, event string) []slog.Attr {
	return []slog.Attr{
		slog.String("component", "apprelay"),
		slog.String("event", event),
		slog.String("node", c.Node),
		slog.String("app_id", c.AppID),
		slog.String("op", c.Op),
		slog.String("name", c.Name),
		slog.String("correlation_id", cid),
	}
}

// reply publishes r on subject. A failure is logged: the agent's own bound
// on the call answers the app.
func (h *Handler) reply(ctx context.Context, pub Publisher, subject string, r proto.AppSecretReply) {
	b, err := json.Marshal(r)
	if err == nil {
		err = pub.Publish(subject, b)
	}
	if err != nil {
		h.d.Log.LogAttrs(ctx, slog.LevelWarn, "app relay reply not sent",
			slog.String("component", "apprelay"),
			slog.String("event", "apprelay.reply_failed"),
			slog.String("correlation_id", r.CorrelationID),
			slog.String("err", err.Error()))
	}
}
