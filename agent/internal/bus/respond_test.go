package bus

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// TestRespond_MarshalFailureSendsNoReply proves the marshal-error guard in
// Respond: when the body cannot be encoded to JSON, Respond logs and returns
// WITHOUT calling m.Respond, so the requester gets nothing rather than an
// empty/garbage reply. Marshalling a channel always fails, which drives the
// error branch deterministically.
//
// The requester subscribes a real responder (so this is a timeout, not a
// no-responders fast-fail); if Respond wrongly fell through to m.Respond it
// would deliver a nil payload and the Request would return without error.
func TestRespond_MarshalFailureSendsNoReply(t *testing.T) {
	s := startServer(t, -1, testNode, "tok-A")
	nc, err := nats.Connect(s.ClientURL(), nats.UserInfo(testNode, "tok-A"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer nc.Close()

	const subj = "test.respond.marshalfail"
	sub, err := nc.Subscribe(subj, func(m *nats.Msg) {
		Respond(m, make(chan int)) // json.Marshal cannot encode a channel
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe() //nolint:errcheck
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	reply, err := nc.Request(subj, nil, 500*time.Millisecond)
	if err == nil {
		t.Fatalf("Request returned a reply %q; Respond must send nothing when the body fails to marshal", reply.Data)
	}
}
