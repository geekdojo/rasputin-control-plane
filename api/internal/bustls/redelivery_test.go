package bustls

// Pin delivery is not one-shot (geekdojo/geekdojo-brain#615): in migrate, a
// heartbeat from a node that is not on TLS offers it the pin again. These are
// the unit tests of that rule; the functional test that walks the whole
// sequence with real agents is
// TestFunctional_NodesMissedAtTheMoveToMigrateStillReachTLS.
//
// Nothing here sleeps. Service.Wait returns once every delivery started so far
// has ended, so "no delivery happened" is read after a Wait, and an agent that
// must be mid-delivery says so on a channel.

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// unitDeadline bounds each wait for a fact in these tests.
const unitDeadline = 10 * time.Second

// pinAgent answers bus.pin for one node the way a test tells it to.
type pinAgent struct {
	id string

	mu       sync.Mutex
	requests int
	reply    func(pin string) proto.BusPinAck
	// hold, when set, is received from before each answer is sent: the
	// delivery stays in flight until the test sends on it or closes it.
	hold chan struct{}

	// asked carries one value per request received, sent before the answer.
	asked chan struct{}
}

func accept(id string) func(string) proto.BusPinAck {
	return func(pin string) proto.BusPinAck {
		return proto.BusPinAck{NodeID: id, OK: true, Pin: pin, Reconnecting: true}
	}
}

func refuse(id, why string) func(string) proto.BusPinAck {
	return func(string) proto.BusPinAck {
		return proto.BusPinAck{NodeID: id, OK: false, Detail: why}
	}
}

func startPinAgent(t *testing.T, nc *nats.Conn, id string, reply func(string) proto.BusPinAck, hold chan struct{}) *pinAgent {
	t.Helper()
	a := &pinAgent{id: id, reply: reply, hold: hold, asked: make(chan struct{}, 64)}
	sub, err := nc.Subscribe(proto.NodeCmdSubject(id, proto.BusPinVerb), func(m *nats.Msg) {
		var cmd proto.BusPinCmd
		_ = json.Unmarshal(m.Data, &cmd)
		a.mu.Lock()
		a.requests++
		reply, hold := a.reply, a.hold
		a.mu.Unlock()
		a.asked <- struct{}{}
		if hold != nil {
			<-hold
		}
		b, _ := json.Marshal(reply(cmd.Pin))
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	return a
}

func (a *pinAgent) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests
}

func (a *pinAgent) answerWith(reply func(string) proto.BusPinAck) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reply = reply
}

// waitAsked blocks until the agent has received one more request.
func (a *pinAgent) waitAsked(t *testing.T) {
	t.Helper()
	select {
	case <-a.asked:
	case <-time.After(unitDeadline):
		t.Fatalf("%s was not sent a pin within %s", a.id, unitDeadline)
	}
}

// heartbeat is one heartbeat from id, handled to the end: the hook, and the
// delivery it started if it started one.
func (x *fixture) heartbeat(id string) {
	x.svc.OnHeartbeat(id)
	x.svc.Wait()
}

func deliveryOf(t *testing.T, x *fixture, id string) *PinDelivery {
	t.Helper()
	st, err := x.svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range st.Nodes {
		if n.ID == id {
			return n.PinDelivery
		}
	}
	t.Fatalf("%s is not in the status: %+v", id, st.Nodes)
	return nil
}

// The production sequence, reduced to the service: the api is at migrate, and
// the node was never heard from by this process — no registration reached it,
// and the node did not read as online when the pin was fanned out. Its
// heartbeat is what offers it the pin.
func TestRedelivery_HeartbeatFromAPlaintextNodeInMigrateDeliversThePin(t *testing.T) {
	nc := startBus(t)
	x := newFixture(t, ModeMigrate, false, nc)
	plain := startPinAgent(t, nc, "plain", accept("plain"), nil)
	silent := startPinAgent(t, nc, "silent", accept("silent"), nil)
	onTLS := startPinAgent(t, nc, "tls", accept("tls"), nil)
	stranger := startPinAgent(t, nc, "stranger", accept("stranger"), nil)
	x.set(func(f *facts) {
		f.nodes = []*proto.Node{
			// Offline by the listing: the fan-out at the move to migrate
			// skips exactly these.
			node("plain", proto.StatusOffline, false),
			// An agent that predates the field reports nothing; that is not TLS.
			node("silent", proto.StatusOffline, nil),
			node("tls", proto.StatusOffline, true),
		}
	})

	// The fan-out reaches none of them: none reads as online.
	x.svc.DeliverToAll(context.Background())
	x.svc.Wait()
	for _, a := range []*pinAgent{plain, silent, onTLS} {
		if n := a.count(); n != 0 {
			t.Fatalf("the fan-out sent %d pin(s) to %s, which does not read as online", n, a.id)
		}
	}

	for _, id := range []string{"plain", "silent", "tls", "stranger"} {
		x.heartbeat(id)
	}
	if n := plain.count(); n != 1 {
		t.Errorf("a heartbeat from a node that last registered over plaintext sent %d pin(s), want 1", n)
	}
	if n := silent.count(); n != 1 {
		t.Errorf("a heartbeat from a node that never reported bus TLS sent %d pin(s), want 1", n)
	}
	if n := onTLS.count(); n != 0 {
		t.Errorf("a heartbeat from a node on TLS sent %d pin(s), want 0", n)
	}
	if n := stranger.count(); n != 0 {
		t.Errorf("a heartbeat from a node that is not in inventory sent %d pin(s), want 0", n)
	}
	if d := deliveryOf(t, x, "plain"); d == nil || d.Outcome != PinDelivered || !d.Reconnecting || d.Attempts != 1 || d.At.IsZero() {
		t.Errorf("status for plain = %+v, want delivered, reconnecting, 1 attempt, with a time", d)
	}
	if d := deliveryOf(t, x, "tls"); d != nil {
		t.Errorf("status for a node that was never offered the pin = %+v, want none", d)
	}
}

// A registration outranks the inventory row: a node this process saw register
// over TLS is not offered the pin whatever a listing says, and one it saw
// register over plaintext is, without a listing being read at all.
func TestRedelivery_TheLastRegistrationDecides(t *testing.T) {
	ctx := context.Background()
	nc := startBus(t)
	x := newFixture(t, ModeMigrate, false, nc)
	a := startPinAgent(t, nc, "n1", accept("n1"), nil)
	x.set(func(f *facts) { f.nodes = []*proto.Node{node("n1", proto.StatusOnline, false)} })

	x.svc.OnRegistered(ctx, node("n1", proto.StatusOnline, true))
	x.svc.Wait()
	x.heartbeat("n1")
	if n := a.count(); n != 0 {
		t.Fatalf("a node that registered over TLS was sent %d pin(s) on its heartbeat", n)
	}

	// It comes back over plaintext: the registration delivers (as before),
	// the node acknowledges, and its heartbeats then add nothing.
	x.svc.OnRegistered(ctx, node("n1", proto.StatusOnline, false))
	x.svc.Wait()
	if n := a.count(); n != 1 {
		t.Fatalf("a plaintext registration in migrate sent %d pin(s), want 1", n)
	}
	x.heartbeat("n1")
	x.heartbeat("n1")
	if n := a.count(); n != 1 {
		t.Fatalf("heartbeats after an acknowledged delivery sent %d more pin(s), want 0", n-1)
	}
}

// offer hands out nothing and require has nobody to hand it to: a heartbeat
// delivers in migrate only.
func TestRedelivery_NoDeliveryInOfferOrRequire(t *testing.T) {
	for _, mode := range []Mode{ModeOffer, ModeRequire} {
		t.Run(string(mode), func(t *testing.T) {
			ctx := context.Background()
			nc := startBus(t)
			x := newFixture(t, mode, false, nc)
			a := startPinAgent(t, nc, "plain", accept("plain"), nil)
			x.set(func(f *facts) { f.nodes = []*proto.Node{node("plain", proto.StatusOnline, false)} })

			x.heartbeat("plain")
			// And with the node's report known from a registration, which is
			// the path that reads no inventory.
			x.svc.OnRegistered(ctx, node("plain", proto.StatusOnline, false))
			x.svc.Wait()
			x.heartbeat("plain")

			if x.svc.Mode() != mode {
				t.Fatalf("mode = %s, want it still at %s (the build is not committed)", x.svc.Mode(), mode)
			}
			if n := a.count(); n != 0 {
				t.Fatalf("%s sent %d pin(s) on a heartbeat, want 0", mode, n)
			}
			if d := deliveryOf(t, x, "plain"); d != nil {
				t.Fatalf("%s recorded a delivery attempt: %+v", mode, d)
			}
		})
	}
}

// A mode pinned to migrate delivers on a heartbeat as it delivers on a
// registration: pinning stops the ladder moving, not the pin being handed out.
func TestRedelivery_PinnedMigrateStillDelivers(t *testing.T) {
	nc := startBus(t)
	x := newFixture(t, ModeMigrate, true, nc)
	a := startPinAgent(t, nc, "plain", accept("plain"), nil)
	x.set(func(f *facts) { f.nodes = []*proto.Node{node("plain", proto.StatusOffline, false)} })
	x.heartbeat("plain")
	if n := a.count(); n != 1 {
		t.Fatalf("a mode pinned to migrate sent %d pin(s) on a heartbeat, want 1", n)
	}
}

// One delivery per node at a time: heartbeats that arrive while a delivery is
// in flight start nothing, and once the node has acknowledged, further
// heartbeats start nothing either — until it registers again.
func TestRedelivery_InFlightDeliveryIsNotDuplicated(t *testing.T) {
	ctx := context.Background()
	nc := startBus(t)
	x := newFixture(t, ModeMigrate, false, nc)
	hold := make(chan struct{})
	a := startPinAgent(t, nc, "plain", accept("plain"), hold)
	x.set(func(f *facts) { f.nodes = []*proto.Node{node("plain", proto.StatusOffline, false)} })

	x.svc.OnHeartbeat("plain")
	a.waitAsked(t) // the delivery is in flight: the agent has it and has not answered
	for range 5 {
		x.svc.OnHeartbeat("plain")
	}
	// A registration and the fan-out go through the same gate.
	x.svc.OnRegistered(ctx, node("plain", proto.StatusOnline, false))
	x.set(func(f *facts) { f.nodes = []*proto.Node{node("plain", proto.StatusOnline, false)} })
	x.svc.DeliverToAll(ctx)
	if n := a.count(); n != 1 {
		t.Fatalf("%d deliveries were started while one was in flight, want 1", n)
	}
	close(hold)
	x.svc.Wait()
	if n := a.count(); n != 1 {
		t.Fatalf("%d deliveries in all, want 1", n)
	}
	if d := deliveryOf(t, x, "plain"); d == nil || d.Outcome != PinDelivered || d.Attempts != 1 {
		t.Fatalf("status = %+v, want one delivered attempt", d)
	}

	// Acknowledged: its heartbeats are now silent.
	x.heartbeat("plain")
	x.heartbeat("plain")
	if n := a.count(); n != 1 {
		t.Fatalf("heartbeats after the acknowledgement sent %d more pin(s), want 0", n-1)
	}
}

// A delivery that got no answer is tried again on the node's next heartbeat,
// and the status says what happened each time.
func TestRedelivery_FailedDeliveryIsRetriedOnTheNextHeartbeat(t *testing.T) {
	nc := startBus(t)
	x := newFixture(t, ModeMigrate, false, nc)
	x.set(func(f *facts) { f.nodes = []*proto.Node{node("plain", proto.StatusOffline, false)} })

	// Nothing is subscribed to the node's command subject: the request fails.
	x.heartbeat("plain")
	d := deliveryOf(t, x, "plain")
	if d == nil || d.Outcome != PinError || d.Detail == "" || d.Attempts != 1 {
		t.Fatalf("status after a delivery nobody answered = %+v, want error with the reason, 1 attempt", d)
	}
	x.heartbeat("plain")
	if d = deliveryOf(t, x, "plain"); d == nil || d.Outcome != PinError || d.Attempts != 2 {
		t.Fatalf("status after the second heartbeat = %+v, want error, 2 attempts", d)
	}

	// The node starts listening; its next heartbeat gets it the pin.
	a := startPinAgent(t, nc, "plain", accept("plain"), nil)
	x.heartbeat("plain")
	if n := a.count(); n != 1 {
		t.Fatalf("the heartbeat after a failed delivery sent %d pin(s), want 1", n)
	}
	if d = deliveryOf(t, x, "plain"); d == nil || d.Outcome != PinDelivered || d.Attempts != 3 {
		t.Fatalf("status after the retry = %+v, want delivered, 3 attempts", d)
	}
}

// A refusal is the node's answer, kept in its own words, and offered again on
// the next heartbeat: the reason a node gives can stop being true (a pin file
// it could not write).
func TestRedelivery_RefusalIsReportedAndOfferedAgain(t *testing.T) {
	nc := startBus(t)
	x := newFixture(t, ModeMigrate, false, nc)
	const why = "could not persist the pin: read-only file system"
	a := startPinAgent(t, nc, "plain", refuse("plain", why), nil)
	x.set(func(f *facts) { f.nodes = []*proto.Node{node("plain", proto.StatusOffline, false)} })

	x.heartbeat("plain")
	d := deliveryOf(t, x, "plain")
	if d == nil || d.Outcome != PinRefused || d.Detail != why || d.Reconnecting || d.Attempts != 1 {
		t.Fatalf("status after a refusal = %+v, want refused with the node's reason", d)
	}
	x.heartbeat("plain")
	if n := a.count(); n != 2 {
		t.Fatalf("a refused node was offered the pin %d time(s) over two heartbeats, want 2", n)
	}

	a.answerWith(accept("plain"))
	x.heartbeat("plain")
	if d = deliveryOf(t, x, "plain"); d == nil || d.Outcome != PinDelivered || d.Detail != "" || d.Attempts != 3 {
		t.Fatalf("status once the node took the pin = %+v, want delivered, 3 attempts, no stale reason", d)
	}
	x.heartbeat("plain")
	if n := a.count(); n != 3 {
		t.Fatalf("the node was sent %d pin(s) in all, want 3 (none after it acknowledged)", n)
	}
}

// The status is additive: the fields and blocker strings the contract documents
// are unchanged, and the outcome rides beside them under pinDelivery.
func TestRedelivery_StatusKeepsItsShapeAndAddsTheOutcome(t *testing.T) {
	nc := startBus(t)
	x := newFixture(t, ModeMigrate, false, nc)
	const why = "this node already pins another key"
	startPinAgent(t, nc, "plain", refuse("plain", why), nil)
	x.set(func(f *facts) {
		f.nodes = []*proto.Node{node("plain", proto.StatusOnline, false), node("quiet", proto.StatusOnline, nil)}
	})
	x.heartbeat("plain")

	st, err := x.svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantBlockers := []string{
		"plain last registered over plaintext",
		"quiet has not reported bus TLS (its agent predates it, or it has not registered since)",
	}
	if strings.Join(st.Blockers, "|") != strings.Join(wantBlockers, "|") {
		t.Errorf("blockers = %q, want %q", st.Blockers, wantBlockers)
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Mode  string `json:"mode"`
		Pin   string `json:"pin"`
		Nodes []map[string]json.RawMessage
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Mode != "migrate" || wire.Pin != x.svc.Pin() || len(wire.Nodes) != 2 {
		t.Fatalf("status on the wire = %s", b)
	}
	for _, n := range wire.Nodes {
		for _, k := range []string{"id", "role", "status", "busTls", "reported"} {
			if _, ok := n[k]; !ok {
				t.Errorf("node %s lost its %q field: %s", n["id"], k, b)
			}
		}
	}
	var got map[string]any
	if err := json.Unmarshal(wire.Nodes[0]["pinDelivery"], &got); err != nil {
		t.Fatalf("plain has no pinDelivery on the wire: %s", b)
	}
	if got["outcome"] != "refused" || got["detail"] != why || got["attempts"] != float64(1) || got["at"] == "" {
		t.Errorf("pinDelivery on the wire = %v", got)
	}
	if _, ok := got["reconnecting"]; ok {
		t.Errorf("a refusal says reconnecting: %v", got)
	}
	if _, ok := wire.Nodes[1]["pinDelivery"]; ok {
		t.Errorf("a node that was never offered the pin has a pinDelivery: %s", b)
	}
}

// A stopped service starts nothing.
func TestRedelivery_NothingAfterStop(t *testing.T) {
	nc := startBus(t)
	x := newFixture(t, ModeMigrate, false, nc)
	a := startPinAgent(t, nc, "plain", accept("plain"), nil)
	x.set(func(f *facts) { f.nodes = []*proto.Node{node("plain", proto.StatusOffline, false)} })
	x.svc.Stop()
	x.heartbeat("plain")
	if n := a.count(); n != 0 {
		t.Fatalf("a stopped service sent %d pin(s)", n)
	}
}
