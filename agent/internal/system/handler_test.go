package system

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// startNATS spins up an in-process NATS server on a random port and returns
// a connected client. Both shut down on test cleanup.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	opts := &natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
	}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("nats new server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(2 * time.Second) {
		t.Fatal("nats not ready in 2s")
	}
	t.Cleanup(func() {
		ns.Shutdown()
		ns.WaitForShutdown()
	})
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// TestRegisterRebootHandler_AcksAndPublishesEvent — happy path: send a
// system.reboot cmd, expect a sync ack, expect a rebooting event published.
// We use a tiny DelaySeconds so the heartbeat-mute window stays bounded for
// the rest of the test suite, but we don't *wait* on it: the ack arrives
// before the sleep begins.
func TestRegisterRebootHandler_AcksAndPublishesEvent(t *testing.T) {
	prev := IsMuted()
	t.Cleanup(func() { MutedAtomic().Store(prev) })

	nc := startNATS(t)
	var (
		mu          sync.Mutex
		reregCalled bool
	)
	sub, err := RegisterRebootHandler(nc, "node-1", func(c *nats.Conn) {
		mu.Lock()
		reregCalled = true
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("RegisterRebootHandler: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	evSub, err := nc.SubscribeSync(proto.NodeEvtSubject("node-1", "rebooting"))
	if err != nil {
		t.Fatalf("subscribe ev: %v", err)
	}
	t.Cleanup(func() { _ = evSub.Unsubscribe() })

	cmd, _ := json.Marshal(proto.SystemRebootCmd{DelaySeconds: 1})
	msg, err := nc.Request(proto.NodeCmdSubject("node-1", "system.reboot"), cmd, 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.SystemRebootAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if !ack.OK {
		t.Errorf("ack: %+v", ack)
	}
	if ack.DelaySeconds != 1 {
		t.Errorf("delay: %d", ack.DelaySeconds)
	}

	// The rebooting event is published from the goroutine right at the start
	// of simulateReboot. Should arrive promptly.
	if _, err := evSub.NextMsg(500 * time.Millisecond); err != nil {
		t.Fatalf("rebooting event not published: %v", err)
	}

	// Wait briefly (deterministically — we sized delay at 1s) for the
	// reregister callback to fire.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := reregCalled
		mu.Unlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("reregister callback never fired")
}

// TestRegisterRebootHandler_DelayClampedOnZero — DelaySeconds=0 must be
// rewritten to the default. We can't observe the internal clamp without a
// race, so we send 0 and inspect the ack's clamped value.
func TestRegisterRebootHandler_DelayClamped(t *testing.T) {
	prev := IsMuted()
	t.Cleanup(func() { MutedAtomic().Store(prev) })

	nc := startNATS(t)
	sub, err := RegisterRebootHandler(nc, "node-2", func(c *nats.Conn) {})
	if err != nil {
		t.Fatalf("RegisterRebootHandler: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	cases := []struct {
		in   int
		want int
	}{
		{0, rebootDefaultDelay},                  // zero -> default
		{-3, rebootDefaultDelay},                 // negative -> default
		{rebootMaxDelay + 1, rebootDefaultDelay}, // over max -> default
		{5, 5},                                   // valid pass-through
	}
	for _, tc := range cases {
		cmd, _ := json.Marshal(proto.SystemRebootCmd{DelaySeconds: tc.in})
		msg, err := nc.Request(proto.NodeCmdSubject("node-2", "system.reboot"), cmd, 2*time.Second)
		if err != nil {
			t.Fatalf("request(%d): %v", tc.in, err)
		}
		var ack proto.SystemRebootAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if ack.DelaySeconds != tc.want {
			t.Errorf("in=%d ack.DelaySeconds=%d want %d", tc.in, ack.DelaySeconds, tc.want)
		}
	}
}

// TestRegisterRebootHandler_NilReregisterIsSafe — passing nil for the
// reregister hook should not crash simulateReboot.
func TestRegisterRebootHandler_NilReregisterIsSafe(t *testing.T) {
	prev := IsMuted()
	t.Cleanup(func() { MutedAtomic().Store(prev) })

	nc := startNATS(t)
	sub, err := RegisterRebootHandler(nc, "node-3", nil)
	if err != nil {
		t.Fatalf("RegisterRebootHandler: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	evSub, err := nc.SubscribeSync(proto.NodeEvtSubject("node-3", "rebooting"))
	if err != nil {
		t.Fatalf("subscribe ev: %v", err)
	}
	t.Cleanup(func() { _ = evSub.Unsubscribe() })

	cmd, _ := json.Marshal(proto.SystemRebootCmd{DelaySeconds: 1})
	msg, err := nc.Request(proto.NodeCmdSubject("node-3", "system.reboot"), cmd, 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.SystemRebootAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !ack.OK {
		t.Errorf("ack: %+v", ack)
	}
	// Drain the rebooting event so simulateReboot's goroutine completes.
	if _, err := evSub.NextMsg(500 * time.Millisecond); err != nil {
		t.Errorf("rebooting event: %v", err)
	}
	// Wait for the muted flag to be cleared, which happens after the
	// simulated reboot delay completes. Polling avoids a fixed sleep and
	// stays well under any "no sleep > 200ms" budget for the harness.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !IsMuted() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("muted flag never cleared")
}
