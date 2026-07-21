package bmc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// startNATS spins up an in-process NATS server on a random port and
// returns a connected client. Both shut down on test cleanup.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	opts := &natsserver.Options{
		Host:   "127.0.0.1",
		Port:   -1, // random
		NoLog:  true,
		NoSigs: true,
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

// request publishes cmd payload on subj and decodes the synchronous reply
// into out.
func request[T any](t *testing.T, nc *nats.Conn, subj string, cmd any, out *T) {
	t.Helper()
	payload, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg, err := nc.Request(subj, payload, 2*time.Second)
	if err != nil {
		t.Fatalf("request %s: %v", subj, err)
	}
	if err := json.Unmarshal(msg.Data, out); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
}

func TestRegisterHandlers_AllPowerVerbsAcked(t *testing.T) {
	nc := startNATS(t)
	mb := newMock(t)
	subs, err := RegisterHandlers(nc, "host-1", mb)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	cases := []struct {
		verb      proto.BMCPowerVerb
		wantState proto.BMCPowerState
	}{
		{proto.BMCPowerOn, proto.BMCStateOn},
		{proto.BMCPowerOff, proto.BMCStateOff},
		{proto.BMCPowerCycle, proto.BMCStateOn},
		{proto.BMCPowerReset, proto.BMCStateOn},
		{proto.BMCPowerQuery, proto.BMCStateOn}, // last verb's effect lingers
	}
	for _, tc := range cases {
		t.Run(string(tc.verb), func(t *testing.T) {
			var ack proto.BMCPowerAck
			request(t, nc, proto.BMCPowerSubject("host-1", tc.verb), proto.BMCPowerCmd{TargetNodeID: "target-1"}, &ack)
			if !ack.OK {
				t.Errorf("ack OK=false: %+v", ack)
			}
			if ack.State != tc.wantState {
				t.Errorf("state: got %q, want %q", ack.State, tc.wantState)
			}
		})
	}
}

func TestRegisterHandlers_PowerBadCmdReturnsErr(t *testing.T) {
	nc := startNATS(t)
	mb := newMock(t)
	subs, err := RegisterHandlers(nc, "host-1", mb)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	// Publish raw garbage to the power subject — JSON unmarshal must fail.
	msg, err := nc.Request(proto.BMCPowerSubject("host-1", proto.BMCPowerOn), []byte("not-json"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.BMCPowerAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.OK {
		t.Error("expected OK=false for bad cmd")
	}
	if ack.Detail == "" {
		t.Error("expected detail message for bad cmd")
	}
}

// failingBackend returns an error from Power; used to exercise the error path
// in handler.power.
type failingBackend struct {
	*MockBackend
	err error
}

func (f *failingBackend) Power(_ context.Context, target string, verb proto.BMCPowerVerb) (proto.BMCPowerState, string, error) {
	return proto.BMCStateUnknown, "", f.err
}

func TestRegisterHandlers_PowerBackendErrorAcksFalse(t *testing.T) {
	nc := startNATS(t)
	mb := newMock(t)
	fb := &failingBackend{MockBackend: mb, err: errBackend{}}
	subs, err := RegisterHandlers(nc, "host-1", fb)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	var ack proto.BMCPowerAck
	request(t, nc, proto.BMCPowerSubject("host-1", proto.BMCPowerOn), proto.BMCPowerCmd{TargetNodeID: "tt"}, &ack)
	if ack.OK {
		t.Error("expected OK=false on backend error")
	}
	if ack.Detail == "" {
		t.Error("expected error detail")
	}
}

type errBackend struct{}

func (errBackend) Error() string { return "boom" }

func TestRegisterHandlers_SOLOpenAndClose(t *testing.T) {
	nc := startNATS(t)
	mb := newMock(t)
	subs, err := RegisterHandlers(nc, "host-1", mb)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	sessionID := "abcdef-0123-4567-89ab"

	// Subscribe to the .out subject before opening so we don't miss the banner.
	outSub, err := nc.SubscribeSync(proto.BMCSOLOutSubject(sessionID))
	if err != nil {
		t.Fatalf("subscribe out: %v", err)
	}
	t.Cleanup(func() { _ = outSub.Unsubscribe() })

	// Open
	var openAck proto.BMCSOLOpenAck
	request(t, nc, proto.BMCSOLOpenSubject("host-1"), proto.BMCSOLOpenCmd{
		TargetNodeID: "target-x",
		SessionID:    sessionID,
	}, &openAck)
	if !openAck.OK {
		t.Fatalf("open ack: %+v", openAck)
	}
	if openAck.SessionID != sessionID {
		t.Errorf("session id: got %q, want %q", openAck.SessionID, sessionID)
	}
	if openAck.Backend != "mock" {
		t.Errorf("backend: got %q, want mock", openAck.Backend)
	}

	// The mock's banner should arrive on .out within a tick.
	msg, err := outSub.NextMsg(200 * time.Millisecond)
	if err != nil {
		t.Fatalf("no banner on .out within 200ms: %v", err)
	}
	var evt proto.BMCSOLDataEvt
	if err := json.Unmarshal(msg.Data, &evt); err != nil {
		t.Fatalf("unmarshal data evt: %v", err)
	}
	if evt.SessionID != sessionID {
		t.Errorf("evt session id: %q", evt.SessionID)
	}
	if evt.Data == "" {
		t.Error("evt data empty")
	}

	// Send bytes on .in — backend echoes back on .out.
	inPayload, _ := json.Marshal(proto.BMCSOLDataEvt{
		SessionID: sessionID,
		Data:      "hello",
		Ts:        time.Now().UTC(),
	})
	if err := nc.Publish(proto.BMCSOLInSubject(sessionID), inPayload); err != nil {
		t.Fatalf("publish in: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// Drain until we see the echo (the periodic uptime line may also fire).
	var sawEcho bool
	for i := 0; i < 4 && !sawEcho; i++ {
		m, err := outSub.NextMsg(200 * time.Millisecond)
		if err != nil {
			break
		}
		var e proto.BMCSOLDataEvt
		if err := json.Unmarshal(m.Data, &e); err == nil && contains(e.Data, "mock-echo: hello") {
			sawEcho = true
		}
	}
	if !sawEcho {
		t.Error("did not observe mock-echo on .out")
	}

	// Close
	var closeAck proto.BMCSOLCloseAck
	request(t, nc, proto.BMCSOLCloseSubject("host-1"), proto.BMCSOLCloseCmd{SessionID: sessionID}, &closeAck)
	if !closeAck.OK {
		t.Errorf("close ack: %+v", closeAck)
	}
}

func TestRegisterHandlers_SOLOpenBadCmd(t *testing.T) {
	nc := startNATS(t)
	mb := newMock(t)
	subs, err := RegisterHandlers(nc, "host-1", mb)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	msg, err := nc.Request(proto.BMCSOLOpenSubject("host-1"), []byte("not-json"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.BMCSOLOpenAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.OK {
		t.Error("expected OK=false on bad cmd")
	}
}

func TestRegisterHandlers_SOLCloseBadCmd(t *testing.T) {
	nc := startNATS(t)
	mb := newMock(t)
	subs, err := RegisterHandlers(nc, "host-1", mb)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	msg, err := nc.Request(proto.BMCSOLCloseSubject("host-1"), []byte("not-json"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.BMCSOLCloseAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.OK {
		t.Error("expected OK=false on bad cmd")
	}
}

func TestRegisterHandlers_SOLCloseUnknownSession(t *testing.T) {
	// Closing a session id we never opened must still ack cleanly (idempotent).
	nc := startNATS(t)
	mb := newMock(t)
	subs, err := RegisterHandlers(nc, "host-1", mb)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	var ack proto.BMCSOLCloseAck
	request(t, nc, proto.BMCSOLCloseSubject("host-1"), proto.BMCSOLCloseCmd{SessionID: "ghost"}, &ack)
	if !ack.OK {
		t.Error("close of unknown session should still ack OK")
	}
}

// solOpenFailBackend errors out of OpenSOL to cover the open error path.
type solOpenFailBackend struct {
	*MockBackend
	err error
}

func (s *solOpenFailBackend) OpenSOL(_ context.Context, target, sessionID string) (SOL, error) {
	return nil, s.err
}

func TestRegisterHandlers_SOLOpenBackendErr(t *testing.T) {
	nc := startNATS(t)
	mb := newMock(t)
	fb := &solOpenFailBackend{MockBackend: mb, err: errBackend{}}
	subs, err := RegisterHandlers(nc, "host-1", fb)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	var ack proto.BMCSOLOpenAck
	request(t, nc, proto.BMCSOLOpenSubject("host-1"), proto.BMCSOLOpenCmd{
		TargetNodeID: "t",
		SessionID:    "s",
	}, &ack)
	if ack.OK {
		t.Error("expected OK=false on backend error")
	}
	if ack.Backend != "mock" {
		t.Errorf("backend: got %q", ack.Backend)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestHandler_CloseAllSendsCourtesyFrameAndDrains(t *testing.T) {
	nc := startNATS(t)
	mb := newMock(t)
	h, subs, err := registerHandlers(nc, "host-1", mb)
	if err != nil {
		t.Fatalf("registerHandlers: %v", err)
	}
	defer func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	}()

	var ack proto.BMCSOLOpenAck
	request(t, nc, proto.BMCSOLOpenSubject("host-1"),
		proto.BMCSOLOpenCmd{TargetNodeID: "node-x", SessionID: "sess-close-all"}, &ack)
	if !ack.OK {
		t.Fatalf("sol open: %+v", ack)
	}
	out, err := nc.SubscribeSync(proto.BMCSOLOutSubject("sess-close-all"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Unsubscribe() }()

	h.closeAll("BMC reconfigured from Settings")

	// The courtesy frame names the reason so the operator's console
	// shows why it went quiet.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		msg, err := out.NextMsg(500 * time.Millisecond)
		if err != nil {
			break
		}
		var ev proto.BMCSOLDataEvt
		if json.Unmarshal(msg.Data, &ev) == nil &&
			ev.SessionID == "sess-close-all" &&
			len(ev.Data) > 0 && ev.Ts.After(time.Time{}) &&
			strings.Contains(ev.Data, "session closed: BMC reconfigured") {
			// Sessions map must be drained too.
			h.mu.Lock()
			n := len(h.sessions)
			h.mu.Unlock()
			if n != 0 {
				t.Errorf("sessions not drained: %d", n)
			}
			return
		}
	}
	t.Fatal("no courtesy close frame observed on .out")
}
