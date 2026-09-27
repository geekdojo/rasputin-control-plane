package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// These tests replace the ones that asserted the SIMULATED system.reboot
// (geekdojo/geekdojo-brain#616). Until that fix the handler muted heartbeats,
// slept and re-registered, and the tests here asserted exactly that. They now
// assert that a reboot command runs the OS reboot command, that simulation is
// reachable only through the explicit dev selection, and that a reboot which
// cannot be performed fails instead of being faked.
//
// Nothing here restarts the machine running the tests: every Rebooter is built
// by newTestRebooter, whose exec seam is a recorder.

const rpcWait = 5 * time.Second

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
	if !ns.ReadyForConnections(rpcWait) {
		t.Fatal("nats not ready")
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

// execCall is one invocation of the reboot command the Rebooter asked for.
type execCall struct {
	path string
	args []string
}

// rebootRig is a Rebooter whose OS-facing seams are recorders.
type rebootRig struct {
	rb    *Rebooter
	execs chan execCall
	waits chan time.Duration
	logs  *syncBuffer
	// done receives once each time perform returns.
	done chan struct{}

	mu       sync.Mutex
	lookErr  error
	runErr   error
	runOut   []byte
	lookedUp []string
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newTestRebooter returns a REAL-mode Rebooter (no simulation) on boot
// "boot-before", whose reboot command resolves to /sbin/reboot and whose exec
// records the call instead of running anything.
func newTestRebooter(t *testing.T, pub Publisher, nodeID string) *rebootRig {
	t.Helper()
	prev := IsMuted()
	t.Cleanup(func() { MutedAtomic().Store(prev) })
	MutedAtomic().Store(false)

	rig := &rebootRig{
		execs: make(chan execCall, 4),
		waits: make(chan time.Duration, 4),
		logs:  &syncBuffer{},
		done:  make(chan struct{}, 4),
	}
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(rig.logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	rig.rb = &Rebooter{
		nodeID: nodeID,
		pub:    pub,
		bootID: func() string { return "boot-before" },
		lookPath: func(file string) (string, error) {
			rig.mu.Lock()
			defer rig.mu.Unlock()
			rig.lookedUp = append(rig.lookedUp, file)
			if rig.lookErr != nil {
				return "", rig.lookErr
			}
			return "/sbin/" + file, nil
		},
		run: func(path string, args ...string) ([]byte, error) {
			rig.mu.Lock()
			out, err := rig.runOut, rig.runErr
			rig.mu.Unlock()
			rig.execs <- execCall{path: path, args: slices.Clone(args)}
			return out, err
		},
		// The delay is recorded, not slept.
		wait: func(d time.Duration) { rig.waits <- d },
		performed: func() {
			select {
			case rig.done <- struct{}{}:
			default:
			}
		},
	}
	return rig
}

func (r *rebootRig) nextExec(t *testing.T) execCall {
	t.Helper()
	select {
	case c := <-r.execs:
		return c
	case <-time.After(rpcWait):
		t.Fatal("the reboot command was never run")
		return execCall{}
	}
}

// subscribeEvt subscribes to one of nodeID's events and makes sure the
// subscription is live on the server before returning.
func subscribeEvt(t *testing.T, nc *nats.Conn, nodeID, event string) *nats.Subscription {
	t.Helper()
	sub, err := nc.SubscribeSync(proto.NodeEvtSubject(nodeID, event))
	if err != nil {
		t.Fatalf("subscribe %s: %v", event, err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return sub
}

// nothingPublished asserts sub has received nothing. It is a fact and not a
// wait: Flush is a round trip to the server, and the server delivers every
// message published before it ahead of the reply.
func nothingPublished(t *testing.T, nc *nats.Conn, sub *nats.Subscription, what string) {
	t.Helper()
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	n, _, err := sub.Pending()
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if n != 0 {
		t.Errorf("%s: %d event(s) were published, want none", what, n)
	}
}

func sendReboot(t *testing.T, nc *nats.Conn, nodeID string, delay int) proto.SystemRebootAck {
	t.Helper()
	cmd, _ := json.Marshal(proto.SystemRebootCmd{DelaySeconds: delay})
	msg, err := nc.Request(proto.NodeCmdSubject(nodeID, "system.reboot"), cmd, rpcWait)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.SystemRebootAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	return ack
}

func register(t *testing.T, nc *nats.Conn, nodeID string, rb *Rebooter) {
	t.Helper()
	sub, err := RegisterRebootHandler(nc, nodeID, rb)
	if err != nil {
		t.Fatalf("RegisterRebootHandler: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
}

// The defect: system.reboot never restarted anything. In a non-mock
// configuration it must run the OS reboot command, PLAIN.
func TestSystemReboot_RunsTheRealRebootInPlainMode(t *testing.T) {
	nc := startNATS(t)
	rig := newTestRebooter(t, nc, "node-1")
	register(t, nc, "node-1", rig.rb)
	evSub := subscribeEvt(t, nc, "node-1", "rebooting")

	ack := sendReboot(t, nc, "node-1", 7)
	if !ack.OK || ack.DelaySeconds != 7 {
		t.Fatalf("ack = %+v, want OK with delay 7", ack)
	}

	call := rig.nextExec(t)
	if call.path != "/sbin/reboot" {
		t.Errorf("ran %q, want the resolved reboot command /sbin/reboot", call.path)
	}
	if len(call.args) != 0 {
		t.Errorf("args = %q — an operator's reboot must be PLAIN; a trial-boot argument here "+
			"would start an A/B trial of whatever slot was pending", call.args)
	}
	if d := <-rig.waits; d != 7*time.Second {
		t.Errorf("waited %v before rebooting, want 7s", d)
	}

	msg, err := evSub.NextMsg(rpcWait)
	if err != nil {
		t.Fatalf("rebooting event not published: %v", err)
	}
	var ev proto.SystemRebootingEvt
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev.Reason != ReasonOperator || ev.Mode != string(RebootPlain) || ev.BootID != "boot-before" ||
		ev.DelaySeconds != 7 || ev.Simulated {
		t.Errorf("event = %+v, want reason=system.reboot mode=plain bootId=boot-before delay=7 simulated=false", ev)
	}
	if !IsMuted() {
		t.Error("heartbeats must stay muted once the OS has accepted the reboot")
	}
}

// Simulation exists only behind the explicit dev selection.
func TestSystemReboot_MockConfigurationSimulates(t *testing.T) {
	nc := startNATS(t)
	rig := newTestRebooter(t, nc, "node-2")
	back := make(chan bool, 1)
	if !rig.rb.EnableSimulation("", func() { back <- IsMuted() }) {
		t.Fatal("simulation must be available on an unversioned dev checkout")
	}
	register(t, nc, "node-2", rig.rb)
	evSub := subscribeEvt(t, nc, "node-2", "rebooting")

	if ack := sendReboot(t, nc, "node-2", 1); !ack.OK {
		t.Fatalf("ack = %+v", ack)
	}
	select {
	case mutedAtReregister := <-back:
		if mutedAtReregister {
			t.Error("heartbeats were still muted when the simulated node re-registered")
		}
	case <-time.After(rpcWait):
		t.Fatal("the simulated reboot never re-registered")
	}
	select {
	case c := <-rig.execs:
		t.Errorf("a simulated reboot ran %q %q — it must run nothing", c.path, c.args)
	default:
	}
	rig.mu.Lock()
	looked := len(rig.lookedUp)
	rig.mu.Unlock()
	if looked != 0 {
		t.Error("a simulated reboot looked for the reboot command; a laptop without one must still simulate")
	}
	msg, err := evSub.NextMsg(rpcWait)
	if err != nil {
		t.Fatalf("rebooting event not published: %v", err)
	}
	var ev proto.SystemRebootingEvt
	_ = json.Unmarshal(msg.Data, &ev)
	if !ev.Simulated {
		t.Errorf("event = %+v, want simulated=true so the control plane can say so", ev)
	}
	if !strings.Contains(rig.logs.String(), "SIMULATED") {
		t.Errorf("logs = %q, want the simulation named", rig.logs.String())
	}
}

// A released image can never simulate, whatever was selected.
func TestEnableSimulation_RefusedOnAReleasedImage(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"", true},
		{"2026.09.4-dev.12", true},
		{"2026.09.4", false},
		{"2026.10.0", false},
	} {
		rig := newTestRebooter(t, nil, "node-3")
		got := rig.rb.EnableSimulation(tc.version, nil)
		if got != tc.want || rig.rb.Simulated() != tc.want {
			t.Errorf("EnableSimulation(%q) = %v (Simulated=%v), want %v", tc.version, got, rig.rb.Simulated(), tc.want)
		}
	}

	// And the refusal is not cosmetic: the reboot that follows is real.
	nc := startNATS(t)
	rig := newTestRebooter(t, nc, "node-3")
	rig.rb.EnableSimulation("2026.09.4", func() { t.Error("re-registered: the reboot was simulated on a released image") })
	if _, err := rig.rb.Reboot(RebootRequest{Reason: ReasonOperator}); err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if call := rig.nextExec(t); call.path != "/sbin/reboot" {
		t.Errorf("ran %q, want /sbin/reboot", call.path)
	}
}

// No reboot command: the command FAILS. It is never simulated.
func TestSystemReboot_NoRebootCommandFailsAndIsNotSimulated(t *testing.T) {
	nc := startNATS(t)
	rig := newTestRebooter(t, nc, "node-4")
	rig.lookErr = errors.New(`exec: "reboot": executable file not found in $PATH`)
	register(t, nc, "node-4", rig.rb)
	evSub := subscribeEvt(t, nc, "node-4", "rebooting")

	ack := sendReboot(t, nc, "node-4", 1)
	if ack.OK {
		t.Fatalf("ack = %+v — a node that cannot reboot must not ack a reboot", ack)
	}
	if !strings.Contains(ack.Detail, "reboot") || !strings.Contains(ack.Detail, "not found") {
		t.Errorf("detail = %q, want it to name the missing reboot command", ack.Detail)
	}
	nothingPublished(t, nc, evSub, "a refused reboot")
	if IsMuted() {
		t.Error("heartbeats were muted by a reboot that was refused")
	}
	select {
	case c := <-rig.execs:
		t.Errorf("ran %q after failing to find the command", c.path)
	default:
	}
	if !strings.Contains(rig.logs.String(), "FAILED") || !strings.Contains(rig.logs.String(), "NOT rebooted") {
		t.Errorf("logs = %q, want a loud failure", rig.logs.String())
	}
}

// The command exists and fails when run: reported, unmuted, not faked.
func TestSystemReboot_ExecFailureIsReportedAndIsNotSimulated(t *testing.T) {
	nc := startNATS(t)
	rig := newTestRebooter(t, nc, "node-5")
	rig.runErr = errors.New("exit status 1")
	rig.runOut = []byte("Failed to talk to init daemon\n")
	register(t, nc, "node-5", rig.rb)
	failSub := subscribeEvt(t, nc, "node-5", "reboot_failed")

	if ack := sendReboot(t, nc, "node-5", 2); !ack.OK {
		t.Fatalf("ack = %+v — the command was found, so the request is accepted", ack)
	}
	rig.nextExec(t)

	msg, err := failSub.NextMsg(rpcWait)
	if err != nil {
		t.Fatalf("reboot_failed event not published: %v", err)
	}
	var ev proto.SystemRebootFailedEvt
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.BootID != "boot-before" || ev.Reason != ReasonOperator || !ev.Definitive ||
		!strings.Contains(ev.Detail, "exit status 1") || !strings.Contains(ev.Detail, "Failed to talk to init daemon") {
		t.Errorf("event = %+v, want a definitive report of the boot still running, who asked, and the command's own error", ev)
	}
	// The event is published after the unmute, so this is already true.
	if IsMuted() {
		t.Error("the node did not reboot, so its heartbeats must resume")
	}
	if !strings.Contains(rig.logs.String(), "FAILED") {
		t.Errorf("logs = %q, want a loud failure", rig.logs.String())
	}

	// A failed reboot does not wedge the node: the next request is accepted.
	rig.mu.Lock()
	rig.runErr = nil
	rig.mu.Unlock()
	if _, err := rig.rb.Reboot(RebootRequest{Reason: ReasonOperator}); err != nil {
		t.Errorf("reboot after a failed one: %v", err)
	}
	rig.nextExec(t)
}

// The trial boot is an ARGUMENT to the one function, not a second one.
func TestReboot_TrybootIsAModeOfTheSameFunction(t *testing.T) {
	rig := newTestRebooter(t, nil, "node-6")
	if _, err := rig.rb.Reboot(RebootRequest{Reason: "update.reboot bundle=abc", Mode: RebootTryboot}); err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	call := rig.nextExec(t)
	if call.path != "/sbin/reboot" || !slices.Equal(call.args, []string{"0 tryboot"}) {
		t.Errorf("ran %q %q, want /sbin/reboot [\"0 tryboot\"]", call.path, call.args)
	}
}

func TestReboot_DelayIsClamped(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{0, rebootDefaultDelay},
		{-3, rebootDefaultDelay},
		{rebootMaxDelay + 1, rebootDefaultDelay},
		{5, 5},
		{rebootMaxDelay, rebootMaxDelay},
	} {
		rig := newTestRebooter(t, nil, "node-7")
		got, err := rig.rb.Reboot(RebootRequest{Reason: ReasonOperator, DelaySeconds: tc.in})
		if err != nil {
			t.Fatalf("Reboot(%d): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("delay %d applied as %d, want %d", tc.in, got, tc.want)
		}
		rig.nextExec(t)
	}
}

func TestReboot_Refusals(t *testing.T) {
	t.Run("no reason", func(t *testing.T) {
		rig := newTestRebooter(t, nil, "n")
		if _, err := rig.rb.Reboot(RebootRequest{}); err == nil {
			t.Error("a reboot nobody owns up to must be refused: the journal could not say who asked")
		}
	})
	t.Run("unknown mode", func(t *testing.T) {
		rig := newTestRebooter(t, nil, "n")
		if _, err := rig.rb.Reboot(RebootRequest{Reason: "x", Mode: "kexec"}); err == nil {
			t.Error("an unknown mode must be refused")
		}
	})
	t.Run("nil rebooter", func(t *testing.T) {
		var rb *Rebooter
		if _, err := rb.Reboot(RebootRequest{Reason: "x"}); err == nil {
			t.Error("a nil Rebooter must refuse, not panic or succeed")
		}
	})
	t.Run("already under way", func(t *testing.T) {
		rig := newTestRebooter(t, nil, "n")
		if _, err := rig.rb.Reboot(RebootRequest{Reason: "first"}); err != nil {
			t.Fatalf("first: %v", err)
		}
		if _, err := rig.rb.Reboot(RebootRequest{Reason: "second"}); !errors.Is(err, ErrRebootInProgress) {
			t.Errorf("second reboot: err = %v, want ErrRebootInProgress", err)
		}
		rig.nextExec(t)
		select {
		case c := <-rig.execs:
			t.Errorf("the reboot command ran twice: %v", c)
		default:
		}
	})
}

// Fault injection's announce-and-do-not-reboot goes through the same
// function, and does exactly that.
func TestReboot_AnnounceOnlyAnnouncesAndRunsNothing(t *testing.T) {
	nc := startNATS(t)
	rig := newTestRebooter(t, nc, "node-8")
	evSub := subscribeEvt(t, nc, "node-8", "rebooting")
	if _, err := rig.rb.Reboot(RebootRequest{Reason: "update.reboot fault=no-reboot", AnnounceOnly: true}); err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if _, err := evSub.NextMsg(rpcWait); err != nil {
		t.Fatalf("rebooting event not published: %v", err)
	}
	// AnnounceOnly is synchronous: by the time Reboot returned, everything
	// it will ever do is done.
	select {
	case c := <-rig.execs:
		t.Errorf("ran %q", c.path)
	default:
	}
	if IsMuted() {
		t.Error("announce-only must not mute: the fault is a node that keeps answering")
	}
	if !strings.Contains(rig.logs.String(), "FAULT INJECTION") {
		t.Errorf("logs = %q, want the fault named", rig.logs.String())
	}
}

// The reason the owner asked for one function: every reboot logs the same
// facts, whoever asked.
func TestReboot_EveryCallerLogsTheSameFacts(t *testing.T) {
	for _, req := range []RebootRequest{
		{Reason: ReasonOperator, Mode: RebootPlain, DelaySeconds: 4},
		{Reason: "update.reboot bundle=0123456789ab", Mode: RebootTryboot, DelaySeconds: 4},
		{Reason: "update.mark-bad bundle=0123456789ab", Mode: RebootPlain, DelaySeconds: 4},
	} {
		rig := newTestRebooter(t, nil, "node-9")
		if _, err := rig.rb.Reboot(req); err != nil {
			t.Fatalf("Reboot(%+v): %v", req, err)
		}
		rig.nextExec(t)
		// The request line is written before Reboot returns.
		first, _, _ := strings.Cut(rig.logs.String(), "\n")
		for _, want := range []string{
			"reboot: requested by " + `"` + req.Reason + `"`,
			"mode=" + string(req.Mode),
			"delay=4s",
			"leaving boot boot-before",
			"(real)",
		} {
			if !strings.Contains(first, want) {
				t.Errorf("request line %q is missing %q", first, want)
			}
		}
	}
}
