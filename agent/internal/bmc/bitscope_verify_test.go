package bmc

import (
	"bytes"
	"context"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Tests for geekdojo/geekdojo-brain#617: a reset that reported success
// without the node resetting. The driver used to discard the replies to off
// and on, accept silence, and log nothing when a command succeeded.

// cycleScript is a cycle or reset that works: off, the status between (off),
// on, the status after (on).
var cycleScript = []string{
	"01|\\", "",
	"01|=\n01 ff 0 00 00", "",
	"01|/", "",
	"01|=\n01 ff 1 26 98", "",
}

// captureLog redirects the standard logger for one test.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// wroteOnAfterOff reports whether the on command was written after the off
// command.
func wroteOnAfterOff(wrote string) bool {
	off := strings.Index(wrote, `[01]|\`)
	on := strings.LastIndex(wrote, "[01]|/")
	return off >= 0 && on > off
}

func TestBitScope_ResetThatWorks(t *testing.T) {
	b, port := newBitScopeForTest(t, cycleScript...)
	state, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerReset)
	if err != nil {
		t.Fatalf("Power(reset): %v", err)
	}
	if state != proto.BMCStateOn {
		t.Errorf("state = %q, want on", state)
	}
	// off, status, on, status — four commands, four pipes closed.
	if n := strings.Count(port.wrote.String(), string(bitscopePipeClose)); n != 4 {
		t.Errorf("bus writes %q: want 4 commands each closing its pipe, got %d", port.wrote.String(), n)
	}
}

// A bus that returns nothing after a power verb is an error. It used to be
// indistinguishable from success.
func TestBitScope_SilentReplyToAPowerVerbFails(t *testing.T) {
	for _, tc := range []struct {
		verb proto.BMCPowerVerb
		name string
	}{
		{proto.BMCPowerOn, "on"},
		{proto.BMCPowerOff, "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The verb gets silence. A status reply is scripted after it
			// so that, if the driver went on to read status, the verb
			// would have passed the way it used to.
			b, _ := newBitScopeForTest(t, "", "01|=\n01 ff 1 26 98", "")
			state, _, err := b.Power(context.Background(), "node-a1", tc.verb)
			if err == nil {
				t.Fatalf("Power(%s) with a silent bus returned state %q and no error", tc.verb, state)
			}
			for _, want := range []string{"returned nothing", tc.name + " command", `node "node-a1"`, "pos A-1", "bus address 01"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// The off half of a reset was lost. The reset fails — and the node is still
// told to power on, so the driver's doubt cannot leave it off.
func TestBitScope_ResetWithASilentOffFailsAndStillSendsOn(t *testing.T) {
	b, port := newBitScopeForTest(t,
		"",                        // off: silence
		"01|=\n01 ff 1 26 98", "", // status between: still on
		"01|/", "", // on
		"01|=\n01 ff 1 26 98", "", // status after
	)
	state, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerReset)
	if err == nil {
		t.Fatal("a reset whose off command got no reply reported success")
	}
	for _, want := range []string{"returned nothing after the off command", "did NOT power off", `reports "on" after the off command`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to contain %q", err, want)
		}
	}
	if state != proto.BMCStateOn {
		t.Errorf("state = %q, want the state the BMC read back (on)", state)
	}
	if !wroteOnAfterOff(port.wrote.String()) {
		t.Errorf("bus writes %q: the on command must still be sent", port.wrote.String())
	}
}

// The node never lost power: the off command was echoed and the status
// between still says on. This is the shape of a slot that ignores power
// verbs. It used to be a successful reset.
func TestBitScope_ResetWhereTheNodeStaysOnFails(t *testing.T) {
	b, port := newBitScopeForTest(t,
		`01|\`, "",
		"01|=\n01 00 1 26 98", "", // still on
		"01|/", "",
		"01|=\n01 00 1 26 98", "",
	)
	_, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerReset)
	if err == nil {
		t.Fatal("a reset during which the node never powered off reported success")
	}
	for _, want := range []string{"did NOT power off", `node "node-a1"`, "pos A-1", "bus address 01"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to contain %q", err, want)
		}
	}
	if !wroteOnAfterOff(port.wrote.String()) {
		t.Errorf("bus writes %q: the on command must still be sent", port.wrote.String())
	}
}

// The status between off and on could not be read. Same rule: fail, and
// still power the node on.
func TestBitScope_ResetWithAnUnreadableStatusBetweenFails(t *testing.T) {
	b, port := newBitScopeForTest(t,
		`01|\`, "",
		"", // status between: silence
		"01|/", "",
		"01|=\n01 ff 1 26 98", "",
	)
	_, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerCycle)
	if err == nil || !strings.Contains(err.Error(), "could not read its power state after the off command") {
		t.Fatalf("err = %v, want the unread status named", err)
	}
	if !wroteOnAfterOff(port.wrote.String()) {
		t.Errorf("bus writes %q: the on command must still be sent", port.wrote.String())
	}
}

// An echo naming another address: the command went somewhere else.
func TestBitScope_EchoForAnotherAddressFails(t *testing.T) {
	b, _ := newBitScopeForTest(t, "04|/", "", "01|=\n01 ff 1 26 98", "")
	_, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerOn)
	if err == nil {
		t.Fatal("an on command echoed for another address reported success")
	}
	if !strings.Contains(err.Error(), "echoed for bus address 04") || !strings.Contains(err.Error(), "bus address 01") {
		t.Errorf("err = %q, want both addresses named", err)
	}
}

// Every command is logged — on success as well as on failure — with the node,
// where it sits, the bus address, the verb, what was written and what came
// back.
func TestBitScope_LogsEveryCommand(t *testing.T) {
	logs := captureLog(t)
	b, _ := newBitScopeForTest(t, cycleScript...)
	if _, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerReset); err != nil {
		t.Fatalf("Power(reset): %v", err)
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(logs()), "\n") {
		if strings.Contains(l, "bmc bitscope:") {
			lines = append(lines, l)
		}
	}
	wantVerbs := []string{"off", "status", "on", "status"}
	if len(lines) != len(wantVerbs) {
		t.Fatalf("logged %d command lines, want %d (one per command):\n%s", len(lines), len(wantVerbs), strings.Join(lines, "\n"))
	}
	for i, verb := range wantVerbs {
		for _, want := range []string{"sent verb=" + verb + " ", `node="node-a1"`, "pos=A-1", "addr=01", "wire=", "reply="} {
			if !strings.Contains(lines[i], want) {
				t.Errorf("line %d = %q, want it to contain %q", i, lines[i], want)
			}
		}
		if strings.Contains(lines[i], "error=") {
			t.Errorf("line %d = %q: a command that succeeded logged an error", i, lines[i])
		}
	}
	if !strings.Contains(lines[0], `wire="[01]|\\"`) || !strings.Contains(lines[2], `wire="[01]|/"`) {
		t.Errorf("lines = %q: want the exact bytes written for off and on", lines)
	}
	if !strings.Contains(lines[3], `01 ff 1 26 98`) {
		t.Errorf("status line = %q, want the reply that came back", lines[3])
	}
}

func TestBitScope_LogsACommandThatFailed(t *testing.T) {
	logs := captureLog(t)
	b, _ := newBitScopeForTest(t, "", "01|=\n01 ff 1 26 98", "")
	if _, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerOff); err == nil {
		t.Fatal("want an error")
	}
	got := logs()
	for _, want := range []string{"sent verb=off ", `node="node-a1"`, "addr=01", `reply=""`} {
		if !strings.Contains(got, want) {
			t.Errorf("logs = %q, want them to contain %q", got, want)
		}
	}
}

// The unlock sequence is a secret. It is written to the bus and never to the
// journal.
func TestBitScope_NeverLogsTheUnlockSecret(t *testing.T) {
	logs := captureLog(t)
	const secret = "per-cluster-unlock-5ekr1t"
	port := &fakePort{script: append([]string{
		"ok", "", // unlock
		"=\n01 00 1 22 88", "", // local status probe
	}, cycleScript...)}
	b := newBitScope(port, map[string]bitscopeTarget{"node-a1": {pos: "A-1", addr: 0x01}}, secret)
	b.settle = 0
	if err := b.unlockBus(); err != nil {
		t.Fatalf("unlockBus: %v", err)
	}
	if _, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerReset); err != nil {
		t.Fatalf("Power(reset): %v", err)
	}
	if !strings.Contains(port.wrote.String(), secret) {
		t.Fatal("the test did not exercise the unlock: the secret never reached the bus")
	}
	if strings.Contains(logs(), secret) {
		t.Errorf("the unlock secret is in the journal:\n%s", logs())
	}
}
