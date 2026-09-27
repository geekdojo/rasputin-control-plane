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

// cycleScript is a cycle or reset that works, as the rack answers it: the
// power verbs get NO reply, and the two status reads say off, then on.
var cycleScript = []string{
	"",                        // off: nothing comes back
	"01|=\n01 ff 0 00 00", "", // status between: off
	"",                        // on: nothing comes back
	"01|=\n01 ff 1 26 98", "", // status after: on
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

// The BMC returns nothing after a power verb. Silence there is NOT an error:
// the status read that follows decides. (This test used to assert the
// opposite, on a guess about the protocol that the rack's operator corrected.)
func TestBitScope_SilentPowerVerbIsDecidedByTheStatusRead(t *testing.T) {
	for _, tc := range []struct {
		verb   proto.BMCPowerVerb
		status string
		want   proto.BMCPowerState
	}{
		{proto.BMCPowerOn, "01|=\n01 ff 1 26 98", proto.BMCStateOn},
		{proto.BMCPowerOff, "01|=\n01 ff 0 00 00", proto.BMCStateOff},
	} {
		t.Run(string(tc.verb), func(t *testing.T) {
			b, port := newBitScopeForTest(t, "", tc.status, "")
			state, _, err := b.Power(context.Background(), "node-a1", tc.verb)
			if err != nil {
				t.Fatalf("Power(%s) with a silent power verb and a matching status: %v", tc.verb, err)
			}
			if state != tc.want {
				t.Errorf("state = %q, want %q", state, tc.want)
			}
			if !strings.Contains(port.wrote.String(), "[01]|=") {
				t.Errorf("bus writes %q: the status read is the evidence and must be made", port.wrote.String())
			}
		})
	}
}

// A silent power verb followed by a status showing the WRONG state fails.
func TestBitScope_SilentPowerVerbThenTheWrongStateFails(t *testing.T) {
	for _, tc := range []struct {
		verb   proto.BMCPowerVerb
		status string
		got    proto.BMCPowerState
		want   []string
	}{
		{proto.BMCPowerOn, "01|=\n01 ff 0 00 00", proto.BMCStateOff, []string{`is "off" after the on command`, `"on" was intended`}},
		{proto.BMCPowerOff, "01|=\n01 ff 1 26 98", proto.BMCStateOn, []string{`is "on" after the off command`, `"off" was intended`}},
	} {
		t.Run(string(tc.verb), func(t *testing.T) {
			b, _ := newBitScopeForTest(t, "", tc.status, "")
			state, _, err := b.Power(context.Background(), "node-a1", tc.verb)
			if err == nil {
				t.Fatalf("Power(%s) left the node %q and reported success", tc.verb, state)
			}
			if state != tc.got {
				t.Errorf("state = %q, want the state the BMC read back (%q)", state, tc.got)
			}
			for _, want := range append(tc.want, `node "node-a1"`, "pos A-1", "bus address 01") {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// A silent power verb followed by a SILENT status fails: the status is the
// evidence, and there is none.
func TestBitScope_SilentPowerVerbThenASilentStatusFails(t *testing.T) {
	for _, verb := range []proto.BMCPowerVerb{proto.BMCPowerOn, proto.BMCPowerOff} {
		t.Run(string(verb), func(t *testing.T) {
			b, _ := newBitScopeForTest(t, "", "")
			state, _, err := b.Power(context.Background(), "node-a1", verb)
			if err == nil {
				t.Fatalf("Power(%s) with no status reply reported success (state %q)", verb, state)
			}
			if state != proto.BMCStateUnknown {
				t.Errorf("state = %q, want unknown", state)
			}
			for _, want := range []string{"returned nothing to the status command", `node "node-a1"`, "bus address 01"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// A status that answers for another address fails, as it always did.
func TestBitScope_StatusForAnotherAddressFails(t *testing.T) {
	b, _ := newBitScopeForTest(t, "", "04|=\n04 ff 1 26 98", "")
	if _, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerOn); err == nil ||
		!strings.Contains(err.Error(), "expected 01") {
		t.Fatalf("err = %v, want the status reply refused for naming another node", err)
	}
}

// The node never lost power: the status between still says on. This is the
// shape of a slot that ignores power verbs, and of an off that was lost. The
// reset fails — and the node is still told to power on, so the driver's doubt
// cannot leave it off.
func TestBitScope_ResetWhereTheNodeStaysOnFails(t *testing.T) {
	b, port := newBitScopeForTest(t,
		"",                        // off
		"01|=\n01 00 1 26 98", "", // status between: still on
		"",                        // on
		"01|=\n01 00 1 26 98", "", // status after
	)
	state, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerReset)
	if err == nil {
		t.Fatal("a reset during which the node never powered off reported success")
	}
	for _, want := range []string{"did NOT power off", `reports "on" after the off command`, `node "node-a1"`, "pos A-1", "bus address 01"} {
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

// The status between off and on could not be read. Same rule: fail, and
// still power the node on.
func TestBitScope_ResetWithASilentStatusBetweenFails(t *testing.T) {
	b, port := newBitScopeForTest(t,
		"", // off
		"", // status between: silence
		"", // on
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

// The node went off and did not come back on.
func TestBitScope_ResetThatLeavesTheNodeOffFails(t *testing.T) {
	b, _ := newBitScopeForTest(t,
		"",
		"01|=\n01 ff 0 00 00", "",
		"",
		"01|=\n01 ff 0 00 00", "", // still off after on
	)
	state, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerReset)
	if err == nil || !strings.Contains(err.Error(), `is "off" after the reset command`) {
		t.Fatalf("err = %v, want the node reported off after the reset", err)
	}
	if state != proto.BMCStateOff {
		t.Errorf("state = %q, want off", state)
	}
}

// Bytes that DO arrive after a power verb are logged and never fail the verb,
// whatever they are — including a line naming another address, which the
// journal points out.
func TestBitScope_BytesAfterAPowerVerbAreLoggedNotFailed(t *testing.T) {
	for _, reply := range []string{"01|/", "ok", "04|/"} {
		t.Run(reply, func(t *testing.T) {
			logs := captureLog(t)
			b, _ := newBitScopeForTest(t, reply, "", "01|=\n01 ff 1 26 98", "")
			if _, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerOn); err != nil {
				t.Fatalf("Power(on) failed on the reply %q to the power verb: %v", reply, err)
			}
			if !strings.Contains(logs(), `reply="`+reply+`"`) {
				t.Errorf("logs = %q, want the reply %q in them", logs(), reply)
			}
			if named := strings.Contains(logs(), "names bus address 04"); named != (reply == "04|/") {
				t.Errorf("logs = %q: foreign-address note present=%v for reply %q", logs(), named, reply)
			}
		})
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
	// No reply to a power verb is normal and is written as that.
	for _, i := range []int{0, 2} {
		if !strings.HasSuffix(lines[i], "reply=(none)") {
			t.Errorf("line %d = %q, want it to end reply=(none)", i, lines[i])
		}
	}
	if !strings.Contains(lines[3], `01 ff 1 26 98`) {
		t.Errorf("status line = %q, want the reply that came back", lines[3])
	}
}

func TestBitScope_LogsAFailedVerbsCommands(t *testing.T) {
	logs := captureLog(t)
	b, _ := newBitScopeForTest(t, "", "")
	if _, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerOff); err == nil {
		t.Fatal("want an error: the status read got nothing")
	}
	got := logs()
	for _, want := range []string{"sent verb=off ", "sent verb=status ", `node="node-a1"`, "addr=01", "reply=(none)"} {
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
