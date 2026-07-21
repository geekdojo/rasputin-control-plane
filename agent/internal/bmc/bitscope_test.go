package bmc

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// fakePort scripts the bus side of a conversation. Each Read pops one
// entry; an empty entry (and script exhaustion) reads as io.EOF — the
// quiet-line timeout readReply expects. Writes are captured verbatim.
type fakePort struct {
	script []string
	wrote  bytes.Buffer
	closed bool
}

func (p *fakePort) Read(b []byte) (int, error) {
	if len(p.script) == 0 {
		return 0, io.EOF
	}
	s := p.script[0]
	p.script = p.script[1:]
	if s == "" {
		return 0, io.EOF
	}
	return copy(b, s), nil
}

func (p *fakePort) Write(b []byte) (int, error) { return p.wrote.Write(b) }
func (p *fakePort) Close() error                { p.closed = true; return nil }
func (p *fakePort) DrainInput() error           { return nil }

// newBitScopeForTest wires a backend onto a scripted port with no
// cycle settle delay.
func newBitScopeForTest(t *testing.T, script ...string) (*BitScopeBackend, *fakePort) {
	t.Helper()
	port := &fakePort{script: script}
	targets := map[string]bitscopeTarget{
		"node-a1": {pos: "A-1", addr: 0x01},
		"node-f3": {pos: "F-3", addr: 0x17},
	}
	b := newBitScope(port, targets, bitscopeDefaultUnlock)
	b.settle = 0
	return b, port
}

func TestBitScope_NameIsBitscope(t *testing.T) {
	b, _ := newBitScopeForTest(t)
	if b.Name() != "bitscope" {
		t.Errorf("Name: %q, want bitscope", b.Name())
	}
}

func TestBitScope_PowerOn(t *testing.T) {
	// Round 1: '/' verb ack. Round 2: '=' status reply.
	b, port := newBitScopeForTest(t, "ok", "", "ENABLED", "")
	state, detail, err := b.Power(context.Background(), "node-a1", proto.BMCPowerOn)
	if err != nil {
		t.Fatalf("Power(on): %v", err)
	}
	if state != proto.BMCStateOn {
		t.Errorf("state: %q, want on", state)
	}
	if !strings.Contains(detail, "powered on") {
		t.Errorf("detail: %q, want powered on", detail)
	}
	got := port.wrote.String()
	if !strings.Contains(got, "01|/") || !strings.Contains(got, "01|=") {
		t.Errorf("bus writes %q, want 01|/ then 01|=", got)
	}
}

func TestBitScope_PowerOffDecodesOff(t *testing.T) {
	b, port := newBitScopeForTest(t, "ok", "", "OFF", "")
	state, _, err := b.Power(context.Background(), "node-f3", proto.BMCPowerOff)
	if err != nil {
		t.Fatalf("Power(off): %v", err)
	}
	if state != proto.BMCStateOff {
		t.Errorf("state: %q, want off", state)
	}
	got := port.wrote.String()
	if !strings.Contains(got, `17|\`) || !strings.Contains(got, "17|=") {
		t.Errorf(`bus writes %q, want 17|\ then 17|=`, got)
	}
}

func TestBitScope_CycleSendsOffThenOn(t *testing.T) {
	b, port := newBitScopeForTest(t, "ok", "", "ok", "", "ENABLED", "")
	state, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerCycle)
	if err != nil {
		t.Fatalf("Power(cycle): %v", err)
	}
	if state != proto.BMCStateOn {
		t.Errorf("state: %q, want on", state)
	}
	got := port.wrote.String()
	off := strings.Index(got, `01|\`)
	on := strings.Index(got, "01|/")
	if off < 0 || on < 0 || off > on {
		t.Errorf("bus writes %q, want off before on", got)
	}
}

func TestBitScope_ResetDisclosesHardCycle(t *testing.T) {
	// D-1: reset is a hard power-cycle and the detail must say so.
	b, _ := newBitScopeForTest(t, "ok", "", "ok", "", "ENABLED", "")
	_, detail, err := b.Power(context.Background(), "node-a1", proto.BMCPowerReset)
	if err != nil {
		t.Fatalf("Power(reset): %v", err)
	}
	if !strings.Contains(detail, "no reset line") {
		t.Errorf("detail: %q, want the no-reset-line disclosure", detail)
	}
}

func TestBitScope_StatusDisabledIsOffWithDetail(t *testing.T) {
	// D-2: DISABLED decodes to off, disclosed in the detail.
	b, _ := newBitScopeForTest(t, "DISABLED", "")
	state, detail, err := b.Power(context.Background(), "node-a1", proto.BMCPowerQuery)
	if err != nil {
		t.Fatalf("Power(status): %v", err)
	}
	if state != proto.BMCStateOff {
		t.Errorf("state: %q, want off", state)
	}
	if !strings.Contains(detail, "disabled") {
		t.Errorf("detail: %q, want disabled", detail)
	}
}

func TestBitScope_GarbageReplyIsUnknownError(t *testing.T) {
	b, _ := newBitScopeForTest(t, "%$#!", "")
	state, _, err := b.Power(context.Background(), "node-a1", proto.BMCPowerQuery)
	if err == nil {
		t.Fatal("Power(status) on garbage reply: expected error")
	}
	if state != proto.BMCStateUnknown {
		t.Errorf("state: %q, want unknown", state)
	}
}

func TestBitScope_UnmappedTargetErrors(t *testing.T) {
	b, port := newBitScopeForTest(t)
	_, _, err := b.Power(context.Background(), "node-nope", proto.BMCPowerOn)
	if err == nil || !strings.Contains(err.Error(), "address map") {
		t.Fatalf("expected address-map error, got %v", err)
	}
	if port.wrote.Len() != 0 {
		t.Errorf("unmapped target must not touch the bus, wrote %q", port.wrote.String())
	}
}

func TestBitScope_UnlockWritesSequence(t *testing.T) {
	b, port := newBitScopeForTest(t, "ok", "")
	if err := b.unlockBus(); err != nil {
		t.Fatalf("unlockBus: %v", err)
	}
	if !strings.Contains(port.wrote.String(), bitscopeDefaultUnlock) {
		t.Errorf("bus writes %q, want the unlock sequence", port.wrote.String())
	}
}

func TestBitScope_OpenSOLNotImplemented(t *testing.T) {
	b, _ := newBitScopeForTest(t)
	if _, err := b.OpenSOL(context.Background(), "node-a1", "sess"); err == nil {
		t.Fatal("OpenSOL: expected not-implemented error")
	}
}

func TestParseBitScopePos(t *testing.T) {
	good := map[string]byte{"A-0": 0x00, "A-1": 0x01, "b-2": 0x06, "F-3": 0x17}
	for pos, want := range good {
		got, err := parseBitScopePos(pos)
		if err != nil {
			t.Errorf("parse %q: %v", pos, err)
			continue
		}
		if got != want {
			t.Errorf("parse %q: %#02x, want %#02x", pos, got, want)
		}
	}
	for _, bad := range []string{"", "G-0", "A-4", "A0", "AA-1"} {
		if _, err := parseBitScopePos(bad); err == nil {
			t.Errorf("parse %q: expected error", bad)
		}
	}
}

func writeMap(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bitscope-map.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadBitScopeMap(t *testing.T) {
	path := writeMap(t, `{"targets": [
		{"pos": "A-0", "node_id": "node-a0", "serial": "6001df8e"},
		{"pos": "F-3", "node_id": "node-f3"}
	]}`)
	targets, err := loadBitScopeMap(path)
	if err != nil {
		t.Fatalf("loadBitScopeMap: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets: %d, want 2", len(targets))
	}
	if targets["node-a0"].addr != 0x00 || targets["node-f3"].addr != 0x17 {
		t.Errorf("derived addrs wrong: %+v", targets)
	}
	if targets["node-a0"].serial != "6001df8e" {
		t.Errorf("serial not kept: %+v", targets["node-a0"])
	}
}

func TestLoadBitScopeMap_Rejects(t *testing.T) {
	cases := map[string]string{
		"missing node_id": `{"targets": [{"pos": "A-0"}]}`,
		"bad pos":         `{"targets": [{"pos": "Z-9", "node_id": "n"}]}`,
		"duplicate pos":   `{"targets": [{"pos": "A-0", "node_id": "a"}, {"pos": "a-0", "node_id": "b"}]}`,
		"duplicate node":  `{"targets": [{"pos": "A-0", "node_id": "a"}, {"pos": "A-1", "node_id": "a"}]}`,
		"empty":           `{"targets": []}`,
	}
	for name, content := range cases {
		if _, err := loadBitScopeMap(writeMap(t, content)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestNew_BitscopeWithoutMapErrors(t *testing.T) {
	// Registered in the registry, but constructing without an address
	// map must fail loudly before any hardware is touched.
	if _, err := New("bitscope", Config{StateDir: t.TempDir()}); err == nil {
		t.Fatal("New(bitscope) without a map: expected error")
	}
}
