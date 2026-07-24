package bmc

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
	b, port := newBitScopeForTest(t, "ok", "", "01|=\n01 ff 1 26 98", "")
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
	b, port := newBitScopeForTest(t, "ok", "", "17|=\n17 ff 0 00 00", "")
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
	b, port := newBitScopeForTest(t, "ok", "", "ok", "", "01|=\n01 ff 1 26 98", "")
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
	b, _ := newBitScopeForTest(t, "ok", "", "ok", "", "01|=\n01 ff 1 26 98", "")
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
	b, _ := newBitScopeForTest(t, "01|=\n01 ff 2 26 98", "")
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

func TestBitScope_OpenSOLUnmappedTargetErrors(t *testing.T) {
	b, _ := newBitScopeForTest(t)
	if _, err := b.OpenSOL(context.Background(), "node-nope", "sess"); err == nil {
		t.Fatal("OpenSOL: expected address-map error")
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

func TestBitscopeSettings_Defaults(t *testing.T) {
	dev, unlock, mapPath := bitscopeSettings(Config{StateDir: "/sd"})
	if dev != "/dev/serial0" {
		t.Errorf("dev: %q, want /dev/serial0", dev)
	}
	if unlock != "UnLockMe" {
		t.Errorf("unlock: %q, want the EEPROM default", unlock)
	}
	if mapPath != filepath.Join("/sd", "bitscope-map.json") {
		t.Errorf("mapPath: %q", mapPath)
	}
}

func TestBitscopeSettings_Overrides(t *testing.T) {
	dev, unlock, mapPath := bitscopeSettings(Config{
		StateDir:       "/sd",
		BitScopeDev:    "/dev/ttyUSB7",
		BitScopeUnlock: "sekrit",
		BitScopeMap:    "/etc/map.json",
	})
	if dev != "/dev/ttyUSB7" || unlock != "sekrit" || mapPath != "/etc/map.json" {
		t.Errorf("overrides not honored: %q %q %q", dev, unlock, mapPath)
	}
}

func TestBitScope_TimingDefaults(t *testing.T) {
	// The settle delay and read budget are contract-adjacent (the cycle
	// off→on gap, the reply-collection cap) — pin their defaults.
	b := newBitScope(&fakePort{}, nil, bitscopeDefaultUnlock)
	if b.settle != 2*time.Second {
		t.Errorf("settle: %v, want 2s", b.settle)
	}
	if b.readBudget != 2*time.Second {
		t.Errorf("readBudget: %v, want 2s", b.readBudget)
	}
}

func TestBitScope_TargetsSorted(t *testing.T) {
	b, _ := newBitScopeForTest(t)
	got := b.Targets()
	if len(got) != 2 || got[0] != "node-a1" || got[1] != "node-f3" {
		t.Errorf("Targets: %v, want [node-a1 node-f3]", got)
	}
}

func TestNewBitScopeBackend_PortOpenFails(t *testing.T) {
	// Valid map, hopeless device: the map must parse first, then the
	// port open must fail loudly (stub error off-linux, ENOENT on it).
	mapPath := writeMap(t, `{"targets": [{"pos": "A-0", "node_id": "n0"}]}`)
	_, err := NewBitScopeBackend(Config{
		BitScopeMap: mapPath,
		BitScopeDev: filepath.Join(t.TempDir(), "no-such-tty"),
	})
	if err == nil {
		t.Fatal("expected port-open error")
	}
}

func TestNew_BitscopeWithoutMapErrors(t *testing.T) {
	// Registered in the registry, but constructing without an address
	// map must fail loudly before any hardware is touched.
	if _, err := New("bitscope", Config{StateDir: t.TempDir()}); err == nil {
		t.Fatal("New(bitscope) without a map: expected error")
	}
}

func TestNewFromSelection_BitscopeHonorsCustomDev(t *testing.T) {
	// The dev default branch: a custom device must be the one opened —
	// the open error names it (the stub error off-linux doesn't, so
	// assert only where the real port code runs).
	_, err := NewFromSelection("bitscope",
		[]byte(`{"dev":"/definitely/custom-tty","targets":[{"pos":"A-0","node_id":"n0"}]}`), t.TempDir())
	if err == nil {
		t.Fatal("expected open error")
	}
	if runtime.GOOS == "linux" && !strings.Contains(err.Error(), "/definitely/custom-tty") {
		t.Errorf("error should name the custom device: %v", err)
	}
}

func TestNewFromSelection_MockAndUnknown(t *testing.T) {
	b, err := NewFromSelection("mock", []byte(`{"targets":["a","b"]}`), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Targets(); len(got) != 2 {
		t.Errorf("mock targets: %v", got)
	}
	if _, err := NewFromSelection("bogus", []byte(`{}`), t.TempDir()); err == nil {
		t.Error("unknown kind must error")
	}
}

func TestDecodeBitScopeState_LiveCapture(t *testing.T) {
	// The exact first reply the rack ever gave us (2026-07-22, c05/B-0):
	// command echo, then ID MS XX YY ZZ.
	state, detail, err := decodeBitScopeState(0x04, "04|=\n04 ff 1 26 98")
	if err != nil {
		t.Fatalf("live capture: %v", err)
	}
	if state != proto.BMCStateOn {
		t.Errorf("state: %q, want on", state)
	}
	if !strings.Contains(detail, "current=0x26") || !strings.Contains(detail, "fan=0x98") {
		t.Errorf("detail: %q, want telemetry fields", detail)
	}
}

func TestDecodeBitScopeState_TokensAndGuards(t *testing.T) {
	if st, d, err := decodeBitScopeState(0x04, "04 ff 0 00 00"); err != nil || st != proto.BMCStateOff || strings.Contains(d, "disabled") {
		t.Errorf("token 0: %v %q %v", st, d, err)
	}
	if st, d, err := decodeBitScopeState(0x04, "04 ff 2 10 20"); err != nil || st != proto.BMCStateOff || !strings.Contains(d, "disabled") {
		t.Errorf("token 2: %v %q %v", st, d, err)
	}
	// Mis-routed reply: another node's address must never be trusted.
	if _, _, err := decodeBitScopeState(0x04, "05 ff 1 26 98"); err == nil {
		t.Error("wrong-address reply must error")
	}
	// Unknown token, short reply, garbage.
	if _, _, err := decodeBitScopeState(0x04, "04 ff 9 26 98"); err == nil {
		t.Error("unknown token must error")
	}
	if _, _, err := decodeBitScopeState(0x04, "%$#!"); err == nil {
		t.Error("garbage must error")
	}
	// Minimal three-field reply still decodes (older firmware safety).
	if st, _, err := decodeBitScopeState(0x04, "04 ff 1"); err != nil || st != proto.BMCStateOn {
		t.Errorf("three-field: %v %v", st, err)
	}
}
