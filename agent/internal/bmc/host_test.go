package bmc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// attachHost wires h to a fresh in-process bus and returns the client
// connection plus a re-registration counter.
func attachHost(t *testing.T, h *Host) (*nats.Conn, *int) {
	t.Helper()
	nc := startNATS(t)
	count := 0
	if err := h.Attach(nc, func() { count++ }); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(h.Shutdown)
	return nc, &count
}

func TestHost_BootOffByDefault(t *testing.T) {
	h, err := NewHost("n1", t.TempDir(), "", Config{})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	if h.Active() || h.Advertisement() != nil {
		t.Error("fresh host must be off with no advertisement")
	}
}

func TestHost_ConfigureTurnsOnAndPersists(t *testing.T) {
	dir := t.TempDir()
	h, err := NewHost("n1", dir, "", Config{})
	if err != nil {
		t.Fatal(err)
	}
	nc, rereg := attachHost(t, h)

	var ack proto.BMCConfigureAck
	request(t, nc, proto.BMCConfigureSubject("n1"), proto.BMCConfigureCmd{
		Kind: "mock", Config: json.RawMessage(`{"targets":["node-x"]}`), ConfigHash: "h1",
	}, &ack)
	if !ack.OK || ack.ConfigHash != "h1" {
		t.Fatalf("configure ack: %+v", ack)
	}
	adv := h.Advertisement()
	if adv == nil || adv.ConfigHash != "h1" || len(adv.Targets) != 1 || adv.Targets[0] != "node-x" {
		t.Fatalf("advertisement: %+v", adv)
	}
	if *rereg == 0 {
		t.Error("configure must trigger re-registration")
	}
	// Persisted for boot re-apply
	if _, err := os.Stat(filepath.Join(dir, hostConfigFile)); err != nil {
		t.Errorf("persisted selection missing: %v", err)
	}
	// Power handlers now live: a power status RPC answers.
	var pack proto.BMCPowerAck
	request(t, nc, proto.BMCPowerSubject("n1", proto.BMCPowerQuery),
		proto.BMCPowerCmd{TargetNodeID: "node-x"}, &pack)
	if !pack.OK {
		t.Errorf("power status after configure: %+v", pack)
	}
}

func TestHost_DeconfigureGoesHardOff(t *testing.T) {
	dir := t.TempDir()
	h, err := NewHost("n1", dir, "", Config{})
	if err != nil {
		t.Fatal(err)
	}
	nc, _ := attachHost(t, h)

	var ack proto.BMCConfigureAck
	request(t, nc, proto.BMCConfigureSubject("n1"), proto.BMCConfigureCmd{
		Kind: "mock", Config: json.RawMessage(`{"targets":["node-x"]}`), ConfigHash: "h1",
	}, &ack)
	if !ack.OK {
		t.Fatal(ack.Detail)
	}
	request(t, nc, proto.BMCConfigureSubject("n1"), proto.BMCConfigureCmd{Kind: BackendNone}, &ack)
	if !ack.OK {
		t.Fatalf("deconfigure: %+v", ack)
	}
	if h.Active() || h.Advertisement() != nil {
		t.Error("deconfigure must go hard off")
	}
	if _, err := os.Stat(filepath.Join(dir, hostConfigFile)); !os.IsNotExist(err) {
		t.Error("persisted selection must be cleared")
	}
}

func TestHost_BootReappliesPersistedSelection(t *testing.T) {
	dir := t.TempDir()
	sel := proto.BMCConfigureCmd{
		Kind: "mock", Config: json.RawMessage(`{"targets":["node-y"]}`), ConfigHash: "h9",
	}
	if err := persistSelection(dir, sel); err != nil {
		t.Fatal(err)
	}
	h, err := NewHost("n1", dir, "", Config{})
	if err != nil {
		t.Fatal(err)
	}
	adv := h.Advertisement()
	if adv == nil || adv.ConfigHash != "h9" || len(adv.Targets) != 1 || adv.Targets[0] != "node-y" {
		t.Fatalf("boot re-apply advertisement: %+v", adv)
	}
}

func TestHost_EnvPinNacksConfigure(t *testing.T) {
	h, err := NewHost("n1", t.TempDir(), "mock", Config{StateDir: t.TempDir(), MockTargets: []string{"pin-t"}})
	if err != nil {
		t.Fatal(err)
	}
	nc, _ := attachHost(t, h)

	adv := h.Advertisement()
	if adv == nil || !adv.Pinned || adv.ConfigHash != "" {
		t.Fatalf("pinned advertisement: %+v", adv)
	}
	var ack proto.BMCConfigureAck
	request(t, nc, proto.BMCConfigureSubject("n1"), proto.BMCConfigureCmd{
		Kind: "mock", Config: json.RawMessage(`{"targets":["other"]}`), ConfigHash: "h1",
	}, &ack)
	if ack.OK || !strings.Contains(ack.Detail, "pinned") {
		t.Fatalf("pinned host must nack with the pin detail: %+v", ack)
	}
}

func TestHost_BadSelectionRollsBack(t *testing.T) {
	dir := t.TempDir()
	h, err := NewHost("n1", dir, "", Config{})
	if err != nil {
		t.Fatal(err)
	}
	nc, _ := attachHost(t, h)

	var ack proto.BMCConfigureAck
	request(t, nc, proto.BMCConfigureSubject("n1"), proto.BMCConfigureCmd{
		Kind: "mock", Config: json.RawMessage(`{"targets":["good"]}`), ConfigHash: "h1",
	}, &ack)
	if !ack.OK {
		t.Fatal(ack.Detail)
	}
	// bitscope with an empty target list is invalid — construction fails
	// before any hardware is touched, and the previous selection returns.
	request(t, nc, proto.BMCConfigureSubject("n1"), proto.BMCConfigureCmd{
		Kind: "bitscope", Config: json.RawMessage(`{"targets":[]}`), ConfigHash: "h2",
	}, &ack)
	if ack.OK {
		t.Fatal("invalid selection must nack")
	}
	if !strings.Contains(ack.Detail, "restored") {
		t.Errorf("detail should mention rollback: %q", ack.Detail)
	}
	adv := h.Advertisement()
	if adv == nil || adv.ConfigHash != "h1" || len(adv.Targets) != 1 || adv.Targets[0] != "good" {
		t.Fatalf("rollback advertisement: %+v", adv)
	}
}
