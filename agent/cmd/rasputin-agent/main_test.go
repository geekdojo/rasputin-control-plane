package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func TestAgentStateDir(t *testing.T) {
	// Unset (t.Setenv to "" — agentStateDir treats empty as unset):
	// dev default, relative, with the per-node suffix.
	t.Setenv("RASPUTIN_AGENT_STATE_DIR", "")
	if got, want := agentStateDir("node-dev"), filepath.Join("agent-state", "node-dev"); got != want {
		t.Errorf("default: got %q, want %q", got, want)
	}

	// Set: used verbatim — absolute, and NO nodeID suffix appended. The
	// rasputin-os systemd unit and the OpenWrt init script rely on this
	// (they point at a flat dir on persistent storage), as does the dev
	// workflow in the wiki's getting-started.md, which appends its own
	// per-node suffix.
	t.Setenv("RASPUTIN_AGENT_STATE_DIR", "/var/lib/rasputin/agent-state")
	if got, want := agentStateDir("node-dev"), "/var/lib/rasputin/agent-state"; got != want {
		t.Errorf("env override: got %q, want %q", got, want)
	}
}

func TestAutodetectUCIBackend(t *testing.T) {
	// No uci binary on PATH → mock, regardless of the config file.
	cfgDir := t.TempDir()
	cfg := filepath.Join(cfgDir, "firewall")
	if err := os.WriteFile(cfg, []byte("config defaults\n"), 0o644); err != nil {
		t.Fatalf("write fake firewall config: %v", err)
	}
	t.Setenv("PATH", t.TempDir()) // empty dir — nothing on PATH
	if got := autodetectUCIBackendAt(cfg); got != "mock" {
		t.Errorf("no uci on PATH: got %q, want mock", got)
	}

	// uci on PATH but no /etc/config/firewall (e.g. a dev box with a
	// stray uci binary) → mock.
	binDir := t.TempDir()
	fakeUCI := filepath.Join(binDir, "uci")
	if err := os.WriteFile(fakeUCI, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake uci: %v", err)
	}
	t.Setenv("PATH", binDir)
	if got := autodetectUCIBackendAt(filepath.Join(cfgDir, "missing")); got != "mock" {
		t.Errorf("uci without firewall config: got %q, want mock", got)
	}

	// Both present → uci (a real OpenWrt root).
	if got := autodetectUCIBackendAt(cfg); got != "uci" {
		t.Errorf("uci + firewall config: got %q, want uci", got)
	}
}

func TestUCIBackendSelectionEnvOverride(t *testing.T) {
	// Autodetect would say mock (nothing on PATH), but the env forces uci.
	t.Setenv("PATH", t.TempDir())
	t.Setenv("RASPUTIN_UCI_BACKEND", "uci")
	if got := envOr("RASPUTIN_UCI_BACKEND", autodetectUCIBackend()); got != "uci" {
		t.Errorf("env override: got %q, want uci", got)
	}
	// Empty env falls through to autodetect.
	t.Setenv("RASPUTIN_UCI_BACKEND", "")
	if got := envOr("RASPUTIN_UCI_BACKEND", autodetectUCIBackend()); got != "mock" {
		t.Errorf("autodetect fallback: got %q, want mock", got)
	}
}

func TestSplitCSV(t *testing.T) {
	cases := map[string][]string{
		"":            nil,
		"a":           {"a"},
		"a,b":         {"a", "b"},
		" a , b ,":    {"a", "b"},
		",,":          nil,
		"node-1, ,x2": {"node-1", "x2"},
	}
	for in, want := range cases {
		if got := splitCSV(in); !reflect.DeepEqual(got, want) {
			t.Errorf("splitCSV(%q) = %v, want %v", in, got, want)
		}
	}
}

// testBus starts an in-process NATS server so the real publish path can
// be exercised.
func testBus(t *testing.T) *nats.Conn {
	t.Helper()
	s, err := server.NewServer(&server.Options{Port: -1})
	if err != nil {
		t.Fatalf("nats server: %v", err)
	}
	go s.Start()
	t.Cleanup(s.Shutdown)
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	nc, err := nats.Connect(s.ClientURL())
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func registeredEvt(t *testing.T, nc *nats.Conn, nodeID string, adv *bmc.Advertisement) proto.NodeRegisteredEvt {
	t.Helper()
	sub, err := nc.SubscribeSync(proto.NodeRegisteredSubject(nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	publishRegistered(nc, nodeID, proto.RoleControlPlane, nil, adv)
	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("no registered event: %v", err)
	}
	var ev proto.NodeRegisteredEvt
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return ev
}

func TestPublishRegistered_AdvertisesBMCTargets(t *testing.T) {
	// Pins the wire format the api's inventory store and the UI decode:
	// capability tag in capabilities[], list + config hash + pin marker
	// under the proto.MetadataBMC* keys.
	nc := testBus(t)
	ev := registeredEvt(t, nc, "cp-test", &bmc.Advertisement{
		Targets: []string{"n-a", "n-b"}, ConfigHash: "h1", Pinned: true,
	})
	if !reflect.DeepEqual(ev.Capabilities, []string{proto.CapabilityBMCTargets}) {
		t.Errorf("capabilities: %v, want [%s]", ev.Capabilities, proto.CapabilityBMCTargets)
	}
	got, ok := ev.Metadata[proto.MetadataBMCTargets].([]any)
	if !ok || len(got) != 2 || got[0] != "n-a" || got[1] != "n-b" {
		t.Errorf("metadata %s: %v", proto.MetadataBMCTargets, ev.Metadata[proto.MetadataBMCTargets])
	}
	if ev.Metadata[proto.MetadataBMCConfigHash] != "h1" {
		t.Errorf("metadata %s: %v", proto.MetadataBMCConfigHash, ev.Metadata[proto.MetadataBMCConfigHash])
	}
	if ev.Metadata[proto.MetadataBMCConfigPinned] != true {
		t.Errorf("metadata %s: %v", proto.MetadataBMCConfigPinned, ev.Metadata[proto.MetadataBMCConfigPinned])
	}
}

func TestPublishRegistered_OffAdvertisesNothing(t *testing.T) {
	nc := testBus(t)
	ev := registeredEvt(t, nc, "cp-test", nil)
	for _, c := range ev.Capabilities {
		if c == proto.CapabilityBMCTargets {
			t.Errorf("capability advertised while off: %v", ev.Capabilities)
		}
	}
	for _, key := range []string{proto.MetadataBMCTargets, proto.MetadataBMCConfigHash, proto.MetadataBMCConfigPinned} {
		if _, present := ev.Metadata[key]; present {
			t.Errorf("metadata %s present while off: %v", key, ev.Metadata)
		}
	}
}
