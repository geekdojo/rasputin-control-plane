package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/configfault"
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
	return registeredEvtWithFaults(t, nc, nodeID, adv, nil)
}

// registeredEvtWithFaults is registeredEvt plus the startup config-fault set,
// so the reporting half of #89 can be exercised on the real publish path.
func registeredEvtWithFaults(t *testing.T, nc *nats.Conn, nodeID string, adv *bmc.Advertisement, faults *configfault.Set) proto.NodeRegisteredEvt {
	t.Helper()
	sub, err := nc.SubscribeSync(proto.NodeRegisteredSubject(nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	// A fixed resolver rather than the live host one: this helper asserts what
	// the publish path CARRIES, and reading the test machine's own routing
	// table would make that assertion depend on where the suite runs.
	lanAddr := func() (string, string) { return "192.168.1.50", "192.168.1.50/24" }
	publishRegistered(nc, nodeID, proto.RoleControlPlane, nil, adv, faults, lanAddr)
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

// TestBMCConfigFromEnvCoversEveryField is a drift guard, not a value
// check: it sets every RASPUTIN_BMC_* driver var and then walks
// bmc.Config by reflection asserting nothing is left at its zero value.
//
// The turingpi driver shipped with six env vars that registry.go
// documented and main.go never read (CP #46). Construction failed with
// "endpoint is required" and log.Fatalf took the agent down at boot —
// found on the bench, not by the suite, because every backend test
// builds Config directly and never exercises the env path.
//
// So this asserts the seam rather than the driver. Add a field to
// bmc.Config without an env read here and this test names it.
func TestBMCConfigFromEnvCoversEveryField(t *testing.T) {
	for k, v := range map[string]string{
		"RASPUTIN_BMC_BITSCOPE_DEV":         "/dev/ttyS0",
		"RASPUTIN_BMC_BITSCOPE_UNLOCK":      "unlock",
		"RASPUTIN_BMC_BITSCOPE_MAP":         "/tmp/bitscope-map.json",
		"RASPUTIN_BMC_MOCK_TARGETS":         "mock-a,mock-b",
		"RASPUTIN_BMC_TURINGPI_ENDPOINT":    "turingpi.local",
		"RASPUTIN_BMC_TURINGPI_USER":        "root",
		"RASPUTIN_BMC_TURINGPI_PASS":        "turing",
		"RASPUTIN_BMC_TURINGPI_MAP":         "tp-cp1:1,tp-n1:2",
		"RASPUTIN_BMC_TURINGPI_FINGERPRINT": "41:7C:1E:EA",
		"RASPUTIN_BMC_TURINGPI_INSECURE":    "true",
	} {
		t.Setenv(k, v)
	}

	cfg := bmcConfigFromEnv("/var/lib/rasputin/agent/bmc")
	rv := reflect.ValueOf(cfg)
	for i := 0; i < rv.NumField(); i++ {
		if rv.Field(i).IsZero() {
			t.Errorf("bmc.Config.%s is zero after bmcConfigFromEnv — no env var feeds it, "+
				"so the setting is unreachable in a deployed agent",
				rv.Type().Field(i).Name)
		}
	}
}

// TestEnvBool pins the fail-closed reading: only an explicit true-ish
// value enables the flag. TuringPiInsecure disables TLS verification, so
// a typo'd value must read false rather than "not false".
func TestEnvBool(t *testing.T) {
	for _, v := range []string{"true", "1", "TRUE", "T"} {
		t.Setenv("RASPUTIN_TEST_BOOL", v)
		if !envBool("RASPUTIN_TEST_BOOL") {
			t.Errorf("envBool(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "false", "0", "yes", "on", "maybe", "  "} {
		t.Setenv("RASPUTIN_TEST_BOOL", v)
		if envBool("RASPUTIN_TEST_BOOL") {
			t.Errorf("envBool(%q) = true, want false", v)
		}
	}
}

// --- cluster name derivation (ADR-0003) --------------------------------------

// Both agent call sites — the name guard on the controlplane, hostsync on the
// firewall — mean the SAME name, and both used to hardcode "rasputin.local".
func TestClusterName(t *testing.T) {
	t.Setenv("RASPUTIN_CLUSTER_ID", "home1")
	if got := clusterName(); got != "home1.local" {
		t.Errorf("clusterName() = %q, want home1.local", got)
	}
	t.Setenv("RASPUTIN_CLUSTER_ID", "  home1  ")
	if got := clusterName(); got != "home1.local" {
		t.Errorf("clusterName() = %q, want the id trimmed (a hand-edited node.env can carry padding)", got)
	}
}

// The no-migration promise: an unset or empty cluster id must derive exactly
// the literal both call sites hardcoded before this change. If this drifts, a
// firewall republishes the wrong name into dnsmasq and tailscaled loses the
// mesh login server.
func TestClusterNameDefaultsToTodaysLiteral(t *testing.T) {
	for _, v := range []string{"", "   "} {
		t.Setenv("RASPUTIN_CLUSTER_ID", v)
		if got := clusterName(); got != "rasputin.local" {
			t.Errorf("clusterName() with id %q = %q, want rasputin.local — existing nodes would rename", v, got)
		}
	}
}

// FaultFailHealth drives the mark-bad branch of the update saga — the one that
// unconfirms inventory instead of recording a version, because a node on the
// new slot that is about to revert has no version worth writing. The reply has
// to be shaped exactly like a genuine health failure, or the api takes a
// different path than it would in the real thing and the round proves nothing.
func TestHandleHealth_FaultReportsUnhealthyWithoutChangingTheReplyShape(t *testing.T) {
	nc := testBus(t)
	const nodeID = "n"

	ask := func(t *testing.T, inject bool) proto.DiagHealthAck {
		t.Helper()
		subj := proto.NodeCmdSubject(nodeID, "diag.health."+map[bool]string{true: "fault", false: "clean"}[inject])
		sub, err := nc.Subscribe(subj, func(m *nats.Msg) {
			handleHealth(context.Background(), nodeID, proto.RoleCompute, m, inject)
		})
		if err != nil {
			t.Fatalf("subscribe: %v", err)
		}
		defer func() { _ = sub.Unsubscribe() }()

		cmd, _ := json.Marshal(proto.DiagHealthCmd{JobID: "job-1"})
		msg, err := nc.Request(subj, cmd, 15*time.Second)
		if err != nil {
			t.Fatalf("health rpc: %v", err)
		}
		var ack proto.DiagHealthAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			t.Fatalf("ack: %v", err)
		}
		return ack
	}

	faulted := ask(t, true)
	if faulted.OK {
		t.Error("armed fault must report NOT ok")
	}
	if faulted.Detail == "" {
		t.Error("a failure with no detail gives the operator nothing to go on")
	}
	// The identifying fields must survive the injection — the api correlates on
	// them, and a fault that also broke correlation would fail for the wrong
	// reason.
	if faulted.JobID != "job-1" {
		t.Errorf("JobID = %q, want it preserved through the injection", faulted.JobID)
	}
	if faulted.NodeID != nodeID {
		t.Errorf("NodeID = %q, want %q", faulted.NodeID, nodeID)
	}

	// And unarmed, the same handler must report the real battery's verdict —
	// otherwise the test above is measuring a broken handler, not a fault.
	clean := ask(t, false)
	if clean.JobID != "job-1" || clean.NodeID != nodeID {
		t.Errorf("clean ack lost its identity fields: %+v", clean)
	}
	if clean.Detail == faulted.Detail && clean.Detail != "" {
		t.Errorf("clean and faulted details are identical (%q) — the fault is not distinguishable", clean.Detail)
	}
}

// ⚠️ THE #89 REGRESSION GUARD, and it reads the source on purpose.
//
// Six environment-selected switches used to reject an unrecognised value with
// log.Fatalf. On an appliance that is not a loud failure: rasputin-agent.service
// pairs Restart=always with RestartSec=2, node.env is hand-edited on the
// persistent partition, and / is read-only — so one typo permanently prevents
// the agent from starting, on a box whose only remaining door is SSH. Confirmed
// on hardware 2026-07-28 (tp-cp1, RASPUTIN_BMC_BACKEND), where the api kept
// serving a UI for a controlplane that no longer had an agent.
//
// A behavioural test would have to start the process and prove a negative about
// something that does not happen, which is slow and flaky. Scanning the source
// is blunt but it pins the exact property that regressed, and it is the check
// that would have caught the seventh instance this campaign added and removed.
// If a genuinely fatal use of one of these variables is ever justified, this
// test is the place to argue it — not a silent edit.
func TestNoConfigVariableIsFatal(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	vars := []string{
		"RASPUTIN_NODE_ROLE",
		"RASPUTIN_BMC_BACKEND",
		"RASPUTIN_DOCKER_BACKEND",
		"RASPUTIN_UCI_BACKEND",
		"RASPUTIN_UPDATE_BACKEND",
		"RASPUTIN_TAILSCALE_BACKEND",
	}
	for _, line := range strings.Split(string(src), "\n") {
		if !strings.Contains(line, "log.Fatalf") {
			continue
		}
		for _, v := range vars {
			if strings.Contains(line, v) {
				t.Errorf("log.Fatalf mentions %s:\n\t%s\n"+
					"An unrecognised value for this variable must be survived and reported "+
					"(configfault.Set.Reject), never fatal — Restart=always turns it into a "+
					"permanently unreachable node. See #89.", v, strings.TrimSpace(line))
			}
		}
	}
}

// The other half: surviving quietly would trade a dead node for a lying one, so
// the faults have to leave the box. This pins that publishRegistered puts them
// in the registration metadata under the agreed key — the api stores Metadata
// wholesale, so this is the whole of the reporting path.
func TestPublishRegistered_CarriesConfigFaults(t *testing.T) {
	var faults configfault.Set
	orig := log.Writer()
	log.SetOutput(io.Discard)
	faults.Reject("RASPUTIN_UPDATE_BACKEND", "racu", []string{"rauc", "mock"}, "OS updates are disabled")
	log.SetOutput(orig)

	ev := registeredEvtWithFaults(t, testBus(t), "n", nil, &faults)
	raw, ok := ev.Metadata[proto.MetadataConfigFaults]
	if !ok {
		t.Fatalf("registration carries no %q — the node survived a bad node.env and told nobody",
			proto.MetadataConfigFaults)
	}
	if !strings.Contains(fmt.Sprint(raw), "RASPUTIN_UPDATE_BACKEND") {
		t.Errorf("config faults = %v, must name the variable", raw)
	}
	if !strings.Contains(fmt.Sprint(raw), "OS updates are disabled") {
		t.Errorf("config faults = %v, must carry the EFFECT — that is what an operator acts on", raw)
	}
}

// A healthy node must not carry the key at all — absence is the signal, and an
// empty list would make every clean node look like it had something to say.
func TestPublishRegistered_CleanNodeCarriesNoFaultKey(t *testing.T) {
	var faults configfault.Set // nothing rejected
	ev := registeredEvtWithFaults(t, testBus(t), "n", nil, &faults)
	if _, ok := ev.Metadata[proto.MetadataConfigFaults]; ok {
		t.Error("a clean node must not carry the config-faults key at all")
	}
}
