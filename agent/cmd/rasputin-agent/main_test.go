package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
	// No uci binary on PATH → unavailable, regardless of the config file.
	// NOT mock: the file-backed openwrt mock acks rule changes and reads them
	// back, so an operator would believe a deny rule was enforced by a
	// firewall that never received it.
	cfgDir := t.TempDir()
	cfg := filepath.Join(cfgDir, "firewall")
	if err := os.WriteFile(cfg, []byte("config defaults\n"), 0o644); err != nil {
		t.Fatalf("write fake firewall config: %v", err)
	}
	t.Setenv("PATH", t.TempDir()) // empty dir — nothing on PATH
	if got := autodetectUCIBackendAt(cfg); got != backendUnavailable {
		t.Errorf("no uci on PATH: got %q, want backendUnavailable", got)
	}

	// uci on PATH but no /etc/config/firewall (e.g. a dev box with a
	// stray uci binary) → unavailable.
	binDir := t.TempDir()
	fakeUCI := filepath.Join(binDir, "uci")
	if err := os.WriteFile(fakeUCI, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake uci: %v", err)
	}
	t.Setenv("PATH", binDir)
	if got := autodetectUCIBackendAt(filepath.Join(cfgDir, "missing")); got != backendUnavailable {
		t.Errorf("uci without firewall config: got %q, want backendUnavailable", got)
	}

	// Both present → uci (a real OpenWrt root).
	if got := autodetectUCIBackendAt(cfg); got != "uci" {
		t.Errorf("uci + firewall config: got %q, want uci", got)
	}
}

// TC-591-11: drives the uciBackendFromEnv resolver main calls, with the real
// autodetect probe on a PATH that holds nothing.
func TestUCIBackendSelectionEnvOverride(t *testing.T) {
	// Autodetect finds nothing on PATH, but the env forces uci.
	t.Setenv("PATH", t.TempDir())
	t.Setenv("RASPUTIN_UCI_BACKEND", "uci")
	if got := uciBackendFromEnv(autodetectUCIBackend); got != "uci" {
		t.Errorf("env override: got %q, want uci", got)
	}
	// Explicit mock is still honoured — it is a legitimate dev selection,
	// just never an inferred one.
	t.Setenv("RASPUTIN_UCI_BACKEND", "mock")
	if got := uciBackendFromEnv(autodetectUCIBackend); got != "mock" {
		t.Errorf("explicit mock: got %q, want mock", got)
	}
	// Empty env falls through to autodetect, which on a box with no uci
	// yields unavailable — NOT mock.
	t.Setenv("RASPUTIN_UCI_BACKEND", "")
	if got := uciBackendFromEnv(autodetectUCIBackend); got != backendUnavailable {
		t.Errorf("autodetect fallback: got %q, want backendUnavailable", got)
	}
}

// ⚠️ THE 2026-09-01 REGRESSION GUARD — the whole point of this change.
//
// On e3bench, a real n100 controlplane, `wipefs` was missing from the OS image.
// storage.ToolingAvailable() went false, autodetectStorageBackend() answered
// "mock", and storage.enumerate replied with the mock's fixture machine: three
// disks that do not exist in that box, one carrying a plausible exfat volume,
// with ok:true. The operator would have seen them in the backup-target picker,
// and storage.claim force-formats. Nothing in the reply said it was fiction.
//
// This runs every autodetect on a machine stripped of ALL tooling — the exact
// condition that used to produce mock — and asserts none of them does. A
// missing prerequisite must disable a subsystem, never fabricate one.
func TestNoAutodetectEverYieldsMock(t *testing.T) {
	// Empty PATH: no docker, no rauc, no tailscale, no uci, no util-linux.
	t.Setenv("PATH", t.TempDir())

	cases := []struct {
		name string
		got  string
	}{
		{"docker", autodetectDockerBackend()},
		{"storage", autodetectStorageBackend()},
		{"tailscale", autodetectTailscaleBackend()},
		{"uci", autodetectUCIBackendAt(filepath.Join(t.TempDir(), "no-such-firewall-config"))},
		{"updater/compute", autodetectUpdaterBackend(proto.RoleCompute)},
		{"updater/controlplane", autodetectUpdaterBackend(proto.RoleControlPlane)},
		{"updater/storage", autodetectUpdaterBackend(proto.RoleStorage)},
	}
	for _, c := range cases {
		if c.got == "mock" {
			t.Errorf("autodetect %s returned %q with no tooling on PATH.\n"+
				"Mock must be OPT-IN and never inferred: an inferred mock on real hardware "+
				"reports fixture disks, fixture slots and a fixture tailnet as fact. Return "+
				"backendUnavailable and let the switch record a configfault instead. See #89 "+
				"and the e3bench incident in agent/internal/configfault.", c.name, c.got)
		}
		if c.got != backendUnavailable {
			t.Errorf("autodetect %s = %q with no tooling on PATH, want backendUnavailable", c.name, c.got)
		}
	}

	// The firewall updater keys off a real absolute path, so only assert it
	// when this machine genuinely isn't OpenWrt (every dev box and CI runner).
	if _, err := os.Stat(defaultFirewallConfig); os.IsNotExist(err) {
		if got := autodetectUpdaterBackend(proto.RoleFirewall); got != backendUnavailable {
			t.Errorf("autodetect updater/firewall = %q off OpenWrt, want backendUnavailable", got)
		}
	}
}

// The other half of the contract: an operator who ASKS for mock still gets it.
// Breaking this would push developers back toward re-adding the inference.
//
// TC-591-11: this drives the five resolvers main calls (F-591-05), each with
// the real autodetect probe on a PATH that holds nothing.
func TestExplicitMockIsAlwaysHonoured(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // autodetect would find nothing

	cases := []struct {
		env     string
		resolve func() string
	}{
		{"RASPUTIN_DOCKER_BACKEND", func() string { return dockerBackendFromEnv(autodetectDockerBackend) }},
		{"RASPUTIN_STORAGE_BACKEND", func() string { return storageBackendFromEnv(autodetectStorageBackend) }},
		{"RASPUTIN_TAILSCALE_BACKEND", func() string { return tailscaleBackendFromEnv(autodetectTailscaleBackend) }},
		{"RASPUTIN_UCI_BACKEND", func() string { return uciBackendFromEnv(autodetectUCIBackend) }},
		{"RASPUTIN_UPDATE_BACKEND", func() string {
			return updateBackendFromEnv(func() string { return autodetectUpdaterBackend(proto.RoleCompute) })
		}},
	}
	for _, c := range cases {
		t.Setenv(c.env, "mock")
		if got := c.resolve(); got != "mock" {
			t.Errorf("%s=mock: got %q, want mock — an explicit request must always win", c.env, got)
		}
		// With nothing asked for, the empty probe answer disables the
		// subsystem rather than falling back to the mock.
		t.Setenv(c.env, "")
		if got := c.resolve(); got != backendUnavailable {
			t.Errorf("%s unset with nothing on PATH: got %q, want backendUnavailable", c.env, got)
		}
	}
}

// A disabled subsystem is only actionable if it names what is missing. The
// e3bench incident needed the sentence "wipefs is not on PATH" and the bool
// ToolingAvailable() could not produce it.
func TestMissingPrereqNamesTheMissingThing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	if got := storageMissingPrereq(); !strings.Contains(got, "wipefs") {
		t.Errorf("storageMissingPrereq() = %q, must name the absent tools (wipefs was THE one that "+
			"caused the incident); an operator has to know what to add to the image", got)
	}
	if got := dockerMissingPrereq(); !strings.Contains(got, "docker") {
		t.Errorf("dockerMissingPrereq() = %q, must name docker", got)
	}
	if got := tailscaleMissingPrereq(); !strings.Contains(got, "tailscale") {
		t.Errorf("tailscaleMissingPrereq() = %q, must name tailscale", got)
	}
	if got := updaterMissingPrereq(proto.RoleCompute); !strings.Contains(got, "rauc") {
		t.Errorf("updaterMissingPrereq(compute) = %q, must name rauc", got)
	}
	// Role-aware: the firewall has no rauc BY DESIGN, so telling its operator
	// that rauc is missing would send them after a package that does not exist
	// for OpenWrt. It must name the OpenWrt signal instead.
	fw := updaterMissingPrereq(proto.RoleFirewall)
	if strings.Contains(fw, "rauc") {
		t.Errorf("updaterMissingPrereq(firewall) = %q — must not blame rauc; a firewall node "+
			"legitimately has none", fw)
	}
	if !strings.Contains(fw, defaultFirewallConfig) {
		t.Errorf("updaterMissingPrereq(firewall) = %q, must name %s", fw, defaultFirewallConfig)
	}
	// And the expected-backend list follows the role, so the fault never
	// suggests a backend the node could not have run.
	if got := updaterExpectedFor(proto.RoleFirewall); len(got) != 1 || got[0] != "openwrt-ab" {
		t.Errorf("updaterExpectedFor(firewall) = %v, want [openwrt-ab]", got)
	}
	if got := updaterExpectedFor(proto.RoleCompute); len(got) != 1 || got[0] != "rauc" {
		t.Errorf("updaterExpectedFor(compute) = %v, want [rauc]", got)
	}

	// uci distinguishes its two causes, so the operator knows which to fix.
	if got := uciMissingPrereqAt("/nope"); !strings.Contains(got, "uci") {
		t.Errorf("uciMissingPrereqAt with no uci = %q, must name uci", got)
	}
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "uci"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake uci: %v", err)
	}
	t.Setenv("PATH", binDir)
	if got := uciMissingPrereqAt("/nope/firewall"); !strings.Contains(got, "/nope/firewall") {
		t.Errorf("uciMissingPrereqAt with uci present = %q, must name the absent config path", got)
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
	return registeredEvtKeys(t, nc, nodeID, adv, faults, nil)
}

// registeredEvtKeys is registeredEvtWithFaults plus the node's key hashes.
func registeredEvtKeys(t *testing.T, nc *nats.Conn, nodeID string, adv *bmc.Advertisement, faults *configfault.Set, keys proto.NodeKeys) proto.NodeRegisteredEvt {
	t.Helper()
	return registeredEvtFacts(t, nc, nodeID, adv, faults, registrationFacts{
		TrustFingerprint: func() string { return "fp-test" },
		NodeKeys:         keys,
	})
}

// registeredEvtFacts is the one publish the helpers above share: every
// reported fact arrives in one struct, so a new cutover fact is a field here
// and nowhere else.
func registeredEvtFacts(t *testing.T, nc *nats.Conn, nodeID string, adv *bmc.Advertisement, faults *configfault.Set, facts registrationFacts) proto.NodeRegisteredEvt {
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
	publishRegistered(nc, nodeID, proto.RoleControlPlane, nil, adv, faults, lanAddr, facts)
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
	if want := []string{proto.CapabilityKeyBoundTransfer, proto.CapabilityBMCTargets}; !reflect.DeepEqual(ev.Capabilities, want) {
		t.Errorf("capabilities: %v, want %v", ev.Capabilities, want)
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

// TC-517-12 and TC-539-08: a registration carries the node keys, and none of
// the retired cutover keys — busTls and httpsPinned are gone with the plaintext
// bus (geekdojo/geekdojo-brain#517), tokenSource with the agent's environment
// token fallback (geekdojo/geekdojo-brain#539).
func TestPublishRegistered_CarriesNoLadderMetadata(t *testing.T) {
	nc := testBus(t)
	keys := proto.NodeKeys{
		proto.NodeKeyAgent:     testKeyHash(t),
		proto.NodeKeyCollector: testKeyHash(t),
	}
	ev := registeredEvtKeys(t, nc, "cp-test", nil, nil, keys)
	for _, gone := range []string{"busTls", "httpsPinned", "tokenSource"} {
		if v, present := ev.Metadata[gone]; present {
			t.Errorf("metadata %s = %v, want the key absent", gone, v)
		}
	}
	decoded, ok, err := proto.DecodeNodeKeys(ev.Metadata)
	if err != nil || !ok || len(decoded) == 0 {
		t.Fatalf("nodeKeys = (%v, %v, %v), want the node's keys", decoded, ok, err)
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
		"RASPUTIN_BMC_BITSCOPE_DEV":      "/dev/ttyS0",
		"RASPUTIN_BMC_BITSCOPE_UNLOCK":   "unlock",
		"RASPUTIN_BMC_BITSCOPE_MAP":      "/tmp/bitscope-map.json",
		"RASPUTIN_BMC_MOCK_TARGETS":      "mock-a,mock-b",
		"RASPUTIN_BMC_TURINGPI_ENDPOINT": "turingpi.local",
		"RASPUTIN_BMC_TURINGPI_USER":     "root",
		"RASPUTIN_BMC_TURINGPI_PASS":     "turing",
		"RASPUTIN_BMC_TURINGPI_MAP":      "tp-cp1:1,tp-n1:2",
		"RASPUTIN_BMC_TURINGPI_PIN":      "sha256/epr81hmPYzpdyR6LUQ2gb+spADtZSHpXfIQ5fF+AHqs=",
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

// The retired BMC TLS env vars are not read any more, and a box still
// carrying one must be TOLD rather than silently reconfigured or taken down:
// the env selection is rejected, the node comes up BMC-off, and the
// registration carries the reason (geekdojo/geekdojo-brain#548).
func TestRetiredBMCEnvInUse(t *testing.T) {
	const pin = "sha256/epr81hmPYzpdyR6LUQ2gb+spADtZSHpXfIQ5fF+AHqs="

	t.Run("a retired variable is named", func(t *testing.T) {
		for _, key := range retiredBMCEnv {
			t.Run(key, func(t *testing.T) {
				t.Setenv("RASPUTIN_BMC_TURINGPI_PIN", pin)
				t.Setenv(key, "true")
				got := retiredBMCEnvInUse("turingpi", bmcConfigFromEnv(t.TempDir()).TuringPiPin)
				if got == "" {
					t.Fatalf("%s is set; the selection must be rejected", key)
				}
				if !strings.Contains(got, key) {
					t.Errorf("the reason must name the variable to fix; got %q", got)
				}
			})
		}
	})

	t.Run("no pin at all", func(t *testing.T) {
		got := retiredBMCEnvInUse("turingpi", bmcConfigFromEnv(t.TempDir()).TuringPiPin)
		if got == "" || !strings.Contains(got, "RASPUTIN_BMC_TURINGPI_PIN") {
			t.Errorf("a turingpi selection with no pin must be rejected by name; got %q", got)
		}
	})

	t.Run("a pinned selection is honoured", func(t *testing.T) {
		t.Setenv("RASPUTIN_BMC_TURINGPI_PIN", pin)
		if got := retiredBMCEnvInUse("turingpi", bmcConfigFromEnv(t.TempDir()).TuringPiPin); got != "" {
			t.Errorf("a pinned turingpi selection must be honoured; got %q", got)
		}
	})

	t.Run("other backends are untouched", func(t *testing.T) {
		t.Setenv("RASPUTIN_BMC_TURINGPI_INSECURE", "true")
		for _, kind := range []string{"", "none", "mock", "bitscope"} {
			if got := retiredBMCEnvInUse(kind, bmcConfigFromEnv(t.TempDir()).TuringPiPin); got != "" {
				t.Errorf("kind %q must be unaffected; got %q", kind, got)
			}
		}
	})
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
		// Added 2026-09-01. Storage landed after #89 and was never added to
		// this list, so the one subsystem that force-formats disks was the one
		// not covered by the guard. Nothing was wrong with it — but that is
		// luck, not a check, and this list is the check.
		"RASPUTIN_STORAGE_BACKEND",
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

// uciLANAddr's whole job is to prefer the box's own answer while GUARANTEEING
// it never leaves the node without one. An empty lanIP drops the node out of
// cluster DNS entirely — strictly worse than the wrong-interface value this
// code exists to replace — so every failure shape must reach the fallback.
func TestUCILANAddr(t *testing.T) {
	fallback := func() (string, string) { return "10.9.9.9", "10.9.9.9/24" }

	for _, tc := range []struct {
		name             string
		ip, cidr         string
		err              error
		wantIP, wantCIDR string
	}{
		{
			name: "uci answers — the LAN wins over the default route",
			ip:   "192.168.1.1", cidr: "192.168.1.1/24",
			wantIP: "192.168.1.1", wantCIDR: "192.168.1.1/24",
		},
		{
			name:   "uci errors — fall back rather than report nothing",
			err:    errors.New("uci: command not found"),
			wantIP: "10.9.9.9", wantCIDR: "10.9.9.9/24",
		},
		{
			// The subtle one: no error, but nothing useful. Returning this
			// through would publish an empty lanIP and look like a success.
			name: "uci answers empty — still falls back",
			ip:   "", cidr: "",
			wantIP: "10.9.9.9", wantCIDR: "10.9.9.9/24",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolve := uciLANAddr(func(context.Context) (string, string, error) {
				return tc.ip, tc.cidr, tc.err
			}, fallback)
			ip, cidr := resolve()
			if ip != tc.wantIP || cidr != tc.wantCIDR {
				t.Errorf("got %q / %q, want %q / %q", ip, cidr, tc.wantIP, tc.wantCIDR)
			}
			if ip == "" {
				t.Error("returned an empty lanIP — the node would vanish from cluster DNS")
			}
		})
	}
}

// The lookup must be given a deadline: it shells out to uci on a box that may
// be mid-boot, and a hung call here stalls registration.
func TestUCILANAddr_PassesADeadline(t *testing.T) {
	var hadDeadline bool
	resolve := uciLANAddr(func(ctx context.Context) (string, string, error) {
		_, hadDeadline = ctx.Deadline()
		return "192.168.1.1", "192.168.1.1/24", nil
	}, func() (string, string) { return "", "" })
	resolve()
	if !hadDeadline {
		t.Error("uciLANAddr called the lookup with no deadline")
	}
}

// The registration carries the fingerprint of the mesh CA this node trusts,
// under the key the api's converge_trust reads — and never the PEM. This is
// the one fact that lets the api re-deliver a CA it changed under an enrolled
// node (e3bench 2026-09-04).
func TestPublishRegistered_CarriesMeshCAFingerprint(t *testing.T) {
	nc := testBus(t)
	ev := registeredEvt(t, nc, "cp-test", nil)
	if got := ev.Metadata[proto.MetadataMeshCAFingerprint]; got != "fp-test" {
		t.Errorf("metadata %s = %v, want the backend's fingerprint", proto.MetadataMeshCAFingerprint, got)
	}
	for k, v := range ev.Metadata {
		if s, ok := v.(string); ok && strings.Contains(s, "BEGIN CERTIFICATE") {
			t.Errorf("metadata %s carries PEM material", k)
		}
	}
}

// TC-517-12: node keys ride out on every registration that has them
// (geekdojo/geekdojo-brain#514). Every connection the agent makes is TLS with
// the server verified by the bus pin, so there is no transport condition on
// the report; a node with no keys sends no key.
func TestPublishRegistered_ReportsNodeKeys(t *testing.T) {
	nc := testBus(t)
	keys := proto.NodeKeys{
		proto.NodeKeyAgent:     testKeyHash(t),
		proto.NodeKeyCollector: testKeyHash(t),
	}
	for _, tc := range []struct {
		name string
		keys proto.NodeKeys
		want bool
	}{
		{"keys", keys, true},
		{"no keys", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := registeredEvtKeys(t, nc, "cp-test", nil, nil, tc.keys)
			got, present := ev.Metadata[proto.MetadataNodeKeys]
			if present != tc.want {
				t.Fatalf("metadata %s present = %v, want %v (value %v)",
					proto.MetadataNodeKeys, present, tc.want, got)
			}
			if !tc.want {
				return
			}
			// What the api will decode is what arrives after the JSON
			// round-trip the bus does, so assert on that.
			decoded, ok, err := proto.DecodeNodeKeys(ev.Metadata)
			if err != nil || !ok {
				t.Fatalf("DecodeNodeKeys = (%v, %v, %v)", decoded, ok, err)
			}
			if !decoded.Equal(keys) {
				t.Errorf("decoded %v, want %v", decoded, keys)
			}
		})
	}
}

// testKeyHash is the SPKI hash of a throwaway key, in the canonical form an
// agent reports.
func testKeyHash(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h, err := proto.NodeKeySPKIHash(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TC-514-25: every role advertises key-bound transfer — it is a property of
// this binary's backup clients — and a BMC host still advertises its targets.
func TestPublishRegistered_AdvertisesKeyBoundTransferOnEveryRole(t *testing.T) {
	nc := testBus(t)
	lanAddr := func() (string, string) { return "192.168.1.50", "192.168.1.50/24" }
	for _, role := range []proto.NodeRole{proto.RoleCompute, proto.RoleControlPlane, proto.RoleFirewall} {
		for _, adv := range []*bmc.Advertisement{nil, {Targets: []string{"n-a"}}} {
			sub, err := nc.SubscribeSync(proto.NodeRegisteredSubject("n-" + string(role)))
			if err != nil {
				t.Fatal(err)
			}
			publishRegistered(nc, "n-"+string(role), role, nil, adv, nil, lanAddr, registrationFacts{
				TrustFingerprint: func() string { return "fp-test" },
			})
			msg, err := sub.NextMsg(2 * time.Second)
			_ = sub.Unsubscribe()
			if err != nil {
				t.Fatalf("%s: no registered event: %v", role, err)
			}
			var ev proto.NodeRegisteredEvt
			if err := json.Unmarshal(msg.Data, &ev); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(ev.Capabilities, proto.CapabilityKeyBoundTransfer) {
				t.Errorf("%s (bmc %v): capabilities %v lack %s", role, adv != nil, ev.Capabilities, proto.CapabilityKeyBoundTransfer)
			}
			if adv != nil && !slices.Contains(ev.Capabilities, proto.CapabilityBMCTargets) {
				t.Errorf("%s with a BMC backend: capabilities %v lack %s", role, ev.Capabilities, proto.CapabilityBMCTargets)
			}
		}
	}
}
