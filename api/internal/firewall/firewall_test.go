package firewall

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(context.Background(), filepath.Join(dir, "fw.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func makePortForwardIntent(t *testing.T, id, name string, enabled bool, wan, lan int) *Intent {
	t.Helper()
	spec, err := json.Marshal(proto.PortForwardSpec{
		WanPort:  wan,
		LanHost:  "10.0.0.5",
		LanPort:  lan,
		Protocol: proto.ProtoTCP,
		Comment:  "test",
	})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	now := time.Now().UTC()
	return &Intent{
		ID:        id,
		Kind:      string(proto.IntentPortForward),
		Name:      name,
		Enabled:   enabled,
		Spec:      spec,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// ============================================================================
// Intent CRUD
// ============================================================================

func TestStore_CreateAndGetIntent(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	want := makePortForwardIntent(t, "i-1", "web", true, 8080, 80)
	if err := s.CreateIntent(ctx, want); err != nil {
		t.Fatalf("CreateIntent: %v", err)
	}

	got, err := s.GetIntent(ctx, "i-1")
	if err != nil {
		t.Fatalf("GetIntent: %v", err)
	}
	if got == nil {
		t.Fatal("GetIntent returned nil for known id")
	}
	if got.Name != "web" || got.Kind != string(proto.IntentPortForward) || !got.Enabled {
		t.Errorf("scalar mismatch: %+v", got)
	}
	if string(got.Spec) != string(want.Spec) {
		t.Errorf("Spec round-trip: got %s want %s", got.Spec, want.Spec)
	}
}

func TestStore_GetIntent_Unknown(t *testing.T) {
	s := newStore(t)
	got, err := s.GetIntent(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("GetIntent: %v", err)
	}
	if got != nil {
		t.Errorf("want nil, got %+v", got)
	}
}

func TestStore_UpdateIntent(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	i := makePortForwardIntent(t, "i", "name1", true, 8080, 80)
	if err := s.CreateIntent(ctx, i); err != nil {
		t.Fatalf("CreateIntent: %v", err)
	}
	i.Name = "name2"
	i.Enabled = false
	i.UpdatedAt = i.UpdatedAt.Add(1 * time.Second)
	if err := s.UpdateIntent(ctx, i); err != nil {
		t.Fatalf("UpdateIntent: %v", err)
	}
	got, _ := s.GetIntent(ctx, "i")
	if got.Name != "name2" || got.Enabled {
		t.Errorf("Update fields not persisted: %+v", got)
	}
}

func TestStore_UpdateIntent_UnknownIsErrNoRows(t *testing.T) {
	s := newStore(t)
	i := makePortForwardIntent(t, "ghost", "x", true, 1, 2)
	err := s.UpdateIntent(context.Background(), i)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("want sql.ErrNoRows, got %v", err)
	}
}

func TestStore_DeleteIntent(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	i := makePortForwardIntent(t, "i", "x", true, 1, 2)
	if err := s.CreateIntent(ctx, i); err != nil {
		t.Fatalf("CreateIntent: %v", err)
	}
	if err := s.DeleteIntent(ctx, "i"); err != nil {
		t.Fatalf("DeleteIntent: %v", err)
	}
	got, _ := s.GetIntent(ctx, "i")
	if got != nil {
		t.Errorf("intent should be gone, got %+v", got)
	}
}

func TestStore_DeleteIntent_UnknownIsErrNoRows(t *testing.T) {
	s := newStore(t)
	err := s.DeleteIntent(context.Background(), "ghost")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("want sql.ErrNoRows, got %v", err)
	}
}

func TestStore_ListIntents_StableOrder(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	// Two intents at the same CreatedAt — ORDER BY adds id as the tiebreaker.
	t0 := time.UnixMilli(1717000000000).UTC()
	for _, id := range []string{"b", "a"} {
		i := makePortForwardIntent(t, id, id, true, 8080, 80)
		i.CreatedAt = t0
		i.UpdatedAt = t0
		if err := s.CreateIntent(ctx, i); err != nil {
			t.Fatalf("CreateIntent %s: %v", id, err)
		}
	}
	got, err := s.ListIntents(ctx)
	if err != nil {
		t.Fatalf("ListIntents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	// Created at same instant → tiebreak by id ASC → a, b.
	if got[0].ID != "a" || got[1].ID != "b" {
		t.Errorf("tiebreak order: got %s, %s", got[0].ID, got[1].ID)
	}
}

// ============================================================================
// NodeState lifecycle
// ============================================================================

func TestStore_GetNodeState_Unknown(t *testing.T) {
	s := newStore(t)
	got, err := s.GetNodeState(context.Background(), "n")
	if err != nil {
		t.Fatalf("GetNodeState: %v", err)
	}
	if got != nil {
		t.Errorf("want nil, got %+v", got)
	}
}

func TestStore_UpdateAfterApply_SetsBothHashes(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	t0 := time.Now().UTC()
	if err := s.UpdateAfterApply(ctx, "n", "deadbeef", t0); err != nil {
		t.Fatalf("UpdateAfterApply: %v", err)
	}
	got, err := s.GetNodeState(ctx, "n")
	if err != nil {
		t.Fatalf("GetNodeState: %v", err)
	}
	if got == nil {
		t.Fatal("state should exist after UpdateAfterApply")
	}
	if got.IntentHash != "deadbeef" {
		t.Errorf("IntentHash: got %q", got.IntentHash)
	}
	// observed_hash is reset to intentHash on apply, so Drift is false.
	if got.ObservedHash != "deadbeef" {
		t.Errorf("ObservedHash: got %q", got.ObservedHash)
	}
	if got.Drift {
		t.Errorf("Drift should be false right after a successful apply")
	}
	if got.LastApplied == nil || got.LastApplied.UnixMilli() != t0.UnixMilli() {
		t.Errorf("LastApplied: got %v", got.LastApplied)
	}
	if got.LastReconciled != nil {
		t.Errorf("LastReconciled should be nil until reconcile runs, got %v", got.LastReconciled)
	}
}

func TestStore_UpdateAfterReconcile_DriftDetection(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	// Apply baseline.
	if err := s.UpdateAfterApply(ctx, "n", "intent-1", time.Now().UTC()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Agent reports a different observed hash → drift.
	t1 := time.Now().UTC()
	if err := s.UpdateAfterReconcile(ctx, "n", "observed-rogue", t1); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got, _ := s.GetNodeState(ctx, "n")
	if got.IntentHash != "intent-1" {
		t.Errorf("IntentHash should be preserved across reconcile: %q", got.IntentHash)
	}
	if got.ObservedHash != "observed-rogue" {
		t.Errorf("ObservedHash: got %q", got.ObservedHash)
	}
	if !got.Drift {
		t.Errorf("Drift should be true when observed != intent")
	}
	if got.LastReconciled == nil || got.LastReconciled.UnixMilli() != t1.UnixMilli() {
		t.Errorf("LastReconciled: got %v", got.LastReconciled)
	}
	// Apply hash preserved.
	if got.LastApplied == nil {
		t.Error("LastApplied should still be set after a reconcile")
	}
}

func TestStore_UpdateAfterReconcile_InSyncClearsDrift(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.UpdateAfterApply(ctx, "n", "hash-x", time.Now().UTC()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := s.UpdateAfterReconcile(ctx, "n", "hash-x", time.Now().UTC()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got, _ := s.GetNodeState(ctx, "n")
	if got.Drift {
		t.Errorf("Drift should be false when observed == intent")
	}
}

func TestStore_UpdateAfterReconcile_FreshNodeNoApply(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	// Reconcile arrives before any apply: intent_hash is empty, observed
	// is populated, Drift should be false because we don't claim drift on
	// no data.
	if err := s.UpdateAfterReconcile(ctx, "n", "observed-only", time.Now().UTC()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got, _ := s.GetNodeState(ctx, "n")
	if got == nil {
		t.Fatal("state should be created by reconcile")
	}
	if got.IntentHash != "" {
		t.Errorf("IntentHash should be empty on first reconcile, got %q", got.IntentHash)
	}
	if !got.Drift {
		// With observed != intent ("" != "observed-only"), the current
		// Drift rule treats this as drift. This pins that behavior.
		t.Errorf("Drift behavior: observed-only after no-apply should still report drift per current rule")
	}
}

// ============================================================================
// Compile: pure helper, no DB needed.
// ============================================================================

func TestCompile_EmptyAndDisabledProduceStableHash(t *testing.T) {
	// Two cases that should compile to the same canonical empty state and
	// therefore the same hash.
	_, h1, err := Compile(nil)
	if err != nil {
		t.Fatalf("Compile(nil): %v", err)
	}
	disabled := makePortForwardIntent(t, "i", "x", false, 1, 2)
	_, h2, err := Compile([]*Intent{disabled})
	if err != nil {
		t.Fatalf("Compile(disabled): %v", err)
	}
	if h1 != h2 {
		t.Errorf("disabled intents should be omitted: %q vs %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("hex sha256 should be 64 chars, got %d", len(h1))
	}
}

func TestCompile_EnabledPortForwardShape(t *testing.T) {
	in := makePortForwardIntent(t, "i", "ssh", true, 2222, 22)
	state, h, err := Compile([]*Intent{in})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if h == "" {
		t.Error("hash should be non-empty")
	}
	fw, ok := state["firewall"].(map[string]any)
	if !ok {
		t.Fatalf("missing firewall root: %v", state)
	}
	red, ok := fw["redirect"].([]map[string]any)
	if !ok || len(red) != 1 {
		t.Fatalf("redirect: %v", fw["redirect"])
	}
	r := red[0]
	if r["src_dport"] != "2222" || r["dest_port"] != "22" {
		t.Errorf("ports: %v", r)
	}
	if r["proto"] != "tcp" {
		t.Errorf("proto: %v", r["proto"])
	}
	if r["target"] != "DNAT" {
		t.Errorf("target: %v", r["target"])
	}
	if r["_comment"] != "test" {
		t.Errorf("comment: %v", r["_comment"])
	}
}

func TestCompile_ProtocolDefaultsToTCP(t *testing.T) {
	spec, _ := json.Marshal(proto.PortForwardSpec{
		WanPort: 80, LanHost: "h", LanPort: 80, // Protocol left empty
	})
	in := &Intent{
		ID: "i", Kind: string(proto.IntentPortForward), Name: "n",
		Enabled: true, Spec: spec,
	}
	state, _, err := Compile([]*Intent{in})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	r := state["firewall"].(map[string]any)["redirect"].([]map[string]any)[0]
	if r["proto"] != "tcp" {
		t.Errorf("default proto should be tcp, got %v", r["proto"])
	}
}

func TestCompile_ProtocolTCPUDPExpands(t *testing.T) {
	spec, _ := json.Marshal(proto.PortForwardSpec{
		WanPort: 53, LanHost: "h", LanPort: 53, Protocol: proto.ProtoTCPUDP,
	})
	in := &Intent{
		ID: "i", Kind: string(proto.IntentPortForward), Name: "dns",
		Enabled: true, Spec: spec,
	}
	state, _, err := Compile([]*Intent{in})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	r := state["firewall"].(map[string]any)["redirect"].([]map[string]any)[0]
	if r["proto"] != "tcp udp" {
		t.Errorf("tcpudp should expand to 'tcp udp', got %v", r["proto"])
	}
}

func TestCompile_RejectsBadSpec(t *testing.T) {
	cases := []struct {
		name  string
		spec  proto.PortForwardSpec
		match string
	}{
		{"wan-zero", proto.PortForwardSpec{WanPort: 0, LanHost: "h", LanPort: 1}, "wanport"},
		{"wan-overflow", proto.PortForwardSpec{WanPort: 99999, LanHost: "h", LanPort: 1}, "wanport"},
		{"lan-zero", proto.PortForwardSpec{WanPort: 1, LanHost: "h", LanPort: 0}, "lanport"},
		{"missing-host", proto.PortForwardSpec{WanPort: 1, LanPort: 1}, "lanhost"},
		{"bad-protocol", proto.PortForwardSpec{WanPort: 1, LanPort: 1, LanHost: "h", Protocol: "ftp"}, "protocol"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, _ := json.Marshal(tc.spec)
			in := &Intent{
				ID: "i", Kind: string(proto.IntentPortForward), Name: "n",
				Enabled: true, Spec: spec,
			}
			_, _, err := Compile([]*Intent{in})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.match) {
				t.Errorf("want error containing %q, got %v", tc.match, err)
			}
		})
	}
}

func TestCompile_RejectsInvalidJSONSpec(t *testing.T) {
	in := &Intent{
		ID: "i", Kind: string(proto.IntentPortForward), Name: "n",
		Enabled: true, Spec: json.RawMessage("not-json"),
	}
	if _, _, err := Compile([]*Intent{in}); err == nil {
		t.Error("expected error for invalid spec JSON")
	}
}

func TestCompile_RejectsUnknownKind(t *testing.T) {
	in := &Intent{
		ID: "i", Kind: "wireguard_peer", Name: "n", Enabled: true,
		Spec: json.RawMessage("{}"),
	}
	_, _, err := Compile([]*Intent{in})
	if err == nil || !strings.Contains(err.Error(), "unsupported kind") {
		t.Errorf("want 'unsupported kind' error, got %v", err)
	}
}

func makeRuleIntent(t *testing.T, id, name string, spec proto.FirewallRuleSpec) *Intent {
	t.Helper()
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	now := time.Now().UTC()
	return &Intent{
		ID: id, Kind: string(proto.IntentFirewallRule), Name: name,
		Enabled: true, Spec: b, CreatedAt: now, UpdatedAt: now,
	}
}

func TestCompile_EmptyStateIncludesBothSlices(t *testing.T) {
	// Both kind slices appear even when nothing is on file, so the canonical
	// empty-state shape is stable as new kinds land.
	state, _, err := Compile(nil)
	if err != nil {
		t.Fatalf("Compile(nil): %v", err)
	}
	fw, ok := state["firewall"].(map[string]any)
	if !ok {
		t.Fatalf("missing firewall key: %v", state)
	}
	if _, ok := fw["redirect"]; !ok {
		t.Error("missing redirect key in empty state")
	}
	if _, ok := fw["rule"]; !ok {
		t.Error("missing rule key in empty state")
	}
}

func TestCompile_FirewallRuleShape(t *testing.T) {
	in := makeRuleIntent(t, "i", "block-iot-out", proto.FirewallRuleSpec{
		Src: "iot", Dest: "wan",
		SrcIP: "10.0.7.0/24", DestPort: "443",
		Proto: proto.RuleProtoTCP, Target: proto.RuleTargetReject,
		Log: true, Comment: "block IoT",
	})
	state, _, err := Compile([]*Intent{in})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rules, ok := state["firewall"].(map[string]any)["rule"].([]map[string]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("rule slice: %v", state["firewall"].(map[string]any)["rule"])
	}
	r := rules[0]
	// Targets are upper-cased to match UCI's expected form.
	if r["target"] != "REJECT" {
		t.Errorf("target should be UPPERCASE REJECT, got %v", r["target"])
	}
	if r["src"] != "iot" || r["dest"] != "wan" {
		t.Errorf("zones: %v %v", r["src"], r["dest"])
	}
	if r["src_ip"] != "10.0.7.0/24" || r["dest_port"] != "443" {
		t.Errorf("ip/port: %v %v", r["src_ip"], r["dest_port"])
	}
	if r["proto"] != "tcp" {
		t.Errorf("proto: %v", r["proto"])
	}
	if r["log"] != "1" {
		t.Errorf("log: %v", r["log"])
	}
	if r["_comment"] != "block IoT" {
		t.Errorf("comment: %v", r["_comment"])
	}
	// Unset optionals must not appear — keeps the canonical map small + the
	// hash invariant against api changes that introduce new optional fields.
	for _, k := range []string{"src_port", "dest_ip"} {
		if _, ok := r[k]; ok {
			t.Errorf("unset field %q should be omitted, got %v", k, r[k])
		}
	}
}

func TestCompile_FirewallRuleProtoDefaultIsAll(t *testing.T) {
	in := makeRuleIntent(t, "i", "n", proto.FirewallRuleSpec{
		Src: "lan", Target: proto.RuleTargetAccept,
		// Proto left empty
	})
	state, _, err := Compile([]*Intent{in})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	r := state["firewall"].(map[string]any)["rule"].([]map[string]any)[0]
	if r["proto"] != "all" {
		t.Errorf("default proto should be 'all' (UCI wildcard), got %v", r["proto"])
	}
}

func TestCompile_FirewallRuleProtoTCPUDPExpands(t *testing.T) {
	in := makeRuleIntent(t, "i", "n", proto.FirewallRuleSpec{
		Src: "lan", Target: proto.RuleTargetAccept, Proto: proto.RuleProtoTCPUDP,
	})
	state, _, err := Compile([]*Intent{in})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	r := state["firewall"].(map[string]any)["rule"].([]map[string]any)[0]
	if r["proto"] != "tcp udp" {
		t.Errorf("tcpudp should expand to 'tcp udp', got %v", r["proto"])
	}
}

func TestCompile_FirewallRuleEmptyDestIsInputChain(t *testing.T) {
	// An empty Dest is OpenWrt's idiom for "traffic terminating at the
	// firewall itself" (the INPUT chain). Stays out of the map so UCI's
	// default behavior takes over.
	in := makeRuleIntent(t, "i", "ssh-to-router", proto.FirewallRuleSpec{
		Src: "lan", Target: proto.RuleTargetAccept,
		DestPort: "22", Proto: proto.RuleProtoTCP,
	})
	state, _, err := Compile([]*Intent{in})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	r := state["firewall"].(map[string]any)["rule"].([]map[string]any)[0]
	if _, ok := r["dest"]; ok {
		t.Errorf("empty Dest should be omitted, got %v", r["dest"])
	}
}

func TestCompile_FirewallRuleRejectsBadSpec(t *testing.T) {
	cases := map[string]proto.FirewallRuleSpec{
		"missing-src":    {Target: proto.RuleTargetAccept},
		"missing-target": {Src: "lan"},
		"bad-target":     {Src: "lan", Target: "yeet"},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			in := makeRuleIntent(t, "i", "n", spec)
			if _, _, err := Compile([]*Intent{in}); err == nil {
				t.Errorf("want error for %s", name)
			}
		})
	}
}

// ============================================================================
// Hash determinism — sanity that equivalent maps hash identically.
// ============================================================================

// ============================================================================
// Workflow constructors and small helpers — no NATS required.
// ============================================================================

func TestApplyWorkflowShape(t *testing.T) {
	w := ApplyWorkflow(nil, nil, nil)
	if w.Kind != "firewall.apply" {
		t.Errorf("Kind: %q", w.Kind)
	}
	wantSteps := []string{"find_target", "compile", "push"}
	if len(w.Steps) != len(wantSteps) {
		t.Fatalf("step count: got %d want %d", len(w.Steps), len(wantSteps))
	}
	for i, name := range wantSteps {
		if w.Steps[i].Name != name {
			t.Errorf("step %d: got %q want %q", i, w.Steps[i].Name, name)
		}
	}
}

func TestReconcileWorkflowShape(t *testing.T) {
	w := ReconcileWorkflow(nil, nil, nil)
	if w.Kind != "firewall.reconcile" {
		t.Errorf("Kind: %q", w.Kind)
	}
	if len(w.Steps) < 2 {
		t.Errorf("expected at least 2 steps, got %d", len(w.Steps))
	}
}

func TestShort(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"abc", "abc"},
		{"123456789012", "123456789012"},
		{"1234567890123", "123456789012"},
		{"deadbeefcafe1234567890", "deadbeefcafe"},
	}
	for _, tc := range cases {
		if got := short(tc.in); got != tc.want {
			t.Errorf("short(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHash_Determinism(t *testing.T) {
	m1 := map[string]any{"firewall": map[string]any{"redirect": []map[string]any{
		{"name": "a", "src": "wan"},
	}}}
	m2 := map[string]any{"firewall": map[string]any{"redirect": []map[string]any{
		{"src": "wan", "name": "a"}, // key order swapped — encoding/json sorts.
	}}}
	h1, err := Hash(m1)
	if err != nil {
		t.Fatalf("Hash m1: %v", err)
	}
	h2, err := Hash(m2)
	if err != nil {
		t.Fatalf("Hash m2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash should be invariant to map key order: %q vs %q", h1, h2)
	}
}
