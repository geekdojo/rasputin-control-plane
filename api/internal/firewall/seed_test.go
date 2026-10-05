package firewall

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// findIntent returns the intent with the given name, or nil.
func findIntent(intents []*Intent, name string) *Intent {
	for _, in := range intents {
		if in.Name == name {
			return in
		}
	}
	return nil
}

func TestSeedBaselineRules_CreatesExactlyThree(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	n, err := SeedBaselineRules(ctx, s, "node-fw")
	if err != nil {
		t.Fatalf("SeedBaselineRules: %v", err)
	}
	if n != 3 {
		t.Fatalf("created = %d, want 3", n)
	}

	intents, err := s.ListIntents(ctx)
	if err != nil {
		t.Fatalf("ListIntents: %v", err)
	}
	if len(intents) != 3 {
		t.Fatalf("len(intents) = %d, want 3", len(intents))
	}

	// Every seeded intent is an enabled firewall_rule (so it shows up in the
	// rules table identically to a user-created rule) and starts NOT applied
	// (pending) — there's no node state written by seeding.
	for _, in := range intents {
		if in.Kind != string(proto.IntentFirewallRule) {
			t.Errorf("%s: kind = %q, want firewall_rule", in.Name, in.Kind)
		}
		if !in.Enabled {
			t.Errorf("%s: should be enabled", in.Name)
		}
	}

	type want struct {
		src      string
		proto    proto.FirewallRuleProto
		destPort string
		target   proto.FirewallRuleTarget
	}
	wants := map[string]want{
		"Allow-DHCP-Renew": {src: "wan", proto: proto.RuleProtoUDP, destPort: "68", target: proto.RuleTargetAccept},
		"Allow-Ping":       {src: "wan", proto: proto.RuleProtoICMP, destPort: "", target: proto.RuleTargetAccept},
		"Allow-IGMP":       {src: "wan", proto: proto.RuleProtoIGMP, destPort: "", target: proto.RuleTargetAccept},
	}
	for name, w := range wants {
		in := findIntent(intents, name)
		if in == nil {
			t.Fatalf("missing seeded rule %q", name)
		}
		var spec proto.FirewallRuleSpec
		if err := json.Unmarshal(in.Spec, &spec); err != nil {
			t.Fatalf("%s: unmarshal spec: %v", name, err)
		}
		if spec.Src != w.src || spec.Proto != w.proto || spec.DestPort != w.destPort || spec.Target != w.target {
			t.Errorf("%s: spec = %+v, want src=%s proto=%s destPort=%q target=%s",
				name, spec, w.src, w.proto, w.destPort, w.target)
		}
	}
}

func TestSeedBaselineRules_IdempotentSecondCallNoOps(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if n, err := SeedBaselineRules(ctx, s, "node-fw"); err != nil || n != 3 {
		t.Fatalf("first seed: n=%d err=%v", n, err)
	}
	// Second call must create nothing.
	n, err := SeedBaselineRules(ctx, s, "node-fw")
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if n != 0 {
		t.Fatalf("second seed created = %d, want 0", n)
	}
	intents, err := s.ListIntents(ctx)
	if err != nil {
		t.Fatalf("ListIntents: %v", err)
	}
	if len(intents) != 3 {
		t.Fatalf("len(intents) after re-seed = %d, want 3", len(intents))
	}
}

// The load-bearing guarantee: a baseline rule the operator DELETES must not
// resurrect when the seeding hook fires again.
func TestSeedBaselineRules_DeletedRuleStaysDeleted(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if _, err := SeedBaselineRules(ctx, s, "node-fw"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	intents, _ := s.ListIntents(ctx)
	ping := findIntent(intents, "Allow-Ping")
	if ping == nil {
		t.Fatal("Allow-Ping missing after seed")
	}
	if err := s.DeleteIntent(ctx, ping.ID); err != nil {
		t.Fatalf("DeleteIntent: %v", err)
	}

	// Hook fires again (e.g. inventory row was wiped + node re-registered).
	if n, err := SeedBaselineRules(ctx, s, "node-fw"); err != nil || n != 0 {
		t.Fatalf("reseed after delete: n=%d err=%v", n, err)
	}
	intents, _ = s.ListIntents(ctx)
	if findIntent(intents, "Allow-Ping") != nil {
		t.Fatal("Allow-Ping resurrected after operator deleted it")
	}
	if len(intents) != 2 {
		t.Fatalf("len(intents) = %d, want 2 (Allow-Ping stays gone)", len(intents))
	}
}

// The baseline is CLUSTER-GLOBAL, not per-node: firewall intents have no
// target_node_id (one firewall per cluster), so re-enrolling the firewall under
// a DIFFERENT node-id (rename / re-provision / a fresh firewall after removal)
// must NOT re-seed and duplicate the baseline. Regression test for the
// 2026-07-02 duplicate-rules bug (per-node guard + global intents = duplicates).
func TestSeedBaselineRules_ClusterGlobalNoDuplicateOnNodeIDChange(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if n, err := SeedBaselineRules(ctx, s, "node-a"); err != nil || n != 3 {
		t.Fatalf("seed node-a: n=%d err=%v", n, err)
	}
	// Firewall re-enrolls under a NEW node-id — must be a no-op, not a re-seed.
	if n, err := SeedBaselineRules(ctx, s, "node-b"); err != nil || n != 0 {
		t.Fatalf("re-enroll under node-b should not reseed: n=%d err=%v", n, err)
	}
	intents, _ := s.ListIntents(ctx)
	if len(intents) != 3 {
		t.Fatalf("len(intents) = %d, want 3 (no duplication across node-ids)", len(intents))
	}
}

// Migration: a cluster seeded under the OLD per-node scheme (a per-node marker
// exists, no global marker) is ADOPTED on the next seed call — the global marker
// is set and nothing is re-seeded, so upgrading never duplicates (and never
// resurrects rules the operator may have deleted).
func TestSeedBaselineRules_AdoptsLegacyPerNodeMarker(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Simulate a pre-fix cluster: a per-node marker exists, no global marker.
	if _, err := s.MarkBaselineSeeded(ctx, "legacy-fw"); err != nil {
		t.Fatalf("seed legacy marker: %v", err)
	}
	// Next firewall registration must adopt (no re-seed), not duplicate.
	if n, err := SeedBaselineRules(ctx, s, "new-fw"); err != nil || n != 0 {
		t.Fatalf("adopt legacy: n=%d err=%v", n, err)
	}
	if intents, _ := s.ListIntents(ctx); len(intents) != 0 {
		t.Fatalf("adoption must not seed: len(intents)=%d", len(intents))
	}
	// Sticky: subsequent calls stay no-ops.
	if n, _ := SeedBaselineRules(ctx, s, "another"); n != 0 {
		t.Fatal("should remain a no-op after adoption")
	}
}

func TestMarkBaselineSeeded_CheckAndSet(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	first, err := s.MarkBaselineSeeded(ctx, "n1")
	if err != nil {
		t.Fatalf("first mark: %v", err)
	}
	if !first {
		t.Fatal("first MarkBaselineSeeded should return true")
	}
	second, err := s.MarkBaselineSeeded(ctx, "n1")
	if err != nil {
		t.Fatalf("second mark: %v", err)
	}
	if second {
		t.Fatal("second MarkBaselineSeeded should return false (already set)")
	}
}

// Concurrent MarkBaselineSeeded on the same node id: exactly one caller wins.
// The store pins MaxOpenConns(1) + the node_id PRIMARY KEY makes the
// INSERT...ON CONFLICT DO NOTHING the serialization point.
func TestMarkBaselineSeeded_RaceExactlyOneWinner(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	const goroutines = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			won, err := s.MarkBaselineSeeded(ctx, "racy-node")
			if err != nil {
				t.Errorf("MarkBaselineSeeded: %v", err)
				return
			}
			if won {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins)
	}
}

func TestCompile_FirewallRuleProtoIGMP(t *testing.T) {
	in := makeRuleIntent(t, "i", "Allow-IGMP", proto.FirewallRuleSpec{
		Src: "wan", Proto: proto.RuleProtoIGMP, Target: proto.RuleTargetAccept,
	})
	state, h1, err := Compile([]*Intent{in})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	r := state["firewall"].(map[string]any)["rule"].([]map[string]any)[0]
	if r["proto"] != "igmp" {
		t.Errorf("proto = %v, want igmp", r["proto"])
	}
	// Hash is stable across recompiles of the same intent.
	_, h2, err := Compile([]*Intent{in})
	if err != nil {
		t.Fatalf("Compile (2): %v", err)
	}
	if h1 != h2 {
		t.Errorf("igmp compile hash not stable: %s != %s", h1, h2)
	}
}
