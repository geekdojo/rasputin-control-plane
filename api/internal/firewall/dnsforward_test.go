package firewall

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

func dnsForwardIntent(t *testing.T, id string, enabled bool, zone, target string) *Intent {
	t.Helper()
	spec, err := json.Marshal(proto.DNSForwardSpec{Zone: zone, Target: target})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	now := time.Now().UTC()
	return &Intent{
		ID: id, Kind: string(proto.IntentDNSForward), Name: dnsForwardName,
		Enabled: enabled, Spec: spec, CreatedAt: now, UpdatedAt: now,
	}
}

func TestCompile_DNSForward(t *testing.T) {
	state, _, err := Compile([]*Intent{dnsForwardIntent(t, "d1", true, "home1.internal", "192.168.1.5")})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dhcp, ok := state["dhcp"].(map[string]any)
	if !ok {
		t.Fatalf("no dhcp key: %v", state)
	}
	if dhcp["server"] != "/home1.internal/192.168.1.5" {
		t.Errorf("server = %v, want /home1.internal/192.168.1.5", dhcp["server"])
	}
}

func TestCompile_DNSForwardDisabledOmitsKey(t *testing.T) {
	state, _, err := Compile([]*Intent{dnsForwardIntent(t, "d1", false, "home1.internal", "192.168.1.5")})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, ok := state["dhcp"]; ok {
		t.Error("a disabled dns_forward must emit no dhcp key (the agent then removes the forward)")
	}
}

func TestCompile_DNSForwardRejectsIPv6Target(t *testing.T) {
	if _, _, err := Compile([]*Intent{dnsForwardIntent(t, "d1", true, "home1.internal", "fd00::1")}); err == nil {
		t.Error("IPv6 target must be rejected (decision #9)")
	}
}

func TestCompile_DNSForwardRejectsTwoEnabled(t *testing.T) {
	ins := []*Intent{
		dnsForwardIntent(t, "d1", true, "home1.internal", "192.168.1.5"),
		dnsForwardIntent(t, "d2", true, "home1.internal", "192.168.1.6"),
	}
	if _, _, err := Compile(ins); err == nil {
		t.Error("two enabled dns_forward intents must error")
	}
}

func TestUpsertDNSForward_CreateUpdateNoopRemove(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	// Create.
	if changed, err := UpsertDNSForward(ctx, s, "home1.internal", "192.168.1.5", true); err != nil || !changed {
		t.Fatalf("create: changed=%v err=%v", changed, err)
	}
	if onlyDNSForward(t, s) == nil {
		t.Fatal("no dns_forward intent after create")
	}

	// No-op when unchanged.
	if changed, err := UpsertDNSForward(ctx, s, "home1.internal", "192.168.1.5", true); err != nil || changed {
		t.Fatalf("unchanged upsert should be a no-op: changed=%v err=%v", changed, err)
	}

	// Update on a new CP IP.
	if changed, err := UpsertDNSForward(ctx, s, "home1.internal", "192.168.1.9", true); err != nil || !changed {
		t.Fatalf("update: changed=%v err=%v", changed, err)
	}
	var spec proto.DNSForwardSpec
	_ = json.Unmarshal(onlyDNSForward(t, s).Spec, &spec)
	if spec.Target != "192.168.1.9" {
		t.Errorf("target = %q, want 192.168.1.9", spec.Target)
	}

	// Remove when not wanted (mode left a firewall mode).
	if changed, err := UpsertDNSForward(ctx, s, "home1.internal", "192.168.1.9", false); err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	if onlyDNSForward(t, s) != nil {
		t.Error("dns_forward intent still present after removal")
	}

	// Idempotent remove.
	if changed, _ := UpsertDNSForward(ctx, s, "home1.internal", "192.168.1.9", false); changed {
		t.Error("removing an absent forward must be a no-op")
	}
}

func onlyDNSForward(t *testing.T, s *Store) *Intent {
	t.Helper()
	ins, err := s.ListIntents(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found *Intent
	for _, in := range ins {
		if proto.FirewallIntentKind(in.Kind) == proto.IntentDNSForward {
			if found != nil {
				t.Fatal("more than one dns_forward intent")
			}
			found = in
		}
	}
	return found
}

// applyCounter is a runner with a stand-in firewall.apply that counts its runs,
// so a test sees whether the dns_forward step auto-applied.
func applyCounter(t *testing.T) (*jobs.Runner, chan struct{}) {
	t.Helper()
	nc := startNATS(t)
	js, err := jobs.OpenStore(context.Background(), filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatalf("jobs store: %v", err)
	}
	t.Cleanup(func() { _ = js.Close() })
	runner := jobs.NewRunner(js, nc)
	ran := make(chan struct{}, 8)
	runner.Register(jobs.Workflow{Kind: "firewall.apply", Steps: []jobs.WorkflowStep{{
		Name: "count", Timeout: time.Second,
		Do: func(*jobs.StepCtx) (json.RawMessage, error) { ran <- struct{}{}; return nil, nil },
	}}})
	return runner, ran
}

func expectApply(t *testing.T, ran chan struct{}, want bool, why string) {
	t.Helper()
	select {
	case <-ran:
		if !want {
			t.Fatalf("auto-applied, but should not have: %s", why)
		}
	case <-time.After(500 * time.Millisecond): // bounds the test only
		if want {
			t.Fatalf("no auto-apply: %s", why)
		}
	}
}

// TestDNSForwardReconcile_AppliesWhatNeverLanded is the case the registration
// trigger depends on (#431): the forward moved while the firewall was away, so
// its apply failed. The run when the firewall comes back finds the intent
// unchanged — and must still push it, because it has never been applied. Once
// an apply has landed, a further run is a no-op.
func TestDNSForwardReconcile_AppliesWhatNeverLanded(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	inv := newInventory(t)
	fwID := seedFirewallNode(t, inv, "fw-1")
	runner, ran := applyCounter(t)
	target := "192.168.1.225"
	cfg := DNSForwardConfig{
		Zone:   func() string { return "e12bench.internal" },
		Target: func() string { return target },
		Inv:    inv,
	}
	run := func() map[string]any {
		t.Helper()
		out, err := dnsForwardReconcile(store, runner, cfg)(newStepCtxNATS(`{}`, nil))
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		var m map[string]any
		_ = json.Unmarshal(out, &m)
		return m
	}

	// First creation applies, and the apply lands.
	run()
	expectApply(t, ran, true, "first creation")
	if err := store.UpdateAfterApply(ctx, fwID, "h1", time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if m := run(); m["changed"] != false || m["unapplied"] == true {
		t.Fatalf("after a landed apply: %v, want a no-op", m)
	}
	expectApply(t, ran, false, "forward unchanged and applied")

	// The address moves while the firewall is away: changed, apply submitted,
	// but it never lands (no UpdateAfterApply).
	target = "192.168.1.226"
	if err := store.UpdateAfterApply(ctx, fwID, "h1", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	run()
	expectApply(t, ran, true, "address changed")

	// The firewall registers again: nothing changed, but it is unapplied.
	if m := run(); m["changed"] != false || m["unapplied"] != true {
		t.Fatalf("firewall back: %v, want unchanged but unapplied", m)
	}
	expectApply(t, ran, true, "unchanged but never applied")

	// That apply lands; the next registration is a no-op.
	if err := store.UpdateAfterApply(ctx, fwID, "h2", time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	run()
	expectApply(t, ran, false, "applied after it landed")
}

func TestForwardUnapplied(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	inv := newInventory(t)

	if u, err := forwardUnapplied(ctx, store, inv); err != nil || u {
		t.Fatalf("no firewall node: %v %v, want false", u, err)
	}
	fwID := seedFirewallNode(t, inv, "fw-1")
	if u, err := forwardUnapplied(ctx, store, inv); err != nil || u {
		t.Fatalf("no forward intent: %v %v, want false", u, err)
	}
	updated := time.Now().UTC().Truncate(time.Millisecond)
	fwd := dnsForwardIntent(t, "d1", true, "e12bench.internal", "192.168.1.2")
	fwd.UpdatedAt = updated
	if err := store.CreateIntent(ctx, fwd); err != nil {
		t.Fatal(err)
	}
	if u, err := forwardUnapplied(ctx, store, inv); err != nil || !u {
		t.Fatalf("never applied: %v %v, want true", u, err)
	}
	if err := store.UpdateAfterApply(ctx, fwID, "h", updated.Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if u, _ := forwardUnapplied(ctx, store, inv); !u {
		t.Fatal("applied before the forward was written: want true")
	}
	if err := store.UpdateAfterApply(ctx, fwID, "h", updated); err != nil {
		t.Fatal(err)
	}
	if u, _ := forwardUnapplied(ctx, store, inv); u {
		t.Fatal("applied in the same millisecond the forward was written: want false (apply follows the write)")
	}
	if err := store.UpdateAfterApply(ctx, fwID, "h", updated.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if u, _ := forwardUnapplied(ctx, store, inv); u {
		t.Fatal("applied after: want false")
	}
	seedFirewallNode(t, inv, "fw-2")
	if u, _ := forwardUnapplied(ctx, store, inv); u {
		t.Fatal("two firewall nodes: no apply could target one, want false")
	}
}
