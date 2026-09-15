package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync/atomic"
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
	r, _, ran := applyCounterStore(t)
	return r, ran
}

func applyCounterStore(t *testing.T) (*jobs.Runner, *jobs.Store, chan struct{}) {
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
	return runner, js, ran
}

// expectApply asserts how many firewall.apply jobs the reconcile run just before
// it submitted: exactly one when want is true, none when it is false.
//
// It waits for a fact, not a timer: the reconcile step calls runner.Submit
// synchronously, so by the time it returns every job it submitted is already
// counted by the runner's WaitGroup, and runner.Wait returns only once each of
// them has finished — the stand-in step has sent on ran, or never will. Only
// then is ran read, without blocking. A late apply cannot slip past a "none"
// check and a slow one cannot fail a "one" check, however loaded the host is.
// The deadline bounds the single wait so a wedged runner fails naming what
// never happened, instead of hanging to the package timeout.
func expectApply(t *testing.T, runner *jobs.Runner, ran chan struct{}, want bool, why string) {
	t.Helper()
	done := make(chan struct{})
	go func() { runner.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("submitted jobs never finished within 30s: %s", why)
	}
	got := 0
	for len(ran) > 0 {
		<-ran
		got++
	}
	switch {
	case want && got != 1:
		t.Fatalf("firewall.apply runs = %d, want 1: %s", got, why)
	case !want && got != 0:
		t.Fatalf("auto-applied %d time(s), but should not have: %s", got, why)
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
	expectApply(t, runner, ran, true, "first creation")
	if err := store.UpdateAfterApply(ctx, fwID, "h1", time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if m := run(); m["changed"] != false || m["unapplied"] == true {
		t.Fatalf("after a landed apply: %v, want a no-op", m)
	}
	expectApply(t, runner, ran, false, "forward unchanged and applied")

	// The address moves while the firewall is away: changed, apply submitted,
	// but it never lands (no UpdateAfterApply).
	target = "192.168.1.226"
	if err := store.UpdateAfterApply(ctx, fwID, "h1", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	run()
	expectApply(t, runner, ran, true, "address changed")

	// The firewall registers again: nothing changed, but it is unapplied.
	if m := run(); m["changed"] != false || m["unapplied"] != true {
		t.Fatalf("firewall back: %v, want unchanged but unapplied", m)
	}
	expectApply(t, runner, ran, true, "unchanged but never applied")

	// That apply lands; the next registration is a no-op.
	if err := store.UpdateAfterApply(ctx, fwID, "h2", time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	run()
	expectApply(t, runner, ran, false, "applied after it landed")
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

// TestDNSForwardWorkflow_BoundedRetries runs the registered workflow through
// the real runner. A step that fails twice and then succeeds ends with the job
// succeeding and exactly one firewall.apply submitted, not one per attempt. A
// step that always fails ends failed after dnsForwardAttempts attempts, with
// nothing else submitted: no apply, and no further dns_forward job.
func TestDNSForwardWorkflow_BoundedRetries(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failures    int32 // how many leading attempts fail
		wantStatus  jobs.Status
		wantAttempt int
		wantApplies int
	}{
		{"fails twice then succeeds", 2, jobs.StatusSucceeded, 3, 1},
		{"always fails", 1 << 30, jobs.StatusFailed, dnsForwardAttempts, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := newStore(t)
			runner, js, ran := applyCounterStore(t)
			// Production spaces retries with jobs.DefaultBackoff; zero keeps the
			// test fast and changes nothing about how many attempts run.
			runner.SetBackoff(func(int) time.Duration { return 0 })

			var calls atomic.Int32
			wf := DNSForwardWorkflow(store, runner, DNSForwardConfig{
				Zone:   func() string { return "e12bench.internal" },
				Target: func() string { return "192.168.1.226" },
				// The step's first input; failing it fails the attempt before
				// anything is written, as a transient setup-store error would.
				Managed: func(context.Context) (bool, error) {
					if calls.Add(1) <= tc.failures {
						return false, errors.New("setup store: database is locked")
					}
					return true, nil
				},
			})
			if err := jobs.ValidateWorkflow(wf); err != nil {
				t.Fatalf("workflow does not validate: %v", err)
			}
			runner.Register(wf)

			j, err := runner.Submit(ctx, "firewall.dns_forward", json.RawMessage(`{}`), "test")
			if err != nil {
				t.Fatal(err)
			}
			runner.Wait()

			got, err := js.GetJob(ctx, j.ID)
			if err != nil || got == nil {
				t.Fatalf("GetJob: %v %v", got, err)
			}
			if got.Status != tc.wantStatus {
				t.Fatalf("job status = %s (%s), want %s", got.Status, got.Error, tc.wantStatus)
			}
			if n := calls.Load(); int(n) != tc.wantAttempt {
				t.Fatalf("step attempts = %d, want %d", n, tc.wantAttempt)
			}
			applies := 0
			for len(ran) > 0 {
				<-ran
				applies++
			}
			if applies != tc.wantApplies {
				t.Fatalf("firewall.apply runs = %d, want %d", applies, tc.wantApplies)
			}
			if fwd, _ := js.ListJobsByKind(ctx, "firewall.dns_forward", 100); len(fwd) != 1 {
				t.Fatalf("dns_forward jobs = %d, want only the one submitted", len(fwd))
			}
		})
	}
}
