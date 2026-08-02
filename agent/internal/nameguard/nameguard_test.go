package nameguard

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func fixedLocal(ips ...string) LocalIPs {
	return func() []string { return ips }
}

// failLookup stands in for the system resolver being unable to answer. Tests
// must always inject a lookup: this box has an /etc/hosts entry for
// rasputin.local, so falling through to the real resolver would quietly change
// what the tests assert.
func failLookup(string) ([]string, error) { return nil, errors.New("no such host") }

func fixedLookup(addrs ...string) SystemLookup {
	return func(string) ([]string, error) { return addrs, nil }
}

func TestProbeClassifies(t *testing.T) {
	tests := []struct {
		name       string
		resolveIP  string
		resolveEr  error
		local      []string
		wantState  State
		wantOwner  string
		wantSource Source
	}{
		{
			name:       "answers with one of our own addresses",
			resolveIP:  "192.168.1.10",
			local:      []string{"10.0.0.1", "192.168.1.10"},
			wantState:  StateOK,
			wantOwner:  "192.168.1.10",
			wantSource: SourceMDNS,
		},
		{
			name:       "answers with someone else's address",
			resolveIP:  "192.168.1.245",
			local:      []string{"192.168.1.240"},
			wantState:  StateConflict,
			wantOwner:  "192.168.1.245",
			wantSource: SourceMDNS,
		},
		{
			name:       "nobody answers",
			resolveEr:  errors.New("mdns: no A answer (timeout)"),
			local:      []string{"192.168.1.240"},
			wantState:  StateUnpublished,
			wantSource: SourceNone,
		},
		{
			name:       "empty answer without an error is still unpublished",
			resolveIP:  "",
			local:      []string{"192.168.1.240"},
			wantState:  StateUnpublished,
			wantSource: SourceNone,
		},
		{
			// A control plane with no addresses yet (very early boot) must not
			// read an answer as OK — it cannot be us.
			name:       "no local addresses means any answer is a conflict",
			resolveIP:  "192.168.1.245",
			local:      nil,
			wantState:  StateConflict,
			wantOwner:  "192.168.1.245",
			wantSource: SourceMDNS,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolve := func(string, time.Duration) (string, error) { return tc.resolveIP, tc.resolveEr }
			got, owner, source := probe("rasputin.local", time.Second, resolve, fixedLocal(tc.local...), failLookup)
			if got != tc.wantState {
				t.Errorf("state = %q, want %q", got, tc.wantState)
			}
			if owner != tc.wantOwner {
				t.Errorf("owner = %q, want %q", owner, tc.wantOwner)
			}
			if source != tc.wantSource {
				t.Errorf("source = %q, want %q", source, tc.wantSource)
			}
		})
	}
}

type answer struct {
	ip  string
	err error
}

// harness drives Run with a scripted sequence of probe answers, counting
// recovery attempts and recording every Status the loop produces. Each test
// gets its own, so nothing races on package state.
type harness struct {
	mu         sync.Mutex
	answers    []answer
	calls      int
	recoveries int
	statuses   []Status
}

func (h *harness) resolve(string, time.Duration) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	i := h.calls
	if i >= len(h.answers) {
		i = len(h.answers) - 1 // repeat the last answer forever
	}
	h.calls++
	return h.answers[i].ip, h.answers[i].err
}

func (h *harness) runCmd(context.Context, string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recoveries++
	return "", nil
}

func (h *harness) record(s Status) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.statuses = append(h.statuses, s)
}

func (h *harness) counts() (calls, recoveries int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls, h.recoveries
}

func (h *harness) last() Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.statuses) == 0 {
		return Status{}
	}
	return h.statuses[len(h.statuses)-1]
}

// firstWithState returns the first recorded Status in state s. Tests that
// compare two states must use this rather than last(): with a millisecond
// interval the loop can move on between two reads, so last() can return the
// same Status twice and quietly assert nothing.
func (h *harness) firstWithState(s State) (Status, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, st := range h.statuses {
		if st.State == s {
			return st, true
		}
	}
	return Status{}, false
}

func (h *harness) sawState(s State) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, st := range h.statuses {
		if st.State == s {
			return true
		}
	}
	return false
}

func (h *harness) start(t *testing.T, cfg Config) {
	t.Helper()
	cfg.Resolve = h.resolve
	cfg.runCmd = h.runCmd
	cfg.onStatus = h.record
	if cfg.Lookup == nil {
		cfg.Lookup = failLookup
	}
	if cfg.Interval == 0 {
		cfg.Interval = time.Millisecond
	}
	if cfg.Name == "" {
		cfg.Name = "rasputin.local"
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Run(ctx, cfg)
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", msg)
}

// A conflict must NOT trigger recovery. Restarting the responder while another
// host legitimately holds the name just re-probes, loses again, and flaps.
func TestConflictDoesNotRecover(t *testing.T) {
	h := &harness{answers: []answer{{ip: "192.168.1.245"}}}
	h.start(t, Config{
		MissesBeforeRecover: 1,
		RecoverCmd:          "systemctl restart systemd-resolved",
		Local:               fixedLocal("192.168.1.240"),
	})

	waitFor(t, func() bool { c, _ := h.counts(); return c >= 5 }, "several probes")
	if _, rec := h.counts(); rec != 0 {
		t.Fatalf("recovery ran %d times during a conflict; it must never run", rec)
	}
	if got := h.last(); got.State != StateConflict || got.OwnerIP != "192.168.1.245" {
		t.Fatalf("status = %+v, want conflict owned by 192.168.1.245", got)
	}
}

// The bench-observed sequence (2026-07-28): the conflicting host leaves, the
// responder stays backed off, and nothing re-probes on its own. The guard must
// notice the name has gone unpublished and restart the responder.
func TestRecoversWhenConflictClears(t *testing.T) {
	h := &harness{answers: []answer{
		{ip: "192.168.1.245"},          // the other cluster owns the name
		{err: errors.New("no answer")}, // it left; resolved is still backed off
		{err: errors.New("no answer")}, // second miss crosses the threshold
		{ip: "192.168.1.240"},          // the restart worked — it's ours again
	}}
	h.start(t, Config{
		MissesBeforeRecover: 2,
		RecoverCmd:          "systemctl restart systemd-resolved",
		Local:               fixedLocal("192.168.1.240"),
	})

	waitFor(t, func() bool { _, rec := h.counts(); return rec >= 1 }, "recovery after the conflict cleared")
	waitFor(t, func() bool { return h.last().State == StateOK }, "healthy status after recovery")

	if !h.sawState(StateConflict) || !h.sawState(StateUnpublished) {
		t.Error("expected the run to pass through conflict and unpublished before recovering")
	}
	if got := h.last().Recoveries; got != 0 {
		t.Errorf("recoveries = %d once healthy, want the episode budget reset to 0", got)
	}
}

// A recovery that cannot work must not become a restart loop.
func TestRecoveryIsCappedPerEpisode(t *testing.T) {
	h := &harness{answers: []answer{{err: errors.New("no answer")}}}
	h.start(t, Config{
		MissesBeforeRecover: 1,
		MaxRecoveries:       3,
		RecoverCmd:          "systemctl restart systemd-resolved",
		Local:               fixedLocal("192.168.1.240"),
	})

	waitFor(t, func() bool { c, _ := h.counts(); return c >= 30 }, "many probes")
	if _, rec := h.counts(); rec != 3 {
		t.Fatalf("recovery ran %d times, want it capped at 3", rec)
	}
}

// With no RecoverCmd the guard must still observe and report — the correct
// configuration on OpenWrt (no systemd) and in dev/CI.
func TestReportOnlyWithoutRecoverCmd(t *testing.T) {
	h := &harness{answers: []answer{{err: errors.New("no answer")}}}
	h.start(t, Config{
		MissesBeforeRecover: 1,
		Local:               fixedLocal("192.168.1.240"),
	})

	waitFor(t, func() bool { return h.last().State == StateUnpublished }, "unpublished status")
	if _, rec := h.counts(); rec != 0 {
		t.Errorf("recovery ran %d times with no RecoverCmd, want 0", rec)
	}
}

// Run must publish to the package-level snapshot, which is what diag.health
// reads.
func TestSnapshotIsPublished(t *testing.T) {
	h := &harness{answers: []answer{{ip: "192.168.1.240"}}}
	h.start(t, Config{Name: "snapshot-test.local", Local: fixedLocal("192.168.1.240")})

	waitFor(t, func() bool {
		s := Snapshot()
		return s.Name == "snapshot-test.local" && s.State == StateOK
	}, "snapshot to reflect the running guard")
}

// The zero Status must be distinguishable from healthy — a caller that read
// "not running" as OK would report a green check on a node that never probed.
func TestZeroStatusIsNotHealthy(t *testing.T) {
	if got := (Status{}).State; got != StateUnknown {
		t.Fatalf("zero Status state = %q, want StateUnknown", got)
	}
	if StateUnknown == StateOK {
		t.Fatal("StateUnknown must not equal StateOK")
	}
}

func TestRunWithoutNameReturns(t *testing.T) {
	done := make(chan struct{})
	go func() {
		Run(context.Background(), Config{Name: ""})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run with an empty name should return immediately")
	}
}

// --- the system-resolver cross-check -----------------------------------------

// If our own responder's multicast answer never reaches our socket, the mDNS
// probe goes silent even though the name IS published. Restarting the responder
// on that would be a self-inflicted outage, repeated forever. The resolver
// cross-check must catch it.
func TestSilentMDNSButResolverSeesUsIsHealthy(t *testing.T) {
	resolve := func(string, time.Duration) (string, error) {
		return "", errors.New("mdns: no A answer (timeout)")
	}
	got, owner, source := probe("rasputin.local", time.Second,
		resolve, fixedLocal("192.168.1.240"), fixedLookup("192.168.1.240"))
	if got != StateOK {
		t.Fatalf("state = %q, want StateOK — the resolver can still map the name to us", got)
	}
	if owner != "192.168.1.240" {
		t.Errorf("owner = %q, want our own address", owner)
	}
	// The whole point of recording Source: this healthy verdict came from the
	// FALLBACK, meaning our own responder's answer is not reaching our socket.
	// Indistinguishable from a wire-answered OK without it.
	if source != SourceResolver {
		t.Errorf("source = %q, want SourceResolver — a healthy verdict from the fallback must be distinguishable from one off the wire", source)
	}
}

// The cross-check must not launder someone else's answer into a pass.
func TestSilentMDNSAndResolverSeesSomeoneElseIsUnpublished(t *testing.T) {
	resolve := func(string, time.Duration) (string, error) { return "", errors.New("no answer") }
	got, _, source := probe("rasputin.local", time.Second,
		resolve, fixedLocal("192.168.1.240"), fixedLookup("192.168.1.245"))
	if source != SourceNone {
		t.Errorf("source = %q, want SourceNone — nothing produced a usable answer", source)
	}
	if got != StateUnpublished {
		t.Fatalf("state = %q, want StateUnpublished — the resolver answered with a host that isn't us", got)
	}
}

// A conflict seen on the wire is definitive and must not be overridden by a
// stale resolver answer (an /etc/hosts pin, a cached record).
func TestWireConflictBeatsResolver(t *testing.T) {
	resolve := func(string, time.Duration) (string, error) { return "192.168.1.245", nil }
	got, owner, source := probe("rasputin.local", time.Second,
		resolve, fixedLocal("192.168.1.240"), fixedLookup("192.168.1.240"))
	if source != SourceMDNS {
		t.Errorf("source = %q, want SourceMDNS — the wire is what saw the conflict", source)
	}
	if got != StateConflict {
		t.Fatalf("state = %q, want StateConflict — the wire is authoritative on who owns the name", got)
	}
	if owner != "192.168.1.245" {
		t.Errorf("owner = %q, want the conflicting host", owner)
	}
}

// End-to-end through Run: a box whose responder is fine but whose loopback is
// silent must never restart the responder.
func TestNoRecoveryWhenResolverConfirmsUs(t *testing.T) {
	h := &harness{answers: []answer{{err: errors.New("no answer")}}}
	h.start(t, Config{
		MissesBeforeRecover: 1,
		RecoverCmd:          "systemctl restart systemd-resolved",
		Local:               fixedLocal("192.168.1.240"),
		Lookup:              fixedLookup("192.168.1.240"),
	})

	waitFor(t, func() bool { c, _ := h.counts(); return c >= 5 }, "several probes")
	if _, rec := h.counts(); rec != 0 {
		t.Fatalf("recovery ran %d times while the resolver still mapped the name to us; want 0", rec)
	}
	if got := h.last().State; got != StateOK {
		t.Errorf("state = %q, want StateOK", got)
	}
}

// --- config defaults ----------------------------------------------------------

// Every other test sets Interval and MissesBeforeRecover explicitly, so nothing
// exercises the defaults — and a zeroed Interval would spin the loop hot on
// every appliance. Pin them.
func TestApplyDefaults(t *testing.T) {
	var c Config
	c.applyDefaults()

	if c.Interval != 60*time.Second {
		t.Errorf("Interval = %s, want 60s", c.Interval)
	}
	if c.ProbeTimeout != 3*time.Second {
		t.Errorf("ProbeTimeout = %s, want 3s", c.ProbeTimeout)
	}
	if c.MissesBeforeRecover != 2 {
		t.Errorf("MissesBeforeRecover = %d, want 2 (a single miss must not restart the resolver)", c.MissesBeforeRecover)
	}
	if c.MaxRecoveries != 3 {
		t.Errorf("MaxRecoveries = %d, want 3", c.MaxRecoveries)
	}
	if c.Resolve == nil || c.Local == nil || c.runCmd == nil {
		t.Error("Resolve, Local and runCmd must all get defaults")
	}
}

// Explicitly-set values must survive applyDefaults untouched.
func TestApplyDefaultsKeepsExplicitValues(t *testing.T) {
	c := Config{
		Interval:            5 * time.Second,
		ProbeTimeout:        time.Second,
		MissesBeforeRecover: 7,
		MaxRecoveries:       9,
	}
	c.applyDefaults()

	if c.Interval != 5*time.Second || c.ProbeTimeout != time.Second {
		t.Errorf("durations overwritten: %+v", c)
	}
	if c.MissesBeforeRecover != 7 || c.MaxRecoveries != 9 {
		t.Errorf("counts overwritten: misses=%d max=%d", c.MissesBeforeRecover, c.MaxRecoveries)
	}
}

// --- behaviour after the cap --------------------------------------------------

// Hitting the recovery cap must not stop the guard reporting. Giving up on
// repair and giving up on observation are different things: the operator still
// needs to see that the name is unpublished.
func TestKeepsReportingAfterGivingUp(t *testing.T) {
	h := &harness{answers: []answer{{err: errors.New("no answer")}}}
	h.start(t, Config{
		MissesBeforeRecover: 1,
		MaxRecoveries:       2,
		RecoverCmd:          "systemctl restart systemd-resolved",
		Local:               fixedLocal("192.168.1.240"),
	})

	waitFor(t, func() bool { c, _ := h.counts(); return c >= 25 }, "well past the cap")
	if _, rec := h.counts(); rec != 2 {
		t.Fatalf("recovery ran %d times, want it capped at 2", rec)
	}
	if got := h.last().State; got != StateUnpublished {
		t.Errorf("state = %q after giving up, want it still reporting StateUnpublished", got)
	}
}

// A recovery command that fails must be survivable — the responder restart is
// best-effort, and a broken command must not wedge or panic the guard.
func TestRecoveryCommandFailureIsSurvivable(t *testing.T) {
	h := &harness{answers: []answer{{err: errors.New("no answer")}}}
	failing := func(context.Context, string) (string, error) {
		h.mu.Lock()
		h.recoveries++
		h.mu.Unlock()
		return "Failed to restart systemd-resolved: Unit not found.", errors.New("exit 5")
	}
	cfg := Config{
		Name:                "rasputin.local",
		Interval:            time.Millisecond,
		MissesBeforeRecover: 1,
		MaxRecoveries:       2,
		RecoverCmd:          "systemctl restart systemd-resolved",
		Resolve:             h.resolve,
		Local:               fixedLocal("192.168.1.240"),
		Lookup:              failLookup,
		runCmd:              failing,
		onStatus:            h.record,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Run(ctx, cfg)

	waitFor(t, func() bool { c, _ := h.counts(); return c >= 15 }, "probes to continue after a failed recovery")
	if _, rec := h.counts(); rec != 2 {
		t.Errorf("recovery attempted %d times, want 2 — a failing command must still count against the cap", rec)
	}
	if got := h.last().State; got != StateUnpublished {
		t.Errorf("state = %q, want the guard still reporting", got)
	}
}

// Since marks when the state last CHANGED, not when it was last probed —
// otherwise "conflicting since" in an operator-facing surface would be a lie
// that resets every probe.
func TestSinceTracksTransitionsNotProbes(t *testing.T) {
	h := &harness{answers: []answer{{ip: "192.168.1.240"}}}
	h.start(t, Config{Local: fixedLocal("192.168.1.240")})

	waitFor(t, func() bool { return h.last().State == StateOK }, "a healthy status")
	first := h.last().Since

	waitFor(t, func() bool { c, _ := h.counts(); return c >= 10 }, "several more probes in the same state")
	if got := h.last().Since; !got.Equal(first) {
		t.Errorf("Since moved from %s to %s without a state change", first, got)
	}
}

// ...and the inverse: Since MUST advance when the state actually changes.
//
// Without this, negating the `state != prev` guard survives: prev stays pinned
// at StateUnknown forever, so Since freezes at process start and logTransition
// is never called even once. That silently removes every operator-facing log
// line — the exact signal this package exists to provide, and the reason the
// original bug cost a day to diagnose. Asserting only that Since holds steady
// within a state cannot catch it, because "never moves at all" satisfies that.
func TestSinceAdvancesOnStateChange(t *testing.T) {
	h := &harness{answers: []answer{
		{ip: "192.168.1.240"}, // ours
		{ip: "192.168.1.245"}, // someone else takes it
	}}
	h.start(t, Config{Local: fixedLocal("192.168.1.240")})

	waitFor(t, func() bool {
		_, ok := h.firstWithState(StateConflict)
		return ok
	}, "the run to reach the conflict")

	healthySt, ok := h.firstWithState(StateOK)
	if !ok {
		t.Fatal("never observed the healthy state before the conflict")
	}
	conflictSt, _ := h.firstWithState(StateConflict)
	healthy, conflicted := healthySt.Since, conflictSt.Since

	if !conflicted.After(healthy) {
		t.Fatalf("Since did not advance across a state change (%s -> %s): transitions are not being observed",
			healthy, conflicted)
	}
}

// describe exists for exactly one reason: the bench printed "(was )" when the
// zero State reached a log line, which reads like a bug in the logging rather
// than the honest "we had not probed yet". Pin that contract — a pure function
// with a stated guarantee is worth a test, unlike the log-string branches
// around it.
func TestDescribeRendersUnknown(t *testing.T) {
	if got := describe(StateUnknown); got != "unknown" {
		t.Errorf("describe(StateUnknown) = %q, want %q — an empty rendering is what made the log look broken", got, "unknown")
	}
	for _, s := range []State{StateOK, StateConflict, StateUnpublished} {
		if got := describe(s); got != string(s) {
			t.Errorf("describe(%q) = %q, want the state verbatim", s, got)
		}
		if got := describe(s); got == "unknown" {
			t.Errorf("describe(%q) must not collapse a real state into \"unknown\"", s)
		}
	}
}
