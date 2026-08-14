package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The canary gate — ADR-0005 Decisions 6 + 11, story #73.
//
// Two halves, tested separately because they fail differently:
//
//   - assignCanaries picks WHO gates a fan-out. Pure, and the interesting
//     cases are all about the (tier, arch) key.
//   - the cascade decides WHAT that pick buys. Driven through the injected
//     childDriver, so a canary failure is one line of stub rather than a
//     bricked bench node.

// ----- helpers -------------------------------------------------------------

func tgt(id string, tier proto.NodeRole, compat string) plannedTarget {
	return plannedTarget{
		NodeID:       id,
		BundleSHA256: "sha-" + compat,
		Compatible:   compat,
		Tier:         tier,
	}
}

const (
	arm = "rasputin-rpi-arm64"
	x86 = "rasputin-n100"
	fw  = "rasputin-fw-n100"
)

func canaryIDsOf(targets []plannedTarget) []string {
	var out []string
	for _, t := range targets {
		if t.Canary {
			out = append(out, t.NodeID)
		}
	}
	return out
}

func eqIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// stubDriver scripts each node's outcome and records what the scheduler did:
// the order children were submitted in, and the PEAK number in flight at once.
// Peak concurrency is the only direct evidence that a bound is a bound.
//
// Thread-safe because bounded fan-out calls it from several goroutines — the
// first version of this stub was not, and `-race` said so immediately.
type stubDriver struct {
	mu       sync.Mutex
	started  []string
	inFlight int
	peak     int

	fail map[string]bool
	// submitErr nodes fail at submission rather than at completion — a
	// different code path, and one that used to be able to skip the gate.
	submitErr map[string]bool
	// hold is how long each child "runs". Non-zero makes overlap observable;
	// with instant children a serial run and a parallel one look identical.
	hold time.Duration
}

func (s *stubDriver) startOrder() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.started...)
}

func (s *stubDriver) peakInFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}

func (s *stubDriver) driver() childDriver {
	return childDriver{
		submit: func(sc *jobs.StepCtx, t plannedTarget) (string, error) {
			if s.submitErr[t.NodeID] {
				return "", errors.New("no runner")
			}
			s.mu.Lock()
			s.started = append(s.started, t.NodeID)
			s.inFlight++
			if s.inFlight > s.peak {
				s.peak = s.inFlight
			}
			s.mu.Unlock()
			return "child-" + t.NodeID, nil
		},
		wait: func(sc *jobs.StepCtx, childID string) (jobs.Status, error) {
			if s.hold > 0 {
				time.Sleep(s.hold)
			}
			id := strings.TrimPrefix(childID, "child-")
			s.mu.Lock()
			s.inFlight--
			s.mu.Unlock()
			if s.fail[id] {
				return jobs.StatusFailed, nil
			}
			return jobs.StatusSucceeded, nil
		},
	}
}

// serial is the spec every test that asserts an exact start ORDER must use.
// Above k=1 the fan-out finishes in whatever sequence the fleet reboots in,
// which is the feature, so pinning order there would be testing the scheduler
// for a property it deliberately does not have.
func serial() proto.SystemUpdateSpec {
	k := proto.Int(1)
	return proto.SystemUpdateSpec{Version: "2026.08.0", MaxInFlight: &k}
}

// runCascade drives the cascade step over a fixed plan, bypassing step 1 by
// handing the plan in through PriorResults exactly as the saga does.
//
// The step itself no longer errors on a node failure — the outcome rides on
// the result so `summarize` can publish the report before the saga is failed
// (#76) — so the verdict under test is `terminalError()`, not the step's own
// error. A non-nil step error here means something structural broke.
func runCascade(t *testing.T, targets []plannedTarget, spec proto.SystemUpdateSpec, drv childDriver) cascadeResult {
	t.Helper()
	planRaw, err := json.Marshal(systemPlanState{Targets: targets})
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	specRaw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	step := systemCascadeWith(nil, nil, nil, SystemUpdateConfig{}, drv)
	raw, runErr := step(&jobs.StepCtx{
		Ctx:          context.Background(),
		JobID:        "parent-1",
		Spec:         specRaw,
		PriorResults: map[string]json.RawMessage{"plan": planRaw},
		Log:          func(level, message string) {},
	})
	if runErr != nil {
		t.Fatalf("cascade step errored: %v — a node failure must ride on the result, not fail the step", runErr)
	}
	var out cascadeResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal cascade result: %v", err)
	}
	return out
}

// outcomes flattens the grid to "node=outcome" strings, in planned order.
func outcomes(g []proto.NodeResult) []string {
	out := make([]string, len(g))
	for i, r := range g {
		out[i] = fmt.Sprintf("%s=%s", r.NodeID, r.Outcome)
	}
	return out
}

// ----- assignCanaries ------------------------------------------------------

func TestAssignCanaries_OnePerTierAndArch(t *testing.T) {
	// A mixed compute tier plus a mixed storage tier: four canaries, because
	// "the image is good" is a claim about one arch in one tier and nothing
	// wider. An arm64 canary authorising amd64 fan-out is the failure this
	// key exists to prevent (Decision 11).
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, arm),
		tgt("c02", proto.RoleCompute, arm),
		tgt("c03", proto.RoleCompute, x86),
		tgt("c04", proto.RoleCompute, x86),
		tgt("s01", proto.RoleStorage, arm),
		tgt("s02", proto.RoleStorage, x86),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	want := []string{"c01", "c03", "s01", "s02"}
	if got := canaryIDsOf(targets); !eqIDs(got, want) {
		t.Errorf("canaries = %v, want %v", got, want)
	}
}

func TestAssignCanaries_FirstInPlannedOrder(t *testing.T) {
	targets := []plannedTarget{
		tgt("c07", proto.RoleCompute, x86),
		tgt("c08", proto.RoleCompute, x86),
		tgt("c09", proto.RoleCompute, x86),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	if got := canaryIDsOf(targets); !eqIDs(got, []string{"c07"}) {
		t.Errorf("canaries = %v, want [c07] — the pick is the first target in planned order", got)
	}
}

func TestAssignCanaries_NeverControlPlaneOrFirewall(t *testing.T) {
	// Neither tier has anything behind it to protect, and the controlplane is
	// ordered last precisely because losing it is expensive.
	targets := []plannedTarget{
		tgt("cp-1", proto.RoleControlPlane, x86),
		tgt("fw-1", proto.RoleFirewall, fw),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	if got := canaryIDsOf(targets); len(got) != 0 {
		t.Errorf("canaries = %v, want none", got)
	}
}

func TestAssignCanaries_OverrideReplacesThePickForItsGroupOnly(t *testing.T) {
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, arm),
		tgt("c02", proto.RoleCompute, arm),
		tgt("c03", proto.RoleCompute, x86),
	}
	if err := assignCanaries(targets, []string{"c02"}); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	// c02 displaces c01 for arm64; the amd64 group keeps its default pick.
	if got := canaryIDsOf(targets); !eqIDs(got, []string{"c02", "c03"}) {
		t.Errorf("canaries = %v, want [c02 c03]", got)
	}
}

func TestAssignCanaries_OverrideErrors(t *testing.T) {
	// Every one of these is an error rather than a silent fallback: an
	// operator who names a canary has a reason, and canarying somebody else
	// while reporting success is worse than refusing the run.
	base := func() []plannedTarget {
		return []plannedTarget{
			tgt("c01", proto.RoleCompute, arm),
			tgt("c02", proto.RoleCompute, arm),
			tgt("cp-1", proto.RoleControlPlane, x86),
		}
	}
	cases := []struct {
		name      string
		overrides []string
		wantMsg   string
	}{
		{"not a target", []string{"c99"}, "not a target"},
		{"controlplane", []string{"cp-1"}, "never the controlplane or the firewall"},
		{"two for one group", []string{"c01", "c02"}, "one canary per tier and architecture"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := assignCanaries(base(), tc.overrides)
			if err == nil {
				t.Fatalf("want an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantMsg)
			}
		})
	}
}

func TestGroupByTier_KeepsPlannedOrder(t *testing.T) {
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, arm),
		tgt("c02", proto.RoleCompute, x86),
		tgt("s01", proto.RoleStorage, arm),
		tgt("fw-1", proto.RoleFirewall, fw),
	}
	got := groupByTier(targets)
	want := []proto.NodeRole{proto.RoleCompute, proto.RoleStorage, proto.RoleFirewall}
	if len(got) != len(want) {
		t.Fatalf("got %d tiers, want %d", len(got), len(want))
	}
	for i, g := range got {
		if g.Tier != want[i] {
			t.Errorf("tier %d = %s, want %s", i, g.Tier, want[i])
		}
	}
	if n := len(got[0].Targets); n != 2 {
		t.Errorf("compute tier has %d targets, want 2", n)
	}
}

// ----- the gate ------------------------------------------------------------

func TestCascade_CanaryFailureAbortsBeforeFanOut(t *testing.T) {
	// The whole point of the gate. c01 is the arm64 canary; when it fails,
	// exactly one node has been touched and everything else is untouched —
	// including the amd64 half of the same tier and every later tier.
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, arm),
		tgt("c02", proto.RoleCompute, arm),
		tgt("c03", proto.RoleCompute, x86),
		tgt("s01", proto.RoleStorage, arm),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	drv := &stubDriver{fail: map[string]bool{"c01": true}}
	res := runCascade(t, targets, serial(), drv.driver())

	err := res.terminalError()
	if err == nil {
		t.Fatal("want a terminal error when the canary fails, got nil")
	}
	if !strings.Contains(err.Error(), "aborted before fan-out") {
		t.Errorf("error = %q, want it to name the canary abort", err)
	}
	if !eqIDs(drv.started, []string{"c01"}) {
		t.Errorf("started %v, want only [c01] — nothing else in the fleet may be touched", drv.started)
	}
	if !eqIDs(res.Remaining, []string{"c02", "c03", "s01"}) {
		t.Errorf("remaining = %v, want [c02 c03 s01]", res.Remaining)
	}
	if !eqIDs(res.Failed, []string{"c01"}) {
		t.Errorf("failed = %v, want [c01]", res.Failed)
	}
	// The grid must distinguish the node that broke from the three the gate
	// protected. Reporting all four as failures would send an operator to
	// look at three healthy machines.
	want := []string{"c01=failed", "c02=not-attempted", "c03=not-attempted", "s01=not-attempted"}
	if got := outcomes(res.Results); !eqIDs(got, want) {
		t.Errorf("grid = %v, want %v", got, want)
	}
}

func TestCascade_CanaryFailureAtSubmitAlsoAborts(t *testing.T) {
	// A canary that never starts has not proved anything, and the gate must
	// treat that identically to one that started and failed. Fanning out
	// anyway because "no child ran" would be the worst version of this bug:
	// an unproven image reaching the whole tier.
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, arm),
		tgt("c02", proto.RoleCompute, arm),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	drv := &stubDriver{submitErr: map[string]bool{"c01": true}}
	res := runCascade(t, targets, serial(), drv.driver())

	if res.terminalError() == nil {
		t.Fatal("want a terminal error when the canary cannot be submitted, got nil")
	}
	if len(drv.started) != 0 {
		t.Errorf("started %v, want nothing", drv.started)
	}
	if !eqIDs(res.Remaining, []string{"c02"}) {
		t.Errorf("remaining = %v, want [c02]", res.Remaining)
	}
}

func TestCascade_CanaryRunsFirstThenTheRestOfItsTier(t *testing.T) {
	// Happy path, mixed tier: both canaries clear before either arch fans
	// out, and the canaries are the first nodes of their tier.
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, arm),
		tgt("c02", proto.RoleCompute, arm),
		tgt("c03", proto.RoleCompute, x86),
		tgt("c04", proto.RoleCompute, x86),
		tgt("s01", proto.RoleStorage, arm),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	drv := &stubDriver{}
	res := runCascade(t, targets, serial(), drv.driver())
	if err := res.terminalError(); err != nil {
		t.Fatalf("terminal error on a clean run: %v", err)
	}
	want := []string{"c01", "c03", "c02", "c04", "s01"}
	if !eqIDs(drv.started, want) {
		t.Errorf("start order = %v, want %v — both canaries before either fan-out", drv.started, want)
	}
	if !eqIDs(res.Canaries, []string{"c01", "c03", "s01"}) {
		t.Errorf("canaries = %v, want [c01 c03 s01]", res.Canaries)
	}
	if len(res.Remaining) != 0 {
		t.Errorf("remaining = %v, want none", res.Remaining)
	}
	if len(res.Results) != len(targets) {
		t.Errorf("grid has %d rows, want one per planned target (%d)", len(res.Results), len(targets))
	}
}

func TestCascade_SecondArchCanaryFailureStopsTheFirstArchFanOut(t *testing.T) {
	// Decision 6's "nothing else in the fleet is touched" composed with
	// Decision 11's per-arch gate: the arm64 canary passed, but the amd64
	// canary failing aborts the run before ANY fan-out — a bad build is far
	// likelier to be a bad release than one bad artifact, and the operator
	// can re-run scoped to the arch that passed.
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, arm),
		tgt("c02", proto.RoleCompute, arm),
		tgt("c03", proto.RoleCompute, x86),
		tgt("c04", proto.RoleCompute, x86),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	drv := &stubDriver{fail: map[string]bool{"c03": true}}
	res := runCascade(t, targets, serial(), drv.driver())
	if res.terminalError() == nil {
		t.Fatal("want a terminal error, got nil")
	}
	if !eqIDs(drv.started, []string{"c01", "c03"}) {
		t.Errorf("started %v, want [c01 c03] — no fan-out node may run", drv.started)
	}
	if !eqIDs(res.Remaining, []string{"c02", "c04"}) {
		t.Errorf("remaining = %v, want [c02 c04]", res.Remaining)
	}
}

func TestCascade_TierWithoutACanaryStillRuns(t *testing.T) {
	// The controlplane and firewall tiers nominate no canary, and that must
	// mean "no gate", not "no fan-out".
	targets := []plannedTarget{
		tgt("cp-1", proto.RoleControlPlane, x86),
		tgt("fw-1", proto.RoleFirewall, fw),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	drv := &stubDriver{}
	res := runCascade(t, targets, serial(), drv.driver())
	if err := res.terminalError(); err != nil {
		t.Fatalf("terminal error: %v", err)
	}
	if !eqIDs(drv.started, []string{"cp-1", "fw-1"}) {
		t.Errorf("started %v, want [cp-1 fw-1]", drv.started)
	}
	if len(res.Canaries) != 0 {
		t.Errorf("canaries = %v, want none", res.Canaries)
	}
}

// ----- best-effort fan-out (#76) -------------------------------------------

func TestCascade_FanOutFailureDoesNotStopTheRun(t *testing.T) {
	// Replaces the halt-on-first assertion this file shipped with. A failed
	// node is a red cell, not a wall: A/B rollback is per-node, and the
	// canary already cleared the image, so c02 breaking says nothing about
	// c03. The run is still failed overall — best-effort changes what gets
	// attempted, not what counts as success.
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, x86),
		tgt("c02", proto.RoleCompute, x86),
		tgt("c03", proto.RoleCompute, x86),
		tgt("s01", proto.RoleStorage, x86),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	drv := &stubDriver{fail: map[string]bool{"c02": true}}
	res := runCascade(t, targets, serial(), drv.driver())

	err := res.terminalError()
	if err == nil {
		t.Fatal("want a terminal error — a partial run is not a success")
	}
	if strings.Contains(err.Error(), "aborted before fan-out") {
		t.Errorf("error = %q, want the ordinary failure, not the canary abort", err)
	}
	if !eqIDs(drv.started, []string{"c01", "c02", "c03", "s01"}) {
		t.Errorf("started %v, want every planned target attempted", drv.started)
	}
	if len(res.Remaining) != 0 {
		t.Errorf("remaining = %v, want none — best-effort leaves nothing unattempted", res.Remaining)
	}
	want := []string{"c01=succeeded", "c02=failed", "c03=succeeded", "s01=succeeded"}
	if got := outcomes(res.Results); !eqIDs(got, want) {
		t.Errorf("grid = %v, want %v", got, want)
	}
}

func TestCascade_AFailedTierDoesNotStopTheNextOne(t *testing.T) {
	// Tiers are an ORDERING, not a gate. Every compute node failing must not
	// silently cancel storage — that is the failure budget's job (#75), and
	// conflating the two would make a tier of flaky nodes look like a
	// deliberate stop.
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, x86),
		tgt("c02", proto.RoleCompute, x86),
		tgt("s01", proto.RoleStorage, x86),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	// c01 is the compute canary, so failing c02 keeps the gate out of it.
	drv := &stubDriver{fail: map[string]bool{"c02": true}}
	res := runCascade(t, targets, serial(), drv.driver())
	if !eqIDs(drv.started, []string{"c01", "c02", "s01"}) {
		t.Errorf("started %v, want storage reached despite the compute failure", drv.started)
	}
	if len(res.Remaining) != 0 {
		t.Errorf("remaining = %v, want none", res.Remaining)
	}
}

func TestCascade_GridCarriesTierArchAndCanary(t *testing.T) {
	// The grid's dimensions are the reason it exists rather than being
	// derived from the child jobs, which know none of them.
	targets := []plannedTarget{
		tgt("pi-1", proto.RoleCompute, arm),
		tgt("n100-1", proto.RoleCompute, x86),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	res := runCascade(t, targets, serial(), (&stubDriver{}).driver())
	if len(res.Results) != 2 {
		t.Fatalf("grid has %d rows, want 2", len(res.Results))
	}
	for _, r := range res.Results {
		if r.Tier != proto.RoleCompute {
			t.Errorf("%s tier = %q, want compute", r.NodeID, r.Tier)
		}
		if r.Compatible == "" {
			t.Errorf("%s has no compatible — the grid cannot say which artifact it took", r.NodeID)
		}
		if !r.Canary {
			t.Errorf("%s should be a canary: it is the only node of its arch", r.NodeID)
		}
		if r.ChildJobID == "" {
			t.Errorf("%s has no childJobId — the grid must link to the per-node job", r.NodeID)
		}
	}
}

// ----- the wire ------------------------------------------------------------

// The gate verdict has to reach the UI, and it has to say which architecture
// it is a verdict ABOUT — a canary_passed with no `compatible` is exactly the
// undifferentiated report Decision 11 exists to stop. Real runner, real NATS,
// real child jobs.
func TestSystemCascade_PublishesTheGateVerdictOnTheWire(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	jobStore := newJobsStore(t)
	runner := jobs.NewRunner(jobStore, nc)
	runner.Register(jobs.Workflow{
		Kind: "node.update",
		Steps: []jobs.WorkflowStep{{
			Name: "noop", Timeout: time.Second,
			Do: func(sc *jobs.StepCtx) (json.RawMessage, error) { return nil, nil },
		}},
	})

	seen := make(chan proto.SystemUpdateChangeEvt, 64)
	sub, err := nc.Subscribe(proto.AllSystemUpdatesFilter, func(m *nats.Msg) {
		var ev proto.SystemUpdateChangeEvt
		if json.Unmarshal(m.Data, &ev) == nil {
			seen <- ev
		}
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	_ = nc.Flush()

	targets := []plannedTarget{
		tgt("n100-1", proto.RoleCompute, x86),
		tgt("n100-2", proto.RoleCompute, x86),
		tgt("pi-1", proto.RoleCompute, arm),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	planRaw, _ := json.Marshal(systemPlanState{BundleVer: "2026.08.4", Component: "os", Targets: targets})

	parent := "parent-gate"
	if err := jobStore.CreateJob(ctx, &jobs.Job{
		ID: parent, Kind: "system.update", Status: jobs.StatusRunning, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	sc := newUpdaterCtx(parent, `{"version":"2026.08.4"}`, nc)
	sc.PriorResults = map[string]json.RawMessage{"plan": planRaw}
	if _, err := systemCascade(store, inv, jobStore, runner, nc, SystemUpdateConfig{})(sc); err != nil {
		t.Fatalf("systemCascade: %v", err)
	}
	runner.Wait()
	_ = nc.Flush()

	// One gate verdict per arch, each naming its own arch and tier.
	passedBy := map[string]proto.SystemUpdateChangeEvt{}
	canaryNodeEvents := map[string]bool{}
	deadline := time.After(5 * time.Second)
collect:
	for {
		select {
		case ev := <-seen:
			switch ev.Change {
			case proto.SystemUpdateCanaryPassed:
				passedBy[ev.Compatible] = ev
			case proto.SystemUpdateNodeSucceeded:
				if ev.Canary {
					canaryNodeEvents[ev.NodeID] = true
				}
			}
			if len(passedBy) == 2 {
				break collect
			}
		case <-deadline:
			break collect
		}
	}

	for _, arch := range []string{x86, arm} {
		ev, ok := passedBy[arch]
		if !ok {
			t.Fatalf("no canary_passed for %s — got verdicts for %v", arch, keysOf(passedBy))
		}
		if ev.Tier != proto.RoleCompute {
			t.Errorf("%s verdict tier = %q, want compute", arch, ev.Tier)
		}
		if !ev.Canary {
			t.Errorf("%s verdict is not flagged as a canary event", arch)
		}
	}
	if passedBy[x86].NodeID != "n100-1" || passedBy[arm].NodeID != "pi-1" {
		t.Errorf("verdict nodes = %s/%s, want n100-1/pi-1",
			passedBy[x86].NodeID, passedBy[arm].NodeID)
	}
	if !canaryNodeEvents["n100-1"] || !canaryNodeEvents["pi-1"] {
		t.Errorf("canary node_succeeded events = %v, want both canaries flagged", canaryNodeEvents)
	}
	if canaryNodeEvents["n100-2"] {
		t.Error("n100-2 is a fan-out target and must not be flagged as a canary")
	}
}

// THE REGRESSION THIS STORY EXISTS TO PREVENT.
//
// A saga stops at its first failed step, so while the cascade step returned an
// error on a node failure it took `summarize` down with it — no `completed`
// event, no counts, no grid, on precisely the runs that had something to
// report. updates.md §4 asserted the opposite and nobody noticed, because
// halt-on-first made a failed run a two-line story. Under best-effort the grid
// IS the report, so losing it on failure loses the feature.
//
// Driven through a real runner with the real cascade and summarize steps, so
// the assertion is about STEP ORDERING and not about either step in isolation.
func TestSystemUpdate_ReportSurvivesAFailedRun(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	jobStore := newJobsStore(t)
	runner := jobs.NewRunner(jobStore, nc)

	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, x86),
		tgt("c02", proto.RoleCompute, x86),
		tgt("c03", proto.RoleCompute, x86),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	planRaw, _ := json.Marshal(systemPlanState{BundleVer: "2026.08.4", Component: "os", Targets: targets})
	drv := (&stubDriver{fail: map[string]bool{"c02": true}}).driver()

	runner.Register(jobs.Workflow{
		Kind: "system.update",
		Steps: []jobs.WorkflowStep{
			{Name: "plan", Timeout: time.Second, Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
				return planRaw, nil
			}},
			{Name: "cascade", Timeout: 30 * time.Second,
				Do: systemCascadeWith(nil, nil, nc, SystemUpdateConfig{}, drv)},
			{Name: "summarize", Timeout: 5 * time.Second, Do: systemSummarize(jobStore, nc)},
		},
	})

	completed := make(chan proto.SystemUpdateChangeEvt, 8)
	sub, err := nc.Subscribe(proto.AllSystemUpdatesFilter, func(m *nats.Msg) {
		var ev proto.SystemUpdateChangeEvt
		if json.Unmarshal(m.Data, &ev) == nil && ev.Change == proto.SystemUpdateCompleted {
			completed <- ev
		}
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	_ = nc.Flush()

	parent, err := runner.Submit(ctx, "system.update", json.RawMessage(`{"version":"2026.08.4"}`), "test")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	runner.Wait()

	// The parent is still failed — best-effort changes what gets attempted,
	// not what counts as success.
	j, err := jobStore.GetJob(ctx, parent.ID)
	if err != nil {
		t.Fatalf("get parent: %v", err)
	}
	if j.Status != jobs.StatusFailed {
		t.Errorf("parent status = %s, want failed", j.Status)
	}
	if !strings.Contains(j.Error, "1 of 3 node(s) failed") {
		t.Errorf("parent error = %q, want it to name the per-node tally", j.Error)
	}

	// ...and the report got out anyway.
	select {
	case ev := <-completed:
		if ev.Counts == nil {
			t.Fatal("completed event carries no counts")
		}
		if ev.Counts.Succeeded != 2 || ev.Counts.Failed != 1 || ev.Counts.Total != 3 {
			t.Errorf("counts = %+v, want 2 succeeded / 1 failed / 3 total", ev.Counts)
		}
		want := []string{"c01=succeeded", "c02=failed", "c03=succeeded"}
		if got := outcomes(ev.Results); !eqIDs(got, want) {
			t.Errorf("grid on the wire = %v, want %v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no completed event — the report did not survive the failed run")
	}
}

// The other half: a canary abort must report the nodes it protected as
// not-attempted, and the count must say so. "0 succeeded, 1 failed" with no
// third number reads as a fleet that broke rather than a gate that worked.
func TestSystemUpdate_CanaryAbortReportsNotAttempted(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	jobStore := newJobsStore(t)
	runner := jobs.NewRunner(jobStore, nc)

	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, x86),
		tgt("c02", proto.RoleCompute, x86),
		tgt("c03", proto.RoleCompute, x86),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	planRaw, _ := json.Marshal(systemPlanState{BundleVer: "2026.08.4", Component: "os", Targets: targets})
	drv := (&stubDriver{fail: map[string]bool{"c01": true}}).driver()

	runner.Register(jobs.Workflow{
		Kind: "system.update",
		Steps: []jobs.WorkflowStep{
			{Name: "plan", Timeout: time.Second, Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
				return planRaw, nil
			}},
			{Name: "cascade", Timeout: 30 * time.Second,
				Do: systemCascadeWith(nil, nil, nc, SystemUpdateConfig{}, drv)},
			{Name: "summarize", Timeout: 5 * time.Second, Do: systemSummarize(jobStore, nc)},
		},
	})

	completed := make(chan proto.SystemUpdateChangeEvt, 8)
	sub, err := nc.Subscribe(proto.AllSystemUpdatesFilter, func(m *nats.Msg) {
		var ev proto.SystemUpdateChangeEvt
		if json.Unmarshal(m.Data, &ev) == nil && ev.Change == proto.SystemUpdateCompleted {
			completed <- ev
		}
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	_ = nc.Flush()

	parent, err := runner.Submit(ctx, "system.update", json.RawMessage(`{"version":"2026.08.4"}`), "test")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	runner.Wait()

	j, _ := jobStore.GetJob(ctx, parent.ID)
	if j.Status != jobs.StatusFailed {
		t.Errorf("parent status = %s, want failed", j.Status)
	}
	if !strings.Contains(j.Error, "aborted before fan-out") {
		t.Errorf("parent error = %q, want it to name the canary abort", j.Error)
	}
	select {
	case ev := <-completed:
		if ev.Counts.NotAttempted != 2 {
			t.Errorf("notAttempted = %d, want 2 — the two nodes the gate protected", ev.Counts.NotAttempted)
		}
		want := []string{"c01=failed", "c02=not-attempted", "c03=not-attempted"}
		if got := outcomes(ev.Results); !eqIDs(got, want) {
			t.Errorf("grid on the wire = %v, want %v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no completed event after a canary abort")
	}
}

func keysOf(m map[string]proto.SystemUpdateChangeEvt) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCascade_SoakHoldsFanOutAndIsSkippedAtZero(t *testing.T) {
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, x86),
		tgt("c02", proto.RoleCompute, x86),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	// Default (0) must not sleep. A wall-clock assertion is the only thing
	// that can catch a soak that fires when it should not.
	start := time.Now()
	if err := runCascade(t, targets, serial(), (&stubDriver{}).driver()).terminalError(); err != nil {
		t.Fatalf("cascade: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("a zero soak took %s; it must not sleep at all", elapsed)
	}

	// A soak that outlives the context fails the step rather than fanning out
	// early — the knob has to be able to hold the fleet back to be worth
	// having.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	sc := &jobs.StepCtx{Ctx: ctx, Log: func(level, message string) {}}
	if err := soak(sc, 30); err == nil {
		t.Error("want an error when the context ends mid-soak, got nil")
	}
	if err := soak(&jobs.StepCtx{Ctx: context.Background()}, 0); err != nil {
		t.Errorf("zero soak returned %v, want nil", err)
	}
}

// ----- bounded fan-out (#74) -----------------------------------------------

// tierOf builds a compute tier of n same-arch nodes, canaries assigned.
func computeTier(t *testing.T, n int) []plannedTarget {
	t.Helper()
	targets := make([]plannedTarget, n)
	for i := range targets {
		targets[i] = tgt(fmt.Sprintf("c%02d", i+1), proto.RoleCompute, x86)
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	return targets
}

func specK(k proto.IntOrString) proto.SystemUpdateSpec {
	return proto.SystemUpdateSpec{Version: "2026.08.0", MaxInFlight: &k}
}

func TestCascade_KEqualsOneIsExactlyTheSerialCascade(t *testing.T) {
	// The backwards-compatibility claim, asserted rather than assumed: at k=1
	// nodes start in planned order and never overlap. If this ever stops
	// holding, "bounded fan-out is expressible as a backwards-compatible
	// change" stops being true.
	targets := computeTier(t, 6)
	drv := &stubDriver{hold: 5 * time.Millisecond}
	runCascade(t, targets, specK(proto.Int(1)), drv.driver())

	want := []string{"c01", "c02", "c03", "c04", "c05", "c06"}
	if got := drv.startOrder(); !eqIDs(got, want) {
		t.Errorf("start order = %v, want %v", got, want)
	}
	if peak := drv.peakInFlight(); peak != 1 {
		t.Errorf("peak in flight = %d, want 1", peak)
	}
}

func TestCascade_FanOutIsBoundedByK(t *testing.T) {
	// 22 compute nodes, k=4: the canary goes alone, then the remaining 21 run
	// four at a time and never five.
	targets := computeTier(t, 22)
	drv := &stubDriver{hold: 10 * time.Millisecond}
	res := runCascade(t, targets, specK(proto.Int(4)), drv.driver())

	if err := res.terminalError(); err != nil {
		t.Fatalf("clean run reported %v", err)
	}
	if peak := drv.peakInFlight(); peak != 4 {
		t.Errorf("peak in flight = %d, want exactly 4 — under is not bounded, over is not honoured", peak)
	}
	if n := len(drv.startOrder()); n != 22 {
		t.Errorf("started %d nodes, want all 22", n)
	}
	// The canary is still alone: it must finish before anything else starts.
	if first := drv.startOrder()[0]; first != "c01" {
		t.Errorf("first node started = %s, want the canary c01", first)
	}
}

func TestCascade_CanariesNeverRunInParallelWithFanOut(t *testing.T) {
	// The gate is worthless if the nodes it gates are already in flight. With
	// k=4 and a tier big enough to overlap, peak concurrency during the canary
	// must still be 1 — which this catches by failing the canary and checking
	// nothing else ever started.
	targets := computeTier(t, 12)
	drv := &stubDriver{hold: 5 * time.Millisecond, fail: map[string]bool{"c01": true}}
	res := runCascade(t, targets, specK(proto.Int(4)), drv.driver())

	if got := drv.startOrder(); !eqIDs(got, []string{"c01"}) {
		t.Errorf("started %v, want only the canary", got)
	}
	if peak := drv.peakInFlight(); peak != 1 {
		t.Errorf("peak in flight = %d, want 1 during the canary phase", peak)
	}
	if len(res.Remaining) != 11 {
		t.Errorf("remaining = %d, want the 11 nodes the gate protected", len(res.Remaining))
	}
}

func TestCascade_ClampForcesSerialOnATwoNodeTier(t *testing.T) {
	// k=4 on a two-node tier is not a bounded fan-out, it is one unbounded
	// batch wearing the word. The clamp holds a node back at every size.
	targets := computeTier(t, 2)
	drv := &stubDriver{hold: 5 * time.Millisecond}
	runCascade(t, targets, specK(proto.Int(4)), drv.driver())
	if peak := drv.peakInFlight(); peak != 1 {
		t.Errorf("peak in flight = %d on a 2-node tier, want 1 — the clamp did not bite", peak)
	}
}

func TestCascade_PercentIsResolvedAgainstTheTier(t *testing.T) {
	// "20%" of a 20-node tier is 4, clamped against 19 → 4.
	targets := computeTier(t, 20)
	drv := &stubDriver{hold: 10 * time.Millisecond}
	runCascade(t, targets, specK(proto.Percent(20)), drv.driver())
	if peak := drv.peakInFlight(); peak != 4 {
		t.Errorf("peak in flight = %d, want 4 (20%% of 20)", peak)
	}
}

func TestCascade_KIsScopedPerTierNotPerRun(t *testing.T) {
	// A big compute tier and a two-node storage tier in one run: the clamp is
	// computed against each tier's own size, so storage runs serially even
	// though compute did not. A run-scoped k would let a 4-wide setting take
	// out both storage nodes at once.
	targets := append(computeTier(t, 10),
		tgt("s01", proto.RoleStorage, x86),
		tgt("s02", proto.RoleStorage, x86),
	)
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	drv := &stubDriver{hold: 10 * time.Millisecond}
	res := runCascade(t, targets, specK(proto.Int(4)), drv.driver())
	if err := res.terminalError(); err != nil {
		t.Fatalf("clean run reported %v", err)
	}
	// s01 is the storage canary and s02 the whole of its fan-out, so the
	// storage tier can never exceed 1 in flight whatever compute did. The
	// assertion that matters is that both ran and the run stayed clean.
	order := drv.startOrder()
	if len(order) != 12 {
		t.Fatalf("started %d nodes, want 12", len(order))
	}
	if last := order[len(order)-1]; last != "s02" {
		t.Errorf("last node started = %s, want s02 — tiers are sequential", last)
	}
}

func TestCascade_GridStaysInPlannedOrderUnderParallelism(t *testing.T) {
	// Nodes finish in whatever order the fleet reboots in; the report must
	// not. A grid that reshuffles between two runs of the same update is one
	// an operator cannot diff.
	targets := computeTier(t, 8)
	drv := &stubDriver{hold: 5 * time.Millisecond, fail: map[string]bool{"c03": true, "c06": true}}
	res := runCascade(t, targets, specK(proto.Int(4)), drv.driver())

	want := []string{
		"c01=succeeded", "c02=succeeded", "c03=failed", "c04=succeeded",
		"c05=succeeded", "c06=failed", "c07=succeeded", "c08=succeeded",
	}
	if got := outcomes(res.Results); !eqIDs(got, want) {
		t.Errorf("grid = %v, want %v", got, want)
	}
	if !eqIDs(res.Failed, []string{"c03", "c06"}) {
		t.Errorf("failed = %v, want [c03 c06] in planned order", res.Failed)
	}
}

func TestClampMaxInFlight(t *testing.T) {
	cases := []struct{ k, tierSize, want int }{
		{4, 22, 4}, // inert on a big tier — the default is meant to be
		{4, 5, 4},  // 4 < 5-1, still inert
		{4, 4, 3},  // one held back
		{4, 2, 1},  // forced serial
		{4, 1, 1},  // a lone node: nothing to hold back, but never zero
		{4, 0, 1},  // empty tier, defensive
		{0, 22, 1}, // a nonsense k is clamped UP; zero in flight never runs
	}
	for _, c := range cases {
		if got := proto.ClampMaxInFlight(c.k, c.tierSize); got != c.want {
			t.Errorf("ClampMaxInFlight(%d, %d) = %d, want %d", c.k, c.tierSize, got, c.want)
		}
	}
}
