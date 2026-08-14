package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

// stubDriver records the order children were submitted in and returns a
// scripted outcome per node id. Anything not in `fail` succeeds.
type stubDriver struct {
	started []string
	fail    map[string]bool
	// submitErr nodes fail at submission rather than at completion — a
	// different code path, and one that used to be able to skip the gate.
	submitErr map[string]bool
}

func (s *stubDriver) driver() childDriver {
	return childDriver{
		submit: func(sc *jobs.StepCtx, t plannedTarget) (string, error) {
			if s.submitErr[t.NodeID] {
				return "", errors.New("no runner")
			}
			s.started = append(s.started, t.NodeID)
			return "child-" + t.NodeID, nil
		},
		wait: func(sc *jobs.StepCtx, childID string) (jobs.Status, error) {
			id := strings.TrimPrefix(childID, "child-")
			if s.fail[id] {
				return jobs.StatusFailed, nil
			}
			return jobs.StatusSucceeded, nil
		},
	}
}

// runCascade drives the cascade step over a fixed plan, bypassing step 1 by
// handing the plan in through PriorResults exactly as the saga does.
func runCascade(t *testing.T, targets []plannedTarget, spec proto.SystemUpdateSpec, drv childDriver) (map[string]any, error) {
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
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("unmarshal cascade result: %v", err)
		}
	}
	return out, runErr
}

func ids(t *testing.T, result map[string]any, key string) []string {
	t.Helper()
	v, ok := result[key]
	if !ok || v == nil {
		return nil
	}
	raw, ok := v.([]any)
	if !ok {
		t.Fatalf("%s is %T, want a list", key, v)
	}
	out := make([]string, len(raw))
	for i, e := range raw {
		out[i] = fmt.Sprint(e)
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
	// The whole point of the story. c01 is the arm64 canary; when it fails,
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
	res, err := runCascade(t, targets, proto.SystemUpdateSpec{Version: "2026.08.0"}, drv.driver())

	if err == nil {
		t.Fatal("want an error when the canary fails, got nil")
	}
	if !strings.Contains(err.Error(), "aborted before fan-out") {
		t.Errorf("error = %q, want it to name the canary abort", err)
	}
	if !eqIDs(drv.started, []string{"c01"}) {
		t.Errorf("started %v, want only [c01] — nothing else in the fleet may be touched", drv.started)
	}
	if got := ids(t, res, "remaining"); !eqIDs(got, []string{"c02", "c03", "s01"}) {
		t.Errorf("remaining = %v, want [c02 c03 s01]", got)
	}
	if got := ids(t, res, "failed"); !eqIDs(got, []string{"c01"}) {
		t.Errorf("failed = %v, want [c01]", got)
	}
}

func TestCascade_CanaryFailureAtSubmitAlsoAborts(t *testing.T) {
	// A canary that never starts has not proved anything, and the gate must
	// treat that identically to one that started and failed. Submitting the
	// fan-out anyway because "no child ran" would be the worst version of
	// this bug: an unproven image reaching the whole tier.
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, arm),
		tgt("c02", proto.RoleCompute, arm),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	drv := &stubDriver{submitErr: map[string]bool{"c01": true}}
	res, err := runCascade(t, targets, proto.SystemUpdateSpec{Version: "2026.08.0"}, drv.driver())

	if err == nil {
		t.Fatal("want an error when the canary cannot be submitted, got nil")
	}
	if len(drv.started) != 0 {
		t.Errorf("started %v, want nothing", drv.started)
	}
	if got := ids(t, res, "remaining"); !eqIDs(got, []string{"c02"}) {
		t.Errorf("remaining = %v, want [c02]", got)
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
	res, err := runCascade(t, targets, proto.SystemUpdateSpec{Version: "2026.08.0"}, drv.driver())
	if err != nil {
		t.Fatalf("cascade: %v", err)
	}
	want := []string{"c01", "c03", "c02", "c04", "s01"}
	if !eqIDs(drv.started, want) {
		t.Errorf("start order = %v, want %v — both canaries before either fan-out", drv.started, want)
	}
	if got := ids(t, res, "canaries"); !eqIDs(got, []string{"c01", "c03", "s01"}) {
		t.Errorf("canaries = %v, want [c01 c03 s01]", got)
	}
	if got := ids(t, res, "remaining"); len(got) != 0 {
		t.Errorf("remaining = %v, want none", got)
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
	res, err := runCascade(t, targets, proto.SystemUpdateSpec{Version: "2026.08.0"}, drv.driver())
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	if !eqIDs(drv.started, []string{"c01", "c03"}) {
		t.Errorf("started %v, want [c01 c03] — no fan-out node may run", drv.started)
	}
	if got := ids(t, res, "remaining"); !eqIDs(got, []string{"c02", "c04"}) {
		t.Errorf("remaining = %v, want [c02 c04]", got)
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
	res, err := runCascade(t, targets, proto.SystemUpdateSpec{Version: "2026.08.0"}, drv.driver())
	if err != nil {
		t.Fatalf("cascade: %v", err)
	}
	if !eqIDs(drv.started, []string{"cp-1", "fw-1"}) {
		t.Errorf("started %v, want [cp-1 fw-1]", drv.started)
	}
	if got := ids(t, res, "canaries"); len(got) != 0 {
		t.Errorf("canaries = %v, want none", got)
	}
}

func TestCascade_FanOutFailureStillHaltsTheRun(t *testing.T) {
	// Unchanged behaviour, asserted so #76 has to delete this test on purpose
	// rather than discover it. Adding the gate must not quietly relax the
	// halt-on-first policy that is still the only failure policy there is.
	targets := []plannedTarget{
		tgt("c01", proto.RoleCompute, x86),
		tgt("c02", proto.RoleCompute, x86),
		tgt("c03", proto.RoleCompute, x86),
	}
	if err := assignCanaries(targets, nil); err != nil {
		t.Fatalf("assignCanaries: %v", err)
	}
	drv := &stubDriver{fail: map[string]bool{"c02": true}}
	res, err := runCascade(t, targets, proto.SystemUpdateSpec{Version: "2026.08.0"}, drv.driver())
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	if strings.Contains(err.Error(), "aborted before fan-out") {
		t.Errorf("error = %q, want the ordinary cascade failure, not the canary abort", err)
	}
	if !eqIDs(drv.started, []string{"c01", "c02"}) {
		t.Errorf("started %v, want [c01 c02]", drv.started)
	}
	if got := ids(t, res, "remaining"); !eqIDs(got, []string{"c03"}) {
		t.Errorf("remaining = %v, want [c03]", got)
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
	if _, err := runCascade(t, targets, proto.SystemUpdateSpec{Version: "2026.08.0"}, (&stubDriver{}).driver()); err != nil {
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
