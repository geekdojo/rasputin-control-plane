package updater

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// THE CI REGRESSION NET for the fan-out orchestration layer
// (geekdojo/geekdojo-brain#99). ⚠️ NOT the functional test ADR-0005 Decision 10
// requires — that is a bench plan against real nodes (#80). Read
// fleetsim_test.go's header before trusting anything here.
//
// Every test drives the REAL system.update saga, which submits REAL node.update
// children through a REAL jobs.Runner, over a REAL NATS bus, to a fleet of
// SIMULATED nodes. The unit suite next door proves what the cascade DECIDES;
// this proves what the machine ABOVE THE BUS does, including everything between
// the decisions — child sagas, the boot-identity handshake, deadlines, store
// writes and the wire events an operator actually watches. Below the bus it
// proves nothing.
//
// ⚠️ EVERY SCENARIO HERE WAS WRITTEN FROM A BUG HARDWARE FOUND FIRST. That is
// what a ratchet is, and it is the honest claim. Do not read a green run as
// evidence that a rollout will work; read it as evidence that the specific
// things which once broke have not broken again.

const fleetVersion = "2026.08.4"

// ----- the flagship rollout ------------------------------------------------

// TestFleetFunctional_MixedArchFleetRollout is the whole feature in one run: a
// 24-node mixed-arch cluster (proto.MaxClusterNodes — the largest the product
// admits) taking one release-keyed UPDATE ALL.
//
// It asserts the four things Decisions 6, 8 and 11 promise together and which
// no unit test sees at once: a per-arch canary gates each tier, the fan-out
// behind it is bounded, the firewall is filtered rather than stranded, and the
// report accounts for every planned node.
func TestFleetFunctional_MixedArchFleetRollout(t *testing.T) {
	f := newFleet(t, bitscopeShaped(), osBundles(fleetVersion))
	run := f.run(releaseSpec(fleetVersion))

	if run.Status != jobs.StatusSucceeded {
		t.Fatalf("parent job = %s (%s); grid: %s", run.Status, run.Error, formatGrid(run))
	}

	// Every OS node updated; the firewall was filtered by the component, which
	// is the designed single-SKU filter and never a stranding (Decision 8).
	osNodes := 23 // 20 compute + 2 storage + 1 controlplane
	if got := len(run.Results); got != osNodes {
		t.Fatalf("grid has %d row(s), want %d: %v", got, osNodes, run.nodeIDs())
	}
	if failed := run.withOutcome(proto.NodeOutcomeFailed); len(failed) > 0 {
		t.Errorf("nodes failed on the happy path: %v", failed)
	}
	if missed := run.withOutcome(proto.NodeOutcomeNotAttempted); len(missed) > 0 {
		t.Errorf("nodes never started on the happy path: %v", missed)
	}
	if reason, ok := run.skipReason("fw01"); !ok || reason != proto.SkipFirewallSKU {
		t.Errorf("firewall skip reason = %q (present=%v), want %q", reason, ok, proto.SkipFirewallSKU)
	}
	if n := f.node(t, "fw01").precheckCount(); n != 0 {
		t.Errorf("the firewall answered %d precheck(s); an OS run must not touch it at all", n)
	}
	if run.Counts.Total != osNodes || run.Counts.Succeeded != osNodes {
		t.Errorf("counts = %+v, want total=succeeded=%d", run.Counts, osNodes)
	}

	// One canary per (tier, arch): compute×{amd64,arm64} and storage×{amd64,
	// arm64}. The controlplane and the firewall never nominate one — neither
	// has anything behind it to protect.
	passed := run.changes(proto.SystemUpdateCanaryPassed)
	if len(passed) != 4 {
		t.Fatalf("canary_passed events = %d, want 4 (one per tier and arch): %s", len(passed), formatGates(run))
	}
	wantGroups := []string{
		"compute/rasputin-n100", "compute/rasputin-rpi-arm64",
		"storage/rasputin-n100", "storage/rasputin-rpi-arm64",
	}
	var gotGroups []string
	for _, ev := range passed {
		gotGroups = append(gotGroups, string(ev.Tier)+"/"+ev.Compatible)
	}
	sort.Strings(gotGroups)
	if strings.Join(gotGroups, " ") != strings.Join(wantGroups, " ") {
		t.Errorf("canary groups = %v, want %v", gotGroups, wantGroups)
	}
	for _, row := range run.Results {
		if row.Tier == proto.RoleControlPlane && row.Canary {
			t.Errorf("%s is a controlplane node and was made a canary", row.NodeID)
		}
	}

	// The gate is a gate: no fan-out node of a tier starts before every canary
	// of that tier has finished.
	assertCanariesGateTheirTier(t, run)

	// Bounded, and bounded at the DEFAULT since the spec named no knob.
	wantK := proto.ClampMaxInFlight(proto.DefaultMaxInFlight.Resolve(20), 20)
	if run.PeakInFlight > wantK {
		t.Errorf("peak in-flight = %d, want ≤ %d (the default K clamped to a 20-node tier)", run.PeakInFlight, wantK)
	}
	if run.PeakInstalling > wantK {
		t.Errorf("peak concurrent installs (observed on the nodes) = %d, want ≤ %d", run.PeakInstalling, wantK)
	}
	// K is scoped per TIER, so the storage pair and the controlplane are bounded
	// by their own sizes rather than by the compute tier's.
	for tier, peak := range run.PeakInFlightTier {
		size := map[proto.NodeRole]int{proto.RoleCompute: 20, proto.RoleStorage: 2, proto.RoleControlPlane: 1}[tier]
		if want := proto.ClampMaxInFlight(proto.DefaultMaxInFlight.Resolve(size), size); peak > want {
			t.Errorf("%s tier peak = %d, want ≤ %d (K is clamped against ITS size, not the run's)", tier, peak, want)
		}
	}

	// Inventory is reconciled from the update outcome, confirmed, for every node
	// that took the update (Decision 4).
	for _, row := range run.Results {
		n := f.invNode(t, row.NodeID)
		if n.ImageVersion != fleetVersion {
			t.Errorf("inventory: %s reports %q, want %q", row.NodeID, n.ImageVersion, fleetVersion)
		}
		if n.ImageVersionConfirmedAt == nil {
			t.Errorf("inventory: %s version is unconfirmed after a clean commit", row.NodeID)
		}
	}
	t.Logf("24-node mixed-arch rollout: %d committed, peak %d in flight, %s",
		run.Counts.Succeeded, run.PeakInFlight, run.Duration.Round(time.Millisecond))
}

// ----- the canary gate -----------------------------------------------------

// TestFleetFunctional_CanaryFailureLeavesTheFleetUntouched is the gate doing the
// only job it has. A canary that fails must stop the run BEFORE fan-out, and
// "before fan-out" has to mean the other nodes were never contacted — not that
// they were contacted and their rows say something reassuring.
//
// The proof is on the simulated nodes rather than in the report: a node that
// answered zero prechecks was genuinely never touched.
func TestFleetFunctional_CanaryFailureLeavesTheFleetUntouched(t *testing.T) {
	specs := behave(computeFleet(12, "amd64"), "c01", simFailInstall)
	f := newFleet(t, specs, osBundles(fleetVersion))
	run := f.run(releaseSpec(fleetVersion))

	if run.Status != jobs.StatusFailed {
		t.Fatalf("parent job = %s, want failed; grid: %s", run.Status, formatGrid(run))
	}
	if !strings.Contains(run.Error, "canary") {
		t.Errorf("terminal error = %q; it must name the canary — \"the canary caught a bad image\" and "+
			"\"some of your fleet is unhappy\" ask an operator for different next moves", run.Error)
	}
	if got := len(run.changes(proto.SystemUpdateCanaryFailed)); got != 1 {
		t.Errorf("canary_failed events = %d, want 1: %s", got, formatGates(run))
	}
	if got := len(run.changes(proto.SystemUpdateCanaryPassed)); got != 0 {
		t.Errorf("canary_passed events = %d, want 0 — nothing was authorised", got)
	}

	if row := run.mustOutcome("c01"); row.Outcome != proto.NodeOutcomeFailed || !row.Canary {
		t.Errorf("c01 row = %+v, want a failed canary", row)
	}
	for _, spec := range specs[1:] {
		row := run.mustOutcome(spec.ID)
		if row.Outcome != proto.NodeOutcomeNotAttempted {
			t.Errorf("%s outcome = %q, want %q", spec.ID, row.Outcome, proto.NodeOutcomeNotAttempted)
		}
		if !strings.Contains(row.Detail, "canary gate") {
			t.Errorf("%s detail = %q; a not-attempted row must say WHICH thing stopped the run", spec.ID, row.Detail)
		}
		if n := f.node(t, spec.ID).precheckCount(); n != 0 {
			t.Errorf("%s answered %d precheck(s) after a canary abort; it should be untouched", spec.ID, n)
		}
	}
}

// TestFleetFunctional_DegradedCanaryStillAuthorisesFanOut pins Decision 3 at the
// gate. A pre-bootId agent cannot satisfy conjunct (a), so its verify degrades —
// and a degraded pass is still a pass, because the FIRST rollout onto every
// existing cluster is degraded on every node and refusing would mean no cluster
// could ever adopt the feature.
//
// What must not happen is that it passes silently: the row carries the gap.
func TestFleetFunctional_DegradedCanaryStillAuthorisesFanOut(t *testing.T) {
	specs := behave(computeFleet(6, "amd64"), "c01", simNoBootID)
	f := newFleet(t, specs, osBundles(fleetVersion))
	run := f.run(releaseSpec(fleetVersion))

	if run.Status != jobs.StatusSucceeded {
		t.Fatalf("parent job = %s (%s); a degraded canary must still authorise fan-out. grid: %s",
			run.Status, run.Error, formatGrid(run))
	}
	if got := len(run.changes(proto.SystemUpdateCanaryPassed)); got != 1 {
		t.Errorf("canary_passed events = %d, want 1", got)
	}
	row := f.nodeUpdateRow(t, run, "c01")
	if row == nil {
		t.Fatal("c01 has no node_update row")
	}
	if row.Status != NodeUpdateCommitted {
		t.Errorf("c01 row status = %q, want %q", row.Status, NodeUpdateCommitted)
	}
	if !row.UnverifiedBoot {
		t.Error("c01 committed on a degraded verify but the row does not say so (unverified_boot is false) — " +
			"a green row that quietly means less than the green row beside it is the thing Decision 3 forbids")
	}
	if failed := run.withOutcome(proto.NodeOutcomeFailed); len(failed) > 0 {
		t.Errorf("fan-out behind a degraded canary failed: %v", failed)
	}
}

// ----- bounded fan-out (#74) ----------------------------------------------

// TestFleetFunctional_FanOutIsBoundedByKUnderRealSagas is the K assertion at the
// only layer that can be wrong in an interesting way. The unit test proves the
// scheduler holds k; this proves the whole machine does — real children, real
// RPCs, real store writes — and it asserts the bound is REACHED as well as not
// exceeded, because a fan-out that never reaches k is not bounded, it is just
// slow, and both look green if you only assert ≤.
func TestFleetFunctional_FanOutIsBoundedByKUnderRealSagas(t *testing.T) {
	specs := computeFleet(13, "amd64")
	for i := range specs {
		// Long enough that the overlap is unambiguous, short enough that the
		// whole run is a few seconds.
		specs[i].InstallFor = 150 * time.Millisecond
	}
	f := newFleet(t, specs, osBundles(fleetVersion))

	k := proto.Int(3)
	spec := releaseSpec(fleetVersion)
	spec.MaxInFlight = &k
	run := f.run(spec)

	if run.Status != jobs.StatusSucceeded {
		t.Fatalf("parent job = %s (%s); grid: %s", run.Status, run.Error, formatGrid(run))
	}
	if run.PeakInFlight != 3 {
		t.Errorf("peak in-flight = %d, want exactly 3: at ≤2 the fan-out never reached K "+
			"(bounded in name only); at ≥4 the bound leaked. Start order: %v", run.PeakInFlight, run.startOrder())
	}
	if run.PeakInstalling > 3 {
		t.Errorf("peak concurrent installs observed on the nodes = %d, want ≤ 3", run.PeakInstalling)
	}
	// The canary is never one of the k. It runs alone, ahead of them.
	assertCanariesGateTheirTier(t, run)
}

// TestFleetFunctional_KOfOneIsExactlyTheSerialCascade pins the compatibility
// claim bounded fan-out rests on: k=1 is byte-for-byte the old behaviour, so the
// feature is describable as backwards compatible rather than as a rewrite.
func TestFleetFunctional_KOfOneIsExactlyTheSerialCascade(t *testing.T) {
	f := newFleet(t, computeFleet(6, "amd64"), osBundles(fleetVersion))

	k := proto.Int(1)
	spec := releaseSpec(fleetVersion)
	spec.MaxInFlight = &k
	run := f.run(spec)

	if run.Status != jobs.StatusSucceeded {
		t.Fatalf("parent job = %s (%s)", run.Status, run.Error)
	}
	if run.PeakInFlight != 1 {
		t.Errorf("peak in-flight at k=1 = %d, want 1 — k=1 must be the serial cascade", run.PeakInFlight)
	}
	if got, want := run.startOrder(), []string{"c01", "c02", "c03", "c04", "c05", "c06"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("start order = %v, want planned order %v", got, want)
	}
}

// ----- the failure budget (#75) -------------------------------------------

// TestFleetFunctional_FailureBudgetStopsNewStarts drives the breaker with real
// failing children. k=1 so the budget is observable exactly: with nothing else
// in flight, the run must stop at the budget rather than overshooting it.
func TestFleetFunctional_FailureBudgetStopsNewStarts(t *testing.T) {
	specs := computeFleet(12, "amd64")
	for _, id := range []string{"c02", "c03", "c04", "c05"} {
		specs = behave(specs, id, simFailInstall)
	}
	f := newFleet(t, specs, osBundles(fleetVersion))

	k, budget := proto.Int(1), proto.Int(2)
	spec := releaseSpec(fleetVersion)
	spec.MaxInFlight, spec.MaxFailures = &k, &budget
	run := f.run(spec)

	if run.Status != jobs.StatusFailed {
		t.Fatalf("parent job = %s, want failed; grid: %s", run.Status, formatGrid(run))
	}
	failed := run.withOutcome(proto.NodeOutcomeFailed)
	if len(failed) != 2 {
		t.Errorf("failed nodes = %v (%d), want exactly 2 — at k=1 nothing is in flight to overshoot with",
			failed, len(failed))
	}
	spent := run.changes(proto.SystemUpdateBudgetSpent)
	if len(spent) != 1 {
		t.Fatalf("budget_spent events = %d, want 1 — an operator must not have to infer a deliberate stop "+
			"from a run that merely ended", len(spent))
	}
	if spent[0].Tier != proto.RoleCompute {
		t.Errorf("budget_spent tier = %q, want %q", spent[0].Tier, proto.RoleCompute)
	}
	notAttempted := run.withOutcome(proto.NodeOutcomeNotAttempted)
	if len(notAttempted) == 0 {
		t.Fatal("no not-attempted rows; the budget stopped nothing")
	}
	for _, id := range notAttempted {
		row := run.mustOutcome(id)
		if !strings.Contains(row.Detail, "failure budget") {
			t.Errorf("%s detail = %q, want it to name the failure budget", id, row.Detail)
		}
		if n := f.node(t, id).precheckCount(); n != 0 {
			t.Errorf("%s answered %d precheck(s) but is reported untouched", id, n)
		}
	}
	if !strings.Contains(run.Error, "budget") {
		t.Errorf("terminal error = %q, want it to name the budget alongside the failures", run.Error)
	}
	// The report survives the failure — that is the whole of #76. Losing the
	// grid on a failed run loses the feature.
	if len(run.Results) != len(specs) {
		t.Errorf("grid has %d row(s) on a failed run, want one per planned target (%d)", len(run.Results), len(specs))
	}
}

// TestFleetFunctional_UnlimitedBudgetAttemptsEveryNode is best-effort fan-out at
// its most literal: a failed node is a red cell, not a wall. Every planned node
// is attempted and the ones that can update, do.
func TestFleetFunctional_UnlimitedBudgetAttemptsEveryNode(t *testing.T) {
	specs := computeFleet(8, "amd64")
	for _, id := range []string{"c03", "c05", "c07"} {
		specs = behave(specs, id, simFailDownload)
	}
	f := newFleet(t, specs, osBundles(fleetVersion))

	k, budget := proto.Int(2), proto.Int(proto.UnlimitedFailures)
	spec := releaseSpec(fleetVersion)
	spec.MaxInFlight, spec.MaxFailures = &k, &budget
	run := f.run(spec)

	if run.Status != jobs.StatusFailed {
		t.Errorf("parent job = %s, want failed — some of the fleet did not take the update, "+
			"however many did", run.Status)
	}
	if missed := run.withOutcome(proto.NodeOutcomeNotAttempted); len(missed) > 0 {
		t.Errorf("not-attempted nodes with an unlimited budget: %v — every node must be attempted", missed)
	}
	if got, want := len(run.withOutcome(proto.NodeOutcomeFailed)), 3; got != want {
		t.Errorf("failed nodes = %d, want %d", got, want)
	}
	if got, want := len(run.withOutcome(proto.NodeOutcomeSucceeded)), 5; got != want {
		t.Errorf("succeeded nodes = %d, want %d — a failure beside them must not stop them", got, want)
	}
	if len(run.changes(proto.SystemUpdateBudgetSpent)) != 0 {
		t.Error("budget_spent fired with an unlimited budget")
	}
}

// ----- the verify contract at fleet scale ---------------------------------

// TestFleetFunctional_C13AndC08AreToldApart is the reason the whole epic exists,
// run at fleet scale with the two shapes side by side in the same cascade.
//
// c13 (acked the reboot, never rebooted) and c08 (rebooted and never came back)
// are OPPOSITES, they produce the same slot reading, and conflating them is what
// marked a healthy node rolled_back. Neither may produce a rolled_back row, each
// must carry its own message, and both must leave inventory unable to vouch for
// what the node is running.
//
// c08 here carries a RebootDelay, so the pre-reboot agent answers a poll on the
// old boot before vanishing — the #90 shape. A latch on "we saw the old boot"
// reports c13's message for it, which is the exact opposite of what happened.
func TestFleetFunctional_C13AndC08AreToldApart(t *testing.T) {
	specs := computeFleet(8, "amd64")
	specs = behave(specs, "c02", simNoReboot)
	specs = behave(specs, "c03", simNeverReturns)
	for i := range specs {
		if specs[i].ID == "c03" {
			specs[i].RebootDelay = 2500 * time.Millisecond // outlives the first 2s poll
		}
	}
	f := newFleet(t, specs, osBundles(fleetVersion))

	k, budget := proto.Int(4), proto.Int(proto.UnlimitedFailures)
	spec := releaseSpec(fleetVersion)
	spec.MaxInFlight, spec.MaxFailures = &k, &budget
	run := f.run(spec)

	if run.Status != jobs.StatusFailed {
		t.Fatalf("parent job = %s, want failed; grid: %s", run.Status, formatGrid(run))
	}

	cases := []struct {
		node, want, shape string
	}{
		{"c02", "never rebooted: still answering on boot", "c13"},
		{"c03", "stopped answering and never came back", "c08"},
	}
	for _, tc := range cases {
		row := f.nodeUpdateRow(t, run, tc.node)
		if row == nil {
			t.Errorf("%s (%s) has no node_update row", tc.node, tc.shape)
			continue
		}
		if row.Status == NodeUpdateRolledBack {
			t.Errorf("%s (%s) recorded as %q — not-coming-back and reverted are opposites, and calling one "+
				"the other is the harm the verify contract exists to prevent", tc.node, tc.shape, row.Status)
		}
		if row.Status != NodeUpdateFailed {
			t.Errorf("%s (%s) row status = %q, want %q", tc.node, tc.shape, row.Status, NodeUpdateFailed)
		}
		if !strings.Contains(row.Error, tc.want) {
			t.Errorf("%s (%s) error = %q, want it to contain %q — that message is the only thing an operator "+
				"has to go on, and naming the wrong shape sends them to the wrong machine",
				tc.node, tc.shape, row.Error, tc.want)
		}
		if n := f.invNode(t, tc.node); n.ImageVersionConfirmedAt != nil {
			t.Errorf("%s (%s): inventory still CONFIRMS version %q after an update that could not verify — "+
				"this is the stranded node reading green (#90)", tc.node, tc.shape, n.ImageVersion)
		}
	}

	// Best-effort: the other six nodes still took the update.
	if got, want := len(run.withOutcome(proto.NodeOutcomeSucceeded)), 6; got != want {
		t.Errorf("succeeded nodes = %d, want %d; grid: %s", got, want, formatGrid(run))
	}
}

// TestFleetFunctional_BootloaderRollbackIsTheOneRealRollback is the control case
// for the test above: the shape that genuinely IS a rollback must still be
// recorded as one, or "no rolled_back rows" becomes true for the wrong reason.
func TestFleetFunctional_BootloaderRollbackIsTheOneRealRollback(t *testing.T) {
	specs := behave(computeFleet(6, "amd64"), "c02", simBootloaderRollback)
	f := newFleet(t, specs, osBundles(fleetVersion))

	budget := proto.Int(proto.UnlimitedFailures)
	spec := releaseSpec(fleetVersion)
	spec.MaxFailures = &budget
	run := f.run(spec)

	row := f.nodeUpdateRow(t, run, "c02")
	if row == nil {
		t.Fatal("c02 has no node_update row")
	}
	if row.Status != NodeUpdateRolledBack {
		t.Errorf("c02 row status = %q, want %q — it came up on a new boot and the OLD slot, which is a "+
			"bootloader revert and nothing else", row.Status, NodeUpdateRolledBack)
	}
	if run.mustOutcome("c02").Outcome != proto.NodeOutcomeFailed {
		t.Error("a rolled-back node must be a red cell in the grid")
	}
	// Ground truth on the node itself, so the assertion above is not just the
	// api agreeing with itself: c02 really is sitting on the slot it started on.
	if got := f.node(t, "c02").activeSlot(); got != proto.SlotA {
		t.Errorf("c02 is on slot %q, want %q — the fixture did not produce a revert at all", got, proto.SlotA)
	}
}

// TestFleetFunctional_HealthFailureRollsBackAndUnconfirms is conjunct (d): the
// node boots the new slot and then fails its health battery. mark-bad is sent,
// the row is rolled_back — and inventory asserts NEITHER version, because the
// node is running the new one and about to leave it.
func TestFleetFunctional_HealthFailureRollsBackAndUnconfirms(t *testing.T) {
	specs := behave(computeFleet(6, "amd64"), "c02", simFailHealth)
	f := newFleet(t, specs, osBundles(fleetVersion))

	budget := proto.Int(proto.UnlimitedFailures)
	spec := releaseSpec(fleetVersion)
	spec.MaxFailures = &budget
	run := f.run(spec)

	row := f.nodeUpdateRow(t, run, "c02")
	if row == nil {
		t.Fatal("c02 has no node_update row")
	}
	if row.Status != NodeUpdateRolledBack {
		t.Errorf("c02 row status = %q, want %q", row.Status, NodeUpdateRolledBack)
	}
	if n := f.invNode(t, "c02"); n.ImageVersionConfirmedAt != nil {
		t.Error("inventory still confirms a version for a node that failed its health check and is about " +
			"to revert; every version available right now is wrong, so it must assert none")
	}
}

// ----- the plan ------------------------------------------------------------

// TestFleetFunctional_ArchUnknownNodeIsStrandedNotGuessed is #67 at fleet scale.
// A node whose agent never reported an architecture has no artifact that can be
// chosen for it, and the plan must say so rather than planning it into whichever
// bundle the run happens to carry.
func TestFleetFunctional_ArchUnknownNodeIsStrandedNotGuessed(t *testing.T) {
	specs := computeFleet(5, "amd64")
	specs = append(specs, simNodeSpec{ID: "c99", Role: proto.RoleCompute, Arch: ""})
	f := newFleet(t, specs, osBundles(fleetVersion))
	run := f.run(releaseSpec(fleetVersion))

	if run.Status != jobs.StatusFailed {
		t.Errorf("parent job = %s, want failed — a stranded node fails the parent even when every child "+
			"committed, because the run did not do what UPDATE ALL says on the button", run.Status)
	}
	reason, ok := run.skipReason("c99")
	if !ok || reason != proto.SkipNoArtifactForArch {
		t.Errorf("c99 skip reason = %q (present=%v), want %q", reason, ok, proto.SkipNoArtifactForArch)
	}
	if _, planned := run.outcome("c99"); planned {
		t.Error("c99 has a grid row: an arch-unknown node was planned into a cascade rather than skipped")
	}
	if n := f.node(t, "c99").precheckCount(); n != 0 {
		t.Errorf("c99 answered %d precheck(s); it should never have been contacted", n)
	}
	if got, want := len(run.withOutcome(proto.NodeOutcomeSucceeded)), 5; got != want {
		t.Errorf("succeeded nodes = %d, want %d — the other nodes still update", got, want)
	}
}

// TestFleetFunctional_UnstagedArchFailsThePlanBeforeAnythingReboots is the
// staging precondition. Finding out an arch is missing forty minutes in, as a
// download failure on node fourteen, is strictly worse than finding out before
// anything moves — so the plan fails, names every missing SKU AND the nodes
// wanting it, and submits zero children.
func TestFleetFunctional_UnstagedArchFailsThePlanBeforeAnythingReboots(t *testing.T) {
	specs := append(computeFleet(4, "amd64"), simNodeSpec{ID: "p01", Role: proto.RoleCompute, Arch: "arm64"})
	amd64Only := osBundles(fleetVersion)[:1]
	f := newFleet(t, specs, amd64Only)
	run := f.run(releaseSpec(fleetVersion))

	if run.Status != jobs.StatusFailed {
		t.Fatalf("parent job = %s, want failed", run.Status)
	}
	for _, want := range []string{"rasputin-rpi-arm64", "p01", "not staged"} {
		if !strings.Contains(run.Error, want) {
			t.Errorf("plan error = %q, want it to contain %q", run.Error, want)
		}
	}
	for _, spec := range specs {
		if n := f.node(t, spec.ID).precheckCount(); n != 0 {
			t.Errorf("%s answered %d precheck(s); a failed plan must submit no children at all", spec.ID, n)
		}
	}
	if len(run.Results) != 0 {
		t.Errorf("grid has %d row(s) for a run that never cascaded", len(run.Results))
	}
}

// ----- the knob sweep ------------------------------------------------------

// TestFleetSweep is the thing ADR-0005's revisit criteria are waiting on: a
// REPEATABLE fan-out venue, so K and maxFailures stop being owed-to-measurement.
//
// It asserts almost nothing on purpose. Its output is a table, and its job is to
// let someone change a default, re-run, and see what moved — the iteration the
// one-or-two `bitscope` runs allowed by Decision 10 cannot supply.
//
// Off by default because it is minutes rather than seconds:
//
//	RASPUTIN_FLEET_SWEEP=1 go test ./api/internal/updater -run TestFleetSweep -v
//
// ⚠️ The wall-clock column measures the HARNESS, not a fleet. Simulated installs
// and reboots are milliseconds and a real one is minutes, so the times are only
// comparable to each other within one sweep. What transfers is the SHAPE: how
// peak concurrency, the failure count and the not-attempted count respond to the
// knobs, and the ratios between rows.
func TestFleetSweep(t *testing.T) {
	if os.Getenv("RASPUTIN_FLEET_SWEEP") != "1" {
		t.Skip("set RASPUTIN_FLEET_SWEEP=1 to run the K × maxFailures sweep")
	}

	type combo struct {
		k       proto.IntOrString
		budget  proto.IntOrString
		failing int // how many fan-out nodes are made to fail
	}
	var combos []combo
	for _, k := range []proto.IntOrString{proto.Int(1), proto.Int(2), proto.Int(4), proto.Int(8), proto.Percent(25)} {
		for _, b := range []proto.IntOrString{proto.Int(proto.UnlimitedFailures), proto.Int(2), proto.Percent(15)} {
			combos = append(combos, combo{k: k, budget: b, failing: 4})
		}
	}

	const tierSize = 20
	// Every table line is prefixed SWEEP so it can be pulled out of the api's
	// own log chatter with a grep — the saga logs to stderr throughout, and an
	// unprefixed table is unreadable in the middle of it.
	t.Logf("SWEEP fleet: %d compute nodes (amd64), %d made to fail at install", tierSize, 4)
	t.Logf("SWEEP %-11s %-11s %-16s %-6s %-6s %-6s %-6s %s",
		"maxInFlight", "maxFailures", "resolved", "peak", "ok", "failed", "never", "wall")

	for _, c := range combos {
		specs := computeFleet(tierSize, "amd64")
		// Fail nodes spread through the fan-out rather than bunched at the
		// front, so the budget trips partway rather than immediately.
		for _, id := range []string{"c04", "c08", "c12", "c16"} {
			specs = behave(specs, id, simFailInstall)
		}
		for i := range specs {
			specs[i].InstallFor = 30 * time.Millisecond
		}
		f := newFleet(t, specs, osBundles(fleetVersion))

		k, budget := c.k, c.budget
		spec := releaseSpec(fleetVersion)
		spec.MaxInFlight, spec.MaxFailures = &k, &budget
		run := f.run(spec)

		resolved := fmt.Sprintf("k=%d/b=%s",
			proto.ClampMaxInFlight(c.k.Resolve(tierSize), tierSize),
			budgetLabel(proto.ResolveMaxFailures(c.budget, tierSize)))
		t.Logf("SWEEP %-11s %-11s %-16s %-6d %-6d %-6d %-6d %s",
			c.k, c.budget, resolved,
			run.PeakInFlight,
			len(run.withOutcome(proto.NodeOutcomeSucceeded)),
			len(run.withOutcome(proto.NodeOutcomeFailed)),
			len(run.withOutcome(proto.NodeOutcomeNotAttempted)),
			run.Duration.Round(time.Millisecond))

		// The one invariant worth failing the sweep over: the bound must hold at
		// every setting, or the numbers beside it mean nothing.
		if want := proto.ClampMaxInFlight(c.k.Resolve(tierSize), tierSize); run.PeakInFlight > want {
			t.Errorf("k=%s: peak in-flight %d exceeded the clamped bound %d", c.k, run.PeakInFlight, want)
		}
	}
}

// ----- assertions + formatting --------------------------------------------

// assertCanariesGateTheirTier checks the ordering property the gate is FOR: no
// fan-out node of a tier is started until every canary of that tier has reached
// a terminal outcome. Derived from the wire events, in publication order, which
// is what an operator watching the bus would see.
func assertCanariesGateTheirTier(t *testing.T, run fleetRun) {
	t.Helper()
	open := map[proto.NodeRole]int{}  // canaries started and not yet finished, per tier
	done := map[proto.NodeRole]bool{} // this tier's canaries have all finished
	seen := map[proto.NodeRole]bool{} // this tier has at least one canary
	for _, ev := range run.Events {
		switch ev.Change {
		case proto.SystemUpdateNodeStarted:
			if ev.Canary {
				seen[ev.Tier] = true
				open[ev.Tier]++
				done[ev.Tier] = false
				continue
			}
			if seen[ev.Tier] && !done[ev.Tier] {
				t.Errorf("fan-out node %s (%s) started while that tier's canary was still running — "+
					"the gate is not a gate. Start order: %v", ev.NodeID, ev.Tier, run.startOrder())
			}
		case proto.SystemUpdateNodeSucceeded, proto.SystemUpdateNodeFailed:
			if ev.Canary {
				open[ev.Tier]--
				if open[ev.Tier] <= 0 {
					done[ev.Tier] = true
				}
			}
		}
	}
}

// formatGrid renders the report for a failure message. A test that says only
// "want succeeded, got failed" about a 24-node cascade sends the reader back to
// the logs; this puts the answer in the failure.
func formatGrid(run fleetRun) string {
	if len(run.Results) == 0 {
		return "(no grid — the run never reached the cascade)"
	}
	var b strings.Builder
	b.WriteString("\n")
	for _, row := range run.Results {
		marker := " "
		if row.Canary {
			marker = "*"
		}
		fmt.Fprintf(&b, "  %s %-6s %-12s %-20s %-14s %s\n",
			marker, row.NodeID, row.Tier, row.Compatible, row.Outcome, row.Detail)
	}
	b.WriteString("  (* = canary)\n")
	return b.String()
}

// formatGates renders the canary verdicts for a failure message.
func formatGates(run fleetRun) string {
	var b strings.Builder
	b.WriteString("\n")
	for _, ev := range run.Events {
		switch ev.Change {
		case proto.SystemUpdateCanaryPassed, proto.SystemUpdateCanaryFailed, proto.SystemUpdateBudgetSpent:
			fmt.Fprintf(&b, "  %-14s %-6s %-12s %-20s %s\n", ev.Change, ev.NodeID, ev.Tier, ev.Compatible, ev.Detail)
		}
	}
	return b.String()
}
