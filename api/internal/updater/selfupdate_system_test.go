package updater

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Tests for #56 — UPDATE ALL includes the controlplane.
//
// The three properties worth holding, in the order they matter:
//
//  1. self is PLANNED, and planned LAST. The resume design has no answer for a
//     target sequenced behind the node that takes the api down.
//  2. the parent DEFERS only when this restart was its own cascade's doing.
//     Deferring any other crash leaves a job that reads `running` forever.
//  3. the report survives the reboot. The grid is rebuilt from durable state,
//     because the in-memory one died with the old api and the cascade step
//     never got far enough to record a result.

// ----- 1. ordering --------------------------------------------------------

// Self sorts last inside its own tier, not by id. "aaa-self" would sort FIRST
// alphabetically among the controlplane nodes, so this fails loudly if the
// self rule is ever dropped from the comparator.
func TestPlanTargets_SelfIsLastInItsTier(t *testing.T) {
	now := time.Now().UTC()
	node := func(id string, role proto.NodeRole) *proto.Node {
		return &proto.Node{ID: id, Role: role, FirstSeen: now, LastSeen: now}
	}
	nodes := []*proto.Node{
		node("zeta-compute", proto.RoleCompute),
		node("aaa-self", proto.RoleControlPlane),
		node("mmm-cp2", proto.RoleControlPlane),
		node("alpha-compute", proto.RoleCompute),
	}

	got, _ := planTargets(nodes, nil, "", "aaa-self")

	want := []string{"alpha-compute", "zeta-compute", "mmm-cp2", "aaa-self"}
	if len(got) != len(want) {
		t.Fatalf("targets: got %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].ID != w {
			ids := make([]string, len(got))
			for j, n := range got {
				ids[j] = n.ID
			}
			t.Fatalf("order: got %v, want %v", ids, want)
		}
	}
}

// With no self configured the id sort is untouched — the rule must not leak
// into clusters that never set RASPUTIN_SELF_NODE_ID.
func TestPlanTargets_NoSelfLeavesOrderAlone(t *testing.T) {
	now := time.Now().UTC()
	nodes := []*proto.Node{
		{ID: "b", Role: proto.RoleControlPlane, FirstSeen: now, LastSeen: now},
		{ID: "a", Role: proto.RoleControlPlane, FirstSeen: now, LastSeen: now},
	}
	got, _ := planTargets(nodes, nil, "", "")
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Errorf("want a,b in id order, got %v", got)
	}
}

// ----- 2. the defer decision ---------------------------------------------

func TestSystemUpdateDeferred(t *testing.T) {
	const self = "cp"
	ctx := context.Background()

	cases := []struct {
		name string
		// seed builds one parent and returns its id.
		seed func(t *testing.T, js *jobs.Store) string
		want bool
	}{
		{
			name: "self child past its reboot → defer",
			seed: func(t *testing.T, js *jobs.Store) string {
				p := seedParent(t, js, "p1")
				seedChild(t, js, "c1", p, self, jobs.StatusRunning, true)
				return p
			},
			want: true,
		},
		{
			name: "self child not yet rebooted → fail",
			seed: func(t *testing.T, js *jobs.Store) string {
				p := seedParent(t, js, "p2")
				seedChild(t, js, "c2", p, self, jobs.StatusRunning, false)
				return p
			},
			want: false,
		},
		{
			// The crash case. A run that died mid-compute-tier has no self
			// child at all, and deferring it would strand the job forever.
			name: "no self child → fail",
			seed: func(t *testing.T, js *jobs.Store) string {
				p := seedParent(t, js, "p3")
				seedChild(t, js, "c3", p, "compute1", jobs.StatusRunning, true)
				return p
			},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			js := newJobStore(t)
			id := c.seed(t, js)
			j, err := js.GetJob(ctx, id)
			if err != nil || j == nil {
				t.Fatalf("GetJob: %v", err)
			}
			if got := SystemUpdateDeferred(ctx, js, j, self); got != c.want {
				t.Errorf("SystemUpdateDeferred = %v, want %v", got, c.want)
			}
		})
	}
}

// The decider routes system.update through SystemUpdateDeferred while leaving
// the node.update behaviour it already had intact.
func TestSelfUpdateRecoverDecider_DefersTheParent(t *testing.T) {
	const self = "cp"
	ctx := context.Background()
	js := newJobStore(t)
	p := seedParent(t, js, "parent")
	seedChild(t, js, "child", p, self, jobs.StatusRunning, true)

	decide := SelfUpdateRecoverDecider(ctx, js, self)
	parent, _ := js.GetJob(ctx, p)
	if got := decide(parent, nil); got != jobs.RecoverDefer {
		t.Errorf("parent decision = %v, want RecoverDefer", got)
	}
}

// ----- 3. the report ------------------------------------------------------

// The grid is rebuilt from the plan step's persisted result plus the child
// jobs' statuses — planned order preserved, and a target with no child
// recorded as not-attempted rather than dropped.
func TestRebuildReport_FromDurableState(t *testing.T) {
	const self = "cp"
	ctx := context.Background()
	js := newJobStore(t)

	p := seedParent(t, js, "parent")
	seedPlanStep(t, js, p, systemPlanState{
		BundleVer: "v9",
		Targets: []plannedTarget{
			{NodeID: "a", Tier: proto.RoleCompute, Compatible: "rasputin-n100", Canary: true},
			{NodeID: "b", Tier: proto.RoleCompute, Compatible: "rasputin-n100"},
			{NodeID: "never", Tier: proto.RoleCompute, Compatible: "rasputin-n100"},
			{NodeID: self, Tier: proto.RoleControlPlane, Compatible: "rasputin-n100"},
		},
		SelfNodeID: self,
	})
	seedChild(t, js, "ca", p, "a", jobs.StatusSucceeded, true)
	seedChild(t, js, "cb", p, "b", jobs.StatusFailed, true)
	seedChild(t, js, "cs", p, self, jobs.StatusRunning, true)

	plan, grid, err := rebuildReport(ctx, js, p, self, jobs.StatusSucceeded, "")
	if err != nil {
		t.Fatalf("rebuildReport: %v", err)
	}
	if plan.BundleVer != "v9" {
		t.Errorf("plan version = %q, want v9", plan.BundleVer)
	}
	if len(grid) != 4 {
		t.Fatalf("grid rows = %d, want 4 (one per planned target)", len(grid))
	}
	want := []struct {
		node    string
		outcome proto.NodeOutcome
	}{
		{"a", proto.NodeOutcomeSucceeded},
		{"b", proto.NodeOutcomeFailed},
		{"never", proto.NodeOutcomeNotAttempted},
		// Read from the resume path's verdict, not the child row, which is
		// still `running` until FinishDeferred lands.
		{self, proto.NodeOutcomeSucceeded},
	}
	for i, w := range want {
		if grid[i].NodeID != w.node || grid[i].Outcome != w.outcome {
			t.Errorf("row %d = %s/%s, want %s/%s", i, grid[i].NodeID, grid[i].Outcome, w.node, w.outcome)
		}
	}
	if !grid[0].Canary {
		t.Error("row a: canary flag lost in the rebuild")
	}
	if grid[3].Tier != proto.RoleControlPlane {
		t.Errorf("row cp: tier = %q, want controlplane", grid[3].Tier)
	}
}

// A plan step with no recorded result cannot be reported against. Better to
// say so than to publish a grid that silently omits every target.
func TestRebuildReport_NoPlanResult(t *testing.T) {
	ctx := context.Background()
	js := newJobStore(t)
	p := seedParent(t, js, "parent")
	if _, _, err := rebuildReport(ctx, js, p, "cp", jobs.StatusSucceeded, ""); err == nil {
		t.Error("want an error when the plan step recorded no result")
	}
}

// End to end across the reboot: a deferred parent whose self child succeeded
// closes green, and one whose self child failed closes red.
func TestResumeSystemUpdates_ClosesTheParent(t *testing.T) {
	for _, c := range []struct {
		name       string
		childState jobs.Status
		want       jobs.Status
	}{
		{"self committed → parent succeeds", jobs.StatusSucceeded, jobs.StatusSucceeded},
		{"self rolled back → parent fails", jobs.StatusFailed, jobs.StatusFailed},
	} {
		t.Run(c.name, func(t *testing.T) {
			const self = "cp"
			ctx := context.Background()
			nc := startNATS(t)
			js := newJobStore(t)
			runner := jobs.NewRunner(js, nc)

			p := seedParent(t, js, "parent")
			seedPlanStep(t, js, p, systemPlanState{
				BundleVer: "v9",
				Targets: []plannedTarget{
					{NodeID: "a", Tier: proto.RoleCompute, Compatible: "rasputin-n100"},
					{NodeID: self, Tier: proto.RoleControlPlane, Compatible: "rasputin-n100"},
				},
				SelfNodeID: self,
			})
			seedChild(t, js, "ca", p, "a", jobs.StatusSucceeded, true)
			// The child is already terminal, as it would be once
			// ResumeSelfUpdates has finished it.
			seedChild(t, js, "cs", p, self, c.childState, true)

			ResumeSystemUpdates(ctx, js, runner, nc, self)

			waitJobStatus(t, js, p, c.want)
		})
	}
}

// The resumed run PUBLISHES the report, and the counts on it are the operator's
// whole picture of a run whose orchestrator rebooted mid-way. Asserted against
// the wire event rather than the internals, because that is what the UI reads.
//
// Also pins the two verdicts that are not "a node failed": a stranded node
// fails the parent even when every child committed, and a planned target that
// was never started is counted as not-attempted rather than as a failure.
func TestResumeSystemUpdates_PublishesTheReport(t *testing.T) {
	const self = "cp"
	ctx := context.Background()
	nc := startNATS(t)
	js := newJobStore(t)
	runner := jobs.NewRunner(js, nc)

	p := seedParent(t, js, "parent")
	seedPlanStep(t, js, p, systemPlanState{
		BundleVer: "v9",
		Targets: []plannedTarget{
			{NodeID: "a", Tier: proto.RoleCompute, Compatible: "rasputin-n100"},
			{NodeID: "never", Tier: proto.RoleCompute, Compatible: "rasputin-n100"},
			{NodeID: self, Tier: proto.RoleControlPlane, Compatible: "rasputin-n100"},
		},
		Skipped: []proto.SkippedNode{
			{NodeID: "arm1", Reason: proto.SkipNoArtifactForArch, Detail: "no artifact"},
		},
		SelfNodeID: self,
	})
	seedChild(t, js, "ca", p, "a", jobs.StatusSucceeded, true)
	seedChild(t, js, "cs", p, self, jobs.StatusSucceeded, true)

	evts := make(chan proto.SystemUpdateChangeEvt, 4)
	sub, err := nc.Subscribe(proto.SystemUpdateChangeSubject(p, proto.SystemUpdateCompleted), func(m *nats.Msg) {
		var ev proto.SystemUpdateChangeEvt
		if json.Unmarshal(m.Data, &ev) == nil {
			evts <- ev
		}
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	ResumeSystemUpdates(ctx, js, runner, nc, self)

	var ev proto.SystemUpdateChangeEvt
	select {
	case ev = <-evts:
	case <-time.After(10 * time.Second):
		t.Fatal("no completed event published within 10s")
	}
	if ev.Counts == nil {
		t.Fatal("completed event carried no counts")
	}
	got := *ev.Counts
	want := proto.SystemUpdateCounts{
		Total: 3, Succeeded: 2, Failed: 0, Skipped: 1, Stranded: 1, NotAttempted: 1,
	}
	if got != want {
		t.Errorf("counts = %+v, want %+v", got, want)
	}
	if len(ev.Results) != 3 {
		t.Errorf("grid rows on the event = %d, want 3", len(ev.Results))
	}
	// Every child committed, but a stranded node means the run did not do what
	// UPDATE ALL says — the parent is red.
	waitJobStatus(t, js, p, jobs.StatusFailed)
}

// A parent whose plan step recorded nothing cannot be reported against. It must
// still reach a terminal state — a deferred job nothing finishes is the exact
// failure the defer test guards the other side of.
func TestResumeSystemUpdates_UnreportableParentStillCloses(t *testing.T) {
	const self = "cp"
	ctx := context.Background()
	nc := startNATS(t)
	js := newJobStore(t)
	runner := jobs.NewRunner(js, nc)

	p := seedParent(t, js, "parent")
	// No plan step seeded, so the rebuild has no targets to report.
	seedChild(t, js, "cs", p, self, jobs.StatusSucceeded, true)

	ResumeSystemUpdates(ctx, js, runner, nc, self)

	waitJobStatus(t, js, p, jobs.StatusFailed)
	j, _ := js.GetJob(ctx, p)
	if j == nil || !strings.Contains(j.Error, "could not rebuild") {
		t.Errorf("job error = %q, want it to name the rebuild failure", j.Error)
	}
}

// ----- fixtures -----------------------------------------------------------

func seedParent(t *testing.T, js *jobs.Store, id string) string {
	t.Helper()
	if err := js.CreateJob(context.Background(), &jobs.Job{
		ID: id, Kind: "system.update", Spec: json.RawMessage(`{"version":"v9"}`),
		Status: jobs.StatusRunning, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateJob parent: %v", err)
	}
	return id
}

// seedChild creates a node.update child of parentID. rebooted controls whether
// it carries a succeeded `reboot` step, which is the signal the defer decision
// keys on.
func seedChild(t *testing.T, js *jobs.Store, id, parentID, nodeID string, status jobs.Status, rebooted bool) {
	t.Helper()
	ctx := context.Background()
	parent := parentID
	if err := js.CreateJob(ctx, &jobs.Job{
		ID: id, Kind: "node.update", Spec: json.RawMessage(specJSON(nodeID, "sha")),
		Status: status, CreatedAt: time.Now().UTC(), ParentID: &parent,
	}); err != nil {
		t.Fatalf("CreateJob child %s: %v", id, err)
	}
	st := jobs.StepRunning
	if rebooted {
		st = jobs.StepSucceeded
	}
	if err := js.CreateStep(ctx, &jobs.JobStep{
		JobID: id, Seq: 4, Name: "reboot", Status: st, Attempt: 1,
	}); err != nil {
		t.Fatalf("CreateStep child %s: %v", id, err)
	}
}

func seedPlanStep(t *testing.T, js *jobs.Store, parentID string, state systemPlanState) {
	t.Helper()
	ctx := context.Background()
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	if err := js.CreateStep(ctx, &jobs.JobStep{
		JobID: parentID, Seq: 0, Name: "plan", Status: jobs.StepRunning, Attempt: 1,
	}); err != nil {
		t.Fatalf("CreateStep plan: %v", err)
	}
	if err := js.MarkStepSucceeded(ctx, parentID, 0, 1, raw, time.Now().UTC()); err != nil {
		t.Fatalf("MarkStepSucceeded plan: %v", err)
	}
}
