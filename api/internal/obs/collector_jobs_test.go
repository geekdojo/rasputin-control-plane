package obs

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

func TestScanNodeJobs(t *testing.T) {
	base := time.Now().UTC()
	mk := func(id string, status jobs.Status, ageMin int) *jobs.Job {
		spec, _ := json.Marshal(CollectorNodeSpec{NodeID: id})
		return &jobs.Job{Spec: spec, Status: status, CreatedAt: base.Add(-time.Duration(ageMin) * time.Minute)}
	}
	// Newest-first, as ListJobsByKind returns.
	js := []*jobs.Job{
		mk("c01", jobs.StatusRunning, 1),   // inflight
		mk("c02", jobs.StatusSucceeded, 5), // newest success
		mk("c02", jobs.StatusSucceeded, 90),
		mk("c03", jobs.StatusFailed, 10),
		{Spec: json.RawMessage(`{"nodeId":""}`), Status: jobs.StatusSucceeded, CreatedAt: base}, // no node id — ignored
	}
	st := scanNodeJobs(js)

	if !st["c01"].inflight {
		t.Errorf("c01 should be inflight")
	}
	if st["c02"].lastSuccess != base.Add(-5*time.Minute) {
		t.Errorf("c02 lastSuccess: got %v, want %v", st["c02"].lastSuccess, base.Add(-5*time.Minute))
	}
	if st["c03"].lastFailedAt != base.Add(-10*time.Minute) {
		t.Errorf("c03 lastFailedAt: got %v", st["c03"].lastFailedAt)
	}
	if _, ok := st[""]; ok {
		t.Errorf("empty node id should be ignored")
	}
}

func TestDecideCollectorActions(t *testing.T) {
	now := time.Now().UTC()
	online := now                        // gap ~0 -> StatusOnline
	offline := now.Add(-5 * time.Minute) // gap 5m -> StatusOffline

	// nodeJobState builders relative to `now`.
	successAgo := func(d time.Duration) *nodeJobState { return &nodeJobState{lastSuccess: now.Add(-d)} }
	failedAgo := func(d time.Duration) *nodeJobState { return &nodeJobState{lastFailedAt: now.Add(-d)} }
	inflight := func() *nodeJobState { return &nodeJobState{inflight: true} }

	tests := []struct {
		name         string
		role         proto.NodeRole
		lastSeen     time.Time
		on           bool
		deploy       *nodeJobState
		teardown     *nodeJobState
		wantDeploy   bool
		wantTeardown bool
		wantSkip     string // "" = expect no skip tally
	}{
		// ---- obs ON: converge collectors onto online compute/storage ----
		{"on: fresh compute, no history -> deploy", proto.RoleCompute, online, true, nil, nil, true, false, ""},
		{"on: storage, no history -> deploy", proto.RoleStorage, online, true, nil, nil, true, false, ""},
		{"on: recent success -> fresh skip", proto.RoleCompute, online, true, successAgo(time.Minute), nil, false, false, "fresh"},
		// disable->re-enable: deploy was recent, but a teardown ran AFTER it, so
		// the collector is down. Must redeploy (with the current config), NOT skip
		// as "fresh". Regression guard for the off->on stuck-collector bug.
		{"on: recent deploy but torn down since -> redeploy", proto.RoleCompute, online, true,
			successAgo(2 * time.Minute), successAgo(30 * time.Second), true, false, ""},
		{"on: stale success -> redeploy", proto.RoleCompute, online, true, successAgo(7 * time.Hour), nil, true, false, ""},
		{"on: inflight -> skip", proto.RoleCompute, online, true, inflight(), nil, false, false, "inflight"},
		{"on: recent failure -> cooldown", proto.RoleCompute, online, true, failedAgo(5 * time.Minute), nil, false, false, "cooldown"},
		{"on: old failure -> retry deploy", proto.RoleCompute, online, true, failedAgo(45 * time.Minute), nil, true, false, ""},
		{"on: offline -> skip", proto.RoleCompute, offline, true, nil, nil, false, false, "offline"},
		{"on: controlplane not targeted", proto.RoleControlPlane, online, true, nil, nil, false, false, ""},
		{"on: firewall not targeted", proto.RoleFirewall, online, true, nil, nil, false, false, ""},

		// ---- obs OFF: tear collectors down ----
		{"off: has collector -> teardown", proto.RoleCompute, online, false, successAgo(time.Hour), nil, false, true, ""},
		{"off: no collector -> nothing", proto.RoleCompute, online, false, nil, nil, false, false, ""},
		{"off: teardown after deploy -> gone, nothing",
			proto.RoleCompute, online, false, successAgo(2 * time.Hour), successAgo(time.Hour), false, false, ""},
		{"off: deploy after teardown -> still has one -> teardown",
			proto.RoleCompute, online, false, successAgo(time.Hour), successAgo(2 * time.Hour), false, true, ""},
		{"off: has collector but offline -> skip", proto.RoleCompute, offline, false, successAgo(time.Hour), nil, false, false, "offline"},
		{"off: teardown inflight -> skip", proto.RoleCompute, online, false, successAgo(time.Hour), inflight(), false, false, "inflight"},
		{"off: teardown recently failed -> cooldown",
			proto.RoleCompute, online, false, successAgo(time.Hour), failedAgo(5 * time.Minute), false, false, "cooldown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes := []*proto.Node{{ID: "n1", Role: tt.role, LastSeen: tt.lastSeen}}
			depState := map[string]*nodeJobState{}
			tearState := map[string]*nodeJobState{}
			if tt.deploy != nil {
				depState["n1"] = tt.deploy
			}
			if tt.teardown != nil {
				tearState["n1"] = tt.teardown
			}
			act := decideCollectorActions(nodes, depState, tearState, tt.on, now)

			gotDeploy := contains(act.deploy, "n1")
			gotTeardown := contains(act.teardown, "n1")
			if gotDeploy != tt.wantDeploy {
				t.Errorf("deploy: got %v, want %v", gotDeploy, tt.wantDeploy)
			}
			if gotTeardown != tt.wantTeardown {
				t.Errorf("teardown: got %v, want %v", gotTeardown, tt.wantTeardown)
			}
			if tt.wantSkip != "" && act.skipped[tt.wantSkip] == 0 {
				t.Errorf("expected skip %q, got tally %v", tt.wantSkip, act.skipped)
			}
			if tt.wantSkip == "" && len(act.skipped) != 0 {
				t.Errorf("expected no skips, got %v", act.skipped)
			}
		})
	}
}

// A multi-node pass mixes roles and states in one call.
func TestDecideCollectorActions_MixedFleet(t *testing.T) {
	now := time.Now().UTC()
	nodes := []*proto.Node{
		{ID: "c01", Role: proto.RoleCompute, LastSeen: now},                       // deploy
		{ID: "c02", Role: proto.RoleStorage, LastSeen: now},                       // fresh -> skip
		{ID: "fw", Role: proto.RoleFirewall, LastSeen: now},                       // not targeted
		{ID: "cp", Role: proto.RoleControlPlane, LastSeen: now},                   // not targeted
		{ID: "c03", Role: proto.RoleCompute, LastSeen: now.Add(-5 * time.Minute)}, // offline -> skip
	}
	depState := map[string]*nodeJobState{
		"c02": {lastSuccess: now.Add(-time.Minute)},
	}
	act := decideCollectorActions(nodes, depState, map[string]*nodeJobState{}, true, now)

	if len(act.deploy) != 1 || act.deploy[0] != "c01" {
		t.Errorf("deploy: got %v, want [c01]", act.deploy)
	}
	if act.skipped["fresh"] != 1 || act.skipped["offline"] != 1 {
		t.Errorf("skips: got %v, want fresh=1 offline=1", act.skipped)
	}
}

func TestCollectorWorkflowKinds(t *testing.T) {
	if got := CollectorReconcileWorkflow(CollectorReconcileDeps{}).Kind; got != CollectorReconcileKind {
		t.Errorf("reconcile kind: %q", got)
	}
	if got := CollectorDeployWorkflow(CollectorDeployDeps{}).Kind; got != CollectorDeployKind {
		t.Errorf("deploy kind: %q", got)
	}
	if got := CollectorTeardownWorkflow().Kind; got != CollectorTeardownKind {
		t.Errorf("teardown kind: %q", got)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
