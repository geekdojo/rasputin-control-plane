package updater

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

func TestSelfUpdateRecoverDecider(t *testing.T) {
	const self = "cp"
	rebootDoneStep := []*jobs.JobStep{{Name: "install", Status: jobs.StepSucceeded}, {Name: "reboot", Status: jobs.StepSucceeded}}
	preReboot := []*jobs.JobStep{{Name: "install", Status: jobs.StepSucceeded}, {Name: "reboot", Status: jobs.StepRunning}}

	cases := []struct {
		name  string
		kind  string
		node  string
		self  string
		steps []*jobs.JobStep
		want  jobs.RecoverDecision
	}{
		{"self past reboot → defer", "node.update", self, self, rebootDoneStep, jobs.RecoverDefer},
		{"self before reboot → fail", "node.update", self, self, preReboot, jobs.RecoverFail},
		{"other node → fail", "node.update", "compute1", self, rebootDoneStep, jobs.RecoverFail},
		{"other kind → fail", "firewall.apply", self, self, rebootDoneStep, jobs.RecoverFail},
		{"no selfNodeID → fail", "node.update", self, "", rebootDoneStep, jobs.RecoverFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			decide := SelfUpdateRecoverDecider(c.self)
			j := &jobs.Job{Kind: c.kind, Spec: json.RawMessage(specJSON(c.node, "sha"))}
			if got := decide(j, c.steps); got != c.want {
				t.Errorf("decide = %v, want %v", got, c.want)
			}
		})
	}
}

// fakeAgentForSelfUpdate answers the three RPCs the reconciler issues: precheck
// (booted slot), diag.ping (health), and mark-good (commit).
func fakeAgentForSelfUpdate(t *testing.T, nc *nats.Conn, nodeID string, bootedSlot proto.UpdateSlot) {
	t.Helper()
	subs := []*nats.Subscription{}
	pre, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{OK: true, ActiveSlot: bootedSlot, InactiveSlot: proto.SlotA, CurrentVersion: "v1"})
		_ = m.Respond(ack)
	})
	ping, _ := nc.Subscribe(proto.NodeCmdSubject(nodeID, "diag.ping"), func(m *nats.Msg) {
		_ = m.Respond([]byte(`{"ok":true}`))
	})
	good, _ := nc.Subscribe(proto.UpdateMarkGoodSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdateMarkGoodAck{OK: true})
		_ = m.Respond(ack)
	})
	subs = append(subs, pre, ping, good)
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
}

func seedSelfUpdateJob(t *testing.T, jobStore *jobs.Store, store *Store, jobID, nodeID, sha string) {
	t.Helper()
	ctx := context.Background()
	if err := jobStore.CreateJob(ctx, &jobs.Job{
		ID: jobID, Kind: "node.update", Spec: json.RawMessage(specJSON(nodeID, sha)),
		Status: jobs.StatusRunning, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := jobStore.CreateStep(ctx, &jobs.JobStep{JobID: jobID, Seq: 4, Name: "reboot", Status: jobs.StepSucceeded, Attempt: 1}); err != nil {
		t.Fatalf("CreateStep: %v", err)
	}
	if err := store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: jobID, NodeID: nodeID, BundleSHA256: sha,
		FromSlot: proto.SlotA, ToSlot: proto.SlotB, ToVersion: "v1",
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateNodeUpdate: %v", err)
	}
}

func waitJobStatus(t *testing.T, jobStore *jobs.Store, jobID string, want jobs.Status) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, err := jobStore.GetJob(context.Background(), jobID)
		if err == nil && j != nil && j.Status == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	j, _ := jobStore.GetJob(context.Background(), jobID)
	got := jobs.Status("<nil>")
	if j != nil {
		got = j.Status
	}
	t.Fatalf("job %s status = %q, want %q", jobID, got, want)
}

func newJobStore(t *testing.T) *jobs.Store {
	t.Helper()
	js, err := jobs.OpenStore(context.Background(), t.TempDir()+"/jobs.db")
	if err != nil {
		t.Fatalf("jobs OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = js.Close() })
	return js
}

// ResumeSelfUpdates finds the deferred self-update, reconciles it, and commits
// when the box came up on the target slot — closing the job succeeded with no
// human step.
func TestResumeSelfUpdates_CommitsOnNewSlot(t *testing.T) {
	const self, sha, jid = "cp", "abc123", "selfjob-commit"
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	jobStore := newJobStore(t)
	runner := jobs.NewRunner(jobStore, nc)

	seedSelfUpdateJob(t, jobStore, store, jid, self, sha)
	fakeAgentForSelfUpdate(t, nc, self, proto.SlotB) // booted the NEW slot

	ResumeSelfUpdates(ctx, store, jobStore, runner, nc, self)

	waitJobStatus(t, jobStore, jid, jobs.StatusSucceeded)
	row, _ := store.GetNodeUpdate(ctx, jid)
	if row == nil || row.Status != NodeUpdateCommitted {
		t.Errorf("node_update status = %+v, want committed", row)
	}
}

// If the box came up on the OLD slot (bootloader auto-rolled-back), the
// reconciler records the rollback and fails the job.
func TestReconcileSelfUpdate_RollbackOnOldSlot(t *testing.T) {
	const self, sha, jid = "cp", "abc123", "selfjob-rollback"
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	jobStore := newJobStore(t)
	runner := jobs.NewRunner(jobStore, nc)

	seedSelfUpdateJob(t, jobStore, store, jid, self, sha)
	fakeAgentForSelfUpdate(t, nc, self, proto.SlotA) // came up on the OLD slot

	reconcileSelfUpdate(ctx, store, runner, nc, UpdateSpec{NodeID: self, BundleSHA256: sha}, jid)

	waitJobStatus(t, jobStore, jid, jobs.StatusFailed)
	row, _ := store.GetNodeUpdate(ctx, jid)
	if row == nil || row.Status != NodeUpdateRolledBack {
		t.Errorf("node_update status = %+v, want rolled_back", row)
	}
}
