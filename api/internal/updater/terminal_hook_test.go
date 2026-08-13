package updater

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// #53: the per-node row only ever reached a terminal status on the
// verify/commit path, so a saga that failed at download, install, or verify
// left it reading in_progress forever while the job was correctly failed. The
// Updates page then rendered a failed run as one still in progress.
// Bench-reproduced on e3bench 2026-08-12 by a firewall update that failed
// conjunct (c) at step 5.

func seedInProgress(t *testing.T, store *Store, jobID string) {
	t.Helper()
	if err := store.CreateNodeUpdate(context.Background(), &NodeUpdate{
		JobID: jobID, NodeID: "n", BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB,
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateNodeUpdate: %v", err)
	}
}

func TestFinalizeNodeUpdateRow_FailedJobFinalizesTheRow(t *testing.T) {
	store := newStoreFixture(t).store
	ctx := context.Background()
	seedInProgress(t, store, "j")

	finalizeNodeUpdateRow(store)(ctx, "j", false, "download: connection reset")

	row, _ := store.GetNodeUpdate(ctx, "j")
	if row.Status != NodeUpdateFailed {
		t.Errorf("status = %q, want %q", row.Status, NodeUpdateFailed)
	}
	if row.Error == "" {
		t.Error("a failed row with no error tells the operator nothing about why")
	}
	if row.FinishedAt == nil {
		t.Error("a terminal row must have a finish time — the History table renders its absence as still-running")
	}
}

// The guard that makes the hook safe to fire on EVERY terminal transition.
// A rolled_back row is a verdict, and relabelling it `failed` because the job
// also ended in error would destroy exactly the distinction the verify contract
// exists to draw (#58: "has not rebooted yet" and "rebooted and fell back" are
// opposites).
func TestFinalizeNodeUpdateRow_NeverOverwritesAVerdict(t *testing.T) {
	ctx := context.Background()
	for _, verdict := range []NodeUpdateStatus{NodeUpdateCommitted, NodeUpdateRolledBack} {
		t.Run(string(verdict), func(t *testing.T) {
			store := newStoreFixture(t).store
			seedInProgress(t, store, "j")
			if err := store.UpdateNodeUpdate(ctx, "j", verdict, proto.SlotB, "v2", "", time.Now().UTC()); err != nil {
				t.Fatalf("seed verdict: %v", err)
			}

			finalizeNodeUpdateRow(store)(ctx, "j", false, "job failed later")

			row, _ := store.GetNodeUpdate(ctx, "j")
			if row.Status != verdict {
				t.Errorf("status = %q, want the original verdict %q preserved", row.Status, verdict)
			}
		})
	}
}

// A job with no per-node row at all (system.update, or any other kind) must be
// a no-op rather than an error or a spurious insert.
func TestFinalizeNodeUpdateRow_NoRowIsANoOp(t *testing.T) {
	store := newStoreFixture(t).store
	finalizeNodeUpdateRow(store)(context.Background(), "no-such-job", false, "boom")
	if row, _ := store.GetNodeUpdate(context.Background(), "no-such-job"); row != nil {
		t.Errorf("hook invented a row: %+v", row)
	}
}

// Succeeding with the row still in_progress means a step ended the workflow
// without recording an outcome. That is a real gap and the row should say so
// rather than silently claiming success.
func TestFinalizeNodeUpdateRow_SucceededButUnrecordedStillGetsAnOutcome(t *testing.T) {
	store := newStoreFixture(t).store
	ctx := context.Background()
	seedInProgress(t, store, "j")

	finalizeNodeUpdateRow(store)(ctx, "j", true, "")

	row, _ := store.GetNodeUpdate(ctx, "j")
	if row.Status == NodeUpdateInProgress {
		t.Fatal("row left in_progress — this is the #53 bug")
	}
	if row.Error == "" {
		t.Error("want an explanation that the job ended without a per-node outcome")
	}
}

// The startup sweep is what reaches rows stranded BEFORE the hook existed —
// including the one this bench session created. It must decide from job state
// only, never from a clock: a legitimately slow install must survive it.
func TestReconcileStrandedRows(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "recon.db")

	store, err := OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	jobStore, err := jobs.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	defer func() { _ = jobStore.Close() }()

	mkJob := func(id string, status jobs.Status) {
		t.Helper()
		if err := jobStore.CreateJob(ctx, &jobs.Job{
			ID: id, Kind: "node.update", Spec: []byte(`{}`),
			Status: jobs.StatusQueued, CreatedBy: "test", CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("CreateJob %s: %v", id, err)
		}
		switch status {
		case jobs.StatusFailed:
			_ = jobStore.MarkJobFailed(ctx, id, "step failed", time.Now().UTC())
		case jobs.StatusSucceeded:
			_ = jobStore.MarkJobSucceeded(ctx, id, time.Now().UTC())
		case jobs.StatusRunning:
			_ = jobStore.MarkJobStarted(ctx, id, time.Now().UTC())
		}
	}

	mkJob("stranded", jobs.StatusFailed)
	seedInProgress(t, store, "stranded")
	mkJob("slow", jobs.StatusRunning)
	seedInProgress(t, store, "slow")

	if err := ReconcileStrandedRows(ctx, store, jobStore); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	stranded, _ := store.GetNodeUpdate(ctx, "stranded")
	if stranded.Status != NodeUpdateFailed {
		t.Errorf("stranded row status = %q, want %q", stranded.Status, NodeUpdateFailed)
	}
	if stranded.Error == "" {
		t.Error("want the job's own error carried onto the row")
	}

	slow, _ := store.GetNodeUpdate(ctx, "slow")
	if slow.Status != NodeUpdateInProgress {
		t.Errorf("running job's row = %q — a genuinely slow install must not be reaped; deciding this from a clock is exactly what ADR-0005 Decision 5 rules out", slow.Status)
	}
}
