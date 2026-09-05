package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// backup.run and the target row tell one story (#398): a fresh health record
// that says MISSING refuses the run at step 1 in the poll's own words; a stale
// one defers to the live preflight, and a preflight that finds the disk gone
// writes that back to the row.

func recordMissing(t *testing.T, st *Store, checkedAt time.Time) proto.BackupTargetHealth {
	t.Helper()
	h, err := st.RecordHealth(context.Background(), runPartUUID, proto.BackupTargetHealth{
		State: proto.BackupTargetHealthMissing, CheckedAt: checkedAt,
		Detail: "nothing attached to " + runNodeID + " carries partition UUID " + runPartUUID + "; nothing is attached at /dev/sdb either",
	})
	if err != nil {
		t.Fatalf("RecordHealth: %v", err)
	}
	return h
}

func TestBackupRunValidateCitesAFreshUnhealthyRecord(t *testing.T) {
	h := newRunHarness(t, &fakeBackupAgent{}, runHarnessOpts{})
	rec := recordMissing(t, h.store, time.Now().UTC().Add(-3*time.Minute))

	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s, want failed", j.Status)
	}
	for _, want := range []string{"MISSING since", "last probe", "nothing is attached at /dev/sdb", "Plug the claimed disk back in"} {
		if !strings.Contains(j.Error, want) {
			t.Errorf("job error = %q, want it to contain %q", j.Error, want)
		}
	}
	if !strings.Contains(j.Error, DescribeHealth(rec)) {
		t.Errorf("the refusal does not cite the row's own sentence:\n  error: %s\n  row:   %s", j.Error, DescribeHealth(rec))
	}
	h.agent.mu.Lock()
	preflights := len(h.agent.preflightCmds)
	h.agent.mu.Unlock()
	if preflights != 0 {
		t.Errorf("the agent was preflighted %d time(s) for a target the poll already found missing", preflights)
	}
	if runs, _ := h.store.ListRunning(context.Background()); len(runs) != 0 {
		t.Errorf("a step-1 refusal left %d running run row(s)", len(runs))
	}
}

func TestBackupRunValidateIgnoresAStaleRecordAndPreflightDecides(t *testing.T) {
	h := newRunHarness(t, &fakeBackupAgent{}, runHarnessOpts{})
	// A record from two hours ago — an api that was down — refuses nothing;
	// the disk may well be back. The live preflight answers, and it is fine.
	recordMissing(t, h.store, time.Now().UTC().Add(-2*time.Hour))

	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s (%s), want succeeded — a stale record must not refuse a run against a disk that answered", j.Status, j.Error)
	}
}

func TestBackupRunPreflightRecordsAMissingTarget(t *testing.T) {
	agent := &fakeBackupAgent{}
	agent.preflight = func(cmd proto.BackupPreflightCmd) proto.BackupPreflightAck {
		return proto.BackupPreflightAck{OK: true, Present: false, PartUUID: cmd.PartUUID}
	}
	h := newRunHarness(t, agent, runHarnessOpts{})
	before, _ := h.store.GetByPartUUID(context.Background(), runPartUUID)
	if before.Health.State != proto.BackupTargetHealthUnknown {
		t.Fatalf("health before the run = %s", before.Health.State)
	}

	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s, want failed", j.Status)
	}
	after, _ := h.store.GetByPartUUID(context.Background(), runPartUUID)
	if after.Health == nil || after.Health.State != proto.BackupTargetHealthMissing {
		t.Fatalf("row health after a preflight that found no disk = %+v, want missing", after.Health)
	}
	if !strings.Contains(after.Health.Detail, "backup preflight") {
		t.Errorf("row detail %q does not say the run found it", after.Health.Detail)
	}
	if !strings.Contains(j.Error, "MISSING since") || !strings.Contains(j.Error, "it was unplugged") {
		t.Errorf("job error = %q, want the preflight refusal to cite the health it just recorded", j.Error)
	}
}

func TestBackupRunValidateAcceptsAnOKRecord(t *testing.T) {
	h := newRunHarness(t, &fakeBackupAgent{}, runHarnessOpts{})
	if _, err := h.store.RecordHealth(context.Background(), runPartUUID, proto.BackupTargetHealth{
		State: proto.BackupTargetHealthOK, CheckedAt: time.Now().UTC(), Detail: "fine",
	}); err != nil {
		t.Fatal(err)
	}
	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	if j := h.waitTerminal(t, jobID); j.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s (%s)", j.Status, j.Error)
	}
}
