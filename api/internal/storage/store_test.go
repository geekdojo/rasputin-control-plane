package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

func TestParseClaimSpec(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "complete", body: `{"nodeId":"n","devicePath":"/dev/sdb","fingerprint":"fp"}`},
		{name: "not json", body: `{`, wantErr: "invalid spec"},
		{name: "no node", body: `{"devicePath":"/dev/sdb","fingerprint":"fp"}`, wantErr: "nodeId is required"},
		{name: "no device", body: `{"nodeId":"n","fingerprint":"fp"}`, wantErr: "devicePath is required"},
		{
			// proto/storage.go is explicit that an empty fingerprint is a
			// refusal and not a wildcard. Enforced here so a blank never
			// reaches the wire at all.
			name: "no fingerprint", body: `{"nodeId":"n","devicePath":"/dev/sdb"}`,
			wantErr: "fingerprint is required",
		},
		{
			name:    "half a key",
			body:    `{"nodeId":"n","devicePath":"/dev/sdb","fingerprint":"fp","archiveKey":{"keyId":"k","wrappedByPassphrase":"a"}}`,
			wantErr: "wrappedByRecoveryCode",
		},
		{
			name: "a whole key",
			body: `{"nodeId":"n","devicePath":"/dev/sdb","fingerprint":"fp","archiveKey":{"keyId":"k","wrappedByPassphrase":"a","wrappedByRecoveryCode":"b"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseClaimSpec(json.RawMessage(tc.body))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want an error mentioning %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// ============================================================================
// The OnTerminal hook — the #53 lesson, applied to backup_targets.
// ============================================================================

func seedPending(t *testing.T, store *Store, jobID string) {
	t.Helper()
	if err := store.CreatePending(context.Background(), jobID, testNode, testDevice, "disk", time.Now().UTC()); err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
}

func TestFinalizeTargetRow_FailedJobFinalizesTheRow(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	seedPending(t, store, "j")

	finalizeTargetRow(store)(ctx, "j", false, "enumerate refused [protected]")

	row, _ := store.GetByJob(ctx, "j")
	if row.Status != TargetFailed {
		t.Errorf("status = %q, want %q", row.Status, TargetFailed)
	}
	if row.Error == "" {
		t.Error("a failed row with no error tells the operator nothing about why")
	}
	if row.ClaimedAt == nil {
		t.Error("a terminal row with no finish time renders as still-running")
	}
}

// The guard that makes the hook safe to fire on every terminal transition,
// success included: a `claimed` row is the verdict step 5 recorded, and a job
// that also failed later must not relabel it.
func TestFinalizeTargetRow_NeverOverwritesAVerdict(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	seedPending(t, store, "j")
	if err := store.MarkClaimed(ctx, "j", ClaimResult{PartUUID: "pu", At: time.Now().UTC()}); err != nil {
		t.Fatalf("MarkClaimed: %v", err)
	}

	finalizeTargetRow(store)(ctx, "j", false, "something later went wrong")

	row, _ := store.GetByJob(ctx, "j")
	if row.Status != TargetClaimed {
		t.Errorf("status = %q, want the recorded verdict %q preserved", row.Status, TargetClaimed)
	}
}

func TestFinalizeTargetRow_NoRowIsANoOp(t *testing.T) {
	store := newStore(t)
	finalizeTargetRow(store)(context.Background(), "no-such-job", false, "boom")
	if row, _ := store.GetByJob(context.Background(), "no-such-job"); row != nil {
		t.Errorf("hook invented a row: %+v", row)
	}
}

// A job that succeeded with its row still pending means a step ended the saga
// without recording a target. Say so rather than inventing one that does not
// exist on any disk.
func TestFinalizeTargetRow_SucceededButUnrecordedStillGetsAnOutcome(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	seedPending(t, store, "j")

	finalizeTargetRow(store)(ctx, "j", true, "")

	row, _ := store.GetByJob(ctx, "j")
	if row.Status == TargetPending {
		t.Fatal("row left pending — this is the #53 bug")
	}
	if row.Error == "" {
		t.Error("want an explanation that the job ended without recording a target")
	}
}

// The startup sweep reaches rows the hook cannot: stranded by a process that
// died between failing the job and firing it. It decides only from a job that
// has already reached a terminal state, never from a clock — a real claim takes
// up to fifteen minutes and a timeout reaper would fail live ones.
func TestReconcileStrandedRows(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "recon.db")

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
			ID: id, Kind: ClaimJobKind, Spec: []byte(`{}`),
			Status: jobs.StatusQueued, CreatedBy: "test", CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("CreateJob %s: %v", id, err)
		}
		switch status {
		case jobs.StatusFailed:
			_ = jobStore.MarkJobFailed(ctx, id, "step failed", time.Now().UTC())
		case jobs.StatusRunning:
			_ = jobStore.MarkJobStarted(ctx, id, time.Now().UTC())
		}
	}

	mkJob("stranded", jobs.StatusFailed)
	seedPending(t, store, "stranded")
	mkJob("slow", jobs.StatusRunning)
	seedPending(t, store, "slow")

	if err := ReconcileStrandedRows(ctx, store, jobStore); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	stranded, _ := store.GetByJob(ctx, "stranded")
	if stranded.Status != TargetFailed {
		t.Errorf("stranded row status = %q, want %q", stranded.Status, TargetFailed)
	}
	if stranded.Error == "" {
		t.Error("want the job's own error carried onto the row")
	}
	slow, _ := store.GetByJob(ctx, "slow")
	if slow.Status != TargetPending {
		t.Errorf("running job's row = %q — a claim in progress must not be reaped", slow.Status)
	}
}

// ============================================================================
// Store
// ============================================================================

func TestStore_MarkClaimedRequiresAPendingRow(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	if err := store.MarkClaimed(ctx, "nope", ClaimResult{PartUUID: "pu", At: time.Now().UTC()}); err == nil {
		t.Error("claiming a job with no pending row should fail rather than silently do nothing")
	}
}

func TestStore_GetByPartUUIDFindsOnlyClaimedTargets(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	seedPending(t, store, "j")
	if row, err := store.GetByPartUUID(ctx, "pu"); err != nil || row != nil {
		t.Errorf("a pending row is not a target yet: %+v (%v)", row, err)
	}
	if err := store.MarkClaimed(ctx, "j", ClaimResult{PartUUID: "pu", At: time.Now().UTC()}); err != nil {
		t.Fatalf("MarkClaimed: %v", err)
	}
	row, err := store.GetByPartUUID(ctx, "pu")
	if err != nil {
		t.Fatalf("GetByPartUUID: %v", err)
	}
	if row == nil || row.JobID != "j" {
		t.Errorf("want the claimed row back, got %+v", row)
	}
	if row, _ := store.GetByPartUUID(ctx, ""); row != nil {
		t.Error("an empty partition UUID matches nothing")
	}
}

func TestStore_MarkReplacedOnlyTouchesClaimedRows(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	seedPending(t, store, "j")
	if err := store.MarkReplaced(ctx, "j", time.Now().UTC()); err != nil {
		t.Fatalf("MarkReplaced: %v", err)
	}
	row, _ := store.GetByJob(ctx, "j")
	if row.Status != TargetPending {
		t.Errorf("a pending claim is not something to supersede: %q", row.Status)
	}
}
