package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// A job in flight holds the runner open; once it ends, QuiesceIfIdle closes
// intake, and a submit after that is refused before anything is written.
func TestQuiesceIfIdle_WaitsForInFlightThenRefusesSubmits(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)

	release := make(chan struct{})
	entered := make(chan struct{})
	r.Register(Workflow{Kind: "block", Steps: []WorkflowStep{{
		Name: "wait",
		Do: func(*StepCtx) (json.RawMessage, error) {
			close(entered)
			<-release
			return nil, nil
		},
	}}})
	r.Register(Workflow{Kind: "noop", Steps: []WorkflowStep{{
		Name: "noop",
		Do:   func(*StepCtx) (json.RawMessage, error) { return nil, nil },
	}}})

	j, err := r.Submit(ctx, "block", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	ok, inFlight, err := r.QuiesceIfIdle(ctx)
	if err != nil || ok || len(inFlight) != 1 {
		t.Fatalf("QuiesceIfIdle with a running job = (%t, %v, %v), want refused naming it", ok, inFlight, err)
	}
	if _, err := r.Submit(ctx, "noop", nil, "test"); err != nil {
		t.Fatalf("intake closed by a refused quiesce: %v", err)
	}

	close(release)
	waitForStatus(t, store, j.ID, StatusSucceeded, 5*time.Second)
	r.Wait()
	ok, inFlight, err = r.QuiesceIfIdle(ctx)
	if err != nil || !ok {
		t.Fatalf("QuiesceIfIdle when idle = (%t, %v, %v), want ok", ok, inFlight, err)
	}

	before, err := store.ListJobs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Submit(ctx, "noop", nil, "test"); !errors.Is(err, ErrQuiesced) {
		t.Fatalf("Submit after quiesce = %v, want ErrQuiesced", err)
	}
	after, err := store.ListJobs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("a refused submit wrote a job row (%d → %d)", len(before), len(after))
	}

	r.Reopen()
	if _, err := r.Submit(ctx, "noop", nil, "test"); err != nil {
		t.Fatalf("Submit after Reopen: %v", err)
	}
}

// A job the ledger holds as running but this runner never started — a
// self-update deferred across a restart — also holds quiesce back.
func TestQuiesceIfIdle_LedgerJobsCount(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	r := NewRunner(store, startNATS(t))
	now := time.Now().UTC()
	if err := store.CreateJob(ctx, &Job{ID: "deferred-1", Kind: "node.update", Spec: json.RawMessage("{}"), Status: StatusQueued, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkJobStarted(ctx, "deferred-1", now); err != nil {
		t.Fatal(err)
	}
	ok, inFlight, err := r.QuiesceIfIdle(ctx)
	if err != nil || ok || len(inFlight) != 1 || inFlight[0] != "node.update deferred-1" {
		t.Fatalf("QuiesceIfIdle = (%t, %v, %v), want refused by the ledger job", ok, inFlight, err)
	}
	if err := store.MarkJobSucceeded(ctx, "deferred-1", now); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := r.QuiesceIfIdle(ctx); !ok || err != nil {
		t.Fatalf("QuiesceIfIdle after the ledger job ended = (%t, %v)", ok, err)
	}
}
