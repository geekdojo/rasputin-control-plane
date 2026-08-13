package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// ADR-0005 Decision 5. The hook has to fire from EVERY terminal transition,
// because the bug it fixes (#53) is precisely a path where nothing fired: a
// step failure marked the job failed and never touched the state the workflow
// owns. One missed transition reintroduces the whole class.

type terminalCall struct {
	jobID   string
	success bool
	errMsg  string
}

type terminalRecorder struct {
	mu    sync.Mutex
	calls []terminalCall
}

func (rec *terminalRecorder) hook(_ context.Context, jobID string, success bool, errMsg string) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.calls = append(rec.calls, terminalCall{jobID, success, errMsg})
}

func (rec *terminalRecorder) snapshot() []terminalCall {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]terminalCall(nil), rec.calls...)
}

func TestOnTerminal_FiresOnSuccessAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		stepErr     error
		wantSuccess bool
	}{
		{"success", nil, true},
		{"failure", errors.New("install: no space left"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			nc := startNATS(t)
			store := newStore(t)
			r := NewRunner(store, nc)
			r.SetBackoff(func(int) time.Duration { return time.Millisecond })

			rec := &terminalRecorder{}
			r.Register(Workflow{
				Kind: "k",
				Steps: []WorkflowStep{{
					Name:    "only",
					Timeout: 2 * time.Second,
					Do:      func(*StepCtx) (json.RawMessage, error) { return nil, tc.stepErr },
				}},
				OnTerminal: rec.hook,
			})

			j, err := r.Submit(ctx, "k", json.RawMessage(`{}`), "test")
			if err != nil {
				t.Fatalf("Submit: %v", err)
			}
			r.Wait()

			calls := rec.snapshot()
			if len(calls) != 1 {
				t.Fatalf("hook fired %d times, want exactly 1: %+v", len(calls), calls)
			}
			if calls[0].jobID != j.ID {
				t.Errorf("jobID = %q, want %q", calls[0].jobID, j.ID)
			}
			if calls[0].success != tc.wantSuccess {
				t.Errorf("success = %v, want %v", calls[0].success, tc.wantSuccess)
			}
			if !tc.wantSuccess && calls[0].errMsg == "" {
				t.Error("a failure must carry its reason — the row shows it to the operator")
			}
		})
	}
}

// An orphan is the case the hook matters most for: nothing else will ever run
// for this job, so state the workflow owns is stranded unless Recover finalizes
// it. This is the api-restart-mid-update path.
func TestOnTerminal_FiresForRecoveredOrphans(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)

	rec := &terminalRecorder{}
	r.Register(Workflow{Kind: "k", Steps: []WorkflowStep{{Name: "s"}}, OnTerminal: rec.hook})

	if err := store.CreateJob(ctx, makeJob("orphan", "k")); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := store.MarkJobStarted(ctx, "orphan", time.Now().UTC()); err != nil {
		t.Fatalf("MarkJobStarted: %v", err)
	}

	if err := r.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}

	calls := rec.snapshot()
	if len(calls) != 1 || calls[0].jobID != "orphan" || calls[0].success {
		t.Fatalf("want one failed-orphan call, got %+v", calls)
	}
}

// FinishDeferred is a terminal transition the ADR's list of hook sites predates
// — it arrived with the self-update resume path. A deferred job that a resume
// handler FAILS strands its workflow state exactly as a step failure would.
func TestOnTerminal_FiresFromFinishDeferred(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)

	rec := &terminalRecorder{}
	r.Register(Workflow{Kind: "k", Steps: []WorkflowStep{{Name: "s"}}, OnTerminal: rec.hook})

	if err := store.CreateJob(ctx, makeJob("deferred", "k")); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := store.MarkJobStarted(ctx, "deferred", time.Now().UTC()); err != nil {
		t.Fatalf("MarkJobStarted: %v", err)
	}

	r.FinishDeferred(ctx, "deferred", false, "verify: node never came back")

	calls := rec.snapshot()
	if len(calls) != 1 || calls[0].success || calls[0].errMsg == "" {
		t.Fatalf("want one failed call carrying its reason, got %+v", calls)
	}
}

// A workflow without a hook is the overwhelmingly common case and must not
// change behaviour at all.
func TestOnTerminal_AbsentHookIsHarmless(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)
	r.Register(Workflow{Kind: "k", Steps: []WorkflowStep{{
		Name: "only", Timeout: time.Second,
		Do: func(*StepCtx) (json.RawMessage, error) { return nil, nil },
	}}})

	j, err := r.Submit(ctx, "k", json.RawMessage(`{}`), "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	r.Wait()
	if got, _ := store.GetJob(ctx, j.ID); got == nil || got.Status != StatusSucceeded {
		t.Errorf("job status = %+v, want succeeded", got)
	}
}

// The hook is workflow-owned code running on the runner's goroutine after the
// ledger is already consistent. A panic there must not unwind into the runner
// or make a correctly-recorded job look like a crash.
func TestOnTerminal_PanicDoesNotEscape(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)
	r.Register(Workflow{
		Kind: "k",
		Steps: []WorkflowStep{{
			Name: "only", Timeout: time.Second,
			Do: func(*StepCtx) (json.RawMessage, error) { return nil, nil },
		}},
		OnTerminal: func(context.Context, string, bool, string) { panic("hook exploded") },
	})

	j, err := r.Submit(ctx, "k", json.RawMessage(`{}`), "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	r.Wait() // must not panic

	if got, _ := store.GetJob(ctx, j.ID); got == nil || got.Status != StatusSucceeded {
		t.Errorf("job status = %+v, want succeeded — the ledger was already correct before the hook ran", got)
	}
}
