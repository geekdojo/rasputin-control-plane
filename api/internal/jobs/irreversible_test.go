package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The saga runner has no compensation: a step's failure terminates the job and
// leaves prior steps as they are. So for a step whose side effect cannot be
// undone, "run it again" is not a recovery strategy — it is the bug. These
// tests are the gate that #395 replaced the prose constraint with.

// An Irreversible step that fails is not retried, and its declaration — not its
// Retries value — is what decides that. Retries is 0 here because Register
// refuses the other combination (see TestRegister_RejectsIrreversibleWithRetries),
// so this pins the runner's behaviour on the path production actually takes.
func TestRunner_Irreversible_NotRetriedOnFailure(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)
	r.SetBackoff(func(int) time.Duration { return 0 })

	var attempts int32
	r.Register(Workflow{
		Kind: "test.irreversible.fail",
		Steps: []WorkflowStep{{
			Name:         "format",
			Timeout:      time.Second,
			Irreversible: true,
			Do: func(*StepCtx) (json.RawMessage, error) {
				atomic.AddInt32(&attempts, 1)
				return nil, errors.New("mkfs: device busy")
			},
		}},
	})

	j, err := r.Submit(context.Background(), "test.irreversible.fail", json.RawMessage(`{}`), "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	done := waitForStatus(t, store, j.ID, StatusFailed, 5*time.Second)
	if done.Error != "mkfs: device busy" {
		t.Errorf("job error = %q, want the step's own error", done.Error)
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("attempts = %d, want exactly 1 — an irreversible step is never re-run", got)
	}
	r.Wait()
}

// Belt-and-braces for a Workflow that never went through Register: the runner
// itself clamps attempts to one rather than trusting registration to have
// caught it. run() is reached here through the registry, so the workflow is
// built with Retries: 0 and the clamp is exercised directly on runStep.
func TestRunner_runStep_IrreversibleClampsAttempts(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)
	r.SetBackoff(func(int) time.Duration { return 0 })

	ctx := context.Background()
	j := makeJob("j-clamp", "k")
	if err := store.CreateJob(ctx, j); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	var attempts int32
	// Retries: 3 on an Irreversible step — the shape Register rejects, reached
	// here by calling runStep directly, which is the only way a bypassed
	// registry could produce it.
	step := WorkflowStep{
		Name:         "burn",
		Timeout:      time.Second,
		Retries:      3,
		Irreversible: true,
		Do: func(*StepCtx) (json.RawMessage, error) {
			atomic.AddInt32(&attempts, 1)
			return nil, errors.New("boom")
		},
	}
	if err := r.runStep(ctx, j, 0, step, nil); err == nil {
		t.Fatal("runStep: want the step's error, got nil")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("attempts = %d, want 1 — Retries must not survive Irreversible", got)
	}
}

// A recorded prior attempt means the side effect may already have happened.
// The runner refuses rather than repeating it, and says so in a way an operator
// and a log sweep can both find.
func TestRunner_Irreversible_RefusesWhenPriorAttemptRecorded(t *testing.T) {
	for _, tc := range []struct {
		name       string
		priorSeq   int
		priorName  string
		priorState StepStatus
	}{
		// The api died mid-install and a resume handler reached the step again.
		{"prior attempt still running", 0, "install", StepRunning},
		// The step ran to completion; a replay would be a second dd.
		{"prior attempt succeeded", 0, "install", StepSucceeded},
		// A failed attempt is the dangerous one: it may have failed AFTER the
		// effect landed. Failure is not evidence that nothing happened.
		{"prior attempt failed", 0, "install", StepFailed},
		// Step list changed between processes, so seq no longer identifies the
		// step. The name still does, and the fail-closed reading wins.
		{"prior attempt under a different seq", 4, "install", StepSucceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			nc := startNATS(t)
			store := newStore(t)
			r := NewRunner(store, nc)

			j := makeJob("j-replay", "k")
			if err := store.CreateJob(ctx, j); err != nil {
				t.Fatalf("CreateJob: %v", err)
			}
			startedAt := time.Now().UTC()
			prior := &JobStep{
				JobID: j.ID, Seq: tc.priorSeq, Name: tc.priorName,
				Status: tc.priorState, StartedAt: &startedAt,
			}
			if err := store.CreateStep(ctx, prior); err != nil {
				t.Fatalf("CreateStep: %v", err)
			}

			var ran int32
			step := WorkflowStep{
				Name:         "install",
				Timeout:      time.Second,
				Irreversible: true,
				Do: func(*StepCtx) (json.RawMessage, error) {
					atomic.AddInt32(&ran, 1)
					return nil, nil
				},
			}
			err := r.runStep(ctx, j, 0, step, nil)
			if err == nil {
				t.Fatal("runStep: want a refusal, got nil")
			}
			if !errors.Is(err, ErrIrreversibleReplay) {
				t.Errorf("error = %v, want ErrIrreversibleReplay", err)
			}
			if !strings.Contains(err.Error(), "jobs: irreversible step refused") {
				t.Errorf("error %q must carry the greppable refusal string", err)
			}
			if !strings.Contains(err.Error(), "install") {
				t.Errorf("error %q must name the step", err)
			}
			if got := atomic.LoadInt32(&ran); got != 0 {
				t.Errorf("Do ran %d times — the whole point is that it does not run at all", got)
			}

			// The prior record is evidence. Refusing must not overwrite it.
			steps, err := store.ListSteps(ctx, j.ID)
			if err != nil {
				t.Fatalf("ListSteps: %v", err)
			}
			if len(steps) != 1 {
				t.Fatalf("ledger holds %d step rows, want the 1 prior record untouched: %+v", len(steps), steps)
			}
			if steps[0].Status != tc.priorState {
				t.Errorf("prior row status = %q, want %q preserved", steps[0].Status, tc.priorState)
			}
		})
	}
}

// A step with no prior record runs normally — the guard must not refuse a
// first attempt, and it must not refuse because some OTHER step of the same job
// is already recorded.
func TestRunner_Irreversible_RunsOnFirstAttempt(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)

	j := makeJob("j-first", "k")
	if err := store.CreateJob(ctx, j); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	startedAt := time.Now().UTC()
	if err := store.CreateStep(ctx, &JobStep{
		JobID: j.ID, Seq: 0, Name: "download", Status: StepSucceeded, StartedAt: &startedAt,
	}); err != nil {
		t.Fatalf("CreateStep: %v", err)
	}

	var ran int32
	step := WorkflowStep{
		Name: "install", Timeout: time.Second, Irreversible: true,
		Do: func(*StepCtx) (json.RawMessage, error) {
			atomic.AddInt32(&ran, 1)
			return json.RawMessage(`{"slot":"B"}`), nil
		},
	}
	if err := r.runStep(ctx, j, 1, step, nil); err != nil {
		t.Fatalf("runStep: %v", err)
	}
	if got := atomic.LoadInt32(&ran); got != 1 {
		t.Errorf("Do ran %d times, want 1", got)
	}
}

// The declaration only binds steps that carry it. A normal step still retries
// per Retries — this is the regression that would turn every saga in the tree
// into a single-attempt saga.
func TestRunner_NormalStep_StillRetriesPerRetries(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)
	r.SetBackoff(func(int) time.Duration { return 0 })

	var attempts int32
	r.Register(Workflow{
		Kind: "test.reversible.retries",
		Steps: []WorkflowStep{{
			Name:    "flaky",
			Timeout: time.Second,
			Retries: 2,
			Do: func(*StepCtx) (json.RawMessage, error) {
				atomic.AddInt32(&attempts, 1)
				return nil, errors.New("nope")
			},
		}},
	})

	j, err := r.Submit(context.Background(), "test.reversible.retries", json.RawMessage(`{}`), "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitForStatus(t, store, j.ID, StatusFailed, 5*time.Second)
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("attempts = %d, want 3 (1 initial + 2 retries)", got)
	}
	r.Wait()
}

// A reversible step is not subject to the prior-attempt refusal either. Only
// the declaration turns that on.
func TestRunner_ReversibleStep_NotRefusedByPriorAttempt(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)

	j := makeJob("j-rev", "k")
	if err := store.CreateJob(ctx, j); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	startedAt := time.Now().UTC()
	if err := store.CreateStep(ctx, &JobStep{
		JobID: j.ID, Seq: 0, Name: "poll", Status: StepFailed, StartedAt: &startedAt,
	}); err != nil {
		t.Fatalf("CreateStep: %v", err)
	}

	var ran int32
	step := WorkflowStep{
		Name: "poll", Timeout: time.Second,
		Do: func(*StepCtx) (json.RawMessage, error) {
			atomic.AddInt32(&ran, 1)
			return nil, nil
		},
	}
	if err := r.runStep(ctx, j, 0, step, nil); err != nil {
		t.Fatalf("runStep: %v", err)
	}
	if got := atomic.LoadInt32(&ran); got != 1 {
		t.Errorf("Do ran %d times, want 1 — the refusal must be opt-in", got)
	}
}

// Register is the fail-closed half: Irreversible + Retries is a programming
// error, and the api refuses to come up rather than quietly meaning something
// other than what the workflow says.
func TestRegister_RejectsIrreversibleWithRetries(t *testing.T) {
	bad := Workflow{
		Kind: "test.bad",
		Steps: []WorkflowStep{
			{Name: "ok"},
			{Name: "format", Retries: 2, Irreversible: true},
		},
	}

	err := ValidateWorkflow(bad)
	if err == nil {
		t.Fatal("ValidateWorkflow: want an error for Irreversible + Retries")
	}
	for _, want := range []string{"test.bad", "format", "Irreversible"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must name %q so the fix is obvious from the panic alone", err, want)
		}
	}

	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)
	func() {
		defer func() {
			p := recover()
			if p == nil {
				t.Fatal("Register: want a panic on an invalid workflow")
			}
			perr, ok := p.(error)
			if !ok || !strings.Contains(perr.Error(), "Irreversible") {
				t.Fatalf("panic value = %v, want the validation error", p)
			}
		}()
		r.Register(bad)
	}()

	// And the workflow must not be half-registered by the panic.
	if _, ok := r.workflowFor("test.bad"); ok {
		t.Error("a rejected workflow must not end up in the registry")
	}
}

// Irreversible with Retries: 0 is the shape production uses and must register.
func TestRegister_AcceptsIrreversibleWithoutRetries(t *testing.T) {
	if err := ValidateWorkflow(Workflow{
		Kind:  "test.good",
		Steps: []WorkflowStep{{Name: "install", Irreversible: true}},
	}); err != nil {
		t.Errorf("ValidateWorkflow: %v", err)
	}
}
