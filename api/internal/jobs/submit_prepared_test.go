package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// SubmitPrepared exists so input a job needs, but must not carry in its spec,
// is stored under the job's id before the job can read it. Submit starts the
// job before it returns, so the ordering is the whole contract.
func TestRunner_SubmitPrepared_PreparesBeforeTheFirstStepRuns(t *testing.T) {
	store := newStore(t)
	r := NewRunner(store, startNATS(t))

	var (
		mu       sync.Mutex
		held     = map[string]string{}
		sawInput string
	)
	r.Register(Workflow{
		Kind: "test.prepared",
		Steps: []WorkflowStep{{Name: "read", Timeout: time.Second, Do: func(sc *StepCtx) (json.RawMessage, error) {
			mu.Lock()
			defer mu.Unlock()
			sawInput = held[sc.JobID]
			return nil, nil
		}}},
	})

	var preparedFor string
	j, err := r.SubmitPrepared(context.Background(), "test.prepared", json.RawMessage(`{}`), "test", func(jobID string) error {
		// The job must not be recorded yet: a job that exists can be run.
		if got, _ := store.GetJob(context.Background(), jobID); got != nil {
			t.Errorf("job %s was recorded before prepare ran", jobID)
		}
		mu.Lock()
		held[jobID] = "the input"
		mu.Unlock()
		preparedFor = jobID
		return nil
	})
	if err != nil {
		t.Fatalf("SubmitPrepared: %v", err)
	}
	r.Wait()
	if preparedFor != j.ID {
		t.Errorf("prepare saw id %q, the job is %q", preparedFor, j.ID)
	}
	if sawInput != "the input" {
		t.Errorf("the first step read %q, want what prepare stored", sawInput)
	}
	if got, _ := store.GetJob(context.Background(), j.ID); got == nil || got.Status != StatusSucceeded {
		t.Errorf("job = %+v, want succeeded", got)
	}
}

func TestRunner_SubmitPrepared_APrepareErrorCreatesNoJob(t *testing.T) {
	store := newStore(t)
	r := NewRunner(store, startNATS(t))
	r.Register(Workflow{Kind: "test.prepared", Steps: []WorkflowStep{{Name: "x", Timeout: time.Second,
		Do: func(*StepCtx) (json.RawMessage, error) {
			t.Error("a job whose prepare failed must not run")
			return nil, nil
		}}}})

	boom := errors.New("could not hold the input")
	if _, err := r.SubmitPrepared(context.Background(), "test.prepared", nil, "test", func(string) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want prepare's", err)
	}
	r.Wait()
	if js, _ := store.ListJobs(context.Background(), 10); len(js) != 0 {
		t.Errorf("a failed prepare left %d jobs", len(js))
	}

	// An unknown kind is refused before prepare is asked to store anything.
	called := false
	if _, err := r.SubmitPrepared(context.Background(), "test.nope", nil, "test", func(string) error { called = true; return nil }); err == nil {
		t.Error("an unknown kind must be refused")
	}
	if called {
		t.Error("prepare ran for a kind that will never run")
	}
}
