package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TC-783-16: a step sees the job's submitter as sc.CreatedBy.
func TestRunner_TC783_16_StepSeesTheSubmitter(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)
	got := make(chan string, 1)
	r.Register(Workflow{
		Kind: "test.createdby",
		Steps: []WorkflowStep{{Name: "a", Timeout: time.Second, Do: func(sc *StepCtx) (json.RawMessage, error) {
			got <- sc.CreatedBy
			return nil, nil
		}}},
	})
	if _, err := r.Submit(context.Background(), "test.createdby", nil, "alice"); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	r.Wait()
	select {
	case who := <-got:
		if who != "alice" {
			t.Errorf("sc.CreatedBy = %q, want alice", who)
		}
	default:
		t.Fatal("the step never ran")
	}
}
