package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// TC-978-20: a kind registered with System is refused over POST /api/jobs
// with the coded 403, the sentence and a correlation id, a WARN record under
// that id naming the kind, and no job row and no step run. Runner.Submit of
// the same kind still creates the job, and a non-system kind posted the same
// way still answers 201.
func TestHandleCreateJob_RefusesASystemKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	ran := make(chan string, 4)
	step := []jobs.WorkflowStep{{Name: "run", Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
		ran <- sc.JobID
		return nil, nil
	}}}
	const systemKind = "identity.recover_admin"
	f.runner.Register(jobs.Workflow{Kind: systemKind, Steps: step, System: true})
	f.runner.Register(jobs.Workflow{Kind: "diag.ping", Steps: noopSteps})

	w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"`+systemKind+`"}`, c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST a system kind: %d %s, want 403", w.Code, w.Body.String())
	}
	var e codedError
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if e.Code != "job_system_only" || e.CorrelationID == "" {
		t.Errorf("body = %+v, want code job_system_only and a correlation id", e)
	}
	if e.Error != "This job runs only when the system starts it." {
		t.Errorf("message = %q, want the sentence", e.Error)
	}
	recs := f.logs.withAttr("correlation_id", e.CorrelationID)
	if len(recs) != 1 || len(f.logs.withAttr("kind", systemKind)) != 1 {
		t.Errorf("want one WARN record under the correlation id naming the kind, got %d", len(recs))
	}
	if got, err := f.jobsStore.ListJobsByKind(f.ctx, systemKind, 10); err != nil || len(got) != 0 {
		t.Fatalf("job rows of the system kind after the refusal: %d (%v), want 0", len(got), err)
	}

	// Submit from Go is the system starting it: the job is created and runs.
	j, err := f.runner.Submit(f.ctx, systemKind, nil, "system")
	if err != nil {
		t.Fatalf("Runner.Submit of the system kind: %v", err)
	}
	f.runner.Wait()
	if len(ran) != 1 || <-ran != j.ID {
		t.Error("the system kind's step did not run exactly once, for the Submit")
	}

	w = f.do(t, http.MethodPost, "/api/jobs", `{"kind":"diag.ping"}`, c)
	if w.Code != http.StatusCreated {
		t.Errorf("POST a non-system kind: %d %s, want 201", w.Code, w.Body.String())
	}
	f.runner.Wait()
}
