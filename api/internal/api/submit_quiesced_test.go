package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// While job intake is closed for the bus switch to TLS-only, every endpoint
// that submits a job answers 503 with Retry-After — not the 400 a bad request
// gets — and records nothing; once intake reopens the same request succeeds.
// POST /api/jobs, and two of the endpoints the UI submits through (every such
// endpoint answers through writeSubmitError).
func TestSubmitWhileIntakeClosed_Is503ThenSucceeds(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	noop := []jobs.WorkflowStep{{Name: "noop", Do: func(*jobs.StepCtx) (json.RawMessage, error) { return nil, nil }}}
	f.runner.Register(jobs.Workflow{Kind: "probe", Steps: noop})
	// The fixture registers no workflows; no-ops stand in (the kind must
	// exist, or the submit is refused as unknown before intake is checked).
	for _, kind := range []string{"firewall.apply", "mesh.reconcile"} {
		f.runner.Register(jobs.Workflow{Kind: kind, Steps: noop})
	}

	ok, inFlight, err := f.runner.QuiesceIfIdle(f.ctx)
	if err != nil || !ok {
		t.Fatalf("QuiesceIfIdle = (%t, %v, %v)", ok, inFlight, err)
	}
	for _, path := range []string{"/api/jobs", "/api/firewall/apply", "/api/mesh/reconcile"} {
		body := ""
		if path == "/api/jobs" {
			body = `{"kind":"probe","spec":{}}`
		}
		w := f.do(t, http.MethodPost, path, body, c)
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
			t.Errorf("POST %s with intake closed = %d (Retry-After %q) %s, want 503 with Retry-After", path, w.Code, w.Header().Get("Retry-After"), w.Body.String())
		}
	}
	if rows, err := f.jobsStore.ListJobs(f.ctx, 10); err != nil || len(rows) != 0 {
		t.Fatalf("refused submits recorded %d job(s) (err %v)", len(rows), err)
	}

	f.runner.Reopen()
	w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"probe","spec":{}}`, c)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /api/jobs after intake reopened = %d %s, want 201", w.Code, w.Body.String())
	}
	f.runner.Wait()
}
