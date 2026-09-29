package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// TC-517-22: job intake has no quiesce. Concurrent submits through the api are
// each accepted: none answers 503, and none carries Retry-After — the refusal
// that existed only while the bus was switched to TLS-only
// (geekdojo/geekdojo-brain#517).
func TestConcurrentSubmits_NoQuiesce(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	noop := []jobs.WorkflowStep{{Name: "noop", Do: func(*jobs.StepCtx) (json.RawMessage, error) { return nil, nil }}}
	f.runner.Register(jobs.Workflow{Kind: "probe", Steps: noop})

	const n = 16
	type result struct {
		code       int
		retryAfter string
	}
	results := make(chan result, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"probe","spec":{}}`, c)
			results <- result{w.Code, w.Header().Get("Retry-After")}
		}()
	}
	wg.Wait()
	close(results)
	for r := range results {
		if r.code != http.StatusCreated {
			t.Errorf("a concurrent submit answered %d, want 201", r.code)
		}
		if r.retryAfter != "" {
			t.Errorf("a concurrent submit carried Retry-After %q", r.retryAfter)
		}
	}
	f.runner.Wait()
	rows, err := f.jobsStore.ListJobs(f.ctx, n+1)
	if err != nil || len(rows) != n {
		t.Fatalf("%d job(s) recorded (err %v), want %d", len(rows), err, n)
	}
}
