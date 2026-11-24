package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// TC-979-03, TC-1001-06: POST /api/jobs refuses the identity kinds. The two
// os.identity_* outcome kinds and identity.service_exit are recorded by the
// api from facts and are never submittable, so they answer 403
// job_not_submittable;
// identity.recover is registered System (as identityStateWiring registers it
// under keycloak), so it answers 403 job_system_only with a correlation id.
// No job row is created for any of them.
func TestHandleCreateJob_RefusesTheIdentityKinds(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	f.runner.Register(jobs.Workflow{Kind: "identity.recover", Steps: noopSteps, System: true})

	for _, kind := range []string{"os.identity_db_init", "os.identity_rollback", "identity.service_exit"} {
		w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"`+kind+`"}`, c)
		var e codedError
		if w.Code != http.StatusForbidden || json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Code != "job_not_submittable" {
			t.Errorf("POST %s: %d %s, want 403 job_not_submittable", kind, w.Code, w.Body.String())
		}
	}
	w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"identity.recover"}`, c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST identity.recover: %d %s, want 403", w.Code, w.Body.String())
	}
	var e codedError
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if e.Code != "job_system_only" || e.CorrelationID == "" {
		t.Errorf("body = %+v, want job_system_only and a correlation id", e)
	}
	for _, kind := range []string{"os.identity_db_init", "os.identity_rollback", "identity.service_exit", "identity.recover"} {
		if got, err := f.jobsStore.ListJobsByKind(f.ctx, kind, 10); err != nil || len(got) != 0 {
			t.Errorf("%s job rows after the refusal: %d (%v), want 0", kind, len(got), err)
		}
	}
}
