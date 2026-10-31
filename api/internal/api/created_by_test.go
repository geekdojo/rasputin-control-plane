package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
)

// noopSecretDeleter and readyStoreState are the app.delete saga's secret-store
// collaborators for endpoint tests, which never reach the store.
type noopSecretDeleter struct{}

func (noopSecretDeleter) Delete(context.Context, secrets.Actor, secrets.Ref) error { return nil }

type readyStoreState struct{}

func (readyStoreState) Configured() bool { return true }
func (readyStoreState) State(context.Context) (storestate.State, error) {
	return storestate.Ready, nil
}

// deleteWorkflowForTest is the app.delete workflow over f's stores.
func deleteWorkflowForTest(t *testing.T, f *apiFixture) jobs.Workflow {
	t.Helper()
	w, err := apps.DeleteWorkflow(f.appsStore, f.inv, f.nc, nil, apps.DeleteSecretsDeps{
		Secrets: noopSecretDeleter{}, Store: readyStoreState{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("DeleteWorkflow: %v", err)
	}
	return w
}

// jobCreatedBy reads job id back from the job store and returns its creator.
func jobCreatedBy(t *testing.T, f *apiFixture, body string) string {
	t.Helper()
	job := decodeBody[jobs.Job](t, body)
	got, err := f.jobsStore.GetJob(f.ctx, job.ID)
	if err != nil || got == nil {
		t.Fatalf("GetJob %s: %v", job.ID, err)
	}
	return got.CreatedBy
}

// TC-783-17: DELETE /api/apps/{id} records the session's user as the job's
// creator, not the "user" placeholder.
func TestDeleteApp_TC783_17_RecordsTheOperator(t *testing.T) {
	f, cookie, _ := volumesFixture(t)
	seedVolumesApp(t, f, volULIDLive, "immich")
	f.runner.Register(deleteWorkflowForTest(t, f))
	w := f.do(t, http.MethodDelete, "/api/apps/"+volULIDLive, "", cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("delete: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	if got := jobCreatedBy(t, f, w.Body.String()); got != "alice" {
		t.Errorf("app.delete created_by = %q, want alice", got)
	}
	f.runner.Wait()
}

// F-783-03: POST /api/jobs records the session's user as the job's creator.
func TestCreateJob_F783_03_RecordsTheOperator(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	f.runner.Register(jobs.Workflow{Kind: "test.createdby", Steps: []jobs.WorkflowStep{{
		Name: "a", Timeout: time.Second, Do: func(*jobs.StepCtx) (json.RawMessage, error) { return nil, nil },
	}}})
	w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"test.createdby","spec":{}}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /api/jobs: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	if got := jobCreatedBy(t, f, w.Body.String()); got != "alice" {
		t.Errorf("created_by = %q, want alice", got)
	}
	f.runner.Wait()
}
