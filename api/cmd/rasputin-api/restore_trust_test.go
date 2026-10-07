package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nodetrust"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
)

// restoreJobs is a job runner and store in one: Submit records the kind and
// each job then reads back as the test set it up.
type restoreJobs struct {
	mu        sync.Mutex
	submitted []string
	submitErr map[string]error
	status    map[string]jobs.Status // by kind; absent = still running
	jobErr    map[string]string
	steps     map[string][]*jobs.JobStep
}

func (r *restoreJobs) Submit(_ context.Context, kind string, _ any, by string) (*jobs.Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.submitErr[kind]; err != nil {
		return nil, err
	}
	if by != "restore-trust" {
		return nil, errors.New("unexpected creator " + by)
	}
	r.submitted = append(r.submitted, kind)
	return &jobs.Job{ID: kind, Kind: kind, Status: jobs.StatusQueued}, nil
}

func (r *restoreJobs) GetJob(_ context.Context, id string) (*jobs.Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.status[id]
	if !ok {
		st = jobs.StatusRunning
	}
	return &jobs.Job{ID: id, Kind: id, Status: st, Error: r.jobErr[id]}, nil
}

func (r *restoreJobs) ListSteps(_ context.Context, id string) ([]*jobs.JobStep, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.steps[id], nil
}

func convergeStep(t *testing.T, res nodetrust.ConvergeResult) []*jobs.JobStep {
	t.Helper()
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return []*jobs.JobStep{{Name: "converge", Result: raw}}
}

type restoreRun struct {
	jobs    *restoreJobs
	records []storage.TrustRedeliveryRecord
	logs    *recordsHandler
}

var restoreClock = time.Date(2026, 10, 7, 9, 30, 0, 0, time.UTC)

func runRestoreKick(t *testing.T, rj *restoreJobs, meshReady bool) *restoreRun {
	t.Helper()
	r := &restoreRun{jobs: rj, logs: &recordsHandler{}}
	var mu sync.Mutex
	kickTrustConvergenceAfterRestore(context.Background(), restoreTrustDeps{
		Log:    slog.New(r.logs),
		Now:    func() time.Time { return restoreClock },
		Submit: rj.Submit,
		Jobs:   rj,
		Record: func(_ context.Context, id string, rec *storage.TrustRedeliveryRecord) error {
			if id != "rep-1" {
				t.Errorf("recorded against %q", id)
			}
			mu.Lock()
			defer mu.Unlock()
			r.records = append(r.records, *rec)
			return nil
		},
		MeshReady:    func() bool { return meshReady },
		Fingerprint:  func() string { return "fp-restored" },
		Settle:       0,
		JobDeadline:  10 * time.Millisecond,
		MeshDeadline: 10 * time.Millisecond,
	}, "rep-1")
	return r
}

func (r *restoreRun) last(t *testing.T) storage.TrustRedeliveryRecord {
	t.Helper()
	if len(r.records) == 0 {
		t.Fatal("nothing recorded")
	}
	rec := r.records[len(r.records)-1]
	if !rec.CheckedAt.Equal(restoreClock) {
		t.Errorf("CheckedAt %v, want the injected clock %v", rec.CheckedAt, restoreClock)
	}
	return rec
}

// TC-741-22: the restore hook kicks trust.converge and records its result;
// with legacy agents it also kicks mesh.reconcile once the mesh is ready;
// every failure lands in Detail; logs go through the injected logger and
// CheckedAt is the injected clock.
func TestKickTrustConvergenceAfterRestore(t *testing.T) {
	converged := nodetrust.ConvergeResult{CAFingerprint: "fp-restored", Redelivered: []string{"c1"}, Stale: []string{"c1"},
		Current: []string{"cp"}, Unreported: []string{}, Skipped: map[string]int{}}
	legacy := converged
	legacy.Skipped = map[string]int{"legacy_agent": 2}

	t.Run("no legacy agents", func(t *testing.T) {
		rj := &restoreJobs{status: map[string]jobs.Status{nodetrust.ConvergeKind: jobs.StatusSucceeded},
			steps: map[string][]*jobs.JobStep{nodetrust.ConvergeKind: convergeStep(t, converged)}}
		r := runRestoreKick(t, rj, true)
		if strings.Join(rj.submitted, ",") != nodetrust.ConvergeKind {
			t.Errorf("submitted %v, want trust.converge alone", rj.submitted)
		}
		rec := r.last(t)
		if rec.CAFingerprint != "fp-restored" || strings.Join(rec.Redelivered, ",") != "c1" || strings.Join(rec.Current, ",") != "cp" || rec.Detail != "" {
			t.Errorf("record %+v", rec)
		}
		if len(r.logs.matching(slog.LevelInfo, "restored controlplane CA delivered")) != 1 {
			t.Error("no INFO record through the injected logger")
		}
	})

	t.Run("legacy agents: mesh.reconcile after the mesh is ready", func(t *testing.T) {
		rj := &restoreJobs{
			status: map[string]jobs.Status{nodetrust.ConvergeKind: jobs.StatusSucceeded, "mesh.reconcile": jobs.StatusSucceeded},
			steps: map[string][]*jobs.JobStep{nodetrust.ConvergeKind: convergeStep(t, legacy),
				"mesh.reconcile": {{Name: "converge_trust", Result: json.RawMessage(`{}`)}}},
		}
		r := runRestoreKick(t, rj, true)
		if strings.Join(rj.submitted, ",") != nodetrust.ConvergeKind+",mesh.reconcile" {
			t.Errorf("submitted %v", rj.submitted)
		}
		if rec := r.last(t); rec.Detail != "" || rec.Skipped["legacy_agent"] != 2 {
			t.Errorf("record %+v", rec)
		}
	})

	t.Run("trust.converge cannot be submitted", func(t *testing.T) {
		rj := &restoreJobs{submitErr: map[string]error{nodetrust.ConvergeKind: errors.New("runner closed")}}
		r := runRestoreKick(t, rj, true)
		rec := r.last(t)
		if !strings.Contains(rec.Detail, "could not submit the post-restore trust.converge") || rec.CAFingerprint != "fp-restored" {
			t.Errorf("record %+v", rec)
		}
		if len(r.logs.matching(slog.LevelWarn, "did not run")) != 1 {
			t.Error("no WARN record")
		}
	})

	t.Run("trust.converge does not finish", func(t *testing.T) {
		rj := &restoreJobs{}
		r := runRestoreKick(t, rj, true)
		if rec := r.last(t); !strings.Contains(rec.Detail, "did not finish within") {
			t.Errorf("record %+v", rec)
		}
	})

	t.Run("legacy agents, mesh never ready", func(t *testing.T) {
		rj := &restoreJobs{status: map[string]jobs.Status{nodetrust.ConvergeKind: jobs.StatusSucceeded},
			steps: map[string][]*jobs.JobStep{nodetrust.ConvergeKind: convergeStep(t, legacy)}}
		r := runRestoreKick(t, rj, false)
		if len(r.records) != 2 {
			t.Fatalf("%d records, want the pass and then the bridge failure", len(r.records))
		}
		rec := r.last(t)
		if !strings.Contains(rec.Detail, "mesh was not ready") || strings.Join(rec.Redelivered, ",") != "c1" {
			t.Errorf("record %+v", rec)
		}
		if strings.Join(rj.submitted, ",") != nodetrust.ConvergeKind {
			t.Errorf("submitted %v, want no mesh.reconcile", rj.submitted)
		}
	})

	t.Run("legacy agents, mesh.reconcile fails", func(t *testing.T) {
		rj := &restoreJobs{
			status: map[string]jobs.Status{nodetrust.ConvergeKind: jobs.StatusSucceeded, "mesh.reconcile": jobs.StatusFailed},
			jobErr: map[string]string{"mesh.reconcile": "headscale down"},
			steps:  map[string][]*jobs.JobStep{nodetrust.ConvergeKind: convergeStep(t, legacy)},
		}
		r := runRestoreKick(t, rj, true)
		if rec := r.last(t); !strings.Contains(rec.Detail, "did not complete") || !strings.Contains(rec.Detail, "headscale down") {
			t.Errorf("record %+v", rec)
		}
	})
}
