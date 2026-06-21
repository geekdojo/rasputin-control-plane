package jobs

import (
	"context"
	"testing"
	"time"
)

// A RecoverDecider returning RecoverDefer leaves the job running for a resume
// handler (e.g. the control-plane self-update), while everything else still
// fails per the default abort policy.
func TestRunner_Recover_DeferKeepsJobRunning(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)
	r.SetRecoverDecider(func(j *Job, _ []*JobStep) RecoverDecision {
		if j.ID == "j-defer" {
			return RecoverDefer
		}
		return RecoverFail
	})

	for _, id := range []string{"j-defer", "j-fail"} {
		if err := store.CreateJob(ctx, makeJob(id, "k")); err != nil {
			t.Fatalf("CreateJob %s: %v", id, err)
		}
		if err := store.MarkJobStarted(ctx, id, time.Now().UTC()); err != nil {
			t.Fatalf("mark started %s: %v", id, err)
		}
	}

	if err := r.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}

	if d, _ := store.GetJob(ctx, "j-defer"); d == nil || d.Status != StatusRunning {
		t.Errorf("j-defer: want running (deferred), got %+v", d)
	}
	if f, _ := store.GetJob(ctx, "j-fail"); f == nil || f.Status != StatusFailed {
		t.Errorf("j-fail: want failed, got %+v", f)
	}
}
