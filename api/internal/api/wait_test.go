package api

import (
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// waitDeadline bounds every wait on a fake agent or the job runner. Each wait
// normally finishes in milliseconds; a regression that never delivers fails
// the test after this long, naming what never happened.
const waitDeadline = 5 * time.Second

// receiveWithin returns the next value on ch, or fails the test if none
// arrives within waitDeadline.
func receiveWithin[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(waitDeadline):
		t.Fatalf("%s within %v", what, waitDeadline)
		var zero T
		return zero
	}
}

// waitForJobs returns once every job the runner started has finished, or
// fails the test if that takes longer than waitDeadline.
func waitForJobs(t *testing.T, r *jobs.Runner) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		r.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(waitDeadline):
		t.Fatalf("jobs still running after %v", waitDeadline)
	}
}
