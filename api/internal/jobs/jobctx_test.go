package jobs

import (
	"context"
	"testing"
)

// TC-760-11 (the jobs half, F-760-03): the job id a step puts on its ctx is
// the one a collaborator reads back, and a ctx without one reads "".
func TestJobIDContext(t *testing.T) {
	ctx := ContextWithJobID(context.Background(), "job-7")
	if got := JobIDFromContext(ctx); got != "job-7" {
		t.Fatalf("JobIDFromContext = %q, want job-7", got)
	}
	if got := JobIDFromContext(context.Background()); got != "" {
		t.Fatalf("JobIDFromContext(no id) = %q, want empty", got)
	}
}
