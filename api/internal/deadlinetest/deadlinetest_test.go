package deadlinetest

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Before Fire the deadline has not passed; after it, the context and a child
// derived from it both report a deadline, not a cancellation, and a second
// Fire is harmless.
func TestManual_FiresOnlyWhenTold(t *testing.T) {
	d := New()
	child, cancel := context.WithTimeout(d, time.Hour)
	defer cancel()

	select {
	case <-d.Done():
		t.Fatal("Done is closed before Fire")
	default:
	}
	if err := d.Err(); err != nil {
		t.Fatalf("Err before Fire = %v, want nil", err)
	}
	if err := child.Err(); err != nil {
		t.Fatalf("child Err before Fire = %v, want nil", err)
	}

	d.Fire()
	d.Fire()

	<-d.Done()
	if err := d.Err(); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Err after Fire = %v, want context.DeadlineExceeded", err)
	}
	<-child.Done()
	if err := child.Err(); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("child Err after Fire = %v, want context.DeadlineExceeded", err)
	}
}
