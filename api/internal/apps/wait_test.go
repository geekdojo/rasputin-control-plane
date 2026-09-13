package apps

import (
	"testing"
	"time"
)

// waitDeadline bounds every wait on a fake agent. Each wait normally finishes
// in milliseconds; a regression that never delivers fails the test after this
// long, naming what never happened.
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
